# How rotation works

Rotating keys is easy; rotating them without breaking anyone is the hard part,
because two parties cache keys:

- **The OpenID Connect server caches your client's JWKS** (fetched from its
  `jwks_uri`). It can only verify a signature, or encrypt to you, with a key
  it has already cached.
- **Your server caches the parameter.** For a while after a rotation it may
  still sign with the previous key, or receive tokens encrypted to it.

`JwksParameter` keeps up to 3 keys and moves each one through a fixed lifecycle,
one step per rotation (every 28 days by default), so that neither cache ever
needs a key that is missing. The lifecycle is the same as `cdk-jwks-secret`'s;
this page repeats it so that it stands alone.

In the timelines below, `*` marks a key that still has its private part.

## Signing keys (`sig`)

| Day | Keys in the parameter | Published | Your server signs with |
| --- | --------------------- | --------- | ---------------------- |
| 0   | `[A*, B*]`            | A, B      | A                      |
| 28  | `[A, B*, C*]`         | A, B, C   | B                      |
| 56  | `[B, C*, D*]`         | B, C, D   | C                      |
| 84  | `[C, D*, E*]`         | C, D, E   | D                      |

Each key goes through three stages:

1. **Next:** added at the end and published, but not used yet. It spends a
   whole rotation interval in the JWKS, so the OpenID Connect server has
   cached it before its first use.
2. **Signing:** the first key with a private part.
3. **Retired:** its private part is removed, but it stays published for one
   more interval, so assertions signed by a server still holding the previous
   value keep verifying. At the next rotation it is dropped.

Day 0 is the exception: both keys are new, so the OpenID Connect server has
not cached either of them. That doesn't matter for a new client, because the
server fetches a client's JWKS the first time it needs it.

## Encryption keys (`enc`)

| Day | Keys in the parameter | Published | Your server decrypts with |
| --- | --------------------- | --------- | ------------------------- |
| 0   | `[A*, B*]`            | A, B      | A, B                      |
| 28  | `[A*, B*, C*]`        | B, C      | A, B, C                   |
| 56  | `[B*, C*, D*]`        | C, D      | B, C, D                   |

Here the OpenID Connect server chooses which published key to encrypt to, so
the rule is reversed: a key is **unpublished one interval before its private
part is deleted**. During that interval the server can no longer pick it from
a fresh JWKS, but anything it encrypted to it from a cached JWKS still
decrypts. Every key in the parameter keeps its private part; your server
decrypts with whichever key the JWE's `kid` names.

## Why 3 keys

Two are enough to start, but not to rotate safely. A `sig` key needs a retired,
a signing and a next slot at the same time. With 2 you would have to drop
either the retired key, and a server with a stale cache would sign with a key
that is no longer published, or the next key, and a new key would start signing
before the OpenID Connect server has cached it. An `enc` key needs its
unpublished interval for the same reason. The count is fixed.

## Timing rules

The lifecycle only works if rotations are far enough apart:

- **Rotation interval > the OpenID Connect server's JWKS cache lifetime.**
  Otherwise a `sig` key can start signing before the server has cached it,
  and an `enc` key can be deleted while the server still encrypts to it.
- **Rotation interval > how long your server caches the parameter.** See
  [Using the keys](using-the-keys.md).
- **Don't rotate twice within the OpenID Connect server's JWKS cache
  lifetime.** Each rotation moves every key one stage on, so two quick
  rotations skip the waiting periods above.

The last rule is enforced, not just documented. A scheduled rotation is
**skipped** when the parameter was modified less than half a rotation interval
ago, which makes a duplicate delivery from Lambda's retries a no-op. To rotate
sooner on purpose, invoke the rotation Lambda with `force`:

```sh
aws lambda invoke --function-name <rotation-lambda> \
  --cli-binary-format raw-in-base64-out \
  --payload '{"action":"rotate","force":true}' response.json
```

Unlike the Secrets Manager construct, changing the schedule does not rotate:
rotation happens only when the schedule fires or when you force it. The
parameter is created before the schedule. EventBridge Scheduler fires a new
schedule shortly after it is created (about 45 seconds in a test deployment),
and that invocation is skipped because the parameter was just created; the
log has a `skip_rotation` event with `event.reason: rotated_recently`. Without
the minimum age, every deployment would rotate its keys at once.

## What the rotation Lambda does

One Lambda serves two kinds of event.

**CloudFormation custom resource** (`Create`, `Update`, `Delete`). CloudFormation
cannot create a `SecureString` parameter, so the Lambda does.

| Request  | What it does                                                                                                                                                                                                                            |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Create` | Creates the parameter with 2 new keys, or adopts an existing parameter whose keys have the configured options.                                                                                                                          |
| `Update` | Checks the parameter, and creates it if it was deleted. It never rotates, and fails if the keys no longer match the options. CloudFormation only sends it when a property of the resource changes (the name, tier, key or key options). |
| `Delete` | Deletes the parameter. CloudFormation only sends this when the removal policy is `DESTROY`; with `RETAIN` the parameter stays.                                                                                                          |

The Lambda sends the response to CloudFormation itself, with a 2 minute service
timeout, so a crash fails the deployment instead of hanging it.

**Scheduled rotation.** EventBridge Scheduler invokes the Lambda with
`{"action":"rotate"}`. It reads the parameter, validates it, computes the next
JWKS, checks that it is exactly the rotation of the current one (the kept keys
unchanged and in order, the retired `sig` key stripped of its private part, and
one new key) and writes it with a single `PutParameter`.

The Lambda logs key ids only, never key material. See [Logging](logging.md).

## What differs from `cdk-jwks-secret`

Secrets Manager rotation is a four step protocol with staging labels, so a
rotation is built as a pending version and promoted only after it is tested.
Parameter Store has none of that:

- **There is no pending version.** The new JWKS is validated in memory and then
  written once. A failed rotation leaves the parameter untouched because
  nothing was written, not because a pending version was discarded.
- **There is no rotation lock.** The construct sets the Lambda's reserved
  concurrency to 1, so two rotations never run at once, and the
  [minimum age](#timing-rules) absorbs duplicate deliveries.
- **Old versions are kept.** Every write keeps the previous version (up to
  100), and `ssm:GetParameter` can read one by its version. A retired `sig`
  key's private part is removed from the current value but is still in the
  older versions. See [Using the keys](using-the-keys.md#old-versions).
- **There is no `LastRotatedDate`.** Check the parameter's `LastModifiedDate`,
  or alarm on the log events; see [Logging](logging.md#alarms).

## When a rotation fails

A failed rotation never changes the current parameter: your server and the
OpenID Connect server carry on with the existing keys. The error is in the
rotation Lambda's log group. Lambda retries the invocation twice (after about
1 minute and again after about 2 minutes), then sends the event to the
construct's dead letter queue, with the error message as a message attribute.
Once the cause is fixed, rotate again with the `force` invocation above.

### A deleted parameter

A scheduled rotation never recreates a parameter that was deleted by hand: it
fails with `parameter_not_found` on each attempt, and the event ends up in the
dead letter queue, so the deletion is noticed instead of silently replacing
the keys. Recreating the parameter generates new keys, so you do it on purpose,
with a forced rotation:

```sh
aws lambda invoke --function-name <rotation-lambda> \
  --cli-binary-format raw-in-base64-out \
  --payload '{"action":"rotate","force":true}' response.json
```

When the parameter is missing, `force` creates it with 2 new keys, as a first
deployment does, and logs `create_parameter` with `event.reason: recreated`.
When it exists, `force` rotates it as usual. A plain redeploy does not recreate
the parameter, because CloudFormation only calls the custom resource on a stack
create or when one of its properties changes.

## Changing the key options

The key options (`use`, `algorithm`, `curve`, `rsaModulusLength`) can't be
changed on an existing parameter. If they no longer match the keys in the
parameter, the next rotation, and a deployment, fails with an error listing the
differences. To change them, create a new `JwksParameter` (a new construct id),
register its JWKS with the OpenID Connect server, and switch your server over to
it.

## See also

- [README](../README.md): props, including the supported algorithms, the
  parameter tier and the AWS resources it creates
- [Using the keys](using-the-keys.md): serving the JWKS and signing or
  decrypting with the keys
- [Logging](logging.md): the events and how to alarm on them
