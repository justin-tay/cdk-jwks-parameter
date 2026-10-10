# Logging

The rotation Lambda writes one JSON record per event to its CloudWatch Logs
log group (`JwksParameter.rotationLogGroup`), in the
[Elastic Common Schema](https://www.elastic.co/docs/reference/ecs) (ECS) 8.11.
This page describes what is logged and how to consume it: the
[schema](#logging-schema), the [event reference](#event-reference) and how to
[query and alert on the logs](#consuming-the-logs).

The records are the function's own account of what it decided: which keys a
rotation added and retired, why a rotation was skipped, and why one failed.
AWS CloudTrail records who called the Systems Manager APIs, but not those
decisions.

The schema is the one `cdk-jwks-secret` uses, with the Secrets Manager rotation
steps replaced by the events below. This package does not ship a Splunk CIM
mapping or an OWASP Logging Cheat Sheet control implementation; the field names
and event actions are the ones those documents in `cdk-jwks-secret` describe,
except where this page differs.

## Where the logs go

- **Log group.** The construct creates the log group and grants the rotation
  role write access to it only. It keeps logs for one year
  (`RetentionDays.ONE_YEAR`) and follows the parameter's removal policy
  (`RETAIN` by default). Override `retention`, `removalPolicy` and
  `encryptionKey` with `rotationLogGroupProps`.
- **Format.** The construct sets Lambda's Text log format, and the function
  writes each record to `process.stdout` as a single line of JSON. Lambda adds a
  timestamp, request ID and level in front of lines written with `console.log`,
  so the function does not use it.
- **Volume.** One event per invocation, plus one when the function starts (a
  cold start). A scheduled rotation that fails is retried twice by Lambda and
  logs again on each attempt.

## Logging schema

Every record is a single JSON object with flat, dotted keys (for example
`"event.action"`). Fields ECS defines keep their ECS names and types. The
project extensions are listed separately below.

### Fields on every event

| Field               | ECS type          | Presence    | Meaning                                                                                                                         |
| ------------------- | ----------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `@timestamp`        | `date`            | Every event | When the event was logged, in UTC, as an ISO 8601 string with milliseconds.                                                     |
| `message`           | `match_only_text` | Every event | Human-readable summary. Query the structured fields instead.                                                                    |
| `ecs.version`       | `keyword`         | Every event | The ECS version of the record, `8.11.0`.                                                                                        |
| `log.level`         | `keyword`         | Every event | `info` for a success, `error` for a failure.                                                                                    |
| `service.name`      | `keyword`         | Conditional | The Lambda function name, from `AWS_LAMBDA_FUNCTION_NAME`.                                                                      |
| `cloud.provider`    | `keyword`         | Every event | Always `aws`.                                                                                                                   |
| `cloud.region`      | `keyword`         | Conditional | The function's region, from `AWS_REGION`.                                                                                       |
| `event.category`    | `keyword[]`       | Every event | `process` for `start_function`, `configuration` otherwise.                                                                      |
| `event.type`        | `keyword[]`       | Every event | `error` for every failure; otherwise `start`, `creation`, `change`, `deletion` or `info` as in the [event index](#event-index). |
| `event.action`      | `keyword`         | Every event | The lower-snake-case operation. The outcome is never part of it.                                                                |
| `event.outcome`     | `keyword`         | Every event | `success` or `failure`.                                                                                                         |
| `aws.xray.trace.id` | `keyword`         | Conditional | The X-Ray trace ID (the `Root` of `_X_AMZN_TRACE_ID`), when Lambda sets one for the invocation.                                 |

### Fields on parameter events

These are on every event except `start_function`.

| Field              | ECS type  | Presence    | Meaning                                                                                                                 |
| ------------------ | --------- | ----------- | ----------------------------------------------------------------------------------------------------------------------- |
| `event.id`         | `keyword` | Conditional | The CloudFormation request ID or the Lambda request ID. It joins the events of one invocation.                          |
| `event.reason`     | `keyword` | Conditional | A controlled reason, on adopted, skipped and refused requests. See the [event reference](#event-reference).             |
| `cloud.account.id` | `keyword` | Conditional | The AWS account ID, taken from the invoked function's ARN.                                                              |
| `error.type`       | `keyword` | Failures    | The error's class name.                                                                                                 |
| `error.message`    | `keyword` | Conditional | The error message, only for errors whose messages are safe to log; see [Sensitive-data policy](#sensitive-data-policy). |

### Project extensions

| Field                                | Type        | Presence                                                | Meaning                                                                      |
| ------------------------------------ | ----------- | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `aws.ssm.parameter.name`             | `keyword`   | Parameter events, `start_function`                      | The name of the parameter.                                                   |
| `aws.ssm.parameter.version`          | `long`      | `create_parameter`, `rotate_parameter`, `skip_rotation` | The parameter version written, or the current one when nothing was written.  |
| `aws.ssm.parameter.previous_version` | `long`      | `rotate_parameter`                                      | The version that was current before the rotation.                            |
| `aws.ssm.parameter.tier`             | `keyword`   | `start_function`                                        | `Standard` or `Advanced`.                                                    |
| `aws.cloudformation.request_type`    | `keyword`   | Custom resource events                                  | `Create`, `Update` or `Delete`.                                              |
| `jwks.kids.current`                  | `keyword[]` | `create_parameter`, `rotate_parameter`                  | The `kid`s (RFC 7638 thumbprints) in the JWKS after the event, oldest first. |
| `jwks.kids.added`                    | `keyword[]` | `create_parameter`, `rotate_parameter`                  | The `kid`s the JWKS gained.                                                  |
| `jwks.kids.removed`                  | `keyword[]` | `create_parameter`, `rotate_parameter`                  | The `kid`s the JWKS lost.                                                    |
| `jwks.parameter.age_seconds`         | `long`      | `skip_rotation`                                         | How long ago the parameter was last modified.                                |
| `jwks.use`                           | `keyword`   | `start_function`                                        | `sig` or `enc`.                                                              |
| `jwks.alg`                           | `keyword`   | `start_function`                                        | The JWA algorithm of every key.                                              |
| `jwks.key_type`                      | `keyword`   | `start_function`                                        | `EC` or `RSA`.                                                               |
| `jwks.curve`                         | `keyword`   | `start_function`                                        | The EC curve, for EC keys.                                                   |
| `jwks.rsa_modulus_length`            | `long`      | `start_function`                                        | The RSA modulus length in bits, for RSA keys.                                |

### Sensitive-data policy

- **Key material is never logged.** No JWK member is written to the log, and
  neither is the parameter value. The only key data logged is the `kid`, a
  public thumbprint. `test/assets/lambda/handlers/rotation.test.ts` asserts that
  no private member of a generated key appears in the output.
- **Error messages are logged only when they are safe.** `error.message` is
  set for `JwksValidationError`, `JwkOptionsMismatchError` and
  `RotationStateError`, which this package writes, and for Systems Manager SDK
  exceptions. Any other error, such as one thrown by a cryptography library,
  might echo its input, so only its `error.type` is logged. The custom resource
  response to CloudFormation follows the same rule.
- **No stack traces or request payloads.** The event is not logged as a whole.
- **Values are data, not markup.** Each record is built with `JSON.stringify`,
  so a value that contains a line break or a quote cannot end the record or add
  a field.
- **The parameter name and account ID are logged.** Treat the log group with
  the same access controls as the parameter's metadata.

## Event index

| Event                                                                          | Level | `event.category` | `event.type` | `event.action`                            | `event.outcome` |
| ------------------------------------------------------------------------------ | ----- | ---------------- | ------------ | ----------------------------------------- | --------------- |
| [Function started](#function-started-and-failed-to-start)                      | info  | `process`        | `start`      | `start_function`                          | `success`       |
| [Function failed to start](#function-started-and-failed-to-start)              | error | `process`        | `error`      | `start_function`                          | `failure`       |
| [Parameter created or adopted](#parameter-created-or-adopted-create_parameter) | info  | `configuration`  | `creation`   | `create_parameter`                        | `success`       |
| [Parameter rotated](#parameter-rotated-rotate_parameter)                       | info  | `configuration`  | `change`     | `rotate_parameter`                        | `success`       |
| [Rotation skipped](#rotation-skipped-skip_rotation)                            | info  | `configuration`  | `info`       | `skip_rotation`                           | `success`       |
| [Parameter deleted](#parameter-deleted-delete_parameter)                       | info  | `configuration`  | `deletion`   | `delete_parameter`                        | `success`       |
| [Request failed](#request-failed)                                              | error | `configuration`  | `error`      | `rotate_parameter` or `validate_rotation` | `failure`       |

## Event reference

Each event also carries the [fields on every event](#fields-on-every-event).

### Function started and failed to start

`start_function`. On success it carries `aws.ssm.parameter.name`,
`aws.ssm.parameter.tier` and the `jwks.use`, `jwks.alg`, `jwks.key_type` and
`jwks.curve` or `jwks.rsa_modulus_length` of the configured keys. On failure it
carries `error.type` and, for a configuration error, `error.message`.

### Parameter created or adopted: `create_parameter`

Logged when CloudFormation creates or updates the custom resource.

| Condition                                                   | `event.reason` | Also carries                                                        |
| ----------------------------------------------------------- | -------------- | ------------------------------------------------------------------- |
| The parameter did not exist and was created with 2 keys     | none           | `jwks.kids.current`, `jwks.kids.added`, `aws.ssm.parameter.version` |
| The parameter already held keys with the configured options | `adopted`      | `jwks.kids.current`, `aws.ssm.parameter.version`                    |
| A forced rotation found the parameter missing               | `recreated`    | `jwks.kids.current`, `jwks.kids.added`, `aws.ssm.parameter.version` |

An adopted parameter is left unchanged. This is how a stack that is deployed
again after its retained parameter was left behind picks the parameter up. A
`recreated` parameter was created by invoking the function with `force` after
the parameter had been deleted; see
[A deleted parameter](how-rotation-works.md#a-deleted-parameter).

### Parameter rotated: `rotate_parameter`

Logged when a scheduled or forced rotation wrote a new version. It carries
`jwks.kids.current`, `jwks.kids.added`, `jwks.kids.removed`,
`aws.ssm.parameter.version` and `aws.ssm.parameter.previous_version`.

### Rotation skipped: `skip_rotation`

A scheduled rotation found the parameter modified less than half a rotation
interval ago and did nothing, which is how a duplicate delivery, an early
manual rotation and the schedule's first invocation just after a deployment are
absorbed. Expect one of these per parameter shortly after each deployment. `event.reason` is `rotated_recently`, with
`jwks.parameter.age_seconds`. Invoke the function with `{"action":"rotate","force":true}`
to rotate anyway.

### Parameter deleted: `delete_parameter`

Logged when the stack is deleted with `RemovalPolicy.DESTROY`. `event.reason`
is `not_found` if the parameter was already gone.

### Request failed

| `event.action`      | When                                                                                                    | `event.reason`                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `rotate_parameter`  | A scheduled rotation threw, e.g. the keys do not match the configured options or Systems Manager failed | none; `error.type` and, if safe, `error.message`                  |
| `validate_rotation` | The request is inconsistent with the parameter or the configuration                                     | `parameter_not_found`, `unknown_event` or `invalid_configuration` |
| `validate_rotation` | A custom resource request failed; CloudFormation received `FAILED`                                      | none; `error.type` and, if safe, `error.message`                  |

A failed scheduled rotation never changes the parameter: the write is a single
`PutParameter` made after the new JWKS has been validated.

## Consuming the logs

Query with CloudWatch Logs Insights on the log group:

```
fields @timestamp, `event.action`, `aws.ssm.parameter.version`, `jwks.kids.added`, `jwks.kids.removed`
| filter `event.action` in ["create_parameter", "rotate_parameter", "skip_rotation"]
| sort @timestamp desc
```

Failures:

```
fields @timestamp, `event.action`, `event.reason`, `error.type`, `error.message`
| filter `event.outcome` = "failure"
| sort @timestamp desc
```

### Alarms

- **A rotation failed.** Alarm on the rotation Lambda's `Errors` metric (the
  construct exposes `rotationLambda`; use `rotationLambda.metricErrors()`), or on
  a metric filter for `{ $.['event.outcome'] = "failure" }` on the log group (the
  field names contain dots, so they are written in single-quoted brackets).
  Lambda retries a failed scheduled rotation twice; the third failure sends the
  event to `rotationDeadLetterQueue`.
- **Rotations stopped.** There is no built-in signal for a rotation that never
  ran, unlike Secrets Manager's `LastRotatedDate`. Alarm on the dead letter
  queue's `ApproximateNumberOfMessagesVisible`, and on the absence of
  `rotate_parameter` events for longer than the rotation interval plus a day.
