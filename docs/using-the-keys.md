# Using the keys in your server

Your server reads the parameter, serves the public keys from its JWKS endpoint
(registered as the client's `jwks_uri` with the OpenID Connect server) and uses
the private keys. See [How rotation works](how-rotation-works.md) for why the
rules below are what they are.

## Requirements

1. **Read the parameter decrypted.** Call `GetParameter` with
   `WithDecryption: true`. Grant access with `jwksParameter.grantRead(role)`.
2. **Re-read it periodically.** Rotation changes the keys; cache the parameter
   for at most a fraction of the rotation interval (e.g. an hour).
3. **Never serve private members.** Remove `d`, `p`, `q`, `dp`, `dq`, `qi`
   (and `oth`) from every published key.

The parameter exists, with its first keys, as soon as the stack has been
deployed, so unlike a secret that is initialised by its first rotation there is
no empty state to handle. `toPublicJwks` still returns `{"keys":[]}` for an
empty JWKS.

### `sig` keys (e.g. `private_key_jwt`)

- **Publish:** every key in the parameter, public members only.
- **Sign with:** the first key that has `d`. Put its `kid` and `alg` in the JWS
  header.

### `enc` keys

- **Publish:** every key, except the first one when there are 3 keys. Public
  members only.
- **Decrypt with:** the key whose `kid` matches the JWE header. Every key in the
  parameter has its private part.
- **Re-read the parameter on an unknown `kid`.** A rotation publishes a new key
  straight away, so the OpenID Connect server may encrypt to it before your
  server's cached copy of the parameter has it. Re-read the parameter once and
  try again before rejecting the JWE. (Signing keys don't need this: a new `sig`
  key isn't used for a whole rotation interval.)

## Helpers (JavaScript / TypeScript)

The rules above are implemented in `cdk-jwks-parameter/jwks`, which does not
depend on the AWS CDK or the AWS SDK. Its API is the same as
`cdk-jwks-secret/jwks`, so moving between the two backends changes only where
the string comes from:

```ts
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { parseJwks, selectDecryptionKey, selectSigningKey, toPublicJwks } from 'cdk-jwks-parameter/jwks';

const client = new SSMClient({});
const { Parameter } = await client.send(
  new GetParameterCommand({ Name: process.env.JWKS_PARAMETER_NAME, WithDecryption: true }),
);
const jwks = parseJwks(Parameter!.Value!); // validates structure and kids

// JWKS endpoint (both sig and enc)
const body = JSON.stringify(toPublicJwks(jwks));

// sig: private_key_jwt client assertion
const signingKey = selectSigningKey(jwks); // { kid, alg, ...private JWK }

// enc: decrypt a JWE
const decryptionKey = selectDecryptionKey(jwks, protectedHeader.kid);
```

`selectSigningKey` throws on an empty JWKS or `enc` keys; `selectDecryptionKey`
returns `undefined` for an unknown `kid`, which is when to re-read the
parameter, and throws on `sig` keys.

## Other languages

Implement the two rules for your key use:

```
sig:  publish = keys.map(publicMembers)
      signingKey = first key with "d"

enc:  publish = (keys.length == 3 ? keys[1..] : keys).map(publicMembers)
      decryptionKey = key with matching "kid" (re-read the parameter once if none)
```

The key use is the `use` member of any key; all keys in a parameter share it.

## Signing and encryption keys on one `jwks_uri`

A client registers a single `jwks_uri`, so a client that both signs (e.g.
`private_key_jwt`) and decrypts (e.g. encrypted ID tokens) serves the keys of
two parameters, one with `use: 'sig'` and one with `use: 'enc'`, in one JWKS.
Apply each parameter's rule and concatenate the keys:

```ts
const jwksList = [sigValue, encValue].map(parseJwks);
const body = JSON.stringify({ keys: jwksList.flatMap((jwks) => toPublicJwks(jwks).keys) });
```

The OpenID Connect server tells the keys apart by their `use`. The example app
in [`bin/`](../bin) serves its two parameters this way.

## Old versions

Parameter Store keeps the previous versions of a parameter (up to 100), and
`ssm:GetParameter` reads one when the name is given as `name:<version>`.
`grantRead` does not include `ssm:GetParameterHistory`, but it cannot prevent
that.

This matters for `sig` keys only. A retired key has its private part removed
from the current value, to limit what a compromised server that reads the
current value can sign with; the earlier versions still hold it. Anyone who can
read the current value can already sign with the current key, so the removal
reduces exposure to old keys, not to a principal that can read old versions. If
that distinction matters to you, restrict `ssm:GetParameter` to principals you
trust with every key the parameter has ever held, or use `cdk-jwks-secret`,
which keeps no versions without a staging label.
