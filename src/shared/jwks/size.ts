import type { JwkEcCurve, ResolvedJwkOptions } from './options';
import { MAX_KEY_COUNT } from './validate';

/** The largest value of a Parameter Store standard-tier parameter, in bytes. */
export const STANDARD_TIER_MAX_BYTES = 4096;

/** The largest value of a Parameter Store advanced-tier parameter, in bytes. */
export const ADVANCED_TIER_MAX_BYTES = 8192;

export type ParameterTier = 'Standard' | 'Advanced';

/** Bytes of the unsigned big-endian integers of an EC key on each curve. */
const EC_COORDINATE_BYTES: Readonly<Record<JwkEcCurve, number>> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
};

/** The length of the base64url encoding, without padding, of `bytes` bytes. */
function base64urlLength(bytes: number): number {
  return Math.ceil((bytes * 4) / 3);
}

/** A string as long as the base64url encoding of `bytes` bytes. */
function member(bytes: number): string {
  return 'x'.repeat(base64urlLength(bytes));
}

/** A JWK with every member the right length, but not valid key material. */
function sampleJwk(options: ResolvedJwkOptions, includePrivate: boolean): Record<string, string> {
  const common = {
    kty: options.keyType,
    // The base64url encoding of a SHA-256 digest.
    kid: member(32),
    use: options.use,
    alg: options.algorithm,
  };
  if (options.keyType === 'RSA') {
    const modulusBytes = options.rsaModulusLength! / 8;
    const primeBytes = Math.ceil(options.rsaModulusLength! / 16);
    return {
      ...common,
      n: member(modulusBytes),
      e: 'AQAB',
      ...(includePrivate && {
        d: member(modulusBytes),
        p: member(primeBytes),
        q: member(primeBytes),
        dp: member(primeBytes),
        dq: member(primeBytes),
        qi: member(primeBytes),
      }),
    };
  }
  const coordinateBytes = EC_COORDINATE_BYTES[options.curve!];
  return {
    ...common,
    crv: options.curve!,
    x: member(coordinateBytes),
    y: member(coordinateBytes),
    ...(includePrivate && { d: member(coordinateBytes) }),
  };
}

/**
 * The size in bytes of the largest JWKS the options can produce, stored as
 * `JSON.stringify` writes it. With 3 `sig` keys the oldest is public-only;
 * with 3 `enc` keys all are private.
 */
export function maxJwksBytes(options: ResolvedJwkOptions): number {
  const keys = Array.from({ length: MAX_KEY_COUNT }, (_, index) =>
    sampleJwk(options, !(options.use === 'sig' && index === 0)),
  );
  return Buffer.byteLength(JSON.stringify({ keys }));
}

/**
 * The cheapest parameter tier that holds the largest JWKS the options can
 * produce.
 *
 * @throws Error if no tier does
 */
export function parameterTierFor(options: ResolvedJwkOptions): ParameterTier {
  const bytes = maxJwksBytes(options);
  if (bytes <= STANDARD_TIER_MAX_BYTES) {
    return 'Standard';
  }
  if (bytes <= ADVANCED_TIER_MAX_BYTES) {
    return 'Advanced';
  }
  throw new Error(
    `${MAX_KEY_COUNT} ${options.algorithm} keys of ${options.rsaModulusLength ?? options.curve} ` +
      `need up to ${bytes} bytes, more than the ${ADVANCED_TIER_MAX_BYTES} bytes of an advanced ` +
      'tier parameter. Use a smaller key, or store the JWKS in a Secrets Manager secret ' +
      'with cdk-jwks-secret.',
  );
}
