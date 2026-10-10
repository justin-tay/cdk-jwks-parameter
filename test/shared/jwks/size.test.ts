import {
  ADVANCED_TIER_MAX_BYTES,
  generateJwk,
  maxJwksBytes,
  parameterTierFor,
  resolveJwkOptions,
  STANDARD_TIER_MAX_BYTES,
  toPublicJwk,
  type JwkOptions,
} from '../../../src/shared/jwks';

/** The size of the largest JWKS the options can produce, from real keys. */
async function actualMaxBytes(options: JwkOptions): Promise<number> {
  const resolved = resolveJwkOptions(options);
  const [a, b, c] = await Promise.all([generateJwk(resolved), generateJwk(resolved), generateJwk(resolved)]);
  const keys = resolved.use === 'sig' ? [toPublicJwk(a), b, c] : [a, b, c];
  return Buffer.byteLength(JSON.stringify({ keys }));
}

test.each([
  [{}],
  [{ algorithm: 'ES384' }],
  [{ algorithm: 'ES512' }],
  [{ use: 'enc' }],
  [{ algorithm: 'ECDH-ES', curve: 'P-521' }],
  [{ algorithm: 'RS256' }],
  [{ algorithm: 'RSA-OAEP-256' }],
  [{ algorithm: 'PS384', rsaModulusLength: 3072 }],
] as const)('estimates the size of the largest JWKS of %j', async (options) => {
  const estimate = maxJwksBytes(resolveJwkOptions(options));
  const actual = await actualMaxBytes(options);
  // A modulus whose top bit is zero in a generated member is a byte shorter, never longer.
  expect(estimate).toBeGreaterThanOrEqual(actual);
  expect(estimate - actual).toBeLessThan(10);
});

test.each([
  [{}, 'Standard'],
  [{ use: 'enc' }, 'Standard'],
  [{ algorithm: 'ES512' }, 'Standard'],
  [{ algorithm: 'RS256' }, 'Standard'],
  [{ algorithm: 'RS256', rsaModulusLength: 3072 }, 'Advanced'],
  [{ algorithm: 'RS256', rsaModulusLength: 4096 }, 'Advanced'],
  [{ algorithm: 'RSA-OAEP-256' }, 'Advanced'],
] as const)('derives the tier of %j: %s', (options, tier) => {
  expect(parameterTierFor(resolveJwkOptions(options))).toBe(tier);
});

test('keeps the largest sizes within the tier limits', () => {
  expect(maxJwksBytes(resolveJwkOptions({ algorithm: 'RS256' }))).toBeLessThanOrEqual(
    STANDARD_TIER_MAX_BYTES,
  );
  expect(maxJwksBytes(resolveJwkOptions({ algorithm: 'RS256', rsaModulusLength: 4096 }))).toBeLessThanOrEqual(
    ADVANCED_TIER_MAX_BYTES,
  );
});

test('rejects encryption keys that fit no tier, pointing at cdk-jwks-secret', () => {
  const options = resolveJwkOptions({ algorithm: 'RSA-OAEP-256', rsaModulusLength: 4096 });
  expect(maxJwksBytes(options)).toBeGreaterThan(ADVANCED_TIER_MAX_BYTES);
  expect(() => parameterTierFor(options)).toThrow(
    /more than the 8192 bytes of an advanced tier parameter.*cdk-jwks-secret/,
  );
});
