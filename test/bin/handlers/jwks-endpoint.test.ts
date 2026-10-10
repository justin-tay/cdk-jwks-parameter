import { resolveJwkOptions, rotateJwks, type Jwks, type ResolvedJwkOptions } from 'cdk-jwks-parameter/jwks';

type Endpoint = typeof import('../../../bin/handlers/jwks-endpoint');
type Ssm = typeof import('@aws-sdk/client-ssm');

const SIG_NAME = '/app/sig-jwks';
const ENC_NAME = '/app/enc-jwks';

const request = (method: string) => ({ requestContext: { http: { method } } });

let send: jest.SpyInstance;

/** A JWKS after `rotations` rotations, the first of which initialises it. */
async function jwksAfter(options: ResolvedJwkOptions, rotations: number): Promise<Jwks> {
  let jwks: Jwks = { keys: [] };
  for (let i = 0; i < rotations; i++) {
    jwks = await rotateJwks(jwks, options);
  }
  return jwks;
}

function parametersHold(parameters: Record<string, Jwks>) {
  send.mockImplementation(async (command: { input: { Name: string; WithDecryption?: boolean } }) => {
    // The values are SecureStrings, so they are only readable decrypted.
    expect(command.input.WithDecryption).toBe(true);
    return { Parameter: { Value: JSON.stringify(parameters[command.input.Name]) } };
  });
}

/** Loads a fresh handler (resetting its cache and config) and spies on the SDK copy it uses. */
function loadHandler(cacheSeconds: string | undefined, names: string[] | null = [SIG_NAME, ENC_NAME]) {
  setEnv('JWKS_PARAMETER_NAMES', names === null ? undefined : JSON.stringify(names));
  setEnv('JWKS_CACHE_SECONDS', cacheSeconds);
  let handler!: Endpoint['handler'];
  jest.isolateModules(() => {
    const { SSMClient } = require('@aws-sdk/client-ssm') as Ssm;
    send = jest.spyOn(SSMClient.prototype, 'send') as jest.SpyInstance;
    send.mockRejectedValue(new Error('unexpected call'));
    ({ handler } = require('../../../bin/handlers/jwks-endpoint') as Endpoint);
  });
  return handler;
}

function setEnv(name: string, value: string | undefined) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

const sig = resolveJwkOptions({ use: 'sig' });
const enc = resolveJwkOptions({ use: 'enc' });

afterEach(() => {
  jest.restoreAllMocks();
});

test('serves the public sig and enc keys in one JWKS', async () => {
  const handler = loadHandler('0');
  const sigJwks = await jwksAfter(sig, 2);
  const encJwks = await jwksAfter(enc, 2);
  parametersHold({ [SIG_NAME]: sigJwks, [ENC_NAME]: encJwks });

  const response = await handler(request('GET'));
  expect(response.statusCode).toBe(200);
  expect(response.headers!['Content-Type']).toBe('application/json');
  const { keys } = JSON.parse(response.body!);
  // All 3 sig keys, and the enc keys except the oldest of 3.
  expect(keys.map((jwk: { kid: string }) => jwk.kid)).toEqual([
    ...sigJwks.keys.map((jwk) => jwk.kid),
    ...encJwks.keys.slice(1).map((jwk) => jwk.kid),
  ]);
  expect(keys.every((jwk: { d?: string }) => jwk.d === undefined)).toBe(true);
});

test('with a cache TTL of 0, reads the parameters on every request', async () => {
  const handler = loadHandler('0');
  parametersHold({ [SIG_NAME]: await jwksAfter(sig, 1), [ENC_NAME]: await jwksAfter(enc, 1) });
  const response = await handler(request('GET'));
  expect(response.headers!['Cache-Control']).toBe('no-cache');
  await handler(request('GET'));
  expect(send).toHaveBeenCalledTimes(4);
});

test('with a cache TTL, caches the parameters and sets max-age', async () => {
  const handler = loadHandler('300');
  parametersHold({ [SIG_NAME]: await jwksAfter(sig, 1), [ENC_NAME]: await jwksAfter(enc, 1) });
  const response = await handler(request('GET'));
  expect(response.headers!['Cache-Control']).toBe('public, max-age=300');
  await handler(request('GET'));
  expect(send).toHaveBeenCalledTimes(2);
});

test('does not cache an empty JWKS', async () => {
  const handler = loadHandler('300');
  parametersHold({ [SIG_NAME]: await jwksAfter(sig, 1), [ENC_NAME]: { keys: [] } });
  const response = await handler(request('GET'));
  expect(JSON.parse(response.body!).keys).toHaveLength(2);
  expect(response.headers!['Cache-Control']).toBe('no-cache');
  await handler(request('GET'));
  // The sig parameter is cached; the empty enc one is read again.
  expect(send).toHaveBeenCalledTimes(3);
});

test('serves an empty JWKS without caching when not configured', async () => {
  const handler = loadHandler(undefined, null);
  const response = await handler(request('GET'));
  expect(JSON.parse(response.body!)).toEqual({ keys: [] });
  expect(response.headers!['Cache-Control']).toBe('public, max-age=0');
  expect(send).not.toHaveBeenCalled();
});

test('answers 503 without caching when a parameter cannot be read, and logs only the error class', async () => {
  const handler = loadHandler('300');
  const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  send.mockRejectedValue(
    Object.assign(new Error('arn:secret-looking-detail'), { name: 'ParameterNotFound' }),
  );

  expect(await handler(request('GET'))).toEqual({
    statusCode: 503,
    headers: { 'Cache-Control': 'no-store' },
  });
  expect(error).toHaveBeenCalledTimes(1);
  expect(String(error.mock.calls[0][0])).toBe('Could not read the JWKS: ParameterNotFound');
});

test('rejects methods other than GET and HEAD', async () => {
  const handler = loadHandler('0');
  expect(await handler(request('POST'))).toEqual({ statusCode: 405, headers: { Allow: 'GET, HEAD' } });
  expect(send).not.toHaveBeenCalled();
});
