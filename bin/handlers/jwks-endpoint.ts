import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { parseJwks, toPublicJwks, type Jwks } from 'cdk-jwks-parameter/jwks';

/** Names of the JWKS parameters whose public keys are served together. */
const PARAMETER_NAMES: readonly string[] = JSON.parse(process.env.JWKS_PARAMETER_NAMES ?? '[]');

/** How long each parameter is cached; also the Cache-Control max-age. 0 disables caching. */
const CACHE_TTL_SECONDS = Number(process.env.JWKS_CACHE_SECONDS ?? '0');

interface FunctionUrlEvent {
  readonly requestContext: { readonly http: { readonly method: string } };
}

interface FunctionUrlResult {
  readonly statusCode: number;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

const client = new SSMClient({});

const cache = new Map<string, { readonly jwks: Jwks; readonly expiresAt: number }>();

/** Whether a JWKS may be cached; not an empty JWKS. */
function isCacheable(jwks: Jwks): boolean {
  return CACHE_TTL_SECONDS > 0 && jwks.keys.length > 0;
}

async function getJwks(parameterName: string): Promise<Jwks> {
  const cached = cache.get(parameterName);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.jwks;
  }
  const { Parameter } = await client.send(
    new GetParameterCommand({ Name: parameterName, WithDecryption: true }),
  );
  const jwks = parseJwks(Parameter?.Value ?? '');
  if (isCacheable(jwks)) {
    cache.set(parameterName, { jwks, expiresAt: Date.now() + CACHE_TTL_SECONDS * 1000 });
  } else {
    cache.delete(parameterName);
  }
  return jwks;
}

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResult> {
  const method = event.requestContext.http.method;
  if (method !== 'GET' && method !== 'HEAD') {
    return { statusCode: 405, headers: { Allow: 'GET, HEAD' } };
  }
  let jwksList: Jwks[];
  try {
    jwksList = await Promise.all(PARAMETER_NAMES.map(getJwks));
  } catch (error) {
    // e.g. a parameter was deleted. Log the class only: a message might echo a value.
    console.error(`Could not read the JWKS: ${error instanceof Error ? error.name : typeof error}`);
    return { statusCode: 503, headers: { 'Cache-Control': 'no-store' } };
  }
  // toPublicJwks applies the publishing rule for each parameter's use (sig or enc).
  const keys = jwksList.flatMap((jwks) => toPublicJwks(jwks).keys);
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': jwksList.every(isCacheable) ? `public, max-age=${CACHE_TTL_SECONDS}` : 'no-cache',
    },
    body: JSON.stringify({ keys }),
  };
}
