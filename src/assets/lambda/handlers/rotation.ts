import { request } from 'node:https';
import {
  DeleteParameterCommand,
  GetParameterCommand,
  ParameterNotFound,
  PutParameterCommand,
  SSMClient,
} from '@aws-sdk/client-ssm';
import {
  assertIsRotationOf,
  assertJwksMatchesOptions,
  JWK_OPTIONS_ENV,
  JwksValidationError,
  PARAMETER_ENV,
  parseJwkOptions,
  parseJwks,
  rotateJwks,
  type Jwks,
  type ParameterTier,
  type ResolvedJwkOptions,
} from '../../../shared/jwks';
import { errorFields, kidChanges, kidsOf, logEvent, parameterFields, type LogFields } from '../logger';
import { RotationStateError } from '../rotation-error';

/** The event EventBridge Scheduler sends to the function. */
export interface ScheduledRotationEvent {
  readonly action: 'rotate';
  /**
   * Rotates even if the parameter was modified less than half a rotation interval ago,
   * and creates the parameter, with new keys, if it does not exist.
   */
  readonly force?: boolean;
}

/** The event CloudFormation sends to the function for the construct's custom resource. */
export interface CloudFormationEvent {
  readonly RequestType: 'Create' | 'Update' | 'Delete';
  readonly ResponseURL: string;
  readonly StackId: string;
  readonly RequestId: string;
  readonly LogicalResourceId: string;
  readonly PhysicalResourceId?: string;
}

export type ParameterEvent = ScheduledRotationEvent | CloudFormationEvent;

/** The parts of the Lambda context the function uses. */
export interface InvocationContext {
  readonly invokedFunctionArn?: string;
  readonly awsRequestId?: string;
}

/** What the construct tells the function about the parameter, through environment variables. */
export interface ParameterConfig {
  readonly name: string;
  readonly tier: ParameterTier;
  /** The KMS key of the `SecureString`; the AWS managed key `alias/aws/ssm` if absent. */
  readonly keyId?: string;
  readonly description?: string;
  readonly rotationIntervalSeconds: number;
}

type ResponseSender = (url: string, body: string) => Promise<void>;

export interface HandlerDependencies {
  readonly now?: () => number;
  readonly sendResponse?: ResponseSender;
}

const CREATE_FAILED_PREFIX = 'create-failed-';

function invalidConfiguration(message: string): never {
  throw new RotationStateError('invalid_configuration', message);
}

export function parseParameterConfig(env: NodeJS.ProcessEnv): ParameterConfig {
  const name = env[PARAMETER_ENV.name];
  if (!name) invalidConfiguration(`${PARAMETER_ENV.name} is not set`);
  const tier = env[PARAMETER_ENV.tier];
  if (tier !== 'Standard' && tier !== 'Advanced') {
    invalidConfiguration(`${PARAMETER_ENV.tier} must be "Standard" or "Advanced"`);
  }
  const rotationIntervalSeconds = Number(env[PARAMETER_ENV.rotationIntervalSeconds]);
  if (!Number.isInteger(rotationIntervalSeconds) || rotationIntervalSeconds <= 0) {
    invalidConfiguration(`${PARAMETER_ENV.rotationIntervalSeconds} must be a positive integer`);
  }
  return {
    name,
    tier,
    keyId: env[PARAMETER_ENV.keyId] || undefined,
    description: env[PARAMETER_ENV.description] || undefined,
    rotationIntervalSeconds,
  };
}

/** Sends the custom resource response to the pre-signed URL CloudFormation provides. */
const sendHttpsResponse: ResponseSender = (url, body) =>
  new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: 'PUT',
        // The URL is signed without a content type, so none may be sent.
        headers: { 'content-type': '', 'content-length': Buffer.byteLength(body) },
      },
      (response) => {
        response.resume();
        response.on('end', () => {
          const status = response.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            resolve();
          } else {
            reject(new Error(`CloudFormation rejected the response with status ${status}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });

interface StoredJwks {
  readonly jwks: Jwks;
  readonly version?: number;
  readonly lastModified?: Date;
}

export function createParameterHandler(
  client: Pick<SSMClient, 'send'>,
  options: ResolvedJwkOptions,
  config: ParameterConfig,
  dependencies: HandlerDependencies = {},
): (event: ParameterEvent, context?: InvocationContext) => Promise<void> {
  const now = dependencies.now ?? Date.now;
  const sendResponse = dependencies.sendResponse ?? sendHttpsResponse;

  async function readParameter(name: string): Promise<StoredJwks | undefined> {
    try {
      const { Parameter } = await client.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
      if (Parameter?.Value === undefined) {
        throw new JwksValidationError(`parameter ${name} has no value`);
      }
      return {
        jwks: parseJwks(Parameter.Value),
        version: Parameter.Version,
        lastModified: Parameter.LastModifiedDate,
      };
    } catch (error) {
      if (error instanceof ParameterNotFound) {
        return undefined;
      }
      throw error;
    }
  }

  async function putParameter(jwks: Jwks, overwrite: boolean): Promise<number | undefined> {
    const { Version } = await client.send(
      new PutParameterCommand({
        Name: config.name,
        Value: JSON.stringify(jwks),
        Type: 'SecureString',
        Tier: config.tier,
        KeyId: config.keyId,
        Description: config.description,
        Overwrite: overwrite,
      }),
    );
    return Version;
  }

  /** Creates the parameter with 2 keys, or adopts an existing one that has the configured options. */
  async function ensureParameter(base: LogFields): Promise<void> {
    const existing = await readParameter(config.name);
    if (existing && existing.jwks.keys.length > 0) {
      assertJwksMatchesOptions(existing.jwks, options);
      logEvent('create_parameter', 'success', 'parameter already exists with the configured keys', {
        ...base,
        'event.reason': 'adopted',
        'aws.ssm.parameter.version': existing.version,
        'jwks.kids.current': kidsOf(existing.jwks),
      });
      return;
    }
    const initial = await rotateJwks({ keys: [] }, options);
    const version = await putParameter(initial, existing !== undefined);
    logEvent('create_parameter', 'success', 'created parameter', {
      ...base,
      ...kidChanges({ keys: [] }, initial),
      'aws.ssm.parameter.version': version,
    });
  }

  async function deleteParameter(name: string, base: LogFields): Promise<void> {
    try {
      await client.send(new DeleteParameterCommand({ Name: name }));
      logEvent('delete_parameter', 'success', 'deleted parameter', base);
    } catch (error) {
      if (!(error instanceof ParameterNotFound)) {
        throw error;
      }
      logEvent('delete_parameter', 'success', 'parameter was already deleted', {
        ...base,
        'event.reason': 'not_found',
      });
    }
  }

  async function rotateParameter(event: ScheduledRotationEvent, base: LogFields): Promise<void> {
    const current = await readParameter(config.name);
    if (!current) {
      if (event.force !== true) {
        throw new RotationStateError(
          'parameter_not_found',
          `Parameter ${config.name} does not exist; invoke the function with force to create it`,
        );
      }
      // Explicit recovery: the new keys are generated as for a first deployment.
      const initial = await rotateJwks({ keys: [] }, options);
      const version = await putParameter(initial, false);
      logEvent('create_parameter', 'success', 'created missing parameter', {
        ...base,
        ...kidChanges({ keys: [] }, initial),
        'event.reason': 'recreated',
        'aws.ssm.parameter.version': version,
      });
      return;
    }
    // Lambda retries asynchronous invocations, and two rotations close together skip the
    // waiting periods that make a rotation safe; see docs/how-rotation-works.md.
    const minimumAgeMs = (config.rotationIntervalSeconds * 1000) / 2;
    const ageMs = current.lastModified ? now() - current.lastModified.getTime() : Infinity;
    if (event.force !== true && current.jwks.keys.length > 0 && ageMs < minimumAgeMs) {
      logEvent('skip_rotation', 'success', 'parameter was modified recently, not rotating', {
        ...base,
        'event.reason': 'rotated_recently',
        'aws.ssm.parameter.version': current.version,
        'jwks.parameter.age_seconds': Math.floor(ageMs / 1000),
      });
      return;
    }
    // rotateJwks validates the current JWKS and that it has the configured options.
    const next = await rotateJwks(current.jwks, options);
    assertIsRotationOf(current.jwks, next);
    const version = await putParameter(next, true);
    logEvent('rotate_parameter', 'success', 'rotated parameter', {
      ...base,
      ...kidChanges(current.jwks, next),
      'aws.ssm.parameter.version': version,
      'aws.ssm.parameter.previous_version': current.version,
    });
  }

  async function respond(
    event: CloudFormationEvent,
    status: 'SUCCESS' | 'FAILED',
    physicalResourceId: string,
    reason?: string,
  ): Promise<void> {
    const body = JSON.stringify({
      Status: status,
      Reason: (reason ?? 'See the function log group in CloudWatch Logs').slice(0, 1000),
      PhysicalResourceId: physicalResourceId,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      Data: {},
    });
    await sendResponse(event.ResponseURL, body);
  }

  async function handleCloudFormation(event: CloudFormationEvent, context: InvocationContext): Promise<void> {
    const type = event.RequestType;
    const base = parameterFields(
      type === 'Delete' ? (event.PhysicalResourceId ?? config.name) : config.name,
      event.RequestId,
      context.invokedFunctionArn,
      { 'aws.cloudformation.request_type': type },
    );
    try {
      if (type === 'Delete') {
        const name = event.PhysicalResourceId;
        // A failed creation has no parameter of its own, and must not delete one it did not make.
        if (name !== undefined && !name.startsWith(CREATE_FAILED_PREFIX)) {
          await deleteParameter(name, base);
        }
        await respond(event, 'SUCCESS', name ?? config.name);
        return;
      }
      // Create, and Update: a changed name creates the new parameter, and a parameter that
      // was deleted by hand is created again. An unchanged one is only checked, never rotated.
      await ensureParameter(base);
      await respond(event, 'SUCCESS', config.name);
    } catch (error) {
      logEvent('validate_rotation', 'failure', `${type}: failed`, { ...base, ...errorFields(error) });
      const safe = errorFields(error)['error.message'];
      await respond(
        event,
        'FAILED',
        event.PhysicalResourceId ?? `${CREATE_FAILED_PREFIX}${event.RequestId}`,
        typeof safe === 'string'
          ? safe
          : `${errorFields(error)['error.type'] as string}; see the function log group`,
      );
    }
  }

  async function handleScheduled(event: ScheduledRotationEvent, context: InvocationContext): Promise<void> {
    const base = parameterFields(config.name, context.awsRequestId, context.invokedFunctionArn);
    try {
      await rotateParameter(event, base);
    } catch (error) {
      if (error instanceof RotationStateError) {
        logEvent('validate_rotation', 'failure', error.message, {
          ...base,
          ...errorFields(error),
          'event.reason': error.reason,
        });
      } else {
        logEvent('rotate_parameter', 'failure', 'rotation failed', { ...base, ...errorFields(error) });
      }
      throw error;
    }
  }

  return async (event, context = {}) => {
    if ('RequestType' in event) {
      return handleCloudFormation(event, context);
    }
    if (event.action === 'rotate') {
      return handleScheduled(event, context);
    }
    throw new RotationStateError(
      'unknown_event',
      'The event is neither a custom resource request nor a rotation',
    );
  };
}

let parameterHandler: ReturnType<typeof createParameterHandler> | undefined;

export function initialiseParameterHandler(
  client: Pick<SSMClient, 'send'> = new SSMClient({}),
  env: NodeJS.ProcessEnv = process.env,
): ReturnType<typeof createParameterHandler> {
  try {
    const options = parseJwkOptions(env[JWK_OPTIONS_ENV]);
    const config = parseParameterConfig(env);
    const created = createParameterHandler(client, options, config);
    logEvent('start_function', 'success', 'rotation function started', {
      'aws.ssm.parameter.name': config.name,
      'aws.ssm.parameter.tier': config.tier,
      'jwks.use': options.use,
      'jwks.alg': options.algorithm,
      'jwks.key_type': options.keyType,
      'jwks.curve': options.curve,
      'jwks.rsa_modulus_length': options.rsaModulusLength,
    });
    return created;
  } catch (error) {
    logEvent('start_function', 'failure', 'rotation function failed to start', errorFields(error));
    throw error;
  }
}

export async function handler(event: ParameterEvent, context?: InvocationContext): Promise<void> {
  parameterHandler ??= initialiseParameterHandler();
  return parameterHandler(event, context);
}
