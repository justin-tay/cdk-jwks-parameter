import { EventEmitter } from 'node:events';
import { request } from 'node:https';
import {
  DeleteParameterCommand,
  GetParameterCommand,
  ParameterNotFound,
  PutParameterCommand,
} from '@aws-sdk/client-ssm';
import {
  createParameterHandler,
  handler as lambdaHandler,
  initialiseParameterHandler,
  parseParameterConfig,
  type CloudFormationEvent,
  type ParameterConfig,
} from '../../../../src/assets/lambda/handlers/rotation';
import { RotationStateError } from '../../../../src/assets/lambda/rotation-error';
import {
  generateJwk,
  JWK_OPTIONS_ENV,
  PARAMETER_ENV,
  resolveJwkOptions,
  rotateJwks,
  type Jwks,
  type ResolvedJwkOptions,
} from '../../../../src/shared/jwks';

// Keep the rest of the module: the AWS SDK's HTTP handler needs `Agent`.
jest.mock('node:https', () => ({ ...jest.requireActual('node:https'), request: jest.fn() }));

const NAME = '/app/jwks';
const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 0, 1);

interface Stored {
  value: string;
  version: number;
  lastModified: Date;
}

/** An in-memory Parameter Store that records every command it receives. */
class FakeSsm {
  public stored: Stored | undefined;

  public readonly commands: unknown[] = [];

  public failPutWith: Error | undefined;

  constructor(initial?: { jwks: Jwks; ageMs: number }) {
    if (initial) {
      this.stored = {
        value: JSON.stringify(initial.jwks),
        version: 1,
        lastModified: new Date(NOW - initial.ageMs),
      };
    }
  }

  async send(command: unknown): Promise<unknown> {
    this.commands.push(command);
    if (command instanceof GetParameterCommand) {
      if (!this.stored) throw new ParameterNotFound({ message: 'not found', $metadata: {} });
      return {
        Parameter: {
          Name: command.input.Name,
          Value: this.stored.value,
          Version: this.stored.version,
          LastModifiedDate: this.stored.lastModified,
        },
      };
    }
    if (command instanceof PutParameterCommand) {
      if (this.failPutWith) throw this.failPutWith;
      if (this.stored && !command.input.Overwrite) throw new Error('ParameterAlreadyExists');
      this.stored = {
        value: command.input.Value!,
        version: (this.stored?.version ?? 0) + 1,
        lastModified: new Date(NOW),
      };
      return { Version: this.stored.version };
    }
    if (command instanceof DeleteParameterCommand) {
      if (!this.stored) throw new ParameterNotFound({ message: 'not found', $metadata: {} });
      this.stored = undefined;
      return {};
    }
    throw new Error(`unexpected command ${(command as object).constructor.name}`);
  }

  public of<T>(type: new (input: never) => T): T[] {
    return this.commands.filter((command): command is T => command instanceof type);
  }

  public get jwks(): Jwks {
    return JSON.parse(this.stored!.value) as Jwks;
  }
}

const sig: ResolvedJwkOptions = resolveJwkOptions({ algorithm: 'ES256' });
const enc: ResolvedJwkOptions = resolveJwkOptions({ use: 'enc' });

const config: ParameterConfig = {
  name: NAME,
  tier: 'Standard',
  rotationIntervalSeconds: 28 * 24 * 60 * 60,
};

function setup(
  options: ResolvedJwkOptions = sig,
  initial?: { jwks: Jwks; ageMs: number },
  overrides: Partial<ParameterConfig> = {},
) {
  const ssm = new FakeSsm(initial);
  const responses: { url: string; body: Record<string, unknown> }[] = [];
  const handler = createParameterHandler(
    ssm,
    options,
    { ...config, ...overrides },
    {
      now: () => NOW,
      sendResponse: async (url, body) => {
        responses.push({ url, body: JSON.parse(body) as Record<string, unknown> });
      },
    },
  );
  return { ssm, handler, responses };
}

const context = {
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:rotation',
  awsRequestId: 'request-1',
};

function cfn(
  requestType: CloudFormationEvent['RequestType'],
  physicalResourceId?: string,
): CloudFormationEvent {
  return {
    RequestType: requestType,
    ResponseURL: 'https://cloudformation.example/response',
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/app/1',
    RequestId: 'cfn-request-1',
    LogicalResourceId: 'Initialisation',
    PhysicalResourceId: physicalResourceId,
  };
}

async function jwksOf(options: ResolvedJwkOptions, rotations = 0): Promise<Jwks> {
  let jwks = await rotateJwks({ keys: [] }, options);
  for (let index = 0; index < rotations; index++) {
    jwks = await rotateJwks(jwks, options);
  }
  return jwks;
}

let output: string[];

beforeEach(() => {
  output = [];
  jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

const logged = () => output.map((line) => JSON.parse(line) as Record<string, unknown>);

describe('the custom resource', () => {
  test('creates a SecureString with 2 keys, and responds SUCCESS with the parameter name', async () => {
    const { ssm, handler, responses } = setup(sig, undefined, {
      keyId: 'arn:aws:kms:us-east-1:123456789012:key/k',
      description: 'JWKS',
    });
    await handler(cfn('Create'), context);

    const [put] = ssm.of(PutParameterCommand);
    expect(put.input).toMatchObject({
      Name: NAME,
      Type: 'SecureString',
      Tier: 'Standard',
      KeyId: 'arn:aws:kms:us-east-1:123456789012:key/k',
      Description: 'JWKS',
      Overwrite: false,
    });
    expect(ssm.jwks.keys).toHaveLength(2);
    expect(ssm.jwks.keys.every((jwk) => jwk.d !== undefined)).toBe(true);
    expect(responses).toEqual([
      {
        url: 'https://cloudformation.example/response',
        body: expect.objectContaining({
          Status: 'SUCCESS',
          PhysicalResourceId: NAME,
          RequestId: 'cfn-request-1',
          LogicalResourceId: 'Initialisation',
        }),
      },
    ]);
    expect(logged().find((record) => record['event.action'] === 'create_parameter')).toMatchObject({
      'event.outcome': 'success',
      'aws.ssm.parameter.name': NAME,
      'cloud.account.id': '123456789012',
      'aws.cloudformation.request_type': 'Create',
    });
  });

  test('adopts an existing parameter with the configured keys, without changing it', async () => {
    const existing = await jwksOf(sig, 1);
    const { ssm, handler, responses } = setup(sig, { jwks: existing, ageMs: DAY_MS });
    await handler(cfn('Create'), context);

    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(ssm.jwks).toEqual(existing);
    expect(responses[0].body.Status).toBe('SUCCESS');
    expect(logged().find((record) => record['event.action'] === 'create_parameter')).toMatchObject({
      'event.reason': 'adopted',
    });
  });

  test('fails when the existing parameter has other key options, and leaves it alone', async () => {
    const other = await jwksOf(enc);
    const { ssm, handler, responses } = setup(sig, { jwks: other, ageMs: DAY_MS });
    await handler(cfn('Create'), context);

    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(responses[0].body).toMatchObject({
      Status: 'FAILED',
      Reason: expect.stringContaining('do not match the configured options'),
    });
    // A failed creation must not own the parameter, so rolling it back must not delete it.
    expect(String(responses[0].body.PhysicalResourceId)).toMatch(/^create-failed-/);
  });

  test('an update that changes nothing checks the parameter and never rotates it', async () => {
    const existing = await jwksOf(sig);
    const { ssm, handler, responses } = setup(sig, { jwks: existing, ageMs: 1000 });
    await handler(cfn('Update', NAME), context);

    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(ssm.jwks).toEqual(existing);
    expect(responses[0].body).toMatchObject({ Status: 'SUCCESS', PhysicalResourceId: NAME });
  });

  test('an update recreates a parameter that was deleted by hand', async () => {
    const { ssm, handler, responses } = setup();
    await handler(cfn('Update', NAME), context);

    expect(ssm.jwks.keys).toHaveLength(2);
    expect(responses[0].body.Status).toBe('SUCCESS');
  });

  test('an update fails when the keys no longer match the options', async () => {
    const { handler, responses } = setup(sig, { jwks: await jwksOf(enc), ageMs: DAY_MS });
    await handler(cfn('Update', NAME), context);
    expect(responses[0].body).toMatchObject({ Status: 'FAILED', PhysicalResourceId: NAME });
  });

  test('a delete removes the parameter it created', async () => {
    const { ssm, handler, responses } = setup(sig, { jwks: await jwksOf(sig), ageMs: DAY_MS });
    await handler(cfn('Delete', NAME), context);

    expect(ssm.stored).toBeUndefined();
    expect(responses[0].body).toMatchObject({ Status: 'SUCCESS', PhysicalResourceId: NAME });
  });

  test('a delete of a parameter that is already gone succeeds', async () => {
    const { handler, responses } = setup();
    await handler(cfn('Delete', NAME), context);
    expect(responses[0].body.Status).toBe('SUCCESS');
    expect(logged().find((record) => record['event.action'] === 'delete_parameter')).toMatchObject({
      'event.reason': 'not_found',
    });
  });

  test('a delete after a failed creation touches no parameter', async () => {
    const { ssm, handler, responses } = setup(sig, { jwks: await jwksOf(sig), ageMs: DAY_MS });
    await handler(cfn('Delete', 'create-failed-cfn-request-1'), context);
    expect(ssm.of(DeleteParameterCommand)).toHaveLength(0);
    expect(responses[0].body.Status).toBe('SUCCESS');
  });

  test('reports an unexpected error without its message, which might echo key material', async () => {
    const { ssm, handler, responses } = setup();
    ssm.failPutWith = new TypeError('d=SECRET');
    await handler(cfn('Create'), context);
    expect(responses[0].body.Status).toBe('FAILED');
    expect(JSON.stringify(responses[0].body)).not.toContain('SECRET');
    expect(output.join('')).not.toContain('SECRET');
  });
});

describe('scheduled rotation', () => {
  test('adds a key and, for sig keys, strips the private part of the oldest', async () => {
    const before = await jwksOf(sig);
    const { ssm, handler } = setup(sig, { jwks: before, ageMs: 28 * DAY_MS });
    await handler({ action: 'rotate' }, context);

    const after = ssm.jwks;
    expect(after.keys).toHaveLength(3);
    expect(after.keys.slice(0, 2).map((jwk) => jwk.kid)).toEqual(before.keys.map((jwk) => jwk.kid));
    expect(after.keys[0].d).toBeUndefined();
    expect(after.keys[1].d).toBeDefined();
    expect(ssm.of(PutParameterCommand)[0].input).toMatchObject({ Overwrite: true, Type: 'SecureString' });
    expect(logged().find((record) => record['event.action'] === 'rotate_parameter')).toMatchObject({
      'event.outcome': 'success',
      'jwks.kids.added': [after.keys[2].kid],
      'aws.ssm.parameter.previous_version': 1,
    });
  });

  test('keeps at most 3 keys, all private for enc keys', async () => {
    const { ssm, handler } = setup(enc, { jwks: await jwksOf(enc, 1), ageMs: 28 * DAY_MS });
    await handler({ action: 'rotate' }, context);
    await handler({ action: 'rotate', force: true }, context);

    expect(ssm.jwks.keys).toHaveLength(3);
    expect(ssm.jwks.keys.every((jwk) => jwk.d !== undefined)).toBe(true);
  });

  test('skips a rotation within half an interval of the last change, and logs why', async () => {
    const before = await jwksOf(sig);
    const { ssm, handler } = setup(sig, { jwks: before, ageMs: 13 * DAY_MS });
    await handler({ action: 'rotate' }, context);

    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(logged().find((record) => record['event.action'] === 'skip_rotation')).toMatchObject({
      'event.outcome': 'success',
      'event.reason': 'rotated_recently',
      'jwks.parameter.age_seconds': 13 * 24 * 60 * 60,
    });
  });

  test('rotates at exactly half an interval', async () => {
    const { ssm, handler } = setup(sig, { jwks: await jwksOf(sig), ageMs: 14 * DAY_MS });
    await handler({ action: 'rotate' }, context);
    expect(ssm.jwks.keys).toHaveLength(3);
  });

  test('force rotates a recently changed parameter', async () => {
    const { ssm, handler } = setup(sig, { jwks: await jwksOf(sig), ageMs: 1000 });
    await handler({ action: 'rotate', force: true }, context);
    expect(ssm.jwks.keys).toHaveLength(3);
  });

  test('a duplicate delivery is a no-op: the second rotation is skipped', async () => {
    const { ssm, handler } = setup(sig, { jwks: await jwksOf(sig), ageMs: 28 * DAY_MS });
    await handler({ action: 'rotate' }, context);
    const afterFirst = ssm.stored!.value;
    await handler({ action: 'rotate' }, context);
    expect(ssm.stored!.value).toBe(afterFirst);
  });

  test('fails, and logs, when the parameter does not exist, and does not create it', async () => {
    const { ssm, handler } = setup();
    await expect(handler({ action: 'rotate' }, context)).rejects.toBeInstanceOf(RotationStateError);
    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(logged().at(-1)).toMatchObject({
      'event.action': 'validate_rotation',
      'event.outcome': 'failure',
      'event.reason': 'parameter_not_found',
      'error.message': expect.stringContaining('invoke the function with force to create it'),
    });
  });

  test('force creates a missing parameter with 2 new keys, without overwriting', async () => {
    const { ssm, handler } = setup(sig, undefined, { keyId: 'alias/jwks', description: 'JWKS' });
    await handler({ action: 'rotate', force: true }, context);

    expect(ssm.of(PutParameterCommand)[0].input).toMatchObject({
      Name: NAME,
      Type: 'SecureString',
      Tier: 'Standard',
      KeyId: 'alias/jwks',
      Description: 'JWKS',
      Overwrite: false,
    });
    expect(ssm.jwks.keys).toHaveLength(2);
    expect(ssm.jwks.keys.every((jwk) => jwk.d !== undefined)).toBe(true);
    expect(logged().find((record) => record['event.action'] === 'create_parameter')).toMatchObject({
      'event.outcome': 'success',
      'event.reason': 'recreated',
      'jwks.kids.added': ssm.jwks.keys.map((jwk) => jwk.kid),
      'aws.ssm.parameter.version': 1,
    });
  });

  test('force on an existing parameter rotates it rather than recreating it', async () => {
    const { ssm, handler } = setup(sig, { jwks: await jwksOf(sig), ageMs: 1000 });
    await handler({ action: 'rotate', force: true }, context);
    expect(ssm.jwks.keys).toHaveLength(3);
    expect(logged().some((record) => record['event.action'] === 'create_parameter')).toBe(false);
  });

  test('fails, without changing the parameter, when its keys do not match the options', async () => {
    const other = await jwksOf(enc);
    const { ssm, handler } = setup(sig, { jwks: other, ageMs: 28 * DAY_MS });
    await expect(handler({ action: 'rotate' }, context)).rejects.toThrow(
      /do not match the configured options/,
    );
    expect(ssm.of(PutParameterCommand)).toHaveLength(0);
    expect(logged().at(-1)).toMatchObject({
      'event.action': 'rotate_parameter',
      'event.outcome': 'failure',
      'error.type': 'JwkOptionsMismatchError',
    });
  });

  test('fails when the parameter does not hold a valid JWKS', async () => {
    const { ssm, handler } = setup();
    ssm.stored = { value: 'not json', version: 1, lastModified: new Date(0) };
    await expect(handler({ action: 'rotate' }, context)).rejects.toThrow('not valid JSON');
  });

  test('rethrows a Systems Manager failure, so Lambda retries it', async () => {
    const { ssm, handler } = setup(sig, { jwks: await jwksOf(sig), ageMs: 28 * DAY_MS });
    ssm.failPutWith = new Error('throttled');
    await expect(handler({ action: 'rotate' }, context)).rejects.toThrow('throttled');
  });

  test('never logs key material', async () => {
    const jwks = await jwksOf(sig, 1);
    const { handler } = setup(sig, { jwks, ageMs: 28 * DAY_MS });
    await handler({ action: 'rotate' }, context);
    const members = jwks.keys.flatMap((jwk) =>
      ['d', 'x', 'y'].map((member) => (jwk as unknown as Record<string, string>)[member]),
    );
    expect(members.filter((value) => output.join('').includes(value))).toEqual([]);
  });
});

test('rejects an event that is neither a custom resource request nor a rotation', async () => {
  const { handler } = setup();
  await expect(handler({ action: 'other' } as never, context)).rejects.toMatchObject({
    reason: 'unknown_event',
  });
});

describe('configuration', () => {
  const env = {
    [PARAMETER_ENV.name]: NAME,
    [PARAMETER_ENV.tier]: 'Advanced',
    [PARAMETER_ENV.rotationIntervalSeconds]: '86400',
    [PARAMETER_ENV.keyId]: 'alias/jwks',
    [PARAMETER_ENV.description]: 'JWKS',
  };

  test('is read from the environment', () => {
    expect(parseParameterConfig(env)).toEqual({
      name: NAME,
      tier: 'Advanced',
      keyId: 'alias/jwks',
      description: 'JWKS',
      rotationIntervalSeconds: 86400,
    });
    expect(
      parseParameterConfig({ ...env, [PARAMETER_ENV.keyId]: '', [PARAMETER_ENV.description]: '' }),
    ).toMatchObject({
      keyId: undefined,
      description: undefined,
    });
  });

  test.each([
    [{ [PARAMETER_ENV.name]: '' }, /JWKS_PARAMETER_NAME is not set/],
    [{ [PARAMETER_ENV.tier]: 'Intelligent-Tiering' }, /must be "Standard" or "Advanced"/],
    [{ [PARAMETER_ENV.rotationIntervalSeconds]: '0' }, /must be a positive integer/],
    [{ [PARAMETER_ENV.rotationIntervalSeconds]: 'soon' }, /must be a positive integer/],
  ])('rejects %j', (override, message) => {
    expect(() => parseParameterConfig({ ...env, ...override })).toThrow(message);
  });

  test('a function with a missing option or name logs a failed start and throws', () => {
    expect(() => initialiseParameterHandler(new FakeSsm(), { ...env })).toThrow(JWK_OPTIONS_ENV);
    expect(logged().at(-1)).toMatchObject({
      'event.action': 'start_function',
      'event.outcome': 'failure',
    });
  });

  test('starts with valid configuration and logs the key options', () => {
    initialiseParameterHandler(new FakeSsm(), {
      ...env,
      [JWK_OPTIONS_ENV]: JSON.stringify(sig),
    });
    expect(logged().at(-1)).toMatchObject({
      'event.action': 'start_function',
      'event.outcome': 'success',
      'jwks.alg': 'ES256',
      'aws.ssm.parameter.tier': 'Advanced',
    });
  });
});

test('generates keys with the thumbprint as kid', async () => {
  const jwk = await generateJwk(sig);
  expect(jwk.kid).toHaveLength(43);
});

function mockHttps(statusCode: number) {
  const sent: { url: unknown; options: Record<string, unknown>; body: string }[] = [];
  jest.mocked(request).mockImplementation(((
    url: unknown,
    options: Record<string, unknown>,
    callback: (response: unknown) => void,
  ) => {
    const req = new EventEmitter() as EventEmitter & { end: (body: string) => void };
    req.end = (body: string) => {
      sent.push({ url, options, body });
      const response = Object.assign(new EventEmitter(), { statusCode, resume: () => undefined });
      callback(response);
      response.emit('end');
    };
    return req;
  }) as never);
  return sent;
}

const bare = () => createParameterHandler(new FakeSsm(), sig, config, { now: () => NOW });

describe('the response to CloudFormation', () => {
  test('is a PUT without a content type, to the pre-signed URL', async () => {
    const sent = mockHttps(200);
    await bare()(cfn('Create'), context);

    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe('https://cloudformation.example/response');
    expect(sent[0].options).toMatchObject({
      method: 'PUT',
      headers: { 'content-type': '', 'content-length': Buffer.byteLength(sent[0].body) },
    });
    expect(JSON.parse(sent[0].body)).toMatchObject({ Status: 'SUCCESS', PhysicalResourceId: NAME });
  });

  test('fails the invocation if CloudFormation rejects the response', async () => {
    mockHttps(403);
    await expect(bare()(cfn('Create'), context)).rejects.toThrow('status 403');
  });

  test('fails the invocation if the request errors', async () => {
    jest.mocked(request).mockImplementation((() => {
      const req = new EventEmitter() as EventEmitter & { end: () => void };
      req.end = () => req.emit('error', new Error('socket hang up'));
      return req;
    }) as never);
    await expect(bare()(cfn('Create'), context)).rejects.toThrow('socket hang up');
  });
});

test('the Lambda entry point configures itself from the environment, once', async () => {
  Object.assign(process.env, {
    [JWK_OPTIONS_ENV]: JSON.stringify(sig),
    [PARAMETER_ENV.name]: NAME,
    [PARAMETER_ENV.tier]: 'Standard',
    [PARAMETER_ENV.rotationIntervalSeconds]: '86400',
  });
  try {
    await expect(lambdaHandler({ action: 'other' } as never)).rejects.toMatchObject({
      reason: 'unknown_event',
    });
    await expect(lambdaHandler({ action: 'other' } as never)).rejects.toMatchObject({
      reason: 'unknown_event',
    });
    expect(logged().filter((record) => record['event.action'] === 'start_function')).toHaveLength(1);
  } finally {
    for (const name of [JWK_OPTIONS_ENV, ...Object.values(PARAMETER_ENV)]) {
      delete process.env[name];
    }
  }
});
