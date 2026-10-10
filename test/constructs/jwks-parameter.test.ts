import { Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Vpc } from 'aws-cdk-lib/aws-ec2';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';
import { JwksParameter, type JwksParameterProps } from '../../src/constructs';

interface Statement {
  readonly Action: string | string[];
  readonly Resource: unknown;
}

/** Every IAM policy statement of the template. */
function statementsOf(template: Template): Statement[] {
  return Object.values(template.findResources('AWS::IAM::Policy')).flatMap(
    (policy) =>
      (policy as { Properties: { PolicyDocument: { Statement: Statement[] } } }).Properties.PolicyDocument
        .Statement,
  );
}

/** The statements that allow exactly `actions` on a resource mentioning `resource`. */
function allowing(template: Template, actions: string[], resource: string): Statement[] {
  return statementsOf(template).filter(
    (statement) =>
      JSON.stringify(statement.Action) === JSON.stringify(actions) &&
      JSON.stringify(statement.Resource).includes(resource),
  );
}

function synth(props?: JwksParameterProps) {
  const stack = new Stack(undefined, 'TestStack', { env: { region: 'us-east-1', account: '123456789012' } });
  const jwksParameter = new JwksParameter(stack, 'JwksParameter', props);
  return { stack, jwksParameter, template: Template.fromStack(stack) };
}

test('creates the parameter through a custom resource that invokes the rotation Lambda directly', () => {
  const { template } = synth();
  template.hasResource('Custom::JwksParameter', {
    Properties: {
      ServiceToken: { 'Fn::GetAtt': [Match.stringLikeRegexp('RotationLambda'), 'Arn'] },
      ServiceTimeout: '120',
      ParameterName: '/TestStack/JwksParameter',
      Tier: 'Standard',
    },
    DeletionPolicy: 'Retain',
    UpdateReplacePolicy: 'Retain',
  });
  // No provider framework.
  template.resourceCountIs('AWS::Lambda::Function', 1);
});

test('creates no AWS::SSM::Parameter, which cannot be a SecureString', () => {
  const { template } = synth();
  template.resourceCountIs('AWS::SSM::Parameter', 0);
});

test('generates a parameter name from the construct path, and exposes it with its ARN', () => {
  const { jwksParameter } = synth();
  expect(jwksParameter.parameterName).toBe('/TestStack/JwksParameter');
  expect(jwksParameter.parameterArn).toEqual(expect.stringContaining(':ssm:'));
});

test('keeps the rotation Lambda logs for a year in a log group that follows the removal policy', () => {
  const { template } = synth();
  template.hasResource('AWS::Logs::LogGroup', {
    Properties: { RetentionInDays: 365 },
    DeletionPolicy: 'Retain',
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    LoggingConfig: { LogFormat: 'Text', LogGroup: { Ref: Match.stringLikeRegexp('RotationLambdaLogGroup') } },
  });
});

test('creates a Node 24 arm64 rotation Lambda with reserved concurrency 1 and a dead letter queue', () => {
  const { template } = synth();
  template.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'nodejs24.x',
    Architectures: ['arm64'],
    Handler: 'index.handler',
    ReservedConcurrentExecutions: 1,
    DeadLetterConfig: { TargetArn: { 'Fn::GetAtt': [Match.stringLikeRegexp('DeadLetterQueue'), 'Arn'] } },
    Environment: {
      Variables: {
        JWK_OPTIONS: JSON.stringify({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' }),
        JWKS_PARAMETER_NAME: '/TestStack/JwksParameter',
        JWKS_PARAMETER_TIER: 'Standard',
        JWKS_ROTATION_INTERVAL_SECONDS: String(28 * 24 * 60 * 60),
      },
    },
  });
  template.hasResourceProperties('AWS::Lambda::EventInvokeConfig', { MaximumRetryAttempts: 2 });
  template.hasResourceProperties('AWS::SQS::Queue', { SqsManagedSseEnabled: true });
});

test('schedules a rotation every 28 days, after the parameter has been created', () => {
  const { template } = synth();
  template.hasResource('AWS::Scheduler::Schedule', {
    Properties: {
      ScheduleExpression: 'rate(28 days)',
      FlexibleTimeWindow: { Mode: 'OFF' },
      Target: Match.objectLike({ Input: JSON.stringify({ action: 'rotate' }) }),
    },
    DependsOn: [Match.stringLikeRegexp('Initialisation')],
  });
});

test('lets Scheduler invoke only the rotation Lambda', () => {
  const { template } = synth();
  expect(allowing(template, ['lambda:InvokeFunction'], 'RotationLambda')).toHaveLength(0);
  const invoke = statementsOf(template).filter((statement) => statement.Action === 'lambda:InvokeFunction');
  expect(invoke).toHaveLength(1);
  expect(JSON.stringify(invoke[0].Resource)).toContain('RotationLambda');
});

test('lets the rotation Lambda read and write only its own parameter', () => {
  const { template } = synth();
  expect(
    allowing(template, ['ssm:GetParameter', 'ssm:PutParameter'], 'parameter/TestStack/JwksParameter'),
  ).toHaveLength(1);
  // The parameter is retained, so the Lambda may not delete it.
  expect(JSON.stringify(statementsOf(template))).not.toContain('ssm:DeleteParameter');
});

test.each([
  [{}, 'Standard', 128],
  [{ use: 'enc' }, 'Standard', 128],
  [{ algorithm: 'RS256' }, 'Standard', 128],
  [{ algorithm: 'RS256', rsaModulusLength: 3072 }, 'Advanced', 512],
  [{ algorithm: 'RSA-OAEP-256' }, 'Advanced', 128],
  [{ algorithm: 'RS256', rsaModulusLength: 4096 }, 'Advanced', 512],
] as const)('derives the tier and memory for %j: %s, %d MB', (props, tier, memorySize) => {
  const { template, jwksParameter } = synth(props);
  expect(jwksParameter.tier).toBe(tier);
  template.hasResourceProperties('AWS::Lambda::Function', {
    MemorySize: memorySize,
    Environment: { Variables: Match.objectLike({ JWKS_PARAMETER_TIER: tier }) },
  });
  template.hasResourceProperties('Custom::JwksParameter', { Tier: tier });
});

test('rejects encryption keys that fit no parameter tier', () => {
  expect(() => synth({ algorithm: 'RSA-OAEP-256', rsaModulusLength: 4096 })).toThrow(
    /more than the 8192 bytes of an advanced tier parameter/,
  );
});

test('applies the optional props', () => {
  const stack = new Stack(undefined, 'TestStack', { env: { region: 'us-east-1', account: '123456789012' } });
  const encryptionKey = new Key(stack, 'Key');
  const vpc = new Vpc(stack, 'Vpc');
  new JwksParameter(stack, 'JwksParameter', {
    parameterProps: {
      parameterName: '/oidc/client-jwks',
      description: 'JWKS',
      encryptionKey,
      removalPolicy: RemovalPolicy.DESTROY,
    },
    algorithm: 'ECDH-ES',
    curve: 'P-384',
    rotationLogGroupProps: { retention: RetentionDays.ONE_MONTH },
    rotationScheduleProps: { automaticallyAfter: Duration.days(7) },
    rotationLambdaProps: { vpc },
  });
  const template = Template.fromStack(stack);

  template.hasResource('AWS::Logs::LogGroup', {
    Properties: { RetentionInDays: 30 },
    DeletionPolicy: 'Delete',
  });
  template.hasResource('Custom::JwksParameter', {
    Properties: { ParameterName: '/oidc/client-jwks', KeyId: Match.anyValue() },
    DeletionPolicy: 'Delete',
  });
  template.hasResourceProperties('AWS::Scheduler::Schedule', { ScheduleExpression: 'rate(7 days)' });
  template.hasResourceProperties('AWS::Lambda::Function', {
    VpcConfig: Match.objectLike({ SubnetIds: Match.anyValue() }),
    Environment: {
      Variables: Match.objectLike({
        JWKS_PARAMETER_NAME: '/oidc/client-jwks',
        JWKS_PARAMETER_DESCRIPTION: 'JWKS',
        JWKS_PARAMETER_KEY_ID: Match.anyValue(),
        JWKS_ROTATION_INTERVAL_SECONDS: String(7 * 24 * 60 * 60),
      }),
    },
  });
  // Deleting the parameter is only allowed when it is removed with the stack.
  expect(
    allowing(
      template,
      ['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter'],
      'parameter/oidc/client-jwks',
    ),
  ).toHaveLength(1);
  // The rotation Lambda may use the key, for exactly the 2 actions SSM needs.
  expect(allowing(template, ['kms:Encrypt', 'kms:Decrypt'], 'Key')).toHaveLength(1);
});

test('grants read access to the parameter, and to the key, without the history', () => {
  const stack = new Stack(undefined, 'TestStack');
  const encryptionKey = new Key(stack, 'Key');
  const jwksParameter = new JwksParameter(stack, 'JwksParameter', {
    parameterProps: { encryptionKey },
  });
  expect(jwksParameter.jwkOptions).toEqual({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' });

  const role = new Role(stack, 'ServerRole', { assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com') });
  jwksParameter.grantRead(role);
  const template = Template.fromStack(stack);
  const policies = template.findResources('AWS::IAM::Policy', {
    Properties: { Roles: [{ Ref: Match.stringLikeRegexp('ServerRole') }] },
  });
  const statements = Object.values(policies).flatMap(
    (policy) =>
      (policy as { Properties: { PolicyDocument: { Statement: unknown[] } } }).Properties.PolicyDocument
        .Statement,
  );
  expect(statements).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ Action: 'ssm:GetParameter' }),
      expect.objectContaining({ Action: 'kms:Decrypt' }),
    ]),
  );
  expect(JSON.stringify(statements)).not.toContain('GetParameterHistory');
});

test('explains how to build a missing rotation Lambda bundle', () => {
  // Spy on the module object itself, which the construct's named import reads from.
  jest.spyOn(require('node:fs') as typeof import('node:fs'), 'existsSync').mockReturnValue(false);
  try {
    expect(() => synth()).toThrow(/Rotation Lambda bundle not found .* Run "npm run build:lambda"/);
  } finally {
    jest.restoreAllMocks();
  }
});

test.each([
  [{ algorithm: 'HS256' }, /Unsupported algorithm/],
  [{ algorithm: 'ES256', rsaModulusLength: 2048 }, /not applicable/],
  [{ use: 'enc', algorithm: 'ES256' }, /but use is "enc"/],
  [
    { rotationLambdaProps: { memorySize: 64 } },
    /rotationLambdaProps.memorySize must be an integer from 128 to 10240/,
  ],
  [{ rotationLambdaProps: { memorySize: 256.5 } }, /rotationLambdaProps.memorySize must be/],
  [{ rotationScheduleProps: { automaticallyAfter: Duration.hours(1) } }, /from 4 hours to 1000 days/],
  [{ rotationScheduleProps: { automaticallyAfter: Duration.days(1001) } }, /from 4 hours to 1000 days/],
  [{ parameterProps: { parameterName: '/has space' } }, /not a valid Parameter Store name/],
  [{ parameterProps: { parameterName: '/aws/jwks' } }, /reserves|reserved/],
  [{ parameterProps: { parameterName: 'SSM-jwks' } }, /reserves|reserved/],
])('rejects invalid props %j at synth time', (props, error) => {
  expect(() => synth(props as JwksParameterProps)).toThrow(error);
});
