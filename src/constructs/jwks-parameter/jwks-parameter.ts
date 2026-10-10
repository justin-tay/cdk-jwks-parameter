import { existsSync } from 'node:fs';
import * as path from 'node:path';
import {
  Arn,
  ArnFormat,
  CustomResource,
  Duration,
  RemovalPolicy,
  Stack,
  Token,
  Validations,
} from 'aws-cdk-lib';
import type { IKey } from 'aws-cdk-lib/aws-kms';
import { Grant, ManagedPolicy, Role, ServicePrincipal, type IGrantable } from 'aws-cdk-lib/aws-iam';
import {
  Architecture,
  Code,
  Function as LambdaFunction,
  LoggingFormat,
  Runtime,
} from 'aws-cdk-lib/aws-lambda';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Schedule, ScheduleExpression, ScheduleTargetInput } from 'aws-cdk-lib/aws-scheduler';
import { LambdaInvoke } from 'aws-cdk-lib/aws-scheduler-targets';
import { Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import {
  JWK_OPTIONS_ENV,
  PARAMETER_ENV,
  parameterTierFor,
  resolveJwkOptions,
  type ParameterTier,
  type ResolvedJwkOptions,
} from '../../shared/jwks';
import type { JwksParameterProps } from './jwks-parameter-props';

// src/ and lib/ sit at the same depth, so this resolves to the bundle under
// lib/ both from the compiled construct and from the TypeScript source in tests.
const ROTATION_HANDLER_ASSET_PATH = path.join(
  __dirname,
  '..',
  '..',
  '..',
  'lib',
  'assets',
  'lambda',
  'handlers',
  'rotation',
);

const MIN_ROTATION_INTERVAL = Duration.hours(4);
const MAX_ROTATION_INTERVAL = Duration.days(1000);

/** Parameter Store names: letters, digits and `_ . - /`, up to 1011 characters. */
const PARAMETER_NAME_PATTERN = /^[a-zA-Z0-9_.\-/]{1,1011}$/;

/** Enough CPU to generate 2 keys well within the timeout: large RSA keys need more than the minimum. */
function defaultRotationLambdaMemorySize(options: ResolvedJwkOptions): number {
  return options.keyType === 'RSA' && options.rsaModulusLength! > 2048 ? 512 : 128;
}

function validateParameterName(name: string): void {
  if (Token.isUnresolved(name)) {
    return;
  }
  if (!PARAMETER_NAME_PATTERN.test(name)) {
    throw new Error(
      `The parameter name "${name}" is not a valid Parameter Store name: use up to 1011 letters, ` +
        'digits and _ . - / characters. Set parameterProps.parameterName.',
    );
  }
  if (/^\/?(aws|ssm)/i.test(name)) {
    throw new Error(
      `The parameter name "${name}" starts with "aws" or "ssm", which Parameter Store reserves. ` +
        'Set parameterProps.parameterName.',
    );
  }
}

/**
 * A JWKS stored verbatim (`{"keys":[...]}`) in an SSM `SecureString` parameter
 * and rotated by a Lambda that EventBridge Scheduler invokes. The parameter is
 * created with 2 keys when the stack is deployed, and each scheduled rotation
 * adds a key, keeping at most 3.
 *
 * CloudFormation cannot create a `SecureString`, so the rotation Lambda also
 * serves a custom resource that creates the parameter. The parameter is
 * therefore not a CloudFormation resource of its own.
 */
export class JwksParameter extends Construct {
  /** The name of the parameter. */
  public readonly parameterName: string;

  /** The ARN of the parameter. */
  public readonly parameterArn: string;

  /**
   * The parameter tier, the cheapest that holds the largest JWKS the key
   * options can produce. `Advanced` costs $0.05 per month.
   */
  public readonly tier: ParameterTier;

  /** The custom resource that creates the parameter; depend on it to read the parameter at deployment. */
  public readonly initialisation: CustomResource;

  public readonly rotationSchedule: Schedule;

  public readonly rotationLambda: LambdaFunction;

  public readonly rotationLogGroup: LogGroup;

  public readonly rotationLambdaRole: Role;

  /** Receives the invocations that still failed after Lambda's retries. */
  public readonly rotationDeadLetterQueue: Queue;

  /** The resolved key options, including the `use` derived from the algorithm. */
  public readonly jwkOptions: ResolvedJwkOptions;

  private readonly encryptionKey?: IKey;

  constructor(scope: Construct, id: string, props: JwksParameterProps = {}) {
    super(scope, id);

    this.jwkOptions = resolveJwkOptions({
      use: props.use,
      algorithm: props.algorithm,
      curve: props.curve,
      rsaModulusLength: props.rsaModulusLength,
    });
    this.tier = parameterTierFor(this.jwkOptions);

    if (!existsSync(path.join(ROTATION_HANDLER_ASSET_PATH, 'index.mjs'))) {
      throw new Error(
        `Rotation Lambda bundle not found at ${ROTATION_HANDLER_ASSET_PATH}. Run "npm run build:lambda".`,
      );
    }

    const { parameterProps = {}, rotationLambdaProps = {}, rotationLogGroupProps = {} } = props;
    const rotationInterval = props.rotationScheduleProps?.automaticallyAfter ?? Duration.days(28);
    if (
      rotationInterval.toMilliseconds() < MIN_ROTATION_INTERVAL.toMilliseconds() ||
      rotationInterval.toMilliseconds() > MAX_ROTATION_INTERVAL.toMilliseconds()
    ) {
      throw new Error(
        `rotationScheduleProps.automaticallyAfter must be from 4 hours to 1000 days, got ${rotationInterval.toHumanString()}`,
      );
    }

    const memorySize = rotationLambdaProps.memorySize ?? defaultRotationLambdaMemorySize(this.jwkOptions);
    if (!Number.isInteger(memorySize) || memorySize < 128 || memorySize > 10240) {
      throw new Error(
        `rotationLambdaProps.memorySize must be an integer from 128 to 10240, got ${memorySize}`,
      );
    }

    this.parameterName = parameterProps.parameterName ?? `/${this.node.path}`;
    validateParameterName(this.parameterName);
    this.parameterArn = Arn.format(
      {
        service: 'ssm',
        resource: 'parameter',
        // The ARN of /a/b is arn:...:parameter/a/b, and of a is arn:...:parameter/a.
        resourceName: this.parameterName.replace(/^\//, ''),
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
      },
      Stack.of(this),
    );
    this.encryptionKey = parameterProps.encryptionKey;
    const removalPolicy = parameterProps.removalPolicy ?? RemovalPolicy.RETAIN;

    this.rotationLogGroup = new LogGroup(this, 'RotationLambdaLogGroup', {
      retention: rotationLogGroupProps.retention ?? RetentionDays.ONE_YEAR,
      encryptionKey: rotationLogGroupProps.encryptionKey,
      removalPolicy: rotationLogGroupProps.removalPolicy ?? removalPolicy,
    });

    // Instead of AWSLambdaBasicExecutionRole, which may write to any log group,
    // the role may write only to the rotation Lambda's own log group.
    this.rotationLambdaRole = new Role(this, 'RotationLambdaRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });
    this.rotationLogGroup.grantWrite(this.rotationLambdaRole);
    if (rotationLambdaProps.vpc) {
      this.rotationLambdaRole.addManagedPolicy(
        ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'),
      );
      Validations.of(this.rotationLambdaRole).acknowledge({
        id: 'AwsSolutions::AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole]',
        reason:
          'Lambda needs these network interface permissions to run in a VPC; they do not support resource-level permissions.',
      });
    }
    const parameterActions = ['ssm:GetParameter', 'ssm:PutParameter'];
    if (removalPolicy === RemovalPolicy.DESTROY) {
      parameterActions.push('ssm:DeleteParameter');
    }
    Grant.addToPrincipal({
      grantee: this.rotationLambdaRole,
      actions: parameterActions,
      resourceArns: [this.parameterArn],
    });
    // SSM encrypts a SecureString with kms:Encrypt and decrypts it with kms:Decrypt; the
    // broader grantEncryptDecrypt would add wildcard actions the Lambda does not use.
    this.encryptionKey?.grant(this.rotationLambdaRole, 'kms:Encrypt', 'kms:Decrypt');

    this.rotationDeadLetterQueue = new Queue(this, 'RotationDeadLetterQueue', {
      encryption: QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
    });

    this.rotationLambda = new LambdaFunction(this, 'RotationLambda', {
      description: 'Creates and rotates the JWKS parameter',
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      handler: 'index.handler',
      code: Code.fromAsset(ROTATION_HANDLER_ASSET_PATH),
      memorySize,
      timeout: Duration.minutes(1),
      environment: {
        [JWK_OPTIONS_ENV]: JSON.stringify(this.jwkOptions),
        [PARAMETER_ENV.name]: this.parameterName,
        [PARAMETER_ENV.tier]: this.tier,
        [PARAMETER_ENV.rotationIntervalSeconds]: String(rotationInterval.toSeconds()),
        ...(parameterProps.encryptionKey && {
          [PARAMETER_ENV.keyId]: parameterProps.encryptionKey.keyArn,
        }),
        ...(parameterProps.description && { [PARAMETER_ENV.description]: parameterProps.description }),
      },
      // Two rotations at once would race on the parameter, which has no
      // compare-and-set.
      reservedConcurrentExecutions: 1,
      retryAttempts: 2,
      deadLetterQueue: this.rotationDeadLetterQueue,
      logGroup: this.rotationLogGroup,
      // The function writes ECS JSON records straight to stdout, which the
      // JSON log format would wrap; see docs/logging.md.
      loggingFormat: LoggingFormat.TEXT,
      role: this.rotationLambdaRole,
      vpc: rotationLambdaProps.vpc,
      vpcSubnets: rotationLambdaProps.vpcSubnets,
      securityGroups: rotationLambdaProps.securityGroups,
    });

    // CloudFormation cannot create a SecureString parameter, so the Lambda creates
    // it. The Lambda is invoked directly, without the provider framework, and
    // sends the response itself. With `RETAIN`, CloudFormation does not call it
    // on delete.
    this.initialisation = new CustomResource(this, 'Initialisation', {
      serviceToken: this.rotationLambda.functionArn,
      // The Lambda's own timeout is 1 minute; this bounds a stack that waits for
      // a response that never comes.
      serviceTimeout: Duration.minutes(2),
      resourceType: 'Custom::JwksParameter',
      removalPolicy,
      properties: {
        ParameterName: this.parameterName,
        Tier: this.tier,
        KeyId: parameterProps.encryptionKey?.keyArn,
        JwkOptions: this.jwkOptions,
      },
    });

    // The role is the construct's own, rather than the one the scheduler targets
    // share per stack, so the acknowledgement below is scoped to it.
    const schedulerRole = new Role(this, 'RotationSchedulerRole', {
      assumedBy: new ServicePrincipal('scheduler.amazonaws.com'),
    });
    this.rotationSchedule = new Schedule(this, 'RotationSchedule', {
      description: 'Rotates the JWKS parameter',
      schedule: ScheduleExpression.rate(rotationInterval),
      target: new LambdaInvoke(this.rotationLambda, {
        role: schedulerRole,
        input: ScheduleTargetInput.fromObject({ action: 'rotate' }),
      }),
    });
    Validations.of(schedulerRole).acknowledge({
      id: 'AwsSolutions::AwsSolutions-IAM5[Resource::<JwksParameterRotationLambda42902BA1.Arn>:*]',
      reason:
        "The scheduler role may invoke only the rotation Lambda and its versions and aliases, which the target's ':*' resource covers.",
    });
    // The parameter must exist before the first scheduled rotation.
    this.rotationSchedule.node.addDependency(this.initialisation);
  }

  /**
   * Grants `grantee` read access to the parameter (and decrypt on the
   * encryption key), e.g. to the server that serves the JWKS endpoint. It does
   * not include `ssm:GetParameterHistory`, but note that `ssm:GetParameter`
   * can read older versions; see docs/using-the-keys.md.
   */
  public grantRead(grantee: IGrantable): Grant {
    const grant = Grant.addToPrincipal({
      grantee,
      actions: ['ssm:GetParameter'],
      resourceArns: [this.parameterArn],
    });
    this.encryptionKey?.grantDecrypt(grantee);
    return grant;
  }
}
