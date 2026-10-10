import type { IKey } from 'aws-cdk-lib/aws-kms';
import type { Duration, RemovalPolicy } from 'aws-cdk-lib';
import type { FunctionProps } from 'aws-cdk-lib/aws-lambda';
import type { LogGroupProps } from 'aws-cdk-lib/aws-logs';
import type { JwkOptions } from '../../shared/jwks';

/** Overrides for the parameter. Its value is always managed by the construct. */
export interface JwksParameterParameterProps {
  /**
   * The name of the parameter. It must be a valid Parameter Store name, and
   * cannot be changed without creating a new parameter, so consumers that read
   * the parameter by name have to follow.
   *
   * @default `/` followed by the construct's path, e.g. `/MyStack/ClientJwks`
   */
  readonly parameterName?: string;

  /**
   * The description of the parameter.
   *
   * @default no description
   */
  readonly description?: string;

  /**
   * The KMS key that encrypts the `SecureString`. The rotation Lambda is
   * granted use of it, and so is anyone given `grantRead`.
   *
   * @default the AWS managed key `alias/aws/ssm`, which is free
   */
  readonly encryptionKey?: IKey;

  /**
   * What happens to the parameter when it is removed from the stack.
   *
   * @default `RemovalPolicy.RETAIN`, since deleting the parameter loses the
   * private keys the OpenID Connect client registration relies on
   */
  readonly removalPolicy?: RemovalPolicy;
}

/**
 * Props for `JwksParameter`. The key options (`use`, `algorithm`, `curve`,
 * `rsaModulusLength`) are the construct's own; the other props override the
 * defaults of the underlying resources.
 */
export interface JwksParameterProps extends JwkOptions {
  /** Overrides for the parameter. */
  readonly parameterProps?: JwksParameterParameterProps;

  /**
   * Overrides for the rotation Lambda. In a VPC, the subnets need a route to
   * Systems Manager, through a VPC endpoint or NAT.
   *
   * @default not in a VPC, and 512 MB memory for RSA keys larger than 2048
   * bits (Lambda allocates CPU in proportion to memory, which RSA key
   * generation needs), 128 MB otherwise
   */
  readonly rotationLambdaProps?: Pick<FunctionProps, 'memorySize' | 'vpc' | 'vpcSubnets' | 'securityGroups'>;

  /**
   * Overrides for the rotation Lambda's log group.
   *
   * @default `RetentionDays.ONE_YEAR`, no customer managed encryption key, and
   * the parameter's removal policy
   */
  readonly rotationLogGroupProps?: Pick<LogGroupProps, 'retention' | 'removalPolicy' | 'encryptionKey'>;

  /**
   * Overrides for the rotation schedule. `automaticallyAfter` is also how long
   * a new key is published before it is used, so it should exceed the OpenID
   * Connect server's JWKS cache lifetime, and from 4 hours to 1000 days. The
   * rotation Lambda skips a scheduled rotation if the parameter was modified
   * less than half this long ago.
   *
   * @default rotation every 28 days
   */
  readonly rotationScheduleProps?: { readonly automaticallyAfter?: Duration };
}
