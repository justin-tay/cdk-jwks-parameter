import * as path from 'node:path';
import { CfnOutput, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Architecture, FunctionUrlAuthType, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import type { Construct } from 'constructs';
import { JwksParameter, type JwkPublicKeyUse, type JwksParameterProps } from 'cdk-jwks-parameter';
import type { AppStackProps } from './app-stack-props';

/**
 * Example of using `JwksParameter`: a rotated JWKS parameter of signing keys
 * and one of encryption keys, and a public JWKS endpoint that serves the
 * public keys of both, as an OpenID Connect client's `jwks_uri` would.
 */
export class AppStack extends Stack {
  public readonly sigJwksParameter: JwksParameter;

  public readonly encJwksParameter: JwksParameter;

  public readonly jwksEndpoint: NodejsFunction;

  constructor(scope: Construct, id: string, props: AppStackProps = {}) {
    super(scope, id, props);

    this.sigJwksParameter = new JwksParameter(
      this,
      'SigJwksParameter',
      withExampleDefaults(props.sigJwksParameter, 'sig'),
    );
    this.encJwksParameter = new JwksParameter(
      this,
      'EncJwksParameter',
      withExampleDefaults(props.encJwksParameter, 'enc'),
    );
    const jwksParameters = [this.sigJwksParameter, this.encJwksParameter];

    this.jwksEndpoint = new NodejsFunction(this, 'JwksEndpoint', {
      description: 'Serves the public keys of the JWKS parameters',
      entry: path.join(__dirname, 'handlers', 'jwks-endpoint.ts'),
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      environment: {
        JWKS_PARAMETER_NAMES: this.toJsonString(
          jwksParameters.map((jwksParameter) => jwksParameter.parameterName),
        ),
        JWKS_CACHE_SECONDS: String((props.jwksCacheTtl ?? Duration.seconds(0)).toSeconds()),
      },
      logGroup: new LogGroup(this, 'JwksEndpointLogGroup', {
        retention: RetentionDays.ONE_WEEK,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
    });
    for (const jwksParameter of jwksParameters) {
      jwksParameter.grantRead(this.jwksEndpoint);
      // The endpoint reads the parameters when it is invoked, not at deployment.
    }

    // A JWKS is public by design, so the endpoint needs no authentication.
    const jwksUrl = this.jwksEndpoint.addFunctionUrl({ authType: FunctionUrlAuthType.NONE });

    new CfnOutput(this, 'JwksUrl', { value: jwksUrl.url });
    new CfnOutput(this, 'SigParameterName', { value: this.sigJwksParameter.parameterName });
    new CfnOutput(this, 'EncParameterName', { value: this.encJwksParameter.parameterName });
    new CfnOutput(this, 'SigRotationLambda', { value: this.sigJwksParameter.rotationLambda.functionName });
    new CfnOutput(this, 'EncRotationLambda', { value: this.encJwksParameter.rotationLambda.functionName });
    new CfnOutput(this, 'SigRotationLogGroup', {
      value: this.sigJwksParameter.rotationLogGroup.logGroupName,
    });
    new CfnOutput(this, 'EncRotationLogGroup', {
      value: this.encJwksParameter.rotationLogGroup.logGroupName,
    });
  }
}

/** The example's defaults, overridable by `props`, for a parameter with the given use. */
function withExampleDefaults(
  props: Omit<JwksParameterProps, 'use'> = {},
  use: JwkPublicKeyUse,
): JwksParameterProps {
  return {
    ...props,
    use,
    // Clean up on `cdk destroy`; the construct retains the parameter by default.
    parameterProps: { removalPolicy: RemovalPolicy.DESTROY, ...props.parameterProps },
    rotationLogGroupProps: { retention: RetentionDays.ONE_WEEK, ...props.rotationLogGroupProps },
  };
}
