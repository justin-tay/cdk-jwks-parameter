import { App, Duration } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AppStack } from '../../bin/app-stack';
import type { AppStackProps } from '../../bin/app-stack-props';

function synth(props?: AppStackProps) {
  const app = new App();
  const stack = new AppStack(app, 'JwksParameterExampleApp', props);
  return { stack, template: Template.fromStack(stack) };
}

const jwkOptions = (options: object) => ({
  Environment: { Variables: Match.objectLike({ JWK_OPTIONS: JSON.stringify(options) }) },
});

test('deploys an ES256 sig and an ECDH-ES+A128KW enc JWKS parameter, destroyed with the stack', () => {
  const { template } = synth();
  template.resourceCountIs('Custom::JwksParameter', 2);
  template.allResources('Custom::JwksParameter', { DeletionPolicy: 'Delete' });
  template.hasResourceProperties(
    'AWS::Lambda::Function',
    jwkOptions({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' }),
  );
  template.hasResourceProperties(
    'AWS::Lambda::Function',
    jwkOptions({ algorithm: 'ECDH-ES+A128KW', use: 'enc', keyType: 'EC', curve: 'P-256' }),
  );
  template.resourceCountIs('AWS::Logs::LogGroup', 3);
  template.allResources('AWS::Logs::LogGroup', { DeletionPolicy: 'Delete' });
});

test('serves both JWKS from a public function URL with read access to both parameters', () => {
  const { stack, template } = synth();
  template.hasResourceProperties('AWS::Lambda::Url', { AuthType: 'NONE' });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        JWKS_PARAMETER_NAMES: stack.resolve(
          stack.toJsonString([stack.sigJwksParameter.parameterName, stack.encJwksParameter.parameterName]),
        ),
        JWKS_CACHE_SECONDS: '0',
      },
    },
  });
  const endpointRole = stack.resolve(stack.jwksEndpoint.role!.roleName);
  for (const jwksParameter of [stack.sigJwksParameter, stack.encJwksParameter]) {
    template.hasResourceProperties('AWS::IAM::Policy', {
      Roles: [endpointRole],
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'ssm:GetParameter',
            Resource: stack.resolve(jwksParameter.parameterArn),
          }),
        ]),
      },
    });
  }
  template.hasOutput('JwksUrl', {});
  template.hasOutput('SigParameterName', {});
  template.hasOutput('EncParameterName', {});
});

test('passes the JWKS parameter props and cache TTL through', () => {
  const { template } = synth({
    sigJwksParameter: { algorithm: 'PS256', rotationScheduleProps: { automaticallyAfter: Duration.days(1) } },
    encJwksParameter: { algorithm: 'RSA-OAEP-256' },
    jwksCacheTtl: Duration.minutes(5),
  });
  template.hasResourceProperties('AWS::Scheduler::Schedule', { ScheduleExpression: 'rate(1 day)' });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        JWK_OPTIONS: Match.stringLikeRegexp('"algorithm":"PS256"'),
        JWKS_PARAMETER_TIER: 'Standard',
      },
    },
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: Match.objectLike({
        JWK_OPTIONS: Match.stringLikeRegexp('"algorithm":"RSA-OAEP-256"'),
        JWKS_PARAMETER_TIER: 'Advanced',
      }),
    },
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: { Variables: Match.objectLike({ JWKS_CACHE_SECONDS: '300' }) },
  });
});

test.each([
  [{ sigJwksParameter: { algorithm: 'ECDH-ES+A128KW' } }, /is a "enc" algorithm, but use is "sig"/],
  [{ encJwksParameter: { algorithm: 'ES256' } }, /is a "sig" algorithm, but use is "enc"/],
] as const)('rejects an algorithm with the wrong use: %j', (props, error) => {
  expect(() => synth(props as AppStackProps)).toThrow(error);
});
