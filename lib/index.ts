// import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export interface CdkJwksParameterProps {
  // Define construct properties here
}

export class CdkJwksParameter extends Construct {

  constructor(scope: Construct, id: string, props: CdkJwksParameterProps = {}) {
    super(scope, id);

    // Define construct contents here

    // example resource
    // const queue = new sqs.Queue(this, 'CdkJwksParameterQueue', {
    //   visibilityTimeout: cdk.Duration.seconds(300)
    // });
  }
}
