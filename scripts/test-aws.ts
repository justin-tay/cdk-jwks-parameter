/**
 * End-to-end test against a real AWS account: deploys the example app, checks
 * the JWKS endpoint after the parameters are created and after a forced
 * rotation of each, checks that each rotation Lambda's log group holds only bare ECS
 * records describing those rotations, then destroys the stack.
 *
 * Uses the AWS credentials and region of the current environment, and costs a
 * few cents. Run with `npm run test:aws`; pass `--keep` to skip the destroy.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { CloudWatchLogsClient, FilterLogEventsCommand } from '@aws-sdk/client-cloudwatch-logs';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { parseJwks, PRIVATE_MEMBERS } from 'cdk-jwks-parameter/jwks';

const STACK = 'JwksParameterExampleApp';
const TIMEOUT_MS = 5 * 60 * 1000;
const POLL_MS = 5000;

interface PublicJwk {
  readonly kid: string;
  readonly use: 'sig' | 'enc';
  readonly d?: string;
}

function cdk(...args: string[]): void {
  const result = spawnSync('npx', ['cdk', ...args], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(`cdk ${args[0]} failed with exit code ${result.status}`);
  }
}

async function fetchKeys(url: string): Promise<PublicJwk[]> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`GET ${url} returned ${response.status}`);
  }
  const { keys } = (await response.json()) as { keys: PublicJwk[] };
  const withPrivatePart = keys.filter((jwk) => jwk.d !== undefined);
  if (withPrivatePart.length > 0) {
    throw new Error(`The endpoint serves private keys: ${withPrivatePart.map((jwk) => jwk.kid).join(', ')}`);
  }
  return keys;
}

const kidsOf = (keys: PublicJwk[], use: PublicJwk['use']) =>
  keys.filter((jwk) => jwk.use === use).map((jwk) => jwk.kid);

/** Polls the endpoint until `done` holds for its keys. */
async function waitFor(
  url: string,
  description: string,
  done: (keys: PublicJwk[]) => boolean,
): Promise<PublicJwk[]> {
  const deadline = Date.now() + TIMEOUT_MS;
  for (;;) {
    const keys = await fetchKeys(url);
    if (done(keys)) {
      console.log(`✓ ${description}`);
      return keys;
    }
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting until ${description}; last keys: ${JSON.stringify(keys)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

type EcsRecord = Readonly<Record<string, unknown>>;

/** Lines the Lambda service itself writes to a log group; every other line must be an ECS record. */
const PLATFORM_LINE = /^(INIT_START|START|END|REPORT|XRAY)\b/;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchLogMessages(logs: CloudWatchLogsClient, logGroupName: string): Promise<string[]> {
  const messages: string[] = [];
  let nextToken: string | undefined;
  do {
    const page = await logs.send(new FilterLogEventsCommand({ logGroupName, nextToken }));
    messages.push(...(page.events ?? []).map((event) => event.message ?? ''));
    nextToken = page.nextToken;
  } while (nextToken);
  return messages;
}

/** Parses the function's log lines, which must be bare JSON ECS records, not prefixed by Lambda. */
function parseEcsRecords(messages: string[]): EcsRecord[] {
  return messages
    .map((message) => message.trimEnd())
    .filter((message) => message !== '' && !PLATFORM_LINE.test(message))
    .map((message) => {
      let record: unknown;
      try {
        record = JSON.parse(message);
      } catch {
        throw new Error(`A log line is not a bare JSON record: ${message}`);
      }
      if (typeof record !== 'object' || record === null || !('ecs.version' in record)) {
        throw new Error(`A log line is not an ECS record: ${message}`);
      }
      return record;
    });
}

/**
 * Checks the rotation Lambda's log group after the creation of one parameter
 * and a forced rotation: every line is an ECS record, none is a failure, the
 * kids match the parameter, and no private key member was logged.
 */
async function checkRotationLogs(
  logs: CloudWatchLogsClient,
  ssm: SSMClient,
  name: string,
  logGroupName: string,
  parameterName: string,
): Promise<void> {
  const deadline = Date.now() + TIMEOUT_MS;
  let messages: string[];
  let records: EcsRecord[];
  for (;;) {
    messages = await fetchLogMessages(logs, logGroupName);
    records = parseEcsRecords(messages);
    if (records.some((record) => record['event.action'] === 'rotate_parameter')) {
      break;
    }
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting for a rotate_parameter event in ${logGroupName}`);
    }
    await sleep(POLL_MS);
  }

  const failures = records.filter((record) => record['event.outcome'] === 'failure');
  if (failures.length > 0) {
    throw new Error(`${name}: rotation failures were logged: ${JSON.stringify(failures)}`);
  }
  if (!records.some((record) => record['event.action'] === 'start_function')) {
    throw new Error(`${name}: no start_function event was logged`);
  }

  const creations = records.filter((record) => record['event.action'] === 'create_parameter');
  const rotations = records.filter((record) => record['event.action'] === 'rotate_parameter');
  if (creations.length !== 1 || rotations.length !== 1) {
    throw new Error(
      `${name}: expected 1 create_parameter and 1 rotate_parameter event, got ${creations.length} and ${rotations.length}`,
    );
  }
  const [creation] = creations;
  const [rotation] = rotations;
  if (
    (creation['jwks.kids.added'] as string[]).length !== 2 ||
    (creation['jwks.kids.removed'] as string[]).length
  ) {
    throw new Error(`${name}: the creation should add 2 keys and remove none`);
  }
  if (
    (rotation['jwks.kids.added'] as string[]).length !== 1 ||
    (rotation['jwks.kids.removed'] as string[]).length
  ) {
    throw new Error(`${name}: the rotation should add 1 key and remove none`);
  }
  if (rotation['aws.ssm.parameter.name'] !== parameterName) {
    throw new Error(`${name}: the rotation logged parameter ${String(rotation['aws.ssm.parameter.name'])}`);
  }

  const { Parameter } = await ssm.send(
    new GetParameterCommand({ Name: parameterName, WithDecryption: true }),
  );
  const jwks = parseJwks(Parameter?.Value ?? '');
  const kids = jwks.keys.map((jwk) => jwk.kid);
  if (JSON.stringify(rotation['jwks.kids.current']) !== JSON.stringify(kids)) {
    throw new Error(`${name}: the rotate_parameter kids do not match the parameter's kids`);
  }

  const output = messages.join('\n');
  for (const jwk of jwks.keys) {
    for (const member of PRIVATE_MEMBERS) {
      const value = (jwk as unknown as Record<string, unknown>)[member];
      if (typeof value === 'string' && output.includes(value)) {
        throw new Error(`${name}: the private member "${member}" of key ${jwk.kid} was logged`);
      }
    }
  }
  console.log(
    `✓ ${name} rotation logs are bare ECS records that describe the rotations and hold no key material`,
  );
}

/** Invokes the rotation Lambda as the schedule does, but with `force`. */
async function forceRotation(lambda: LambdaClient, functionName: string): Promise<void> {
  const result = await lambda.send(
    new InvokeCommand({
      FunctionName: functionName,
      Payload: JSON.stringify({ action: 'rotate', force: true }),
    }),
  );
  if (result.FunctionError) {
    throw new Error(`${functionName} failed: ${new TextDecoder().decode(result.Payload)}`);
  }
}

async function main(): Promise<void> {
  const keep = process.argv.includes('--keep');
  const outDir = mkdtempSync(path.join(tmpdir(), 'jwks-parameter-test-aws-'));
  const outputsFile = path.join(outDir, 'outputs.json');
  const ssm = new SSMClient({});
  const lambda = new LambdaClient({});
  const logs = new CloudWatchLogsClient({});
  try {
    cdk('deploy', STACK, '--require-approval', 'never', '--outputs-file', outputsFile);
    const outputs = JSON.parse(readFileSync(outputsFile, 'utf8'))[STACK] as Record<string, string>;
    const url = outputs.JwksUrl;

    const initial = await waitFor(
      url,
      'the parameters were created with 2 sig and 2 enc keys',
      (keys) => kidsOf(keys, 'sig').length === 2 && kidsOf(keys, 'enc').length === 2,
    );

    // A forced rotation: a scheduled one is skipped within half an interval of the creation.
    await forceRotation(lambda, outputs.SigRotationLambda);
    const afterSig = await waitFor(
      url,
      'rotating the sig parameter added a third sig key and kept the previous ones',
      (keys) =>
        kidsOf(keys, 'sig').length === 3 &&
        kidsOf(initial, 'sig').every((kid) => kidsOf(keys, 'sig').includes(kid)),
    );

    await forceRotation(lambda, outputs.EncRotationLambda);
    await waitFor(
      url,
      'rotating the enc parameter published a new enc key and unpublished the oldest',
      (keys) => {
        const enc = kidsOf(keys, 'enc');
        const [oldest, previous] = kidsOf(afterSig, 'enc');
        return enc.length === 2 && !enc.includes(oldest) && enc[0] === previous;
      },
    );

    await checkRotationLogs(logs, ssm, 'sig', outputs.SigRotationLogGroup, outputs.SigParameterName);
    await checkRotationLogs(logs, ssm, 'enc', outputs.EncRotationLogGroup, outputs.EncParameterName);

    console.log('All checks passed.');
  } finally {
    if (keep) {
      console.log(`--keep: not destroying ${STACK}.`);
    } else {
      cdk('destroy', STACK, '--force');
    }
    rmSync(outDir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
