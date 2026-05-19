import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/PrivacyRequests', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['jwt'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/juice-shop:master',
        databases: ['SQLite', 'MarsDB'],
        user_roles: ['customer', 'deluxe', 'accounting', 'admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/PrivacyRequests`,
      body: {
        UserId: 1,
        deletionRequested: false
      },
      headers: {
        Authorization:
          'Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwiZW1haWwiOiJdemo@juice-sh.opInsecure".aW52YWxpZC1zaWduYXR1cmU',
        'Content-Type': 'application/json'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});