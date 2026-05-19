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

test('POST /b2b/v2/orders', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'jwt'
      ],
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
      url: `${baseUrl}/b2b/v2/orders`,
      body: {
        cid: 'JS0815DE',
        orderLines: [{
          productId: 8,
          quantity: 500,
          customerReference: 'PO0000001'
        }],
        orderLinesData: '[{"productId":12,"quantity":10000,"customerReference":["PO0000001.2","SM20180105|042"],"couponCode":"pes[Bh.u*t"}]'
      },
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});