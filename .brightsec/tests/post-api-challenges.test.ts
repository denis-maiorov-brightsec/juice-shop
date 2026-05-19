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

test('POST /api/Challenges', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'http_method_fuzzing',
        'jwt',
        'bopla',
        'xss'
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
      url: `${baseUrl}/api/Challenges`,
      body: {
        name: 'RESTful XSS',
        category: 'Injection',
        description: 'Demonstration challenge created via API',
        difficulty: 3,
        hint: 'Use proper output encoding',
        hintUrl: 'https://owasp.org/www-community/attacks/xss/',
        mitigationUrl: 'https://owasp.org/www-community/controls/Output_Encoding',
        key: 'restfulXssChallenge',
        disabledEnv: null,
        tutorialOrder: 1,
        tags: 'xss,rest',
        solved: false,
        codingChallengeStatus: 0,
        hasCodingChallenge: false
      },
      headers: {
        'Content-Type': 'application/json'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});