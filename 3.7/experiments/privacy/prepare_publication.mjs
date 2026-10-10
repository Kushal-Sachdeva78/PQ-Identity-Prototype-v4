import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
if (fs.existsSync(path.join(root, 'results/v4/bench/RUNNING'))) throw new Error('benchmark RUNNING marker exists');
const digest = name => createHash('sha256').update(fs.readFileSync(path.join(here, name))).digest('hex');
const registration = {
  schema: 'privacy-publication-registration/v1',
  preparedUtc: new Date().toISOString(),
  protocolFile: 'PROTOCOL.md',
  protocolSha256: digest('PROTOCOL.md'),
  variantSha256: digest('wallet_stateless_v1.ts'),
  policySha256: digest('date_policy.ts'),
  runnerSha256: digest('run.ts'),
  preparedBeforeNewRun: true,
  historicalRegistration: 'preregistration.json',
  scope: 'Fresh runs of the publication copy; historical evidence retains its original dates and digests.',
};
fs.writeFileSync(path.join(here, 'preregistration-publication.json'), JSON.stringify(registration, null, 2) + '\n');
console.log('Prepared current hashes for a fresh privacy run. Historical registration unchanged.');
