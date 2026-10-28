import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const read = path => readFile(resolve(root, path), 'utf8');
const json = async path => JSON.parse(await read(path));
const fixture = name => json(`tests/fixtures/miragemesh/C38/${name}.json`);

test('C38 policies use current locked versions and state actual data lifecycle limits', async () => {
  const positive = await fixture('positive');
  const lock = await json('docs/engineering/toolchain-lock.json');
  const service = await read(positive.policies[0]);
  const maintenance = await read(positive.policies[1]);
  for (const policy of [service, maintenance]) {
    for (const id of ['node-runtime', 'npm-cli', 'go-toolchain', 'podman-provider']) {
      assert.ok(policy.includes(lock.resources.find(resource => resource.id === id).version), `${id} pin missing from policy`);
    }
  }
  for (const section of ['Supported profiles and responsibility', 'What is retained', 'Data locations and ownership', 'Export and disclosure', 'Retention and deletion', 'Backup and recovery procedure', 'Network and diagnostic limits']) {
    assert.ok(service.includes(`## ${section}`), section);
  }
  for (const fact of ['no automatic `~/.local/state/miragemesh` discovery', 'not encrypted at rest', 'Segment retention is not complete-data deletion', 'no supported selective C05 deletion/compaction command', 'No egress by default', 'No hosted subscription, paid core feature']) {
    assert.ok(service.toLowerCase().includes(fact.toLowerCase()), fact);
  }
  const startup = await read('scripts/start-local.mjs');
  for (const flag of ['sensor-status-dir', 'incident-state-dir', 'incident-segments-dir', 'rotation-state-dir', 'update-state-dir']) {
    assert.ok(startup.includes(`'${flag}'`), `not an actual startup flag: ${flag}`);
    assert.ok(service.includes(`--${flag}`), `undocumented location: ${flag}`);
  }
  assert.ok((await read('scripts/install-release.mjs')).includes("options.dataDir ?? join(prefix, 'data')"));
  assert.ok(service.includes('`<prefix>/data`'));
  const expected = await fixture('expected-output');
  assert.equal(expected.retention_changes_c05, false);
  assert.equal(expected.automatic_expiry, false);
  assert.equal(expected.runtime_egress_required, false);
});

test('C38 policy links resolve and operator entry guides expose both policies', async () => {
  const { policies } = await fixture('positive');
  for (const path of policies) {
    for (const [, target] of (await read(path)).matchAll(/\]\(([^)]+)\)/g)) {
      if (/^https:/.test(target)) continue;
      const file = resolve(dirname(resolve(root, path)), target.split('#')[0]);
      assert.ok(!relative(root, file).startsWith('..'), `link escapes source: ${target}`);
      await access(file);
    }
  }
  for (const path of ['README.md', 'docs/release/USER_GUIDE.md', 'docs/engineering/CLONE_TO_RUN.md']) {
    const text = await read(path);
    for (const name of ['SERVICE_POLICY.md', 'MAINTENANCE.md']) assert.ok(text.includes(name), `${path} omits ${name}`);
  }
});

test('C38 support policy rejects placeholder contacts and unearned SLA claims', async () => {
  const security = await read('SECURITY.md');
  const maintenance = await read('docs/release/MAINTENANCE.md');
  assert.ok(security.includes('No alternate private mailbox is currently'));
  assert.ok(security.includes('if the repository'));
  assert.ok(security.includes('Community security work is best effort'));
  assert.ok(!security.includes('security@miragemesh.local'));
  assert.ok(!security.includes('Within **48 hours**'));
  assert.ok(!security.includes('Within **5 business days**'));
  assert.ok(maintenance.includes('no blanket support promise for all `v0.x` tags'));
  const updates = await read('.github/dependabot.yml');
  assert.equal((updates.match(/interval: "?weekly"?/g) ?? []).length, 2);
  assert.ok(maintenance.includes('weekly npm and GitHub Actions proposals'));
  for (const workflow of ['contracts', 'plan-consistency', 'engine-runtime', 'web-foundation']) assert.ok(maintenance.includes(`\`${workflow}\``));
});

test('C38 licensed fixtures bind required crash, ACK, quota and egress proof to real anchors', async () => {
  for (const name of ['positive', 'negative', 'expected-output']) {
    const value = await fixture(name);
    assert.equal(value.fixture_version, 1);
    assert.equal(value.license, 'Apache-2.0');
    assert.ok(value.provenance.includes('Repository-authored synthetic'));
  }
  const negative = await fixture('negative');
  const guard = await read('scripts/verify-engine-tests.mjs');
  const sources = (await Promise.all(['internal/storage/recovery_test.go', 'tests/replay_test.go', 'internal/events/retention_recovery_test.go', 'tests/egress_test.go'].map(read))).join('\n');
  for (const name of Object.values(negative.existing_required_proofs)) {
    assert.ok(guard.includes(`'${name}'`), `proof is not required: ${name}`);
    assert.ok(sources.includes(`func ${name}(`), `proof does not exist: ${name}`);
  }
  for (const name of ['TestC38StoppedCopyPreservesExactAcceptedState', 'TestC38RetentionKeepsAuthoritativeCopiesAndAudit']) assert.ok(guard.includes(`'${name}'`));
});
