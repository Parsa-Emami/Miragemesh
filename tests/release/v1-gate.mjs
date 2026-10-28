import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm, mkdir, copyFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import * as gate from '../../scripts/release-gate.mjs';
import { tmpdir } from 'node:os';

const repository = join(import.meta.dirname, '../..');

async function checkout(t) {
  const root = await mkdtemp(join(tmpdir(), 'c39-gate-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clone = spawnSync('git', ['clone', '--quiet', '--shared', repository, root], { encoding: 'utf8' });
  assert.equal(clone.status, 0, clone.stderr);
  const files = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { cwd: repository, encoding: 'utf8' });
  for (const path of new Set(files.stdout.split('\0').filter(Boolean))) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await copyFile(join(repository, path), join(root, path));
  }
  return root;
}

test('C39 release check refuses verified status flags without a real verification report', async t => {
  const root = await checkout(t);
  const path = join(root, 'plans/release-gates.json');
  const gates = JSON.parse(await readFile(path, 'utf8'));
  gates.core_ready = true;
  await writeFile(path, JSON.stringify(gates));
  await rm(join(root, 'docs/evidence/v1-gate.json'), { force: true });
  const result = spawnSync(process.execPath, ['scripts/roadmap.mjs', 'release-check'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 2, 'status flags must never certify actual release evidence');
  assert.match(result.stdout + result.stderr, /missing_report/);
});

const baseline = '33040632a3a079774666d39bf7bfb4d54277b37f';

test('C39 historical audit checks all 38 original records and rejects relabelled evidence', async t => {
  assert.equal(typeof gate.auditHistoricalEvidence, 'function');
  const root = await checkout(t);
  const original = await gate.auditHistoricalEvidence(root, baseline);
  assert.equal(original.length, 38);
  assert.equal(original[0].id, 'C01');
  assert.equal(original[37].id, 'C38');
  const path = join(root, 'docs/evidence/C14.json');
  const record = JSON.parse(await readFile(path, 'utf8'));
  record.source_identity = 'sha256:' + 'a'.repeat(64);
  await writeFile(path, JSON.stringify(record));
  await assert.rejects(gate.auditHistoricalEvidence(root, baseline), { code: 'changed_historical_evidence' });
});

test('C39 release input identity detects engine and fixture changes while allowing status certification', async t => {
  assert.equal(typeof gate.releaseInputIdentity, 'function');
  const root = await checkout(t);
  const original = await gate.releaseInputIdentity(root);
  const progressPath = join(root, 'plans/progress.json');
  const progress = JSON.parse(await readFile(progressPath, 'utf8'));
  progress.commits[38].status = 'in_progress';
  await writeFile(progressPath, JSON.stringify(progress));
  assert.equal(await gate.releaseInputIdentity(root), original);
  const path = join(root, 'internal/contracts/event.go');
  const source = await readFile(path);
  await writeFile(path, Buffer.concat([source, Buffer.from('\n// changed accepted runtime input\n')]));
  assert.notEqual(await gate.releaseInputIdentity(root), original);
  await writeFile(path, source);
  const fixture = join(root, 'tests/fixtures/miragemesh/C39/positive.json');
  await writeFile(fixture, (await readFile(fixture, 'utf8')).replace('/synthetic/c39/release', '/changed'));
  assert.notEqual(await gate.releaseInputIdentity(root), original);
});

test('C39 licenses reject missing fixture provenance and unknown transitive licenses', async t => {
  assert.equal(typeof gate.inventoryLicenses, 'function');
  const root = await checkout(t);
  const inventory = await gate.inventoryLicenses(root);
  assert.ok(inventory.fixtures.length > 100);
  const path = join(root, 'tests/fixtures/miragemesh/C39/positive.json');
  const original = await readFile(path, 'utf8');
  const bad = JSON.parse(original);
  delete bad.provenance;
  await writeFile(path, JSON.stringify(bad));
  await assert.rejects(gate.inventoryLicenses(root), { code: 'unlicensed_fixture' });
  await writeFile(path, original);
  const lockPath = join(root, 'package-lock.json');
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  lock.packages['node_modules/react'].license = 'LicenseRef-Unknown';
  await writeFile(lockPath, JSON.stringify(lock));
  await assert.rejects(gate.inventoryLicenses(root), { code: 'unlicensed_dependency' });
});

test('C39 validates actual Go test streams and rejects skipped crash or lost-ACK anchors', async t => {
  assert.equal(typeof gate.verifyEngineLog, 'function');
  const root = await checkout(t);
  const raw = gunzipSync(await readFile(join(repository, 'docs/evidence/C38/engine-tests.jsonl.gz'))).toString('utf8');
  const valid = await gate.verifyEngineLog(root, raw);
  assert.equal(valid.required_anchors, 209);
  for (const name of ['TestStorageSIGKILLAtPublicationBoundaries', 'TestCollectorLostAcknowledgementReplayIsIdempotent', 'TestDecoyIsolationDeniesInternetAndPrivateSubnets']) {
    const changed = raw.split('\n').filter(Boolean).map(line => {
      const event = JSON.parse(line);
      return JSON.stringify(event.Test === name && event.Action === 'pass' ? { ...event, Action: 'skip' } : event);
    }).join('\n');
    await assert.rejects(gate.verifyEngineLog(root, changed), { code: 'failed_required_test' });
  }
});

test('C39 refuses incomplete or wrong-source clone proof rather than trusting passed=true', async () => {
  assert.equal(typeof gate.verifyOnboarding, 'function');
  const proof = JSON.parse(await readFile(join(repository, 'docs/evidence/C38/onboarding.json'), 'utf8'));
  const source = { identity: proof.source_identity, tree: proof.staged_tree };
  assert.equal(gate.verifyOnboarding(proof, source).independent_runs, 2);
  const incomplete = structuredClone(proof);
  incomplete.runs[1].coreWorkflow.restoreEquivalent = false;
  assert.throws(() => gate.verifyOnboarding(incomplete, source), { code: 'incomplete_clone' });
  assert.throws(() => gate.verifyOnboarding(proof, { ...source, identity: 'sha256:' + 'a'.repeat(64) }), { code: 'wrong_source' });
});

test('C39 release CLI refuses unknown options instead of ignoring a missing proof', async t => {
  const root = await checkout(t);
  const result = spawnSync(process.execPath, ['scripts/roadmap.mjs', 'release-check', '--unknown'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stdout + result.stderr, /usage/);
});

test('C39 rejects changed historical source inventories as well as changed evidence envelopes', async t => {
  const root = await checkout(t);
  const path = join(root, 'docs/evidence/C06/source-files.json');
  const inventory = JSON.parse(await readFile(path, 'utf8'));
  inventory.source_identity = 'sha256:' + 'b'.repeat(64);
  await writeFile(path, JSON.stringify(inventory));
  await assert.rejects(gate.auditHistoricalEvidence(root, baseline), { code: 'changed_historical_evidence' });
});

test('C39 rejects template reports before any readiness success', async t => {
  const root = await checkout(t);
  await writeFile(join(root, 'docs/evidence/v1-gate.json'), JSON.stringify({ schema_version: 1, project: 'MirageMesh', kind: 'local-oss-v1-readiness', passed: true, planning_template: true, published: false }));
  const result = await gate.verifyReleaseGate({ root });
  assert.equal(result.passed, false);
  assert.equal(result.errors[0].code, 'incomplete_proof');
});

test('C39 proof reads enforce hashes, missing-file refusal and path confinement', async t => {
  assert.equal(typeof gate.readProof, 'function');
  const root = await mkdtemp(join(tmpdir(), 'c39-proof-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const raw = Buffer.from('actual command output\n');
  await writeFile(join(root, 'command.log'), raw);
  const item = { path: 'command.log', sha256: createHash('sha256').update(raw).digest('hex') };
  assert.equal(await gate.readProof(root, item), raw.toString());
  await writeFile(join(root, 'command.log'), 'changed after verification');
  await assert.rejects(gate.readProof(root, item), { code: 'proof_digest_mismatch' });
  await assert.rejects(gate.readProof(root, { ...item, path: 'missing.log' }), { code: 'missing_proof' });
  await assert.rejects(gate.readProof(root, { ...item, path: '../command.log' }), { code: 'unsafe_path' });
});

test('C39 requires actual Node results including egress and data-safe signed upgrade checks', () => {
  assert.equal(typeof gate.verifyNodeLog, 'function');
  const critical = [
    'runtime makes no internet connection by default',
    'two builds from one source and toolchain are byte-identical',
    'real engine and authoritative store report ready, survive restart and reset diagnostics',
    'C35 verifies the real artifact against an independently trusted key',
    'C35 rejects modified bytes, expired manifests, missing evidence and untrusted signers',
    'C35 installs the verified release without touching accepted data',
    'C35 rolls back to the recorded release and can upgrade again without data loss',
    'C37 repeated install and upgrade reject modified installed bytes without changing accepted data',
  ];
  const summary = '# tests 151\n# pass 151\n# fail 0\n# skipped 0\n';
  const raw = Array.from({ length: 151 }, (_, i) => `ok ${i + 1} - ${critical[i] ?? 'synthetic validator case ' + i}`).join('\n') + '\n' + summary;
  assert.equal(gate.verifyNodeLog(raw).passed, 151);
  assert.throws(() => gate.verifyNodeLog(summary), { code: 'failed_required_test' });
  assert.throws(() => gate.verifyNodeLog(raw.replace(critical[0], critical[0] + ' # SKIP no strace')), { code: 'failed_required_test' });
});

test('C39 browser proof requires completed security, accessibility and workflow cases', () => {
  assert.equal(typeof gate.verifyBrowserLog, 'function');
  const proof = { stats: { expected: 24, unexpected: 0, skipped: 0, flaky: 0 }, errors: [], suites: ['security.spec.ts', 'full-workflow-accessibility.spec.ts', 'clone-to-value.spec.ts'].map(file => ({ file, specs: Array.from({ length: 8 }, () => ({ ok: true, tests: [{ expectedStatus: 'passed', status: 'expected', results: [{ status: 'passed' }] }] })) })) };
  assert.equal(gate.verifyBrowserLog(JSON.stringify(proof)).passed, 24);
  proof.suites[0].specs[0].tests[0].results[0].status = 'skipped';
  assert.throws(() => gate.verifyBrowserLog(JSON.stringify(proof)), { code: 'failed_required_test' });
  proof.suites = [];
  assert.throws(() => gate.verifyBrowserLog(JSON.stringify(proof)), { code: 'failed_required_test' });
});
