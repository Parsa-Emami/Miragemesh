import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { packageWeb } from '../../scripts/package-web.mjs';

test('C40 complete package runs the reference workflow and real installed engine without a compiler', { timeout: 180000 }, async t => {
  const work = await mkdtemp(join(tmpdir(), 'c40-installed-'));
  t.after(() => rm(work, { recursive: true, force: true }));
  const artifact = join(work, 'miragemesh-0.0.1-linux-amd64');
  await packageWeb({ output: artifact, build: false });
  const report = join(work, 'proof.json');
  const result = spawnSync(process.execPath, [join(artifact, 'scripts/verify-installed-release.mjs'), report], { cwd: work, encoding: 'utf8', timeout: 120000, env: { ...process.env, GOTOOLCHAIN: 'local', MIRAGEMESH_C30_FIXTURES: '' } });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  const proof = JSON.parse(await readFile(report, 'utf8'));
  assert.equal(proof.passed, true);
  assert.equal(proof.steps.length, 8);
  assert.equal(proof.negative.length, 6);
  assert.equal(proof.installed_engine_restart_cycles, 2);
  assert.equal(proof.restore_equivalent, true);
  assert.equal(proof.accepted_state_unchanged, true);
  assert.equal(proof.exact_fixture_event, true);
  assert.equal(proof.malformed_event_rejected, true);
  assert.equal(proof.installed_root.replace(/\/$/, ''), artifact);
});
