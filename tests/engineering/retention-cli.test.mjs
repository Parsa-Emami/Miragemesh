import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const binary = 'dist/engine/miragemesh';
const fixture = JSON.parse(readFileSync('tests/fixtures/miragemesh/C23/positive.json', 'utf8'));
const invoke = args => spawnSync(binary, args, { encoding: 'utf8', timeout: 15000 });
const options = directory => ['--expire-segments', '--retention-dir', join(directory, 'segments'), '--retention-before', fixture.before, '--retention-reason', fixture.reason, '--retention-key', fixture.idempotency_key, '--retention-max-segments', '16', '--retention-max-records', '2', '--retention-max-bytes', '32768'];

test('retention CLI previews, applies and replays without rewriting C05', () => {
  const directory = mkdtempSync(join(tmpdir(), 'miragemesh-c23-cli-'));
  try {
    const seed = spawnSync('go', ['run', './tests/fixtures/miragemesh/C23', directory], { encoding: 'utf8', timeout: 30000 });
    assert.equal(seed.status, 0, seed.stderr);
    const manifest = readFileSync(join(directory, 'state', 'manifest.json'), 'utf8');
    const args = options(directory);
    let result = invoke(args); assert.equal(result.status, 0, result.stderr);
    let value = JSON.parse(result.stdout); assert.equal(value.status, 'planned'); assert.equal(value.result.segments.length, 2); assert.equal(value.index_records, 6);
    assert.equal(existsSync(join(directory, 'segments', 'retention.json')), false);
    result = invoke([...args, '--retention-apply']); assert.equal(result.status, 0, result.stderr);
    value = JSON.parse(result.stdout); assert.equal(value.status, 'applied'); assert.equal(value.result.applied, true); assert.equal(value.result.replayed, false); assert.equal(value.index_records, 2); assert.equal(value.index_complete, false);
    const applied = value.result.segments;
    result = invoke([...args, '--retention-apply']); assert.equal(result.status, 0, result.stderr);
    value = JSON.parse(result.stdout); assert.equal(value.result.replayed, true); assert.deepEqual(value.result.segments, applied);
    result = invoke([...args, '--retention-apply', '--retention-reason', 'Changed body']); assert.equal(result.status, 1); assert.equal(JSON.parse(result.stdout).error_kind, 'conflict');
    assert.equal(readFileSync(join(directory, 'state', 'manifest.json'), 'utf8'), manifest);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('retention CLI rejects missing storage and mixed or incomplete modes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'miragemesh-c23-invalid-'));
  try {
    const args = options(directory);
    for (const extra of [['--listen', '127.0.0.1:0'], ['--version'], ['--project-segments'], ['unexpected']]) {
      const result = invoke([...args, ...extra]); assert.equal(result.status, 2, result.stderr);
    }
    assert.equal(invoke(['--retention-apply']).status, 2);
    assert.equal(invoke(['--expire-segments']).status, 2);
    const missing = invoke([...args, '--retention-apply']); assert.equal(missing.status, 1); assert.equal(JSON.parse(missing.stdout).error_kind, 'io');
    assert.equal(existsSync(join(directory, 'segments')), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
