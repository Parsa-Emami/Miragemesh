import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, statSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const invoke = args => spawnSync('dist/engine/miragemesh', args, { encoding: 'utf8', timeout: 15000 });
const common = dir => ['--rotate-certificates', '--rotation-state-dir', join(dir, 'state'), '--rotation-issuer-file', join(dir, 'issuer.pem'), '--rotation-max-operations', '128', '--rotation-max-bytes', '2097152', '--rotation-max-manifest-bytes', '131072', '--rotation-max-sensors', '16', '--rotation-max-lifetime-seconds', '86400', '--rotation-max-overlap-seconds', '3600', '--rotation-max-recovery-ttl-seconds', '900'];

function seed(t) {
 const dir = mkdtempSync(join(tmpdir(), 'miragemesh-c24-cli-'));
 t.after(() => rmSync(dir, { recursive: true, force: true }));
 const result = spawnSync('go', ['run', './tests/fixtures/miragemesh/C24/seed', dir], { encoding: 'utf8', timeout: 30000 });
 assert.equal(result.status, 0, result.stderr); return dir;
}

test('certificate CLI issues a private scoped token, recovers and replays the same signed certificate', t => {
 const dir = seed(t), args = common(dir), tokenPath = join(dir, 'recovery-token');
 let result = invoke([...args, '--rotation-action', 'status']); assert.equal(result.status, 0, result.stderr);
 let value = JSON.parse(result.stdout); assert.equal(value.snapshot.sensors[0].revision, 2); assert.equal(value.snapshot.sensors[0].recovery_available, true);
 result = invoke([...args, '--rotation-action', 'issue-token', '--rotation-sensor', 'sensor-24', '--rotation-token-file', tokenPath, '--rotation-token-ttl-seconds', '600']);
 assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).status, 'token_issued'); assert.equal(statSync(tokenPath).mode & 0o777, 0o600);
 const token = readFileSync(tokenPath, 'utf8').trim(); assert.equal(token.length, 43); assert.equal(result.stdout.includes(token), false);
 const recovery = [...args, '--rotation-action', 'recover', '--rotation-sensor', 'sensor-24', '--rotation-expected-revision', '2', '--rotation-csr-file', join(dir, 'recovery-csr.pem'), '--rotation-key-file', join(dir, 'issuer-key.pem'), '--rotation-token-file', tokenPath, '--rotation-lifetime-seconds', '86400', '--rotation-idempotency-key', 'c24-cli-recovery-operation'];
 result = invoke(recovery); assert.equal(result.status, 0, result.stderr); value = JSON.parse(result.stdout); assert.equal(value.result.revision, 3); assert.equal(value.result.replayed, false); const original = value.result;
 result = invoke(recovery); assert.equal(result.status, 0, result.stderr); value = JSON.parse(result.stdout); assert.equal(value.result.replayed, true); assert.equal(value.result.certificate_pem, original.certificate_pem); assert.deepEqual(value.result.receipt, original.receipt);
 const manifest = readFileSync(join(dir, 'state', 'manifest.json'), 'utf8');
 result = invoke([...recovery, '--rotation-csr-file', join(dir, 'next-csr.pem')]); assert.equal(result.status, 1); assert.equal(JSON.parse(result.stdout).error_kind, 'conflict');
 assert.equal(readFileSync(join(dir, 'state', 'manifest.json'), 'utf8'), manifest);
 assert.equal(manifest.includes(token), false);
});

test('certificate CLI rejects unsafe key inputs, missing prerequisites and mixed runtime modes', t => {
 const dir = seed(t), args = common(dir);
 for (const extra of [['--listen', '127.0.0.1:0'], ['--version'], ['--project-segments'], ['unexpected']]) assert.equal(invoke([...args, '--rotation-action', 'status', ...extra]).status, 2);
 assert.equal(invoke(['--rotation-action', 'status']).status, 2);
 assert.equal(invoke(['--rotate-certificates']).status, 2);
 const ignoredToken = join(dir, 'ignored-token');
 const ignored = invoke([...args, '--rotation-action', 'issue-token', '--rotation-sensor', 'sensor-24', '--rotation-token-file', ignoredToken, '--rotation-token-ttl-seconds', '600', '--rotation-key-file', join(dir, 'issuer-key.pem')]);
 assert.equal(ignored.status, 2); assert.equal(existsSync(ignoredToken), false);
 const tokenPath = join(dir, 'no-token');
 let result = invoke([...args, '--rotation-action', 'issue-token', '--rotation-sensor', 'sensor-24', '--rotation-token-file', tokenPath, '--rotation-token-ttl-seconds', '901']); assert.equal(result.status, 2); assert.equal(existsSync(tokenPath), false);
 writeFileSync(tokenPath, 'do not overwrite', { mode: 0o600 }); result = invoke([...args, '--rotation-action', 'issue-token', '--rotation-sensor', 'sensor-24', '--rotation-token-file', tokenPath, '--rotation-token-ttl-seconds', '600']); assert.notEqual(result.status, 0); assert.equal(readFileSync(tokenPath, 'utf8'), 'do not overwrite');
 chmodSync(join(dir, 'issuer-key.pem'), 0o644);
 result = invoke([...args, '--rotation-action', 'rotate', '--rotation-sensor', 'sensor-24', '--rotation-expected-revision', '2', '--rotation-csr-file', join(dir, 'recovery-csr.pem'), '--rotation-key-file', join(dir, 'issuer-key.pem'), '--rotation-lifetime-seconds', '86400', '--rotation-overlap-seconds', '3600', '--rotation-idempotency-key', 'c24-cli-rotate-operation']);
 assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).error_kind, 'invalid_input');
});
