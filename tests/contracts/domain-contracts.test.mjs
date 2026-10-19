import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { mkdtempSync, openSync, closeSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const binary = resolve('dist/engine/miragemesh');
const read = async name => JSON.parse(await readFile(new URL(`../fixtures/miragemesh/C04/${name}.json`, import.meta.url)));
const positive = await read('positive');
const expected = await read('expected-output');
const invalid = await read('invalid');
const wire = await readFile(new URL('../fixtures/miragemesh/C04/valid-event.txt', import.meta.url));
const run = input => spawnSync(binary, ['--validate-event'], { input, encoding: 'utf8', timeout: 4000 });
let schemas;
async function validators() {
  if (!schemas) {
    const [{ default: Ajv }, { default: formats }] = await Promise.all([import('ajv/dist/2020.js'), import('ajv-formats')]);
    const ajv = new Ajv({ strict: true }); formats(ajv);
    const load = async name => JSON.parse(await readFile(new URL(`../../contracts/${name}.schema.json`, import.meta.url)));
    schemas = { input: ajv.compile(await load('input')), output: ajv.compile(await load('result')) };
  }
  return schemas;
}

test('CLI accepts the exact v1 fixture and reports validation without acceptance authority', () => {
  const actual = run(wire);
  assert.equal(actual.status, 0, actual.stderr);
  assert.equal(actual.stderr, '');
  assert.deepEqual(JSON.parse(actual.stdout), expected.output);
  assert.deepEqual(JSON.parse(run(wire).stdout), expected.output, 'repeat process must preserve deterministic validation output');
});

test('real schemas and Go reject every incompatible structural fixture', async () => {
  const schema = await validators();
  assert.equal(schema.input(positive.event), true, JSON.stringify(schema.input.errors));
  assert.equal(schema.output(expected.output), true, JSON.stringify(schema.output.errors));
  for (const fixture of invalid.cases) {
    if (fixture.input) assert.equal(schema.input(fixture.input), false, fixture.name);
    const bytes = fixture.raw ?? JSON.stringify(fixture.input);
    const actual = run(bytes);
    assert.equal(actual.status, 1, `${fixture.name}: ${actual.stderr}`);
    const output = JSON.parse(actual.stdout);
    assert.equal(schema.output(output), true, `${fixture.name}: ${JSON.stringify(schema.output.errors)}`);
    assert.equal(output.status, 'failed');
    assert.equal(output.result.error.code, fixture.code, fixture.name);
    assert.equal(output.input_digest, createHash('sha256').update(bytes).digest('hex'), fixture.name);
    assert.equal(actual.stdout.includes('synthetic-private-sentinel'), false, fixture.name);
    assert.equal(actual.stderr, '', fixture.name);
  }
});

test('identifier, exact numeric, timestamp and UTF-8 byte boundaries agree with the Go validator', async () => {
  const schema = await validators();
  for (const patch of [{ sensor_id: 'é'.repeat(128) }, { sensor_id: '😀'.repeat(128) }, { event_id: 'x'.repeat(128) }, { sequence: 0 }, { sequence: 9007199254740991 }, { observed_at: '2026-01-01T00:00:00.123456789+03:30' }, { metadata: { path: '<script>synthetic-private-sentinel</script>' } }, { metadata: { path: '\\ud800' } }]) {
    const value = { ...positive.event, ...patch };
    assert.equal(schema.input(value), true, JSON.stringify(schema.input.errors));
    const actual = run(JSON.stringify(value));
    assert.equal(actual.status, 0, actual.stdout + actual.stderr);
    const output = JSON.parse(actual.stdout);
    assert.equal(schema.output(output), true);
    assert.equal(output.result.sensor_id, value.sensor_id);
    assert.equal(output.result.event_id, value.event_id);
    assert.equal(output.result.sequence, value.sequence);
    assert.equal(output.input_digest, createHash('sha256').update(JSON.stringify(value)).digest('hex'));
    assert.equal(actual.stdout.includes('synthetic-private-sentinel'), false);
  }
  const pair = run(wire.toString().replace('"sensor_id":"sensor-01"', '"sensor_id":"\\ud83d\\ude00"'));
  assert.equal(pair.status, 0); assert.equal(JSON.parse(pair.stdout).result.sensor_id, '😀');
  for (const number of ['1.0', '1e0', '-0', '0e999999999999999999999999999']) {
    const bytes = wire.toString().replace('"sequence":1', `"sequence":${number}`);
    assert.equal(run(bytes).status, 0, number);
  }
  for (const number of ['9007199254740990.5', '1e9999999999999999999999999', '1e-9999999999999999999999999']) {
    const actual = run(wire.toString().replace('"sequence":1', `"sequence":${number}`));
    assert.equal(actual.status, 1, number);
    assert.equal(JSON.parse(actual.stdout).result.error.code, 'INVALID_INPUT');
  }
  const base = JSON.stringify({ ...positive.event, metadata: { path: '' } });
  const bytes = Buffer.byteLength(base);
  const bounded = Buffer.from(JSON.stringify({ ...positive.event, metadata: { path: 'é'.repeat(Math.floor((8192 - bytes) / 2)) + 'x'.repeat((8192 - bytes) % 2) } }));
  assert.equal(bounded.length, 8192);
  assert.equal(run(bounded).status, 0);
  const oversized = JSON.parse(run(Buffer.concat([bounded, Buffer.from(' ')])).stdout);
  assert.equal(oversized.result.error.code, 'INPUT_TOO_LARGE'); assert.equal(oversized.input_digest, null);
  const utf8 = run(Buffer.concat([wire.subarray(0, wire.length - 2), Buffer.from([0xff]), Buffer.from('}') ]));
  assert.equal(JSON.parse(utf8.stdout).result.error.code, 'INVALID_JSON');
});

test('invalid CLI combinations fail usage without launching a server', () => {
  for (const args of [['--validate-event', '--version'], ['--validate-event', '--listen', '127.0.0.1:0'], ['--validate-event', 'unexpected']]) {
    const actual = spawnSync(binary, args, { input: wire, encoding: 'utf8', timeout: 3000 });
    assert.equal(actual.status, 2, actual.stdout + actual.stderr); assert.equal(actual.stdout, '');
  }
});

test('result schema rejects contradictory authority, errors and incomplete-input digests', async () => {
  const schema = await validators();
  for (const patch of [{ status: 'complete' }, { warnings: ['anything'] }, { result: { ...expected.output.result, error: { code: 'INVALID_INPUT' } } }, { input_digest: null }]) {
    assert.equal(schema.output({ ...expected.output, ...patch }), false);
  }
  const invalid = JSON.parse(run('{').stdout);
  invalid.result.error.code = 'INPUT_TOO_LARGE';
  assert.equal(schema.output(invalid), false, 'an incomplete read must not carry a full-input digest');
});

test('an actual stdin read failure returns only a typed error and no partial digest', async () => {
  const directory = mkdtempSync(resolve(tmpdir(), 'miragemesh-c04-'));
  const fd = openSync(directory, 'r');
  try {
    const actual = spawnSync(binary, ['--validate-event'], { stdio: [fd, 'pipe', 'pipe'], encoding: 'utf8', timeout: 3000 });
    assert.equal(actual.status, 1);
    const output = JSON.parse(actual.stdout);
    assert.equal((await validators()).output(output), true);
    assert.deepEqual(output.result, { valid: false, error: { code: 'INPUT_READ_FAILED' } });
    assert.equal(output.input_digest, null); assert.equal(actual.stderr, '');
    assert.equal(actual.stdout.includes(directory), false);
  } finally { closeSync(fd); rmSync(directory, { recursive: true }); }
});

test('an open stdin expires and either termination signal returns a redacted cancellation', async t => {
  const schema = await validators();
  for (const signal of [null, 'SIGINT', 'SIGTERM']) {
    const child = spawn(binary, ['--validate-event'], { stdio: ['pipe', 'pipe', 'pipe'] });
    const exit = once(child, 'exit'); let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    child.stdin.write('{"metadata":"synthetic-private-sentinel');
    if (signal) {
      // A live signal handler must be installed before signaling a fresh process.
      await new Promise(resolve => setTimeout(resolve, 100)); child.kill(signal);
    }
    const [code] = await exit; assert.equal(code, 1, stderr);
    const output = JSON.parse(stdout);
    assert.equal(schema.output(output), true, JSON.stringify(schema.output.errors));
    assert.equal(output.result.error.code, signal ? 'CANCELLED' : 'TIMEOUT');
    assert.equal(output.input_digest, null); assert.equal(stdout.includes('synthetic-private-sentinel'), false); assert.equal(stderr, '');
  }
});
