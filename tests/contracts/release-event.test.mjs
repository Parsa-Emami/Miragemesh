import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');

test('C39 licensed positive and negative sensor events produce actual typed engine results', async () => {
  const load = async name => JSON.parse(await readFile(resolve(root, `tests/fixtures/miragemesh/C39/${name}.json`), 'utf8'));
  const expected = await load('expected-output');
  for (const name of ['positive', 'negative']) {
    const fixture = await load(name);
    assert.equal(fixture.fixture_version, 1);
    assert.equal(fixture.license, 'Apache-2.0');
    assert.ok(fixture.provenance.includes('Repository-authored synthetic'));
    const result = spawnSync(resolve(root, 'dist/engine/miragemesh'), ['--validate-event'], { input: JSON.stringify(fixture.event), encoding: 'utf8' });
    assert.equal(result.status, expected[name + '_exit'], result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.result.valid, name === 'positive');
    if (name === 'negative') assert.equal(output.result.error.code, expected.negative_code);
  }
});
