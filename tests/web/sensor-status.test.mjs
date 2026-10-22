import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateSensorSnapshot } from '../../apps/web/src/lib/sensor-status.mjs';

test('validates the versioned sensor snapshot and rejects malformed sensor states', async () => {
  const read = async name => JSON.parse(await readFile(new URL(`../fixtures/miragemesh/C21/${name}.json`, import.meta.url)));
  const expected = await read('expected-output');
  const response = { schema_version: expected.schema_version, offline_after_seconds: expected.offline_after_seconds, sensors: expected.sensors };
  assert.deepEqual(validateSensorSnapshot(response), response);
  const invalid = await read('invalid');
  assert.equal(invalid.fixture_version, 1);
  assert.equal(invalid.license, 'Apache-2.0');
  assert.ok(invalid.provenance);
  for (const item of invalid.cases) assert.throws(() => validateSensorSnapshot(item.response), undefined, item.name);
  assert.throws(() => validateSensorSnapshot({ ...response, sensors: [...response.sensors, response.sensors[0]] }), /Duplicate/);
});
