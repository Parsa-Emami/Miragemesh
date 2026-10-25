import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateSensorSnapshot } from '../../apps/web/src/lib/sensor-status.mjs';
import { validateCertificateSnapshot } from '../../apps/web/src/lib/certificates.mjs';
import { validateIncidentSnapshot } from '../../apps/web/src/lib/incidents.mjs';
import { validateUpdateSnapshot } from '../../apps/web/src/lib/updates.mjs';

test('C33 fixtures validate contract, schema bounds and negative catalog', async () => {
  const positive = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/positive.json', import.meta.url), 'utf8'));
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/negative.json', import.meta.url), 'utf8'));
  const expected = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/expected-output.json', import.meta.url), 'utf8'));

  assert.equal(positive.fixture_version, 1);
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.scope, 'ux-accessibility-workflow');
  assert.equal(positive.viewports.mobile.width, 360);
  assert.equal(positive.viewports.desktop.width, 1440);

  assert.equal(negative.fixture_version, 1);
  assert.equal(negative.license, 'Apache-2.0');
  assert.ok(Array.isArray(negative.cases) && negative.cases.length >= 10);

  assert.equal(expected.fixture_version, 1);
  assert.equal(expected.license, 'Apache-2.0');
  assert.equal(expected.viewports.mobile_360.width, 360);
  assert.equal(expected.viewports.mobile_360.horizontal_scroll_permitted, false);
  assert.equal(expected.keyboard_accessibility.skip_link_functional, true);
  assert.equal(expected.failure_modes.provider_outage_explicit, true);
});

test('C33 N-1 snapshot fixtures are cleanly accepted by existing domain validators', async () => {
  const positive = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/positive.json', import.meta.url), 'utf8'));
  const n1 = positive.n_minus_1_compatibility;

  assert.doesNotThrow(() => validateSensorSnapshot(n1.sensor_snapshot_v0));
  assert.doesNotThrow(() => validateCertificateSnapshot(n1.certificate_snapshot_v0));
  assert.doesNotThrow(() => validateIncidentSnapshot(n1.incident_snapshot_v0));
  assert.doesNotThrow(() => validateUpdateSnapshot(n1.update_snapshot_v0));
});

test('C33 negative cases correctly identify error and failure handling modes', async () => {
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/negative.json', import.meta.url), 'utf8'));

  const emptyCases = negative.cases.filter(c => c.name.startsWith('empty-'));
  assert.equal(emptyCases.length, 4);
  for (const c of emptyCases) {
    assert.equal(c.expected_status, 200);
    assert.ok(typeof c.expected_ui === 'string' && c.expected_ui.length > 0);
  }

  const outageCases = negative.cases.filter(c => c.name.includes('outage') || c.name.endsWith('-503'));
  assert.ok(outageCases.length >= 5);
  for (const c of outageCases) {
    assert.equal(c.status, 503);
    assert.ok(c.role === 'alert' || c.role === 'region');
  }

  const malformed = negative.cases.find(c => c.name === 'malformed-json-payload');
  assert.ok(malformed);
  assert.throws(() => JSON.parse(malformed.raw_body));
});

test('C33 advertises only observed platforms and prevents sensitive leaks', async () => {
  const positive = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/positive.json', import.meta.url), 'utf8'));
  const platforms = positive.observed_platforms;

  assert.ok(platforms.some(p => p.os === 'linux' && p.arch === 'amd64' && p.status === 'supported-observed'));
  assert.ok(platforms.some(p => p.os === 'windows' && p.arch === 'x64' && p.status === 'supported-observed'));
  assert.ok(!platforms.some(p => p.status === 'unverified' || p.status === 'speculative'));

  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C33/negative.json', import.meta.url), 'utf8'));
  const sentinels = negative.cases.find(c => c.name === 'private-key-leak-forbidden').sentinels;

  const content = JSON.stringify(positive);
  for (const sentinel of sentinels) {
    assert.ok(!content.includes(sentinel), `Sentinel ${sentinel} must not appear in positive fixtures`);
  }
});
