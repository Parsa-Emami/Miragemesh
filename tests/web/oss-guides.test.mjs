import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { constants } from 'node:fs';

const fileExists = async (path) => {
  try {
    await access(new URL(path, import.meta.url), constants.R_OK);
    return true;
  } catch {
    return false;
  }
};

test('C34 deliverables and guides exist and are readable', async () => {
  const deliverables = [
    '../../docs/release/USER_GUIDE.md',
    '../../SECURITY.md',
    '../../README.md',
    '../../OPEN_SOURCE.md',
    '../../CONTRIBUTING.md',
    '../../docs/engineering/CLONE_TO_RUN.md',
  ];

  for (const doc of deliverables) {
    const exists = await fileExists(doc);
    assert.equal(exists, true, `File must exist and be readable: ${doc}`);
    const content = await readFile(new URL(doc, import.meta.url), 'utf8');
    assert.ok(content.length > 200, `File must contain substantial content: ${doc}`);
  }
});

test('C34 fixtures validate contract schema, provenance, and required sections', async () => {
  const positive = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C34/positive.json', import.meta.url), 'utf8'));
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C34/negative.json', import.meta.url), 'utf8'));
  const expected = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C34/expected-output.json', import.meta.url), 'utf8'));

  assert.equal(positive.fixture_version, 1);
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.scope, 'oss-documentation-and-guides');
  assert.ok(Array.isArray(positive.guides) && positive.guides.length === 6);

  // Validate each guide contains its required sections
  for (const guide of positive.guides) {
    const content = await readFile(new URL('../../' + guide.path, import.meta.url), 'utf8');
    assert.ok(content.includes(guide.title), `Document ${guide.path} must contain title ${guide.title}`);
    for (const section of guide.required_sections) {
      assert.ok(content.includes(section), `Document ${guide.path} must contain required section: ${section}`);
    }
  }

  assert.equal(negative.fixture_version, 1);
  assert.equal(negative.license, 'Apache-2.0');
  assert.ok(Array.isArray(negative.cases) && negative.cases.length >= 10);

  assert.equal(expected.fixture_version, 1);
  assert.equal(expected.license, 'Apache-2.0');
  assert.equal(expected.documentation_completeness.user_guide_present, true);
  assert.equal(expected.reader_contract.fresh_reader_can_complete_core_task, true);
  assert.equal(expected.reader_contract.no_mandatory_cloud, true);
});

test('SECURITY.md defines conditional private reporting, best-effort support and supported source', async () => {
  const securityMd = await readFile(new URL('../../SECURITY.md', import.meta.url), 'utf8');
  assert.ok(securityMd.includes('GitHub Private Vulnerability Reporting'), 'Must declare GitHub Private Reporting');
  assert.ok(securityMd.includes('No alternate private mailbox is currently'), 'Must not invent a security mailbox');
  assert.ok(!securityMd.includes('security@miragemesh.local'), 'Placeholder must not be advertised as a contact');
  assert.ok(securityMd.includes('do not open a public GitHub issue'), 'Must forbid public issues for vulnerabilities');
  assert.ok(securityMd.includes('Supported Versions'), 'Must specify supported versions');
  assert.ok(securityMd.includes('Community security work is best effort'), 'Must state the actual support commitment');
});

test('USER_GUIDE.md covers full core workflow, source builds, limits, privacy, and recovery without cloud dependency', async () => {
  const userGuide = await readFile(new URL('../../docs/release/USER_GUIDE.md', import.meta.url), 'utf8');
  assert.ok(userGuide.includes('Core Reference Workflow'), 'Must document core reference workflow');
  assert.ok(userGuide.includes('Source Builds and Packaging'), 'Must document source builds');
  assert.ok(userGuide.includes('npm run package'), 'Must specify packaging command');
  assert.ok(userGuide.includes('npm run verify:artifact'), 'Must specify artifact verification command');
  assert.ok(userGuide.includes('Operational Limits and Quotas'), 'Must document operational limits');
  assert.ok(userGuide.includes('8 events/s'), 'Must document measured 8 events/s sustained target');
  assert.ok(userGuide.includes('Privacy and Network Confinement'), 'Must document privacy and network confinement');
  assert.ok(userGuide.includes('no egress by default'), 'Must state no egress by default');
  assert.ok(userGuide.includes('Backup, Recovery, and Disaster Handling'), 'Must document disaster recovery');
  assert.ok(userGuide.includes('--expire-segments'), 'Must document retention commands');
  assert.ok(userGuide.includes('--rotate-certificates'), 'Must document certificate rotation');
  assert.ok(userGuide.includes('without mandatory cloud'), 'Must explicitly state operation without mandatory cloud');
  assert.ok(!userGuide.includes('requires a mandatory cloud'), 'Must not require mandatory cloud');
});

test('C34 negative cases properly model inert sentinels, 360px failure states, and egress denial', async () => {
  const negative = JSON.parse(await readFile(new URL('../fixtures/miragemesh/C34/negative.json', import.meta.url), 'utf8'));

  const sentinels = negative.cases.filter(c => c.category === 'input-sanitization');
  assert.equal(sentinels.length, 3);
  for (const s of sentinels) {
    assert.equal(s.keyboard_action_possible, true);
    assert.equal(s.table_action_possible, true);
    assert.ok(s.expected_handling.length > 0);
  }

  const responsiveFailures = negative.cases.filter(c => c.category === 'responsive-failure-handling');
  assert.equal(responsiveFailures.length, 4);
  for (const r of responsiveFailures) {
    assert.equal(r.viewport.width, 360);
    assert.equal(r.horizontal_scroll_allowed, false);
    assert.ok(r.expected_ui_presentation.length > 0);
  }

  const egress = negative.cases.find(c => c.name === 'denied-default-egress');
  assert.ok(egress);
  assert.equal(egress.external_calls_permitted, false);

  const cloudRejection = negative.cases.find(c => c.name === 'rejected-mandatory-cloud-requirement');
  assert.ok(cloudRejection);
  assert.equal(cloudRejection.cloud_account_required, false);
});
