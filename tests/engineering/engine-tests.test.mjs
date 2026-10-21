import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const module = 'github.com/Parsa-Emami/Miragemesh/';
const suites = {
  'cmd/miragemesh': ['TestLifecycle'],
  'internal/contracts': ['TestValidAndIncompatibleFixtures', 'TestEnrollmentRecordValidation'],
  'internal/storage': ['TestStorageSIGKILLAtPublicationBoundaries', 'TestStorageSyscallFailuresPreserveRecoverableState', 'TestEnrollmentSyscallFailuresPreserveRecoverableState', 'TestEnrollmentSIGKILLAtPublicationBoundaries'],
  tests: ['TestStorageExactBytesReplayAndReopen', 'TestSensorSequenceReplayAndRestart', 'TestSensorRejectsInvalidAndConflictingEvents', 'TestEnrollmentIssueConsumeAndRestart', 'TestEnrollmentRejectsInvalidExpiredAndScopedTokens', 'TestEnrollmentConcurrentConsumptionAndSensorCompatibility', 'TestEnrollmentStorageFailuresAndCancellation', 'TestEnrollmentRechecksClockBeforePublication', 'TestEnrollmentRejectsForgedStoredIdentity', 'TestMTLSTrustedCollectorAcceptsEvents', 'TestMTLSRejectsUntrustedExpiredWrongEKUAndRevokedIdentity', 'TestMTLSTypedVerdictsUseRealHandshakeTranscripts', 'TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects', 'TestMTLSRejectsIssuersWithoutRevocationCoverage', 'TestMTLSRejectsInvalidLocalIdentityConfigurations', 'TestConfigSignedDesiredStateBecomesActive', 'TestConfigRejectsUnsignedDesiredState', 'TestConfigRejectsStaleDesiredStateWithoutReplacingActiveConfig', 'TestConfigRejectsInvalidDesiredStateDocuments', 'TestConfigSignatureCoversExactPayloadBytes', 'TestConfigRejectsMissingPrerequisites', 'TestConfigRejectsDesiredStateSensorQuota', 'TestConfigAppliedPayloadCannotMutateActiveState', 'TestConfigTrustedKeyIsCopiedAtConstruction', 'TestConfigExpiryIsRecheckedAtAcceptanceTime', 'TestConfigSettingsBoundsAreDeploymentPolicy', 'TestConfigRejectsIncoherentDesiredStateSettings', 'TestConfigFreshServiceHasNoRememberedActiveState'],
};
function complete() {
  return Object.entries(suites).flatMap(([path, names]) => [
    { Action: 'start', Package: module + path },
    ...names.flatMap(Test => ['run', 'pass'].map(Action => ({ Action, Package: module + path, Test }))),
    { Action: 'pass', Package: module + path },
  ]);
}
function verify(t, events) {
  const directory = mkdtempSync(join(tmpdir(), 'miragemesh-test-discovery-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'tests.jsonl');
  writeFileSync(path, typeof events === 'string' ? events : events.map(event => JSON.stringify(event)).join('\n') + '\n');
  return spawnSync(process.execPath, ['scripts/verify-engine-tests.mjs', path], { encoding: 'utf8' });
}
test('accepts executed engine, contract and real recovery suites with interleaved output', t => {
  const events = complete();
  events.splice(2, 0, { Action: 'output', Package: module + 'cmd/miragemesh', Output: 'log\n' });
  assert.equal(verify(t, events).status, 0);
});
test('rejects empty discovery and package-only success without executed tests', t => {
  for (const events of [[], complete().filter(event => !event.Test)]) assert.equal(verify(t, events).status, 1);
});
test('rejects a missing required suite or anchor', t => {
  for (const events of [complete().filter(event => event.Package !== module + 'internal/storage'), complete().filter(event => event.Test !== 'TestStorageSIGKILLAtPublicationBoundaries')]) {
    assert.equal(verify(t, events).status, 1);
  }
});
test('requires persistent sensor sequence and invalid-event regression anchors', t => {
  for (const name of ['TestSensorSequenceReplayAndRestart', 'TestSensorRejectsInvalidAndConflictingEvents']) {
    assert.equal(verify(t, complete().filter(event => event.Test !== name)).status, 1);
  }
});
test('rejects a skipped anchor or a pass with no run', t => {
  for (const events of [complete().map(event => event.Test === 'TestLifecycle' && event.Action === 'pass' ? { ...event, Action: 'skip' } : event), complete().filter(event => event.Action !== 'run')]) {
    assert.equal(verify(t, events).status, 1);
  }
});
test('rejects failures in any package and unfinished package results', t => {
  assert.equal(verify(t, [...complete(), { Action: 'fail', Package: module + 'future' }]).status, 1);
  assert.equal(verify(t, complete().slice(0, -1)).status, 1);
  assert.equal(verify(t, complete().filter(event => event.Action !== 'start')).status, 1);
  assert.equal(verify(t, [...complete(), { Action: 'start', Package: module + 'future' }]).status, 1);
});
test('rejects malformed JSON events and missing input', t => {
  for (const raw of ['broken\n', 'null\n', '{}\n']) assert.equal(verify(t, raw).status, 1);
  assert.equal(spawnSync(process.execPath, ['scripts/verify-engine-tests.mjs'], { encoding: 'utf8' }).status, 1);
});

test('requires enrollment validation, durable consumption, scope, clock, concurrency and crash anchors', t => {
  for (const name of ['TestEnrollmentRecordValidation', 'TestEnrollmentIssueConsumeAndRestart', 'TestEnrollmentRejectsInvalidExpiredAndScopedTokens', 'TestEnrollmentConcurrentConsumptionAndSensorCompatibility', 'TestEnrollmentStorageFailuresAndCancellation', 'TestEnrollmentRechecksClockBeforePublication', 'TestEnrollmentRejectsForgedStoredIdentity', 'TestEnrollmentSyscallFailuresPreserveRecoverableState', 'TestEnrollmentSIGKILLAtPublicationBoundaries']) {
    assert.equal(verify(t, complete().filter(event => event.Test !== name)).status, 1);
  }
});

test('requires mTLS acceptance, transport denial, typed verdicts, issuer-bound revocation, revoked replay and configuration anchors', t => {
  for (const name of ['TestMTLSTrustedCollectorAcceptsEvents', 'TestMTLSRejectsUntrustedExpiredWrongEKUAndRevokedIdentity', 'TestMTLSTypedVerdictsUseRealHandshakeTranscripts', 'TestMTLSRejectsIssuersWithoutRevocationCoverage', 'TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects', 'TestMTLSRejectsInvalidLocalIdentityConfigurations']) {
    assert.equal(verify(t, complete().filter(event => event.Test !== name)).status, 1);
  }
});

test('requires signed desired state, unsigned rejection, stale rejection and exact-byte signature anchors', t => {
  for (const name of ['TestConfigSignedDesiredStateBecomesActive', 'TestConfigRejectsUnsignedDesiredState', 'TestConfigRejectsStaleDesiredStateWithoutReplacingActiveConfig', 'TestConfigRejectsInvalidDesiredStateDocuments', 'TestConfigSignatureCoversExactPayloadBytes', 'TestConfigRejectsMissingPrerequisites', 'TestConfigRejectsDesiredStateSensorQuota', 'TestConfigAppliedPayloadCannotMutateActiveState', 'TestConfigTrustedKeyIsCopiedAtConstruction', 'TestConfigExpiryIsRecheckedAtAcceptanceTime', 'TestConfigSettingsBoundsAreDeploymentPolicy', 'TestConfigRejectsIncoherentDesiredStateSettings', 'TestConfigFreshServiceHasNoRememberedActiveState']) {
    assert.equal(verify(t, complete().filter(event => event.Test !== name)).status, 1);
  }
});
