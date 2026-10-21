import { readFileSync } from 'node:fs';

const module = 'github.com/Parsa-Emami/Miragemesh/';
const required = new Map(Object.entries({
  'cmd/miragemesh': ['TestLifecycle'],
  'internal/contracts': ['TestValidAndIncompatibleFixtures', 'TestEnrollmentRecordValidation'],
  'internal/storage': ['TestStorageSIGKILLAtPublicationBoundaries', 'TestStorageSyscallFailuresPreserveRecoverableState', 'TestEnrollmentSyscallFailuresPreserveRecoverableState', 'TestEnrollmentSIGKILLAtPublicationBoundaries'],
  tests: ['TestStorageExactBytesReplayAndReopen', 'TestSensorSequenceReplayAndRestart', 'TestSensorRejectsInvalidAndConflictingEvents', 'TestEnrollmentIssueConsumeAndRestart', 'TestEnrollmentRejectsInvalidExpiredAndScopedTokens', 'TestEnrollmentConcurrentConsumptionAndSensorCompatibility', 'TestEnrollmentStorageFailuresAndCancellation', 'TestEnrollmentRechecksClockBeforePublication', 'TestEnrollmentRejectsForgedStoredIdentity', 'TestMTLSTrustedCollectorAcceptsEvents', 'TestMTLSRejectsUntrustedExpiredWrongEKUAndRevokedIdentity', 'TestMTLSTypedVerdictsUseRealHandshakeTranscripts', 'TestMTLSSubsequentConnectionsStopReplayedIdentityBeforeSideEffects', 'TestMTLSRejectsIssuersWithoutRevocationCoverage', 'TestMTLSRejectsInvalidLocalIdentityConfigurations', 'TestConfigSignedDesiredStateBecomesActive', 'TestConfigRejectsUnsignedDesiredState', 'TestConfigRejectsStaleDesiredStateWithoutReplacingActiveConfig', 'TestConfigRejectsInvalidDesiredStateDocuments', 'TestConfigSignatureCoversExactPayloadBytes', 'TestConfigRejectsMissingPrerequisites', 'TestConfigRejectsDesiredStateSensorQuota', 'TestConfigAppliedPayloadCannotMutateActiveState', 'TestConfigTrustedKeyIsCopiedAtConstruction', 'TestConfigExpiryIsRecheckedAtAcceptanceTime', 'TestConfigSettingsBoundsAreDeploymentPolicy', 'TestConfigFreshServiceHasNoRememberedActiveState'],
}).map(([path, tests]) => [module + path, tests]));

try {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/verify-engine-tests.mjs <go-test-jsonl>');
  const packages = new Map();
  const running = new Set();
  const passed = new Set();
  // Go documents run/pass/skip and package completion separately: https://pkg.go.dev/cmd/test2json#hdr-Output_Format
  for (const line of readFileSync(process.argv[2], 'utf8').split('\n').filter(line => line.trim())) {
    const event = JSON.parse(line);
    if (!event || typeof event.Package !== 'string' || typeof event.Action !== 'string') throw new Error('Invalid Go test event.');
    if (event.Action === 'fail') throw new Error(`Failed engine test: ${event.Package} ${event.Test ?? ''}`);
    if (!event.Test) {
      if (event.Action === 'start') packages.set(event.Package, false);
      if (event.Action === 'pass' || event.Action === 'skip') {
        if (!packages.has(event.Package)) throw new Error('Missing Go package start event.');
        packages.set(event.Package, true);
      }
    } else {
      const key = event.Package + '/' + event.Test;
      if (event.Action === 'run') running.add(key);
      if (event.Action === 'pass' && running.has(key)) passed.add(key);
      if (event.Action === 'skip' && required.get(event.Package)?.includes(event.Test)) throw new Error(`Required engine test skipped: ${key}`);
    }
  }
  for (const [packageName, tests] of required) {
    if (!packages.get(packageName)) throw new Error(`Missing completed engine suite: ${packageName}`);
    for (const name of tests) if (!passed.has(packageName + '/' + name)) throw new Error(`Required engine test not executed successfully: ${packageName}/${name}`);
  }
  if ([...packages.values()].some(complete => !complete)) throw new Error('Incomplete Go test stream.');
  console.log(`Verified ${required.size} engine suites and ${[...required.values()].flat().length} required test anchors.`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
