import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { cp, lstat, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { hostPlatform, sha256, sha256File, verifyRelease } from './verify-release.mjs';

const STATE_FILE = 'install-state.json';
const STATE_SCHEMA = 1;
const PROJECT = 'MirageMesh';

class ReleaseError extends Error {
  constructor(code, detail) {
    super(detail);
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, detail) {
  throw new ReleaseError(code, detail);
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isoSeconds(date) {
  return new Date(date).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function semverCompare(a, b) {
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function statePath(prefix) {
  return join(prefix, STATE_FILE);
}

function relativeAttestation(name) {
  return `attestations/${name}.release.json`;
}

function relativeSignature(name) {
  return `attestations/${name}.release.sig.json`;
}

function validateState(state) {
  if (!plain(state) || state.schema_version !== STATE_SCHEMA || state.project !== PROJECT) fail('state_invalid', 'Install state has an unsupported schema.');
  if (state.current !== null && typeof state.current !== 'string') fail('state_invalid', 'Install state current release is invalid.');
  if (state.previous !== null && typeof state.previous !== 'string') fail('state_invalid', 'Install state previous release is invalid.');
  if (!Number.isInteger(state.highest_revision) || state.highest_revision < 0) fail('state_invalid', 'Install state revision is invalid.');
  if (typeof state.trusted_key_fingerprint !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(state.trusted_key_fingerprint)) fail('state_invalid', 'Install state trust fingerprint is invalid.');
  if (typeof state.data_dir !== 'string' || !state.data_dir) fail('state_invalid', 'Install state data directory is invalid.');
  if (!plain(state.releases)) fail('state_invalid', 'Install state releases are invalid.');
  for (const [name, record] of Object.entries(state.releases)) {
    if (!plain(record) || record.version === undefined || !Number.isInteger(record.revision) || typeof record.key_fingerprint !== 'string' || typeof record.manifest_sha256 !== 'string') {
      fail('state_invalid', `Install state record is invalid: ${name}`);
    }
    if (!plain(record.attestation) || typeof record.attestation.manifest !== 'string' || typeof record.attestation.signature !== 'string') {
      fail('state_invalid', `Install state attestation is invalid: ${name}`);
    }
  }
  if (state.current !== null && !state.releases[state.current]) fail('state_invalid', 'Install state current release is missing.');
  if (state.previous !== null && !state.releases[state.previous]) fail('state_invalid', 'Install state previous release is missing.');
  return state;
}

export async function readInstallState(prefix, { required = false } = {}) {
  let bytes;
  try { bytes = await readFile(statePath(prefix)); }
  catch (error) {
    if (error.code === 'ENOENT' && !required) return null;
    fail('state_invalid', `Install state is unreadable: ${error.message}`);
  }
  let state;
  try { state = JSON.parse(bytes.toString('utf8')); }
  catch (error) { fail('state_invalid', `Install state is not valid JSON: ${error.message}`); }
  return validateState(state);
}

async function writeState(prefix, state) {
  const target = statePath(prefix);
  const temporary = `${target}.tmp-${randomUUID()}`;
  const handle = await open(temporary, 'w', 0o600);
  try {
    await handle.writeFile(JSON.stringify(state, null, 2) + '\n');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, target);
  try {
    const directory = await open(prefix, 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch { /* directory fsync is not available on every host (notably Windows) */ }
}

async function writeFileAtomic(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${randomUUID()}`;
  await open(temporary, 'w', 0o600).then(async handle => {
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  });
  await rename(temporary, path);
}

async function readDataSchema(dataDir) {
  let info;
  try { info = await lstat(dataDir); }
  catch (error) {
    if (error.code === 'ENOENT') return { schema: 0, present: false };
    fail('data_unreadable', `Data directory is unreadable: ${error.message}`);
  }
  if (!info.isDirectory()) fail('data_unreadable', 'Data directory is not a directory.');
  let bytes;
  try { bytes = await readFile(join(dataDir, 'manifest.json')); }
  catch (error) {
    if (error.code === 'ENOENT') return { schema: 0, present: false };
    fail('data_unreadable', `Data manifest is unreadable: ${error.message}`);
  }
  if (bytes.length > 1024 * 1024) fail('data_unreadable', 'Data manifest exceeds the compatibility-check bound.');
  let document;
  try { document = JSON.parse(bytes.toString('utf8')); }
  catch (error) { fail('data_unreadable', `Data manifest is not valid JSON: ${error.message}`); }
  if (!plain(document) || typeof document.schema_version !== 'string' || !/^\d+$/.test(document.schema_version)) {
    fail('data_unreadable', 'Data manifest does not declare a numeric schema version.');
  }
  const schema = Number(document.schema_version);
  if (!Number.isInteger(schema) || schema < 1) fail('data_unreadable', 'Data manifest schema version is invalid.');
  return { schema, present: true };
}

function assertDataDirectory(prefix, dataDir, artifact) {
  const releases = join(prefix, 'releases');
  if (dataDir === prefix || dataDir.startsWith(releases + sep)) fail('unsafe_data_dir', 'Data directory may not be the install prefix or an installed release.');
  if (artifact && (dataDir === resolve(artifact) || dataDir.startsWith(resolve(artifact) + sep))) fail('unsafe_data_dir', 'Data directory may not be inside the artifact.');
}

async function ensureDataDirectory(dataDir) {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const info = await stat(dataDir);
  if (!info.isDirectory()) fail('unsafe_data_dir', 'Data directory is not a directory.');
}

function assertDataCompatible(manifest, data) {
  if (data.schema > manifest.data.store_schema) {
    fail('data_schema_newer', `Data schema ${data.schema} is newer than release schema ${manifest.data.store_schema}; refusing to reject newer accepted data.`);
  }
}

function assertHost(manifest, allowForeign) {
  const host = hostPlatform();
  if (host && manifest.artifact.platform !== host && !allowForeign) {
    fail('unsupported_host', `Release platform ${manifest.artifact.platform} does not match this host (${host}); use --allow-foreign-platform only for staging.`);
  }
}

function engineCheck(releaseDir, manifest) {
  const host = hostPlatform();
  if (host !== manifest.artifact.platform) return { status: 'skipped-foreign-platform' };
  const engine = join(releaseDir, 'dist/engine/miragemesh');
  const result = spawnSync(engine, ['--version'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0) fail('engine_check_failed', `Installed engine did not report its version: ${(result.stderr || result.error?.message || '').toString().trim()}`);
  let health;
  try { health = JSON.parse(result.stdout); }
  catch (error) { fail('engine_check_failed', `Installed engine returned invalid version output: ${error.message}`); }
  if (health.status !== 'ok' || health.version !== manifest.version) fail('engine_check_failed', 'Installed engine version differs from the signed release.');
  return { status: 'passed', version: health.version };
}

async function verifiedArtifact(options, artifact) {
  const result = await verifyRelease({
    artifact,
    manifest: options.manifest,
    signature: options.signature,
    trustedKey: options.trustedKey,
    now: options.now,
  });
  if (!result.passed) {
    const first = result.errors[0] ?? { code: 'verification_failed', detail: 'Release verification failed.' };
    const error = new ReleaseError(first.code, first.detail);
    error.errors = result.errors;
    throw error;
  }
  return result;
}

async function copyVerifiedRelease(prefix, options, verified) {
  const releasesDir = join(prefix, 'releases');
  await mkdir(releasesDir, { recursive: true, mode: 0o700 });
  const stagingRoot = join(releasesDir, `.staging-${randomUUID()}`);
  const staged = join(stagingRoot, verified.artifact);
  try {
    await cp(options.artifact, staged, { recursive: true, force: false, errorOnExist: true, dereference: false, preserveTimestamps: true });
    const copied = await verifyRelease({
      artifact: staged,
      manifest: options.manifest,
      signature: options.signature,
      trustedKey: options.trustedKey,
      now: options.now,
    });
    if (!copied.passed) {
      const first = copied.errors[0] ?? { code: 'verification_failed', detail: 'Installed copy failed verification.' };
      const error = new ReleaseError(first.code, first.detail);
      error.errors = copied.errors;
      throw error;
    }
    const engine = engineCheck(staged, verified.provenance);
    const final = join(releasesDir, verified.artifact);
    let existing = false;
    try { existing = (await stat(final)).isDirectory(); } catch { existing = false; }
    if (existing) {
      // A recorded release may be re-activated (for example after rollback).
      // Reuse it only when the installed bytes still match the same signed attestation.
      const reused = await verifyRelease({
        artifact: final,
        manifest: options.manifest,
        signature: options.signature,
        trustedKey: options.trustedKey,
        now: options.now,
        enforceValidity: false,
      });
      if (!reused.passed) {
        const integrity = new Set(['checksum_coverage', 'checksum_mismatch', 'unsafe_checksum_path', 'duplicate_checksum_entry', 'missing_required_path', 'missing_evidence', 'evidence_digest_mismatch', 'invalid_provenance', 'invalid_sbom', 'forbidden_material', 'unsafe_artifact_entry']);
        const first = reused.errors.find(error => integrity.has(error.code)) ?? reused.errors[0] ?? { code: 'release_conflict', detail: 'Existing release directory does not match the attestation.' };
        fail(integrity.has(first.code) ? 'installed_release_modified' : 'release_conflict', first.detail);
      }
      await rm(stagingRoot, { recursive: true, force: true });
      return { releaseDir: final, engine: engineCheck(final, verified.provenance), reused: true };
    }
    await rename(staged, final);
    await rm(stagingRoot, { recursive: true, force: true });
    return { releaseDir: final, engine };
  } catch (error) {
    await rm(stagingRoot, { recursive: true, force: true });
    throw error;
  }
}

async function storeAttestation(prefix, options, verified) {
  const manifestBytes = await readFile(options.manifest);
  const signatureBytes = await readFile(options.signature);
  const manifestRelative = relativeAttestation(verified.artifact);
  const signatureRelative = relativeSignature(verified.artifact);
  await writeFileAtomic(join(prefix, ...manifestRelative.split('/')), manifestBytes);
  await writeFileAtomic(join(prefix, ...signatureRelative.split('/')), signatureBytes);
  return {
    manifest: manifestRelative,
    signature: signatureRelative,
    manifest_sha256: sha256(manifestBytes),
    signature_sha256: sha256(signatureBytes),
  };
}

function recordFor(verified, trusted, attestation, now) {
  return {
    version: verified.version,
    revision: verified.revision,
    platform: verified.platform,
    store_schema: verified.data.store_schema,
    manifest_sha256: attestation.manifest_sha256,
    checksums_sha256: verified.checksums_sha256,
    key_fingerprint: trusted,
    attestation,
    installed_at: isoSeconds(now),
  };
}

function baseOptions(options) {
  const prefix = resolve(options.prefix);
  const dataDir = resolve(options.dataDir ?? join(prefix, 'data'));
  const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
  return { ...options, prefix, dataDir, now };
}

export async function installRelease(input = {}) {
  const options = baseOptions(input);
  const artifact = resolve(options.artifact);
  if (!options.prefix || !options.trustedKey || !options.artifact || !options.manifest || !options.signature) {
    fail('usage', 'install requires --prefix, --trusted-key, --artifact, --manifest and --signature.');
  }
  if (artifact === options.prefix || options.prefix.startsWith(artifact + sep)) fail('unsafe_prefix', 'Install prefix may not be inside the artifact.');

  const verified = await verifiedArtifact(options, artifact);
  assertHost(verified.provenance, options.allowForeignPlatform);
  const existing = await readInstallState(options.prefix);
  const dataDir = existing ? existing.data_dir : options.dataDir;
  assertDataDirectory(options.prefix, dataDir, artifact);
  await mkdir(options.prefix, { recursive: true, mode: 0o700 });
  await ensureDataDirectory(dataDir);
  const data = await readDataSchema(dataDir);
  assertDataCompatible({ data: verified.data }, data);

  if (existing) {
    if (existing.current !== verified.artifact) fail('not_an_upgrade', 'A different release is already current; use upgrade or rollback.');
    const record = existing.releases[verified.artifact];
    const manifestDigest = await sha256File(options.manifest);
    if (!record || record.manifest_sha256 !== manifestDigest) fail('release_conflict', 'The current release record does not match the supplied attestation.');
    return {
      status: 'idempotent', current: existing.current, previous: existing.previous, version: verified.version,
      revision: verified.revision, platform: verified.platform, key_fingerprint: existing.trusted_key_fingerprint,
      data_dir: dataDir, data_schema: data.schema, data_unchanged: true,
      engine_check: engineCheck(join(options.prefix, 'releases', verified.artifact), verified.provenance),
      highest_revision: existing.highest_revision,
    };
  }

  const copied = await copyVerifiedRelease(options.prefix, options, verified);
  let attestation;
  const state = {
    schema_version: STATE_SCHEMA,
    project: PROJECT,
    trusted_key_fingerprint: verified.key_fingerprint,
    current: verified.artifact,
    previous: null,
    highest_revision: verified.revision,
    data_dir: dataDir,
    releases: {},
  };
  try {
    attestation = await storeAttestation(options.prefix, options, verified);
    state.releases[verified.artifact] = recordFor(verified, verified.key_fingerprint, attestation, options.now);
    await writeState(options.prefix, state);
  } catch (error) {
    await rm(copied.releaseDir, { recursive: true, force: true });
    fail('state_invalid', `Unable to record the installed release: ${error.message}`);
  }
  return {
    status: 'installed', current: state.current, previous: null, version: verified.version,
    revision: verified.revision, platform: verified.platform, key_fingerprint: verified.key_fingerprint,
    data_dir: dataDir, data_schema: data.schema, data_unchanged: true,
    engine_check: copied.engine, highest_revision: state.highest_revision,
  };
}

export async function upgradeRelease(input = {}) {
  const options = baseOptions(input);
  const artifact = resolve(options.artifact);
  if (!options.trustedKey || !options.artifact || !options.manifest || !options.signature) {
    fail('usage', 'upgrade requires --prefix, --trusted-key, --artifact, --manifest and --signature.');
  }
  if (artifact === options.prefix || options.prefix.startsWith(artifact + sep)) fail('unsafe_prefix', 'Install prefix may not be inside the artifact.');

  const verified = await verifiedArtifact(options, artifact);
  assertHost(verified.provenance, options.allowForeignPlatform);
  const state = await readInstallState(options.prefix, { required: true });
  const dataDir = state.data_dir;
  assertDataDirectory(options.prefix, dataDir, artifact);
  await mkdir(options.prefix, { recursive: true, mode: 0o700 });
  await ensureDataDirectory(dataDir);
  const data = await readDataSchema(dataDir);
  assertDataCompatible({ data: verified.data }, data);
  if (state.current === null) fail('not_an_upgrade', 'No current release is installed.');
  if (state.current === verified.artifact) {
    const record = state.releases[verified.artifact];
    const manifestDigest = await sha256File(options.manifest);
    if (!record || record.manifest_sha256 !== manifestDigest) fail('release_conflict', 'The current release record does not match the supplied attestation.');
    return {
      status: 'idempotent', current: state.current, previous: state.previous, version: verified.version,
      revision: verified.revision, platform: verified.platform, key_fingerprint: state.trusted_key_fingerprint,
      data_dir: dataDir, data_schema: data.schema, data_unchanged: true,
      engine_check: engineCheck(join(options.prefix, 'releases', verified.artifact), verified.provenance),
      highest_revision: state.highest_revision,
    };
  }
  const current = state.releases[state.current];
  const recorded = state.releases[verified.artifact];
  if (recorded) {
    const manifestDigest = await sha256File(options.manifest);
    if (recorded.manifest_sha256 !== manifestDigest) fail('release_conflict', 'An installed release has a different signed attestation.');
  } else if (verified.revision <= state.highest_revision) {
    fail('stale_revision', `Release revision ${verified.revision} is not newer than the accepted revision ${state.highest_revision}.`);
  }
  const sameVersionForward = semverCompare(verified.version, current.version) === 0 && verified.revision > current.revision;
  if (semverCompare(verified.version, current.version) < 0 || (semverCompare(verified.version, current.version) === 0 && !sameVersionForward)) {
    fail('not_an_upgrade', 'The supplied release is not newer than the current release; use rollback for a recorded previous release.');
  }

  const copied = await copyVerifiedRelease(options.prefix, options, verified);
  const next = {
    ...state,
    trusted_key_fingerprint: verified.key_fingerprint,
    current: verified.artifact,
    previous: state.current,
    highest_revision: Math.max(state.highest_revision, verified.revision),
    releases: { ...state.releases },
  };
  try {
    const attestation = await storeAttestation(options.prefix, options, verified);
    next.releases[verified.artifact] = recordFor(verified, verified.key_fingerprint, attestation, options.now);
    await writeState(options.prefix, next);
  } catch (error) {
    await rm(copied.releaseDir, { recursive: true, force: true });
    fail('state_invalid', `Unable to record the upgraded release: ${error.message}`);
  }
  return {
    status: 'upgraded', from: state.current, current: next.current, previous: next.previous,
    version: verified.version, revision: verified.revision, platform: verified.platform,
    key_fingerprint: verified.key_fingerprint, data_dir: dataDir, data_schema: data.schema,
    data_unchanged: true, engine_check: copied.engine, highest_revision: next.highest_revision,
  };
}

export async function rollbackRelease(input = {}) {
  const options = baseOptions(input);
  if (!options.trustedKey) fail('usage', 'rollback requires --prefix and --trusted-key.');
  const state = await readInstallState(options.prefix, { required: true });
  if (!state.previous) fail('no_previous_release', 'No recorded previous release is available for rollback.');
  const targetName = state.previous;
  const currentName = state.current;
  const record = state.releases[targetName];
  if (!record) fail('state_invalid', 'The recorded previous release is missing.');
  if (state.current === targetName) fail('rollback_not_older', 'The recorded previous release is already current.');
  const targetDir = join(options.prefix, 'releases', targetName);
  try { if (!(await stat(targetDir)).isDirectory()) fail('installed_release_modified', 'The recorded previous release directory is missing.'); }
  catch (error) {
    if (error instanceof ReleaseError) throw error;
    fail('installed_release_modified', `The recorded previous release directory is missing: ${error.message}`);
  }

  const verified = await verifyRelease({
    artifact: targetDir,
    manifest: join(options.prefix, ...record.attestation.manifest.split('/')),
    signature: join(options.prefix, ...record.attestation.signature.split('/')),
    trustedKey: options.trustedKey,
    now: options.now,
    enforceValidity: false,
  });
  if (!verified.passed) {
    const integrity = new Set(['checksum_coverage', 'checksum_mismatch', 'unsafe_checksum_path', 'duplicate_checksum_entry', 'missing_required_path', 'missing_evidence', 'evidence_digest_mismatch', 'invalid_provenance', 'invalid_sbom', 'forbidden_material', 'unsafe_artifact_entry']);
    const first = verified.errors.find(error => integrity.has(error.code)) ?? verified.errors[0] ?? { code: 'attestation_invalid', detail: 'Rollback target failed verification.' };
    const error = new ReleaseError(integrity.has(first.code) ? 'installed_release_modified' : 'attestation_invalid', first.detail);
    error.errors = verified.errors;
    throw error;
  }
  if (verified.key_fingerprint !== record.key_fingerprint) fail('attestation_invalid', 'Rollback target was signed by a different trusted key than recorded.');
  assertHost(verified.provenance, options.allowForeignPlatform);
  const data = await readDataSchema(state.data_dir);
  assertDataCompatible({ data: verified.data }, data);
  const engine = engineCheck(targetDir, verified.provenance);

  const next = {
    ...state,
    trusted_key_fingerprint: verified.key_fingerprint,
    current: targetName,
    previous: null,
  };
  try { await writeState(options.prefix, next); }
  catch (error) { fail('state_invalid', `Unable to record the rolled-back release: ${error.message}`); }
  return {
    status: 'rolled-back', from: currentName, current: next.current, previous: null,
    version: verified.version, revision: verified.revision, platform: verified.platform,
    key_fingerprint: verified.key_fingerprint,    data_dir: state.data_dir, data_schema: data.schema, data_unchanged: true, engine_check: engine, highest_revision: next.highest_revision,
  };
}

function parseArguments(args) {
  const [command, ...rest] = args;
  if (!['install', 'upgrade', 'rollback'].includes(command)) {
    throw new Error('Usage: node scripts/install-release.mjs <install|upgrade|rollback> --prefix <dir> --trusted-key <key> [--artifact <dir> --manifest <release.json> --signature <release.sig.json>] [--data-dir <dir>] [--allow-foreign-platform] [--now <timestamp>]');
  }
  const options = { command, prefix: null, trustedKey: null, artifact: null, manifest: null, signature: null, dataDir: null, allowForeignPlatform: false, now: new Date() };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--allow-foreign-platform') { options.allowForeignPlatform = true; continue; }
    const value = rest[index + 1];
    if (value === undefined) throw new Error(`Missing value for ${argument}`);
    if (argument === '--prefix') options.prefix = value;
    else if (argument === '--trusted-key') options.trustedKey = value;
    else if (argument === '--artifact') options.artifact = value;
    else if (argument === '--manifest') options.manifest = value;
    else if (argument === '--signature') options.signature = value;
    else if (argument === '--data-dir') options.dataDir = value;
    else if (argument === '--now') {
      if (!Number.isFinite(Date.parse(value))) throw new Error('--now must be an RFC3339 timestamp');
      options.now = new Date(value);
    } else throw new Error(`Unknown option: ${argument}`);
    index += 1;
  }
  if (!options.prefix || !options.trustedKey) throw new Error('--prefix and --trusted-key are required.');
  if (command !== 'rollback') {
    if (!options.artifact) throw new Error('--artifact is required for install and upgrade.');
    if (!options.manifest) options.manifest = resolve(options.artifact) + '.release.json';
    if (!options.signature) options.signature = resolve(options.manifest).replace(/\.json$/, '.sig.json');
  }
  return options;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let options;
  try { options = parseArguments(process.argv.slice(2)); }
  catch (error) {
    console.error(JSON.stringify({ status: 'failed', code: 'usage', detail: error.message }, null, 2));
    process.exitCode = 2;
  }
  if (options) {
    try {
      const action = { install: installRelease, upgrade: upgradeRelease, rollback: rollbackRelease }[options.command];
      const result = await action(options);
      console.log(JSON.stringify(result, null, 2));
    } catch (error) {
      const payload = { status: 'failed', code: error.code ?? 'install_failed', detail: error.message };
      if (error.errors) payload.errors = error.errors;
      console.error(JSON.stringify(payload, null, 2));
      process.exitCode = 1;
    }
  }
}
