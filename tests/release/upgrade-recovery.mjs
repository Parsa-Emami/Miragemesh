import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyArtifact } from '../../scripts/verify-artifact.mjs';
import { hostPlatform, sha256File } from '../../scripts/verify-release.mjs';

const repository = join(import.meta.dirname, '..', '..');
const fixtureRoot = join(repository, 'tests/fixtures/miragemesh/C35');
const expected = JSON.parse(await readFile(join(fixtureRoot, 'expected-output.json'), 'utf8'));
const positive = JSON.parse(await readFile(join(fixtureRoot, 'positive.json'), 'utf8'));
const negative = JSON.parse(await readFile(join(fixtureRoot, 'negative.json'), 'utf8'));

let work;
let artifact;
let upgradeArtifact;
let trustedPrivate;
let trustedPublic;
let trustedPem;
let untrustedPublic;
let attestation;
let upgradeAttestation;
let staleAttestation;
let expiredAttestation;

function cli(script, args, options = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: repository,
    encoding: 'utf8',
    timeout: 300000,
    env: { ...process.env, ...options.env },
  });
}

function json(result, stream = 'stdout') {
  const text = stream === 'stderr' ? result.stderr : result.stdout;
  try { return JSON.parse(text); }
  catch (error) { throw new Error(`Expected JSON on ${stream}: ${error.message}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`); }
}

function sign({ artifact: target, key, revision, issuedAt, expiresAt, output }) {
  const result = cli('scripts/sign-release.mjs', [
    '--artifact', target, '--key', key, '--revision', String(revision),
    '--issued-at', issuedAt, '--expires-at', expiresAt, '--output', output,
  ]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return json(result);
}

function verify({ artifact: target, manifest, signature, trustedKey = trustedPublic, now }) {
  const args = [target, '--manifest', manifest, '--signature', signature, '--trusted-key', trustedKey];
  if (now) args.push('--now', now);
  const result = cli('scripts/verify-release.mjs', args);
  return { status: result.status, result: json(result), raw: result };
}

function verifyAttestation(target, att, extra = {}) {
  return verify({ artifact: target, manifest: att.manifest, signature: att.signature, trustedKey: extra.trustedKey ?? trustedPublic });
}

function install(command, args) {
  const result = cli('scripts/install-release.mjs', [command, ...args]);
  return {
    status: result.status,
    result: result.status === 0 ? json(result) : json(result, 'stderr'),
    raw: result,
  };
}

function codes(result) {
  return (result.errors ?? []).map(error => error.code);
}

async function listFiles(root, prefix = '') {
  const files = [];
  for (const entry of await readdir(join(root, ...prefix.split('/').filter(Boolean)), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await listFiles(root, name));
    else files.push(name);
  }
  return files.sort();
}

async function treeDigest(root) {
  const { createHash } = await import('node:crypto');
  const digest = createHash('sha256');
  for (const name of await listFiles(root)) {
    digest.update(name + '\0');
    digest.update(createHash('sha256').update(await readFile(join(root, ...name.split('/')))).digest());
  }
  return digest.digest('hex');
}

async function writePublicKey(path, publicKey) {
  await writeFile(path, publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), { mode: 0o644 });
}

async function reversion(source, destination, version) {
  await cp(source, destination, { recursive: true });
  const provenancePath = join(destination, 'provenance.json');
  const nestedPath = join(destination, 'source/provenance.json');
  const provenance = JSON.parse(await readFile(provenancePath, 'utf8'));
  const oldVersion = provenance.version;
  const sbomPath = join(destination, 'sbom.cdx.json');
  const sbom = JSON.parse(await readFile(sbomPath, 'utf8'));
  const revisedSbom = JSON.parse(JSON.stringify(sbom).split(oldVersion).join(version));
  await writeFile(sbomPath, JSON.stringify(revisedSbom, null, 2) + '\n');
  const oldArchive = provenance.source.archive.path;
  const newArchive = oldArchive.split(oldVersion).join(version);
  await rename(join(destination, ...oldArchive.split('/')), join(destination, ...newArchive.split('/')));
  provenance.version = version;
  provenance.artifact.name = provenance.artifact.name.split(oldVersion).join(version);
  provenance.source.archive.path = newArchive;
  provenance.source.archive.prefix = provenance.source.archive.prefix.split(oldVersion).join(version);
  provenance.sbom.sha256 = await sha256File(sbomPath);
  // The engine version is a constant in the reviewed source (0.0.1), so a
  // synthetic newer release cannot contain a real engine reporting the signed
  // version. The upgrade fixture therefore carries a fixture engine that
  // answers --version with exactly the signed release version, keeping the
  // installer's real engine check exercised. Every v1 install/rollback path
  // still runs the real engine binary.
  const engine = join(destination, 'dist/engine/miragemesh');
  const engineStub = [
    '#!/bin/sh',
    '# Synthetic C35 fixture engine; reports only the signed release version.',
    'if [ "$1" = "--version" ]; then',
    `  printf '{"status":"ok","scope":"engine-runtime","version":"${version}","toolchain":"fixture","coreReady":false}\n'`,
    '  exit 0',
    'fi',
    'exit 0',
    '',
  ].join('\n');
  await writeFile(engine, engineStub);
  await chmod(engine, 0o755);
  provenance.contents.engine_sha256 = await sha256File(engine);
  provenance.notes = `${provenance.notes ?? ''} Synthetic C35 upgrade fixture with a fixture engine; not a published release.`.trim();
  await writeFile(provenancePath, JSON.stringify(provenance, null, 2) + '\n');
  await writeFile(nestedPath, JSON.stringify(provenance, null, 2) + '\n');
  const files = (await listFiles(destination)).filter(name => name !== 'SHA256SUMS.txt').sort();
  const sums = [];
  for (const name of files) sums.push(`${await sha256File(join(destination, ...name.split('/')))}  ${name}`);
  await writeFile(join(destination, 'SHA256SUMS.txt'), sums.join('\n') + '\n');
}

async function stateBytes(prefix) {
  return readFile(join(prefix, 'install-state.json'));
}

function installArguments({ target = artifact, att = attestation, prefix, data, extra = [] }) {
  return [
    '--prefix', prefix,
    '--trusted-key', trustedPublic,
    '--artifact', target,
    '--manifest', att.manifest,
    '--signature', att.signature,
    '--data-dir', data,
    ...extra,
  ];
}

before(async () => {
  work = await mkdtemp(join(tmpdir(), 'miragemesh-c35-'));
  if (!existsSync(join(repository, 'dist/web/index.html')) || !existsSync(join(repository, 'dist/engine/miragemesh'))) {
    execFileSync('npm', ['run', 'build'], { cwd: repository, stdio: 'inherit', timeout: 300000 });
  }
  artifact = join(work, 'artifact', positive.artifact.name);
  const packaged = cli('scripts/package-web.mjs', ['--no-build', '--output', artifact]);
  assert.equal(packaged.status, 0, packaged.stderr || packaged.stdout);

  const trusted = generateKeyPairSync('ed25519');
  const untrusted = generateKeyPairSync('ed25519');
  trustedPrivate = join(work, 'keys', 'trusted.pem');
  trustedPublic = join(work, 'keys', 'trusted.pub');
  trustedPem = join(work, 'keys', 'trusted-public.pem');
  untrustedPublic = join(work, 'keys', 'untrusted.pub');
  await mkdir(join(work, 'keys'), { recursive: true });
  await writeFile(trustedPrivate, trusted.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  await writeFile(trustedPem, trusted.publicKey.export({ type: 'spki', format: 'pem' }));
  await writePublicKey(trustedPublic, trusted.publicKey);
  await writePublicKey(untrustedPublic, untrusted.publicKey);

  const now = Date.now();
  const issuedAt = new Date(now - 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const expiresAt = new Date(now + 365 * 24 * 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  attestation = sign({ artifact, key: trustedPrivate, revision: positive.revisions.initial, issuedAt, expiresAt, output: join(work, 'attestations', 'initial') });

  upgradeArtifact = join(work, 'artifact', positive.artifact.upgrade_name);
  await reversion(artifact, upgradeArtifact, positive.artifact.upgrade_version);
  upgradeAttestation = sign({ artifact: upgradeArtifact, key: trustedPrivate, revision: positive.revisions.upgrade, issuedAt, expiresAt, output: join(work, 'attestations', 'upgrade') });
  staleAttestation = sign({ artifact: upgradeArtifact, key: trustedPrivate, revision: positive.revisions.stale, issuedAt, expiresAt, output: join(work, 'attestations', 'stale') });
  expiredAttestation = sign({
    artifact: upgradeArtifact, key: trustedPrivate, revision: 3,
    issuedAt: positive.validity.expired_issued_at, expiresAt: positive.validity.expired_expires_at,
    output: join(work, 'attestations', 'expired'),
  });
});

after(async () => {
  if (work) await rm(work, { recursive: true, force: true });
});

test('C35 fixtures describe licensed positive, negative and expected outcomes', async () => {
  assert.equal(positive.fixture_version, 1);
  assert.equal(positive.license, 'Apache-2.0');
  assert.match(positive.provenance, /synthetic/i);
  assert.equal(negative.fixture_version, 1);
  assert.equal(negative.license, 'Apache-2.0');
  assert.ok(negative.cases.length >= 12);
  const expectedCodes = new Set(expected.refusals.codes);
  for (const item of negative.cases) {
    if (item.expected === 'network_capability') continue;
    assert.ok(expectedCodes.has(item.expected), `Expected code is missing from the refusal contract: ${item.expected}`);
  }
  const supported = JSON.parse(await readFile(join(fixtureRoot, positive.data.supported_store_fixture, positive.data.store_manifest), 'utf8'));
  const future = JSON.parse(await readFile(join(fixtureRoot, positive.data.future_store_fixture, positive.data.store_manifest), 'utf8'));
  assert.equal(Number(supported.schema_version), positive.data.supported_schema);
  assert.equal(Number(future.schema_version), positive.data.future_schema);
  assert.ok(Number(future.schema_version) > Number(supported.schema_version));
});

test('C35 binds the real engine to the shipped artifact and a reporting fixture engine to the synthetic upgrade', async () => {
  const realEngine = join(artifact, 'dist/engine/miragemesh');
  const realProvenance = JSON.parse(await readFile(join(artifact, 'provenance.json'), 'utf8'));
  assert.equal(await sha256File(realEngine), realProvenance.contents.engine_sha256);
  assert.equal((await readFile(realEngine)).subarray(0, 4).toString('latin1'), '\x7fELF', 'the shipped engine is the real Linux binary');

  const fixtureEngine = join(upgradeArtifact, 'dist/engine/miragemesh');
  const fixtureProvenance = JSON.parse(await readFile(join(upgradeArtifact, 'provenance.json'), 'utf8'));
  assert.equal(positive.artifact.upgrade_engine, 'fixture');
  assert.equal(await sha256File(fixtureEngine), fixtureProvenance.contents.engine_sha256);
  const source = await readFile(fixtureEngine, 'utf8');
  assert.ok(source.startsWith('#!/bin/sh'), 'the synthetic upgrade engine is a declared fixture script');
  assert.ok(source.includes(positive.artifact.upgrade_version));
  const executed = spawnSync('sh', [fixtureEngine, '--version'], { encoding: 'utf8', timeout: 10000 });
  if (!executed.error) {
    assert.equal(executed.status, 0, executed.stderr);
    const report = JSON.parse(executed.stdout);
    assert.equal(report.status, 'ok');
    assert.equal(report.version, positive.artifact.upgrade_version);
  }
});

test('C35 verifies the real artifact against an independently trusted key', async () => {
  const raw = verifyAttestation(artifact, attestation);
  assert.equal(raw.status, 0, JSON.stringify(raw.result, null, 2));
  assert.equal(raw.result.passed, true);
  assert.equal(raw.result.artifact, positive.artifact.name);
  assert.equal(raw.result.version, positive.artifact.version);
  assert.equal(raw.result.platform, positive.artifact.platform);
  assert.equal(raw.result.key_fingerprint, attestation.key_fingerprint);
  assert.equal(raw.result.revision, positive.revisions.initial);
  assert.ok(raw.result.files > 0);
  assert.ok(raw.result.checksum_entries > 0);
  assert.deepEqual(raw.result.errors, []);
  assert.ok(raw.result.warnings.every(warning => expected.verify.warnings_allowed.includes(warning.code)));

  const pem = verifyAttestation(artifact, attestation, { trustedKey: trustedPem });
  assert.equal(pem.status, 0, JSON.stringify(pem.result, null, 2));
  assert.equal(pem.result.key_fingerprint, attestation.key_fingerprint);
});

test('C35 rejects modified bytes, expired manifests, missing evidence and untrusted signers', async () => {
  const tamperedArtifact = join(work, 'tampered-artifact');
  await cp(artifact, tamperedArtifact, { recursive: true });
  const webIndex = join(tamperedArtifact, 'dist/web/index.html');
  const bytes = Buffer.from(await readFile(webIndex));
  bytes[bytes.length - 1] ^= 0xff;
  await writeFile(webIndex, bytes);
  const modifiedArtifact = verifyAttestation(tamperedArtifact, attestation);
  assert.equal(modifiedArtifact.status, 1);
  assert.ok(codes(modifiedArtifact.result).includes('checksum_mismatch'));

  const modifiedManifest = join(work, 'modified-manifest.release.json');
  const manifestText = await readFile(attestation.manifest, 'utf8');
  await writeFile(modifiedManifest, manifestText.replace('"revision": 1', '"revision": 9'));
  const modified = verify({ artifact, manifest: modifiedManifest, signature: attestation.signature, trustedKey: trustedPublic });
  assert.equal(modified.status, 1);
  assert.ok(codes(modified.result).includes('manifest_digest_mismatch'));

  const wrongKey = verifyAttestation(artifact, attestation, { trustedKey: untrustedPublic });
  assert.equal(wrongKey.status, 1);
  assert.ok(codes(wrongKey.result).includes('untrusted_signer'));

  const malformedKey = join(work, 'keys', 'malformed.pub');
  await writeFile(malformedKey, Buffer.alloc(31, 1));
  const badKey = verifyAttestation(artifact, attestation, { trustedKey: malformedKey });
  assert.equal(badKey.status, 1);
  assert.ok(codes(badKey.result).includes('trusted_key_invalid'));

  const expired = verifyAttestation(upgradeArtifact, expiredAttestation);
  assert.equal(expired.status, 1);
  assert.ok(codes(expired.result).includes('manifest_expired'));

  const missingSbomArtifact = join(work, 'missing-sbom-artifact');
  await cp(artifact, missingSbomArtifact, { recursive: true });
  await rm(join(missingSbomArtifact, 'sbom.cdx.json'));
  const missing = verifyAttestation(missingSbomArtifact, attestation);
  assert.equal(missing.status, 1);
  assert.ok(codes(missing.result).includes('missing_evidence'));
});

test('C35 installs the verified release without touching accepted data', async () => {
  const prefix = join(work, 'prefix-install');
  const data = join(work, 'data-install');
  await cp(join(fixtureRoot, positive.data.supported_store_fixture), data, { recursive: true });
  const beforeDigest = await treeDigest(data);
  const result = install('install', installArguments({ prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(result.status, 0, JSON.stringify(result.result, null, 2));
  assert.equal(result.result.status, expected.install.status);
  assert.equal(result.result.version, positive.artifact.version);
  assert.equal(result.result.previous, null);
  assert.equal(result.result.data_unchanged, true);
  assert.ok(expected.install.engine_check.includes(result.result.engine_check.status));
  assert.equal(await treeDigest(data), beforeDigest);

  const state = JSON.parse(await stateBytes(prefix));
  assert.equal(state.current, positive.artifact.name);
  assert.equal(state.previous, null);
  assert.equal(state.highest_revision, positive.revisions.initial);
  assert.equal(state.trusted_key_fingerprint, attestation.key_fingerprint);
  assert.ok(existsSync(join(prefix, 'releases', positive.artifact.name, 'dist/engine/miragemesh')));
  assert.ok(existsSync(join(prefix, 'attestations', `${positive.artifact.name}.release.json`)));
  assert.ok(existsSync(join(prefix, 'attestations', `${positive.artifact.name}.release.sig.json`)));
  if (process.platform !== 'win32') {
    assert.equal((await stat(join(prefix, 'install-state.json'))).mode & 0o777, 0o600);
  }
  const installed = await verifyArtifact(join(prefix, 'releases', positive.artifact.name));
  assert.equal(installed.passed, true, JSON.stringify(installed.errors));

  const stateBefore = await stateBytes(prefix);
  const idempotent = install('install', installArguments({ prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(idempotent.status, 0, JSON.stringify(idempotent.result, null, 2));
  assert.equal(idempotent.result.status, 'idempotent');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), beforeDigest);
});

test('C35 refuses stale, expired and replayed authority without changing state or data', async () => {
  const prefix = join(work, 'prefix-install');
  const data = join(work, 'data-install');
  const beforeDigest = await treeDigest(data);
  const stateBefore = await stateBytes(prefix);

  const stale = install('upgrade', installArguments({ target: upgradeArtifact, att: staleAttestation, prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(stale.status, 1);
  assert.equal(stale.result.code, 'stale_revision');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), beforeDigest);

  const expired = install('upgrade', installArguments({ target: upgradeArtifact, att: expiredAttestation, prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(expired.status, 1);
  assert.equal(expired.result.code, 'manifest_expired');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), beforeDigest);

  const upgraded = install('upgrade', installArguments({ target: upgradeArtifact, att: upgradeAttestation, prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(upgraded.status, 0, JSON.stringify(upgraded.result, null, 2));
  assert.equal(upgraded.result.status, expected.upgrade.status);
  assert.equal(upgraded.result.from, positive.artifact.name);
  assert.equal(upgraded.result.current, positive.artifact.upgrade_name);
  assert.equal(upgraded.result.previous, positive.artifact.name);
  assert.equal(upgraded.result.highest_revision, positive.revisions.upgrade);
  assert.equal(upgraded.result.data_unchanged, true);
  assert.equal(await treeDigest(data), beforeDigest);

  const state = JSON.parse(await stateBytes(prefix));
  assert.equal(state.current, positive.artifact.upgrade_name);
  assert.equal(state.previous, positive.artifact.name);
  assert.equal(state.highest_revision, positive.revisions.upgrade);

  const replayState = await stateBytes(prefix);
  const replay = install('upgrade', installArguments({ prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(replay.status, 1);
  assert.equal(replay.result.code, 'not_an_upgrade');
  assert.deepEqual(await stateBytes(prefix), replayState);
  assert.equal(await treeDigest(data), beforeDigest);

  const oldInstall = install('install', installArguments({ prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(oldInstall.status, 1);
  assert.equal(oldInstall.result.code, 'not_an_upgrade');
});

test('C35 rollback refuses newer or malformed accepted data', async () => {
  const prefix = join(work, 'prefix-install');
  const data = join(work, 'data-install');
  const stateBefore = await stateBytes(prefix);
  const supportedManifest = await readFile(join(data, 'manifest.json'));
  await cp(join(fixtureRoot, positive.data.future_store_fixture), data, { recursive: true });
  const futureDigest = await treeDigest(data);

  const newer = install('rollback', ['--prefix', prefix, '--trusted-key', trustedPublic, '--allow-foreign-platform']);
  assert.equal(newer.status, 1);
  assert.equal(newer.result.code, 'data_schema_newer');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), futureDigest);

  await writeFile(join(data, 'manifest.json'), '{not-json');
  const malformedDigest = await treeDigest(data);
  const malformed = install('rollback', ['--prefix', prefix, '--trusted-key', trustedPublic, '--allow-foreign-platform']);
  assert.equal(malformed.status, 1);
  assert.equal(malformed.result.code, 'data_unreadable');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), malformedDigest);

  await writeFile(join(data, 'manifest.json'), supportedManifest);
  assert.equal(await treeDigest(data), await treeDigest(join(fixtureRoot, positive.data.supported_store_fixture)));
});

test('C35 rolls back to the recorded release and can upgrade again without data loss', async () => {
  const prefix = join(work, 'prefix-install');
  const data = join(work, 'data-install');
  const beforeDigest = await treeDigest(data);

  const rolledBack = install('rollback', ['--prefix', prefix, '--trusted-key', trustedPublic, '--allow-foreign-platform']);
  assert.equal(rolledBack.status, 0, JSON.stringify(rolledBack.result, null, 2));
  assert.equal(rolledBack.result.status, expected.rollback.status);
  assert.equal(rolledBack.result.from, positive.artifact.upgrade_name);
  assert.equal(rolledBack.result.current, positive.artifact.name);
  assert.equal(rolledBack.result.previous, null);
  assert.equal(rolledBack.result.data_unchanged, true);
  assert.equal(await treeDigest(data), beforeDigest);
  assert.ok(existsSync(join(prefix, 'releases', positive.artifact.upgrade_name)));

  const state = JSON.parse(await stateBytes(prefix));
  assert.equal(state.current, positive.artifact.name);
  assert.equal(state.previous, null);
  assert.equal(state.highest_revision, positive.revisions.upgrade);

  const repeated = install('rollback', ['--prefix', prefix, '--trusted-key', trustedPublic, '--allow-foreign-platform']);
  assert.equal(repeated.status, 1);
  assert.equal(repeated.result.code, 'no_previous_release');

  const upgradedAgain = install('upgrade', installArguments({ target: upgradeArtifact, att: upgradeAttestation, prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(upgradedAgain.status, 0, JSON.stringify(upgradedAgain.result, null, 2));
  assert.equal(upgradedAgain.result.current, positive.artifact.upgrade_name);
  assert.equal(upgradedAgain.result.previous, positive.artifact.name);
  assert.equal(await treeDigest(data), beforeDigest);
});

test('C35 refuses rollback when the recorded release was modified', async () => {
  const prefix = join(work, 'prefix-tamper');
  const data = join(work, 'data-tamper');
  await cp(join(fixtureRoot, positive.data.supported_store_fixture), data, { recursive: true });
  const installed = install('install', installArguments({ prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(installed.status, 0, JSON.stringify(installed.result, null, 2));
  const upgraded = install('upgrade', installArguments({ target: upgradeArtifact, att: upgradeAttestation, prefix, data, extra: ['--allow-foreign-platform'] }));
  assert.equal(upgraded.status, 0, JSON.stringify(upgraded.result, null, 2));
  const beforeDigest = await treeDigest(data);
  const stateBefore = await stateBytes(prefix);
  await writeFile(join(prefix, 'releases', positive.artifact.name, 'dist/web/index.html'), 'tampered');

  const rolledBack = install('rollback', ['--prefix', prefix, '--trusted-key', trustedPublic, '--allow-foreign-platform']);
  assert.equal(rolledBack.status, 1);
  assert.equal(rolledBack.result.code, 'installed_release_modified');
  assert.deepEqual(await stateBytes(prefix), stateBefore);
  assert.equal(await treeDigest(data), beforeDigest);
});

test('C35 refuses a foreign-platform install unless staging is explicit', { skip: hostPlatform() === positive.artifact.platform && 'host matches the artifact platform' }, async () => {
  const prefix = join(work, 'prefix-foreign');
  const data = join(work, 'data-foreign');
  await cp(join(fixtureRoot, positive.data.supported_store_fixture), data, { recursive: true });
  const beforeDigest = await treeDigest(data);
  const result = install('install', installArguments({ prefix, data }));
  assert.equal(result.status, 1);
  assert.equal(result.result.code, 'unsupported_host');
  assert.equal(existsSync(join(prefix, 'install-state.json')), false);
  assert.equal(await treeDigest(data), beforeDigest);
});

test('C35 scripts have no network capability and preserve the source-build path', async () => {
  const scripts = ['scripts/verify-release.mjs', 'scripts/sign-release.mjs', 'scripts/install-release.mjs'];
  const forbidden = /^node:(?:http|https|http2|net|tls|dns|dgram|worker_threads)$/;
  const observedImports = new Map();
  for (const name of scripts) {
    const source = await readFile(join(repository, name), 'utf8');
    const imports = [
      ...source.matchAll(/^\s*import\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/gm),
      ...source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
    ].map(match => match[1]);
    for (const specifier of imports) {
      if (specifier.startsWith('node:') && !forbidden.test(specifier)) observedImports.set(specifier, true);
      if (forbidden.test(specifier)) assert.fail(`Network import ${specifier} in ${name}`);
      if (!specifier.startsWith('node:') && !specifier.startsWith('.')) assert.fail(`Unexpected dependency ${specifier} in ${name}`);
    }
    for (const token of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'http.request', 'https.request']) {
      assert.equal(source.includes(token), false, `${name} contains network capability ${token}`);
    }
  }
  assert.deepEqual([...observedImports.keys()].sort(), expected.no_network.direct_imports.slice().sort());

  const packageJson = JSON.parse(await readFile(join(repository, 'package.json'), 'utf8'));
  assert.equal(packageJson.scripts.setup, 'node scripts/oss-bootstrap.mjs setup');
  assert.equal(packageJson.scripts.package, 'bash scripts/package.sh');
  for (const document of positive.source_build.documents) {
    const content = await readFile(join(repository, document), 'utf8');
    for (const command of positive.source_build.commands) assert.ok(content.includes(command), `${document} must document ${command}`);
  }
  const provenance = JSON.parse(await readFile(join(artifact, 'provenance.json'), 'utf8'));
  assert.ok(existsSync(join(artifact, ...provenance.source.archive.path.split('/'))));
});

test('C35 documents the trust model, refusal codes and safe upgrade contract', async () => {
  const policy = JSON.parse(await readFile(join(repository, 'docs/evidence/release-verification.json'), 'utf8'));
  assert.equal(policy.task, 'C35');
  assert.equal(policy.license, 'Apache-2.0');
  assert.equal(policy.trust.algorithm, 'ed25519');
  assert.equal(policy.trust.private_key_in_repository, false);
  assert.deepEqual(policy.source_build.commands, positive.source_build.commands);
  assert.equal(policy.verification.test_suite, 'tests/release/upgrade-recovery.mjs');
  for (const code of expected.refusals.codes.filter(item => !['unsupported_host'].includes(item))) {
    assert.ok(policy.rollback.refuses.includes(code) || policy.verification.rejection_codes.includes(code), `Policy does not document ${code}`);
  }
  for (const section of ['## Signed release attestation', '## Verified upgrade and rollback', '## Source-build alternative']) {
    assert.ok((await readFile(join(repository, 'docs/release/ARTIFACTS.md'), 'utf8')).includes(section), `ARTIFACTS.md is missing ${section}`);
  }
  assert.ok((await readFile(join(repository, 'docs/release/USER_GUIDE.md'), 'utf8')).includes('## 11. Verified Release Installation'));
});
