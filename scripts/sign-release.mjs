import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inspectArtifact, sha256, sha256File } from './verify-release.mjs';

const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function isoSeconds(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function parseArguments(args) {
  const options = { artifact: null, key: null, revision: null, issuedAt: null, expiresAt: null, output: null, publicKeyOut: null };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const value = args[index + 1];
    if (value === undefined) throw new Error(`Missing value for ${argument}`);
    if (argument === '--artifact') options.artifact = value;
    else if (argument === '--key') options.key = value;
    else if (argument === '--revision') options.revision = value;
    else if (argument === '--issued-at') options.issuedAt = value;
    else if (argument === '--expires-at') options.expiresAt = value;
    else if (argument === '--output') options.output = value;
    else if (argument === '--public-key-out') options.publicKeyOut = value;
    else throw new Error(`Unknown option: ${argument}`);
    index += 1;
  }
  if (!options.artifact || !options.key || !options.revision || !options.expiresAt) {
    throw new Error('Usage: node scripts/sign-release.mjs --artifact <dir> --key <pkcs8.pem> --revision <n> --expires-at <timestamp> [--issued-at <timestamp>] [--output <dir>] [--public-key-out <file>]');
  }
  const revision = Number(options.revision);
  if (!Number.isInteger(revision) || revision <= 0) throw new Error('--revision must be a positive integer');
  for (const [name, value] of [['--issued-at', options.issuedAt], ['--expires-at', options.expiresAt]]) {
    if (value !== null && (!timestampPattern.test(value) || !Number.isFinite(Date.parse(value)))) throw new Error(`${name} must be an RFC3339 UTC timestamp`);
  }
  options.revision = revision;
  options.issuedAt = options.issuedAt ?? isoSeconds(new Date());
  if (Date.parse(options.expiresAt) <= Date.parse(options.issuedAt)) throw new Error('--expires-at must follow --issued-at');
  options.artifact = resolve(options.artifact);
  options.output = resolve(options.output ?? join(dirname(options.artifact), 'attestations'));
  for (const [name, path] of [['--output', options.output], ['--public-key-out', options.publicKeyOut]]) {
    if (!path) continue;
    if (path === options.artifact || path.startsWith(options.artifact + sep)) throw new Error(`${name} may not be inside the artifact`);
  }
  return options;
}

function loadPrivateKey(bytes) {
  const text = bytes.toString('utf8');
  if (text.includes('BEGIN PRIVATE KEY')) {
    const key = createPrivateKey(text);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Signing key is not Ed25519.');
    return key;
  }
  const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Signing key is not Ed25519.');
  return key;
}

async function writeAtomic(path, bytes, mode = 0o644) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(temporary, bytes, { mode });
  await rename(temporary, path);
}

export async function signRelease({ artifact, key: keyPath, revision, issuedAt, expiresAt, output, publicKeyOut = null } = {}) {
  const errors = [];
  let privateKey;
  try {
    privateKey = loadPrivateKey(await readFile(keyPath));
  } catch (error) {
    errors.push({ code: 'signing_key_invalid', detail: `Signing key is unreadable or invalid: ${error.message}` });
    return { passed: false, errors };
  }
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  if (spki.length !== SPKI_ED25519_PREFIX.length + 32 || !spki.subarray(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)) {
    errors.push({ code: 'signing_key_invalid', detail: 'Signing key does not export a canonical Ed25519 public key.' });
    return { passed: false, errors };
  }
  const rawPublicKey = Buffer.from(spki.subarray(SPKI_ED25519_PREFIX.length));
  const fingerprint = `sha256:${sha256(rawPublicKey)}`;

  const inspection = await inspectArtifact(artifact);
  if (!inspection.passed) return { passed: false, errors: inspection.errors };
  const provenance = inspection.provenance;
  const evidence = {
    checksums: { path: 'SHA256SUMS.txt', sha256: inspection.checksumsDigest },
    provenance: { path: 'provenance.json', sha256: await sha256File(join(artifact, 'provenance.json')) },
    sbom: { path: 'sbom.cdx.json', sha256: inspection.sbomDigest },
    source_archive: { path: inspection.sourceArchive.path, sha256: inspection.sourceArchive.sha256 },
  };
  const manifest = {
    schema_version: 1,
    project: 'MirageMesh',
    version: provenance.version,
    revision,
    license: provenance.license,
    issued_at: issuedAt,
    expires_at: expiresAt,
    artifact: { name: provenance.artifact.name, platform: provenance.artifact.platform },
    source: {
      head_commit: provenance.source.head_commit,
      tree: provenance.source.tree,
      source_identity: provenance.source.source_identity,
    },
    data: { store_schema: 1, segments_schema: 1 },
    evidence,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
  const manifestName = `${manifest.artifact.name}.release.json`;
  const signatureName = `${manifest.artifact.name}.release.sig.json`;
  const manifestPath = join(output, manifestName);
  const signaturePath = join(output, signatureName);
  const signatureDocument = {
    schema_version: 1,
    algorithm: 'ed25519',
    key_fingerprint: fingerprint,
    manifest_sha256: sha256(manifestBytes),
    signature: sign(null, manifestBytes, privateKey).toString('base64'),
  };
  try {
    await writeAtomic(manifestPath, manifestBytes);
    await writeAtomic(signaturePath, Buffer.from(JSON.stringify(signatureDocument, null, 2) + '\n'));
    if (publicKeyOut) await writeAtomic(publicKeyOut, rawPublicKey, 0o644);
  } catch (error) {
    errors.push({ code: 'signing_write_failed', detail: `Unable to write the release attestation: ${error.message}` });
    return { passed: false, errors };
  }
  return {
    passed: true,
    errors: [],
    manifest: manifestPath,
    signature: signaturePath,
    public_key: publicKeyOut,
    key_fingerprint: fingerprint,
    manifest_sha256: signatureDocument.manifest_sha256,
    artifact: manifest.artifact.name,
    version: manifest.version,
    revision: manifest.revision,
    source_identity: manifest.source.source_identity,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(JSON.stringify({ passed: false, errors: [{ code: 'usage', detail: error.message }] }, null, 2));
    process.exitCode = 2;
  }
  if (options) {
    const result = await signRelease(options);
    console.log(JSON.stringify(result, null, 2));
    if (!result.passed) process.exitCode = 1;
  }
}
