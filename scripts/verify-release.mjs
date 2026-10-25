import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { lstat, readFile, readdir, stat } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MANIFEST_FIELDS = [
  'schema_version', 'project', 'version', 'revision', 'license', 'issued_at',
  'expires_at', 'artifact', 'source', 'data', 'evidence',
];
const SIGNATURE_FIELDS = ['schema_version', 'algorithm', 'key_fingerprint', 'manifest_sha256', 'signature'];
const EVIDENCE_FIELDS = ['checksums', 'provenance', 'sbom', 'source_archive'];
const ARTIFACT_FIELDS = ['name', 'platform'];
const SOURCE_FIELDS = ['head_commit', 'tree', 'source_identity'];
const DATA_FIELDS = ['store_schema', 'segments_schema'];
const REQUIRED_PATHS = [
  'SHA256SUMS.txt', 'LICENSE', 'provenance.json', 'sbom.cdx.json',
  'dist/engine/miragemesh', 'dist/web/index.html', 'source/provenance.json',
];
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const digestPattern = /^[0-9a-f]{64}$/;
const sourceIdentityPattern = /^sha256:[0-9a-f]{64}$/;
const versionPattern = /^\d+\.\d+\.\d+$/;
const platformPattern = /^[a-z0-9]{1,16}-[a-z0-9]{1,16}$/;
const commitPattern = /^[0-9a-f]{40}$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function add(errors, code, detail) {
  errors.push({ code, detail });
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!plain(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every(key => keys.includes(key));
}

function timestamp(value) {
  if (typeof value !== 'string' || !timestampPattern.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function sha256File(path) {
  return sha256(await readFile(path));
}

export function isSafeRelativePath(name) {
  if (typeof name !== 'string' || !name || name.includes('\0') || name.includes('\n') || name.includes('\r') || name.includes('\\')) return false;
  if (isAbsolute(name)) return false;
  return !name.split('/').some(part => part === '..' || part === '' || part === '.');
}

export function forbiddenArtifactPath(name) {
  if (/^\.env(?:\.|$)/.test(name) && name !== '.env.example') return true;
  if (/(?:^|\/)(?:node_modules|\.git|docs\/evidence|dist\/release|secrets?)(?:\/|$)/.test(name)) return true;
  if (/\.(?:pem|key|p12|pfx)$/i.test(name)) return true;
  if (/\.sqlite(?:3)?(?:-|$)/i.test(name)) return true;
  return false;
}

export function hostPlatform(platform = process.platform, arch = process.arch) {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  return os && cpu ? `${os}-${cpu}` : null;
}

export async function loadTrustedKey(path) {
  const errors = [];
  let bytes;
  try { bytes = await readFile(path); }
  catch (error) { add(errors, 'trusted_key_invalid', `Trusted key is unreadable: ${error.message}`); return { errors }; }
  let key;
  let raw;
  try {
    if (bytes.length === 32) {
      raw = Buffer.from(bytes);
      key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki' });
    } else {
      const text = bytes.toString('utf8');
      if (!text.includes('BEGIN PUBLIC KEY')) throw new Error('expected a raw 32-byte key or an SPKI PEM public key');
      key = createPublicKey(text);
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('key is not Ed25519');
      const der = key.export({ format: 'der', type: 'spki' });
      if (der.length !== SPKI_ED25519_PREFIX.length + 32 || !der.subarray(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)) {
        throw new Error('unexpected Ed25519 SPKI encoding');
      }
      raw = Buffer.from(der.subarray(SPKI_ED25519_PREFIX.length));
    }
  } catch (error) {
    add(errors, 'trusted_key_invalid', `Trusted key is invalid: ${error.message}`);
    return { errors };
  }
  return { key, raw, fingerprint: `sha256:${sha256(raw)}`, errors };
}

async function walk(root, relative, files, errors) {
  const directory = relative ? join(root, ...relative.split('/')) : root;
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) {
    add(errors, relative ? 'unsafe_artifact_entry' : 'missing_required_path', `Artifact path is unreadable: ${relative || root}: ${error.message}`);
    return;
  }
  for (const entry of entries) {
    const name = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) {
      add(errors, 'unsafe_artifact_entry', `Artifact contains a symbolic link: ${name}`);
      continue;
    }
    if (entry.isDirectory()) {
      await walk(root, name, files, errors);
      continue;
    }
    if (!entry.isFile()) {
      add(errors, 'unsafe_artifact_entry', `Artifact contains a non-regular entry: ${name}`);
      continue;
    }
    files.push(name);
  }
}

async function listArtifactFiles(root, errors) {
  const files = [];
  try {
    const info = await stat(root);
    if (!info.isDirectory()) { add(errors, 'missing_required_path', `Artifact is not a directory: ${root}`); return files; }
  } catch (error) {
    add(errors, 'missing_required_path', `Artifact directory is unreadable: ${error.message}`);
    return files;
  }
  await walk(root, '', files, errors);
  return files.sort();
}

function parseChecksums(text, errors) {
  const entries = [];
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  for (const line of lines) {
    if (!line) { add(errors, 'checksum_coverage', 'Blank line in checksum manifest.'); continue; }
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    if (!match) { add(errors, 'unsafe_checksum_path', `Malformed checksum entry: ${line.slice(0, 100)}`); continue; }
    const [, digest, name] = match;
    if (!isSafeRelativePath(name) || name === 'SHA256SUMS.txt') {
      add(errors, 'unsafe_checksum_path', `Unsafe checksum path: ${name}`);
      continue;
    }
    entries.push({ digest, name });
  }
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.name)) add(errors, 'duplicate_checksum_entry', `Duplicate checksum entry: ${entry.name}`);
    seen.add(entry.name);
  }
  return entries;
}

async function readJson(path, errors, code) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (error) { add(errors, code, `${basename(path)} is unreadable or invalid: ${error.message}`); return null; }
}

async function existsFile(root, name) {
  try { return (await stat(join(root, ...name.split('/')))).isFile(); }
  catch { return false; }
}

async function fileDigest(root, name, errors, code) {
  try { return await sha256File(join(root, ...name.split('/'))); }
  catch (error) { add(errors, code, `${name} is unreadable: ${error.message}`); return null; }
}

/**
 * Inspect the artifact's own evidence without trusting any release manifest.
 * This is the integrity half of C31 that the C35 signature binds.
 */
export async function inspectArtifact(directory) {
  const root = resolve(directory);
  const errors = [];
  const files = await listArtifactFiles(root, errors);
  if (files.length === 0) return { passed: false, errors, root, files, checksumEntries: [], provenance: null };

  for (const name of files) {
    if (!isSafeRelativePath(name)) add(errors, 'unsafe_artifact_entry', `Unsafe artifact path: ${name}`);
    if (forbiddenArtifactPath(name)) add(errors, 'forbidden_material', `Forbidden private/generated path: ${name}`);
  }
  for (const name of REQUIRED_PATHS) {
    if (!(await existsFile(root, name))) add(errors, 'missing_required_path', `Missing required path: ${name}`);
  }
  const enginePath = join(root, 'dist/engine/miragemesh');
  try {
    const info = await stat(enginePath);
    if (!info.isFile()) add(errors, 'missing_required_path', 'Engine binary is not a file.');
    else if (process.platform !== 'win32' && (info.mode & 0o111) === 0) add(errors, 'missing_required_path', 'Engine binary is not executable.');
    if (info.size > MAX_FILE_BYTES) add(errors, 'unsafe_artifact_entry', 'Engine binary exceeds the verification bound.');
  } catch { /* reported by the required-path check */ }

  let checksumEntries = [];
  let checksumsDigest = null;
  try {
    const checksumBytes = await readFile(join(root, 'SHA256SUMS.txt'));
    checksumsDigest = sha256(checksumBytes);
    checksumEntries = parseChecksums(checksumBytes.toString('utf8'), errors);
    const actual = new Set(files.filter(name => name !== 'SHA256SUMS.txt'));
    const listed = new Set(checksumEntries.map(entry => entry.name));
    for (const name of actual) if (!listed.has(name)) add(errors, 'checksum_coverage', `Unlisted artifact file: ${name}`);
    for (const name of listed) if (!actual.has(name)) add(errors, 'checksum_coverage', `Checksum lists a non-file: ${name}`);
    for (const entry of checksumEntries) {
      if (!actual.has(entry.name)) continue;
      const path = join(root, ...entry.name.split('/'));
      try {
        const info = await stat(path);
        if (info.size > MAX_FILE_BYTES) { add(errors, 'unsafe_artifact_entry', `Artifact file exceeds the verification bound: ${entry.name}`); continue; }
      } catch { continue; }
      const observed = await sha256File(path);
      if (observed !== entry.digest) add(errors, 'checksum_mismatch', `Checksum mismatch: ${entry.name}`);
    }
  } catch (error) {
    add(errors, 'checksum_coverage', `Checksum manifest is unreadable: ${error.message}`);
  }

  const provenance = await readJson(join(root, 'provenance.json'), errors, 'invalid_provenance');
  let sbom = null;
  let sbomDigest = null;
  let sourceArchive = null;
  if (provenance) {
    if (!plain(provenance)) add(errors, 'invalid_provenance', 'Provenance is not an object.');
    if (provenance.project !== 'MirageMesh') add(errors, 'invalid_provenance', 'Unexpected provenance project.');
    if (provenance.license !== 'Apache-2.0') add(errors, 'invalid_provenance', 'Unexpected provenance license.');
    if (!versionPattern.test(provenance.version ?? '')) add(errors, 'invalid_provenance', 'Provenance version is malformed.');
    if (!plain(provenance.artifact)) add(errors, 'invalid_provenance', 'Provenance artifact is missing.');
    else {
      if (provenance.artifact.name !== `miragemesh-${provenance.version}-${provenance.artifact.platform}`) add(errors, 'invalid_provenance', 'Provenance artifact name is inconsistent.');
      if (!platformPattern.test(provenance.artifact.platform ?? '')) add(errors, 'invalid_provenance', 'Provenance platform is malformed.');
      if (provenance.artifact.license && provenance.artifact.license !== provenance.license) add(errors, 'invalid_provenance', 'Provenance artifact license is inconsistent.');
    }
    if (!plain(provenance.source)) add(errors, 'invalid_provenance', 'Provenance source is missing.');
    else {
      if (!commitPattern.test(provenance.source.head_commit ?? '')) add(errors, 'invalid_provenance', 'Provenance head commit is malformed.');
      if (!commitPattern.test(provenance.source.tree ?? '')) add(errors, 'invalid_provenance', 'Provenance tree is malformed.');
      if (!sourceIdentityPattern.test(provenance.source.source_identity ?? '')) add(errors, 'invalid_provenance', 'Provenance source identity is malformed.');
    }
    if (provenance.build?.complete_product !== true || provenance.build?.web_only !== false) add(errors, 'invalid_provenance', 'Provenance does not describe a complete product.');
    if (!plain(provenance.contents)) add(errors, 'invalid_provenance', 'Provenance contents are missing.');
    else {
      if (provenance.contents.checksum_manifest !== 'SHA256SUMS.txt') add(errors, 'invalid_provenance', 'Provenance checksum manifest is inconsistent.');
      if (Number.isInteger(provenance.contents.file_count) && provenance.contents.file_count !== files.filter(name => name !== 'SHA256SUMS.txt').length) {
        add(errors, 'invalid_provenance', 'Provenance file count differs from the artifact.');
      }
      if (provenance.contents.engine_sha256) {
        const observed = await fileDigest(root, 'dist/engine/miragemesh', errors, 'invalid_provenance');
        if (observed && observed !== provenance.contents.engine_sha256) add(errors, 'invalid_provenance', 'Engine digest differs from provenance.');
      }
      if (provenance.contents.web_index_sha256) {
        const observed = await fileDigest(root, 'dist/web/index.html', errors, 'invalid_provenance');
        if (observed && observed !== provenance.contents.web_index_sha256) add(errors, 'invalid_provenance', 'Web index digest differs from provenance.');
      }
    }
    if (!plain(provenance.sbom)) add(errors, 'invalid_provenance', 'Provenance SBOM is missing.');
    else {
      if (provenance.sbom.path !== 'sbom.cdx.json') add(errors, 'invalid_provenance', 'Provenance SBOM path is inconsistent.');
      if (!digestPattern.test(provenance.sbom.sha256 ?? '')) add(errors, 'invalid_provenance', 'Provenance SBOM digest is malformed.');
      sbomDigest = await fileDigest(root, 'sbom.cdx.json', errors, 'invalid_sbom');
      if (sbomDigest && provenance.sbom.sha256 !== sbomDigest) add(errors, 'invalid_sbom', 'SBOM digest differs from provenance.');
      sbom = await readJson(join(root, 'sbom.cdx.json'), errors, 'invalid_sbom');
    }
    if (!plain(provenance.source?.archive)) add(errors, 'invalid_provenance', 'Provenance source archive is missing.');
    else {
      const archive = provenance.source.archive;
      if (!isSafeRelativePath(archive.path ?? '')) add(errors, 'invalid_provenance', 'Source archive path is unsafe.');
      else if (!(await existsFile(root, archive.path))) add(errors, 'missing_evidence', `Source archive is missing: ${archive.path}`);
      else {
        const observed = await fileDigest(root, archive.path, errors, 'invalid_provenance');
        if (observed && archive.sha256 !== observed) add(errors, 'invalid_provenance', 'Source archive digest differs from provenance.');
        if (!Number.isInteger(archive.files) || archive.files <= 0) add(errors, 'invalid_provenance', 'Source archive file count is invalid.');
        sourceArchive = { path: archive.path, sha256: observed, files: archive.files };
      }
    }
  }
  if (sbom) {
    if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.5') add(errors, 'invalid_sbom', 'SBOM format or spec version is inconsistent.');
    if (sbom.metadata?.component?.name !== 'MirageMesh') add(errors, 'invalid_sbom', 'SBOM metadata component is missing.');
    if (provenance && sbom.metadata?.component?.version !== provenance.version) add(errors, 'invalid_sbom', 'SBOM version differs from provenance.');
  }
  try {
    const nested = JSON.parse(await readFile(join(root, 'source/provenance.json'), 'utf8'));
    if (provenance && JSON.stringify(nested) !== JSON.stringify(provenance)) add(errors, 'invalid_provenance', 'Bundled source provenance differs from provenance.json.');
  } catch (error) {
    add(errors, 'invalid_provenance', `Bundled source provenance is unreadable: ${error.message}`);
  }

  return {
    passed: errors.length === 0,
    errors,
    root,
    files,
    checksumEntries,
    checksumsDigest,
    provenance,
    sbom,
    sbomDigest,
    sourceArchive,
  };
}

function validateManifest(manifest, errors) {
  if (!exactKeys(manifest, MANIFEST_FIELDS)) {
    add(errors, 'manifest_invalid', 'Release manifest has missing or unknown fields.');
    return;
  }
  if (manifest.schema_version !== 1) add(errors, 'manifest_invalid', 'Unsupported release manifest schema.');
  if (manifest.project !== 'MirageMesh') add(errors, 'manifest_invalid', 'Unexpected release project.');
  if (!versionPattern.test(manifest.version ?? '')) add(errors, 'manifest_invalid', 'Release version is malformed.');
  if (!Number.isInteger(manifest.revision) || manifest.revision <= 0) add(errors, 'manifest_invalid', 'Release revision must be a positive integer.');
  if (manifest.license !== 'Apache-2.0') add(errors, 'manifest_invalid', 'Release license is not Apache-2.0.');
  const issued = timestamp(manifest.issued_at);
  const expires = timestamp(manifest.expires_at);
  if (issued === null || expires === null) add(errors, 'manifest_invalid', 'Release validity timestamps are malformed.');
  else if (expires <= issued) add(errors, 'manifest_invalid', 'Release expiry must follow its issue time.');
  if (!exactKeys(manifest.artifact, ARTIFACT_FIELDS)) add(errors, 'manifest_invalid', 'Release artifact fields are incomplete.');
  else {
    if (!platformPattern.test(manifest.artifact.platform ?? '')) add(errors, 'manifest_invalid', 'Release platform is malformed.');
    if (manifest.artifact.name !== `miragemesh-${manifest.version}-${manifest.artifact.platform}`) add(errors, 'manifest_invalid', 'Release artifact name is inconsistent.');
  }
  if (!exactKeys(manifest.source, SOURCE_FIELDS)) add(errors, 'manifest_invalid', 'Release source fields are incomplete.');
  else {
    if (!commitPattern.test(manifest.source.head_commit ?? '')) add(errors, 'manifest_invalid', 'Release head commit is malformed.');
    if (!commitPattern.test(manifest.source.tree ?? '')) add(errors, 'manifest_invalid', 'Release tree is malformed.');
    if (!sourceIdentityPattern.test(manifest.source.source_identity ?? '')) add(errors, 'manifest_invalid', 'Release source identity is malformed.');
  }
  if (!exactKeys(manifest.data, DATA_FIELDS)) add(errors, 'manifest_invalid', 'Release data compatibility fields are incomplete.');
  else {
    for (const field of DATA_FIELDS) if (!Number.isInteger(manifest.data[field]) || manifest.data[field] <= 0) add(errors, 'manifest_invalid', `Release data field is invalid: ${field}`);
  }
  if (!exactKeys(manifest.evidence, EVIDENCE_FIELDS)) { add(errors, 'manifest_invalid', 'Release evidence fields are incomplete.'); return; }
  const expectedPaths = { checksums: 'SHA256SUMS.txt', provenance: 'provenance.json', sbom: 'sbom.cdx.json' };
  for (const field of EVIDENCE_FIELDS) {
    const item = manifest.evidence[field];
    if (!exactKeys(item, ['path', 'sha256'])) { add(errors, 'manifest_invalid', `Release evidence is incomplete: ${field}`); continue; }
    if (!isSafeRelativePath(item.path ?? '')) add(errors, 'manifest_invalid', `Release evidence path is unsafe: ${field}`);
    if (!digestPattern.test(item.sha256 ?? '')) add(errors, 'manifest_invalid', `Release evidence digest is malformed: ${field}`);
    if (expectedPaths[field] && item.path !== expectedPaths[field]) add(errors, 'manifest_invalid', `Release evidence path is inconsistent: ${field}`);
  }
}

function validateSignatureDocument(document, errors) {
  if (!exactKeys(document, SIGNATURE_FIELDS)) {
    add(errors, 'signature_document_invalid', 'Signature document has missing or unknown fields.');
    return;
  }
  if (document.schema_version !== 1) add(errors, 'signature_document_invalid', 'Unsupported signature schema.');
  if (document.algorithm !== 'ed25519') add(errors, 'signature_document_invalid', 'Unsupported signature algorithm.');
  if (!/^sha256:[0-9a-f]{64}$/.test(document.key_fingerprint ?? '')) add(errors, 'signature_document_invalid', 'Signature fingerprint is malformed.');
  if (!digestPattern.test(document.manifest_sha256 ?? '')) add(errors, 'signature_document_invalid', 'Signature manifest digest is malformed.');
  if (typeof document.signature !== 'string' || document.signature.length === 0) add(errors, 'signature_document_invalid', 'Signature bytes are missing.');
}

/**
 * Verify a detached release attestation and the artifact it names.
 * The trusted key must be supplied outside the artifact.
 */
export async function verifyRelease({
  artifact, manifest, signature, trustedKey, now = new Date(), enforceValidity = true,
} = {}) {
  const errors = [];
  const warnings = [];
  const root = resolve(artifact ?? '.');
  if (!manifest || !signature || !trustedKey) {
    add(errors, 'usage', 'artifact, manifest, signature and trustedKey are required.');
    return { passed: false, errors, warnings };
  }

  const trusted = await loadTrustedKey(trustedKey);
  if (trusted.errors.length) errors.push(...trusted.errors);

  let manifestBytes = null;
  try { manifestBytes = await readFile(manifest); }
  catch (error) { add(errors, 'manifest_unreadable', `Release manifest is unreadable: ${error.message}`); }
  let signatureBytes = null;
  let signatureDocument = null;
  try {
    signatureBytes = await readFile(signature);
    try { signatureDocument = JSON.parse(signatureBytes.toString('utf8')); }
    catch (error) { add(errors, 'signature_document_invalid', `Signature document is not valid JSON: ${error.message}`); }
  } catch (error) { add(errors, 'signature_unreadable', `Signature document is unreadable: ${error.message}`); }

  let parsedManifest = null;
  if (manifestBytes) {
    try { parsedManifest = JSON.parse(manifestBytes.toString('utf8')); }
    catch (error) { add(errors, 'manifest_invalid', `Release manifest is not valid JSON: ${error.message}`); }
  }
  if (parsedManifest) validateManifest(parsedManifest, errors);

  if (signatureDocument) {
    validateSignatureDocument(signatureDocument, errors);
    if (manifestBytes && signatureDocument.manifest_sha256 !== sha256(manifestBytes)) {
      add(errors, 'manifest_digest_mismatch', 'Signature does not cover the supplied manifest bytes.');
    }
    if (trusted.fingerprint && signatureDocument.key_fingerprint !== trusted.fingerprint) {
      add(errors, 'untrusted_signer', 'Signature key does not match the independently trusted key.');
    } else if (trusted.key && manifestBytes && typeof signatureDocument.signature === 'string') {
      let signatureValue = null;
      try { signatureValue = Buffer.from(signatureDocument.signature, 'base64'); } catch { /* validated below */ }
      if (!signatureValue || signatureValue.length !== 64 || signatureValue.toString('base64') !== signatureDocument.signature) {
        add(errors, 'signature_document_invalid', 'Signature bytes are not a base64 Ed25519 signature.');
      } else if (!verifySignature(null, manifestBytes, trusted.key, signatureValue)) {
        add(errors, 'signature_invalid', 'Ed25519 signature verification failed.');
      }
    }
  }

  if (parsedManifest) {
    const issued = timestamp(parsedManifest.issued_at);
    const expires = timestamp(parsedManifest.expires_at);
    const current = now instanceof Date ? now.getTime() : Date.parse(now);
    if (!Number.isFinite(current)) add(errors, 'manifest_invalid', 'Verification time is invalid.');
    else if (issued !== null && current < issued) add(errors, 'manifest_not_yet_valid', 'Release manifest is not yet valid.');
    else if (enforceValidity && expires !== null && current > expires) add(errors, 'manifest_expired', 'Release manifest has expired.');
  }

  const inspection = await inspectArtifact(root);
  errors.push(...inspection.errors);

  const fingerprint = trusted.fingerprint ?? null;
  if (parsedManifest && inspection.provenance) {
    const provenance = inspection.provenance;
    if (parsedManifest.version !== provenance.version) add(errors, 'manifest_invalid', 'Release version differs from provenance.');
    if (parsedManifest.artifact?.name !== provenance.artifact?.name || parsedManifest.artifact?.platform !== provenance.artifact?.platform) {
      add(errors, 'artifact_name_mismatch', 'Release artifact identity differs from provenance.');
    }
    if (parsedManifest.source?.head_commit !== provenance.source?.head_commit ||
        parsedManifest.source?.tree !== provenance.source?.tree ||
        parsedManifest.source?.source_identity !== provenance.source?.source_identity) {
      add(errors, 'invalid_provenance', 'Release source differs from provenance.');
    }
    if (parsedManifest.license !== provenance.license) add(errors, 'manifest_invalid', 'Release license differs from provenance.');
    if (provenance.source?.staged_snapshot?.clean !== true) warnings.push({ code: 'source_dirty', detail: 'Artifact was built from a dirty source tree; it is not a releasable publication.' });

    for (const field of ['checksums', 'provenance', 'sbom', 'source_archive']) {
      const evidence = parsedManifest.evidence?.[field];
      if (!evidence || !isSafeRelativePath(evidence.path)) continue;
      const full = join(root, ...evidence.path.split('/'));
      try {
        if (!(await lstat(full)).isFile()) { add(errors, 'missing_evidence', `Release evidence is not a file: ${evidence.path}`); continue; }
      } catch { add(errors, 'missing_evidence', `Release evidence is missing: ${evidence.path}`); continue; }
      const observed = await sha256File(full);
      if (observed !== evidence.sha256) add(errors, 'evidence_digest_mismatch', `Release evidence digest differs: ${evidence.path}`);
    }
    if (parsedManifest.evidence?.source_archive?.path && parsedManifest.evidence.source_archive.path !== inspection.sourceArchive?.path) {
      add(errors, 'invalid_provenance', 'Release source archive differs from provenance.');
    }
    if (parsedManifest.evidence?.source_archive?.sha256 && parsedManifest.evidence.source_archive.sha256 !== inspection.sourceArchive?.sha256) {
      add(errors, 'evidence_digest_mismatch', 'Release source archive digest differs from provenance.');
    }
    if (parsedManifest.evidence?.sbom?.sha256 && parsedManifest.evidence.sbom.sha256 !== inspection.sbomDigest) {
      add(errors, 'evidence_digest_mismatch', 'Release SBOM digest differs from provenance.');
    }
  }

  return {
    passed: errors.length === 0,
    errors,
    warnings,
    artifact: inspection.provenance?.artifact?.name ?? null,
    version: inspection.provenance?.version ?? parsedManifest?.version ?? null,
    revision: parsedManifest?.revision ?? null,
    platform: inspection.provenance?.artifact?.platform ?? null,
    key_fingerprint: fingerprint,
    source_identity: inspection.provenance?.source?.source_identity ?? null,
    source_clean: inspection.provenance?.source?.staged_snapshot?.clean ?? null,
    files: inspection.files.length,
    checksum_entries: inspection.checksumEntries.length,
    data: parsedManifest?.data ?? null,
    provenance: inspection.provenance,
    checksums_sha256: inspection.checksumsDigest,
    sbom_sha256: inspection.sbomDigest,
    source_archive_sha256: inspection.sourceArchive?.sha256 ?? null,
  };
}

function parseArguments(args) {
  const options = { artifact: null, manifest: null, signature: null, trustedKey: null, now: new Date() };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!argument.startsWith('--')) {
      if (options.artifact) throw new Error(`Unexpected argument: ${argument}`);
      options.artifact = argument;
      continue;
    }
    const value = args[index + 1];
    if (value === undefined) throw new Error(`Missing value for ${argument}`);
    if (argument === '--manifest') options.manifest = value;
    else if (argument === '--signature') options.signature = value;
    else if (argument === '--trusted-key') options.trustedKey = value;
    else if (argument === '--now') {
      if (!Number.isFinite(Date.parse(value))) throw new Error('--now must be an RFC3339 timestamp');
      options.now = new Date(value);
    } else throw new Error(`Unknown option: ${argument}`);
    index += 1;
  }
  if (!options.artifact) throw new Error('Usage: node scripts/verify-release.mjs <artifact-dir> --manifest <release.json> --signature <release.sig.json> --trusted-key <key> [--now <timestamp>]');
  if (!options.manifest) options.manifest = options.artifact.replace(/[\\/]$/, '') + '.release.json';
  if (!options.signature) options.signature = options.manifest.replace(/\.json$/, '.sig.json');
  if (!options.trustedKey) throw new Error('A trusted release key is required (--trusted-key).');
  return options;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await verifyRelease(parseArguments(process.argv.slice(2)));
    console.log(JSON.stringify(result, null, 2));
    if (!result.passed) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({ passed: false, errors: [{ code: 'usage', detail: error.message }] }, null, 2));
    process.exitCode = 2;
  }
}
