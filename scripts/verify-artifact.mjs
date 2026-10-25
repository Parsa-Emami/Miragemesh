import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isSafeRelativePath, listArchive, listDirectoryFiles, repository, sha256File } from './package-source.mjs';

const fixtureRoot = join(repository, 'tests/fixtures/miragemesh/C31');

function add(errors, code, detail) {
  errors.push({ code, detail });
}

async function existsFile(root, name) {
  try { return (await stat(join(root, ...name.split('/')))).isFile(); } catch { return false; }
}

async function readJson(path, errors, code) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (error) { add(errors, code, `${path}: ${error.message}`); return null; }
}

function parseChecksums(text) {
  const entries = [];
  const errors = [];
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  for (const line of lines) {
    if (!line) { add(errors, 'checksum_coverage', 'Blank line in checksum manifest.'); continue; }
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    if (!match) { add(errors, 'unsafe_checksum_path', `Malformed checksum entry: ${line.slice(0, 80)}`); continue; }
    const [, digest, name] = match;
    if (!isSafeRelativePath(name) || name === 'SHA256SUMS.txt') {
      add(errors, 'unsafe_checksum_path', `Unsafe checksum path: ${name}`);
      continue;
    }
    entries.push({ digest, name });
  }
  const seen = new Set();
  for (const { name } of entries) {
    if (seen.has(name)) add(errors, 'duplicate_checksum_entry', `Duplicate checksum entry: ${name}`);
    seen.add(name);
  }
  return { entries, errors };
}

function forbiddenArtifactPath(name) {
  if (/^\.env(?:\.|$)/.test(name) && name !== '.env.example') return true;
  if (/(?:^|\/)(?:node_modules|\.git|docs\/evidence|dist\/release|secrets?)(?:\/|$)/.test(name)) return true;
  if (/\.(?:pem|key|p12|pfx)$/i.test(name)) return true;
  if (/\.sqlite(?:3)?(?:-|$)/i.test(name)) return true;
  return false;
}

function validLicense(component) {
  const licenses = component?.licenses;
  if (!Array.isArray(licenses) || licenses.length === 0) return false;
  return licenses.every(item => item?.expression || item?.license?.id || item?.license?.name);
}

export async function verifyArtifact(directory, { fixturePath = join(fixtureRoot, 'positive.json') } = {}) {
  const root = resolve(directory);
  const errors = [];
  const fixtures = await readJson(fixturePath, errors, 'fixture_invalid');
  if (!fixtures) return { passed: false, errors, artifact: null };
  const requiredPaths = Array.isArray(fixtures.required_paths) ? fixtures.required_paths : [];
  const forbiddenPaths = Array.isArray(fixtures.forbidden_paths) ? fixtures.forbidden_paths : [];

  let files = [];
  try { files = await listDirectoryFiles(root); }
  catch (error) { add(errors, 'missing_required_path', `Artifact directory: ${error.message}`); }

  for (const name of files) {
    if (forbiddenArtifactPath(name)) add(errors, 'forbidden_material', `Forbidden private/generated path: ${name}`);
    if (forbiddenPaths.some(prefix => name === prefix || name.startsWith(prefix + '/'))) add(errors, 'forbidden_material', `Artifact contains forbidden path: ${name}`);
  }
  for (const name of requiredPaths) {
    if (!(await existsFile(root, name))) add(errors, 'missing_required_path', `Missing required path: ${name}`);
  }
  const enginePath = join(root, 'dist/engine/miragemesh');
  try {
    const info = await stat(enginePath);
    if (!info.isFile() || (process.platform !== 'win32' && (info.mode & 0o111) === 0)) add(errors, 'missing_required_path', 'Engine binary is not executable.');
  } catch { /* reported by required path check */ }

  const checksumPath = join(root, 'SHA256SUMS.txt');
  let checksums = { entries: [], errors: [] };
  try {
    const parsed = parseChecksums(await readFile(checksumPath, 'utf8'));
    checksums = parsed;
    for (const error of parsed.errors) add(errors, error.code, error.detail);
    const actual = new Set(files.filter(name => name !== 'SHA256SUMS.txt'));
    const listed = new Set(parsed.entries.map(entry => entry.name));
    for (const name of actual) if (!listed.has(name)) add(errors, 'checksum_coverage', `Unlisted artifact file: ${name}`);
    for (const name of listed) if (!actual.has(name)) add(errors, 'checksum_coverage', `Checksum lists a non-file: ${name}`);
    for (const { digest, name } of parsed.entries) {
      if (!actual.has(name)) continue;
      const observed = await sha256File(join(root, ...name.split('/')));
      if (observed !== digest) add(errors, 'checksum_mismatch', `Checksum mismatch: ${name}`);
    }
  } catch (error) { add(errors, 'checksum_coverage', `Checksum manifest unreadable: ${error.message}`); }

  const provenance = await readJson(join(root, 'provenance.json'), errors, 'invalid_provenance');
  const sbom = await readJson(join(root, 'sbom.cdx.json'), errors, 'invalid_sbom');
  const offline = await readJson(join(root, 'offline/resources.json'), errors, 'offline_resources_invalid');
  const artifactName = `${fixtures.artifact_prefix}`;

  if (provenance) {
    for (const field of fixtures.provenance_fields ?? []) if (!(field in provenance)) add(errors, 'invalid_provenance', `Missing provenance field: ${field}`);
    if (provenance.schema_version !== 1) add(errors, 'invalid_provenance', 'Unsupported provenance schema version.');
    if (provenance.project !== 'MirageMesh') add(errors, 'invalid_provenance', 'Unexpected provenance project.');
    if (provenance.version !== fixtures.version || provenance.artifact?.name !== fixtures.artifact_prefix) add(errors, 'invalid_provenance', 'Unexpected provenance version.');
    if (provenance.license !== fixtures.license) add(errors, 'invalid_provenance', 'Provenance license differs from the fixture.');
    if (provenance.artifact?.name !== artifactName) add(errors, 'invalid_provenance', `Unexpected artifact name: ${provenance.artifact?.name}`);
    if (provenance.artifact?.platform !== fixtures.runtime?.platform) add(errors, 'invalid_provenance', 'Unexpected artifact platform.');
    if (!/^sha256:[0-9a-f]{64}$/.test(provenance.source?.source_identity ?? '')) add(errors, 'invalid_provenance', 'Provenance source identity is missing or malformed.');
    for (const field of ['head_commit', 'tree', 'source_identity', 'staged_snapshot', 'archive']) {
      if (!(field in (provenance.source ?? {}))) add(errors, 'invalid_provenance', `Missing provenance source field: ${field}`);
    }
    if (provenance.build?.complete_product !== true || provenance.build?.web_only !== false) add(errors, 'invalid_provenance', 'Provenance does not describe a complete product.');
    if (provenance.sbom?.spec_version !== fixtures.sbom_spec_version) add(errors, 'invalid_provenance', 'Provenance SBOM spec version mismatch.');
    if (provenance.contents?.offline_resources !== 'offline/resources.json') add(errors, 'invalid_provenance', 'Offline resource manifest is not recorded.');
    if (provenance.source?.archive?.path !== `source/miragemesh-${provenance.version}-source.tar.gz`) add(errors, 'invalid_provenance', 'Source archive path is inconsistent.');
    if (provenance.source?.archive) {
      try {
        const observed = await sha256File(join(root, ...provenance.source.archive.path.split('/')));
        if (observed !== provenance.source.archive.sha256) add(errors, 'invalid_provenance', 'Source archive checksum differs from provenance.');
        const entries = await listArchive(join(root, ...provenance.source.archive.path.split('/')));
        if (entries.filter(entry => !entry.endsWith('/')).length !== provenance.source.archive.files) add(errors, 'invalid_provenance', 'Source archive file count differs from provenance.');
        const prefix = fixtures.source_archive_prefix;
        if (!entries.every(entry => entry.startsWith(prefix))) add(errors, 'invalid_provenance', 'Source archive contains entries outside its prefix.');
        for (const needed of ['go.mod', 'cmd/miragemesh/main.go', 'apps/web/src/main.tsx', 'package-lock.json', 'scripts/package.sh', 'docs/engineering/toolchain-lock.json', 'LICENSE']) {
          if (!entries.includes(prefix + needed)) add(errors, 'invalid_provenance', `Source archive is missing ${needed}`);
        }
        for (const entry of entries) {
          if (/(?:^|\/)(?:node_modules|\.git|docs\/evidence|dist)(?:\/|$)/.test(entry.slice(prefix.length))) add(errors, 'invalid_provenance', `Source archive includes generated/private path: ${entry}`);
        }
      } catch (error) { add(errors, 'invalid_provenance', error.message); }
    }
    try {
      const nested = JSON.parse(await readFile(join(root, 'source/provenance.json'), 'utf8'));
      if (JSON.stringify(nested) !== JSON.stringify(provenance)) add(errors, 'invalid_provenance', 'source/provenance.json differs from provenance.json.');
    } catch (error) { add(errors, 'invalid_provenance', 'Bundled source provenance is unreadable.'); }
  }

  if (sbom) {
    if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== fixtures.sbom_spec_version) add(errors, 'invalid_sbom', 'SBOM format or spec version mismatch.');
    if (sbom.metadata?.component?.name !== 'MirageMesh') add(errors, 'invalid_sbom', 'SBOM metadata component is missing.');
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    const names = new Set([...(sbom.metadata?.component?.name ? [sbom.metadata.component.name] : []), ...components.map(component => component?.name)].filter(Boolean).map(name => name.toLowerCase()));
    for (const name of fixtures.sbom_components ?? []) if (!names.has(name.toLowerCase())) add(errors, 'missing_required_component', `SBOM is missing ${name}`);
    for (const component of components) {
      if (!component?.name || !component?.version || !component?.type) add(errors, 'invalid_sbom', 'SBOM component is incomplete.');
      if (!validLicense(component)) add(errors, 'invalid_sbom', `SBOM component lacks a license: ${component?.name}`);
    }
    if (provenance?.sbom?.sha256) {
      const observed = await sha256File(join(root, 'sbom.cdx.json'));
      if (observed !== provenance.sbom.sha256) add(errors, 'invalid_sbom', 'SBOM checksum differs from provenance.');
    }
  }

  if (offline) {
    if (offline.schema_version !== 1) add(errors, 'offline_resources_invalid', 'Unsupported offline resource schema.');
    if (!Array.isArray(offline.resources) || !Array.isArray(offline.rules) || !Array.isArray(offline.grammars)) add(errors, 'offline_resources_invalid', 'Offline resource manifest is incomplete.');
    for (const item of offline.resources ?? []) {
      if (!item?.path || !isSafeRelativePath(item.path)) { add(errors, 'offline_resources_invalid', 'Unsafe offline resource path.'); continue; }
      if (!(await existsFile(root, item.path))) { add(errors, 'offline_resources_invalid', `Missing offline resource: ${item.path}`); continue; }
      const observed = await sha256File(join(root, ...item.path.split('/')));
      if (observed !== item.sha256) add(errors, 'offline_resources_invalid', `Offline resource checksum mismatch: ${item.path}`);
    }
    if ((offline.rules ?? []).some(rule => rule?.remote === true) || (offline.grammars ?? []).some(grammar => grammar?.remote === true)) {
      add(errors, 'offline_resources_invalid', 'Offline manifest requires network access.');
    }
  }

  return {
    passed: errors.length === 0,
    errors,
    artifact: artifactName,
    version: provenance?.version ?? null,
    files: files.length,
    checksum_entries: checksums.entries.length,
    source_identity: provenance?.source?.source_identity ?? null,
    clean_source: provenance?.source?.staged_snapshot?.clean ?? null,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await verifyArtifact(process.argv[2] ?? 'dist/release');
    console.log(JSON.stringify(result, null, 2));
    if (!result.passed) process.exitCode = 1;
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
