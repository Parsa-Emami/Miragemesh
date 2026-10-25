import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, cp, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import {
  buildSourceArchive, getSourceInfo, listDirectoryFiles, project, repository, repositoryUrl,
  sha256File, sourceArchivePath, toolVersions,
} from './package-source.mjs';
import { verifyArtifact } from './verify-artifact.mjs';

const defaultOutput = join(repository, 'dist/release');
const copyEntries = [
  'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'OPEN_SOURCE.md', 'package.json',
  'scripts/start-local.mjs', 'scripts/serve-web.mjs',
  'apps/web/src/lib', 'ops/web', 'ops/runtime-requirements.json', 'ops/diagnostics.md',
  'docs/engineering/toolchain-lock.json', 'docs/product/REFERENCE_WORKFLOW.md', 'docs/release/ARTIFACTS.md',
  'contracts', 'tests/scenarios/clone-to-value.json',
  'tests/fixtures/miragemesh/C04',
  'tests/fixtures/miragemesh/C30/positive.json', 'tests/fixtures/miragemesh/C30/negative.json',
  'tests/fixtures/miragemesh/C30/expected-output.json', 'licenses',
];
const offlineResources = [
  'contracts/README.md', 'contracts/asyncapi.v1.json', 'contracts/asyncapi.v1.yaml', 'contracts/config.schema.json',
  'contracts/event-types.v1.json', 'contracts/input.schema.json', 'contracts/openapi.v1.json', 'contracts/openapi.v1.yaml',
  'contracts/result.schema.json', 'tests/scenarios/clone-to-value.json',
  'tests/fixtures/miragemesh/C04/positive.json', 'tests/fixtures/miragemesh/C04/expected-output.json',
  'tests/fixtures/miragemesh/C04/invalid.json', 'tests/fixtures/miragemesh/C04/valid-event.txt',
  'tests/fixtures/miragemesh/C30/positive.json', 'tests/fixtures/miragemesh/C30/negative.json',
  'tests/fixtures/miragemesh/C30/expected-output.json',
];

function parseArguments(args) {
  const options = { output: defaultOutput, build: true };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--no-build') options.build = false;
    else if (argument === '--output') {
      if (!args[index + 1]) throw new Error('--output requires a path.');
      options.output = resolve(args[index + 1]);
      index += 1;
    } else throw new Error(`Unknown package option: ${argument}`);
  }
  return options;
}

function assertSafeOutput(output) {
  if (output === repository || repository.startsWith(output + sep)) throw new Error('Artifact output may not be the repository or its ancestor.');
  const insideRepository = output.startsWith(repository + sep);
  const insideTemporary = output.startsWith(resolve(tmpdir()) + sep);
  const artifactDirectory = /^miragemesh-\d+\.\d+\.\d+-linux-amd64$/.test(output.split(sep).at(-1) ?? '');
  if (insideRepository && !output.startsWith(join(repository, 'dist') + sep)) {
    throw new Error('Refusing to replace a directory outside dist/.');
  }
  if (!insideRepository && !insideTemporary && !artifactDirectory) {
    throw new Error('Refusing to replace an arbitrary directory; use dist/release, a temporary path, or miragemesh-<version>-linux-amd64.');
  }
  if (insideTemporary && !artifactDirectory) throw new Error('Temporary artifact output must use the miragemesh-<version>-linux-amd64 directory name.');
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: repository, stdio: 'inherit', timeout: 300000, ...options });
  if (result.error || result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed (${result.error?.message ?? result.status}).`);
}

async function copyEntry(root, name) {
  const source = join(repository, ...name.split('/'));
  const destination = join(root, ...name.split('/'));
  await mkdir(join(destination, '..'), { recursive: true });
  await cp(source, destination, { recursive: true, force: true, dereference: false, errorOnExist: false });
}

async function normalizeModes(root) {
  const files = await listDirectoryFiles(root);
  for (const name of files) await chmod(join(root, ...name.split('/')), name === 'dist/engine/miragemesh' ? 0o755 : 0o644);
  async function directories(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        await chmod(join(directory, entry.name), 0o755);
        await directories(join(directory, entry.name));
      }
    }
  }
  await directories(root);
  await chmod(root, 0o755);
  return files;
}

function licenseObject(value) {
  const spdx = /^(?:MIT|Apache-2\.0|BSD-3-Clause|Artistic-2\.0|MPL-2\.0|Zlib|GPL-2\.0-only)$/;
  return spdx.test(value) ? { license: { id: value } } : { license: { name: value } };
}

function createSbom({ version, source, engineSha256, toolchain, lock }) {
  const rootRef = `pkg:generic/miragemesh@${version}?arch=amd64&os=linux`;
  const rootComponent = {
    'bom-ref': rootRef,
    type: 'application',
    name: 'MirageMesh',
    version,
    description: 'Open-source local-first sensor observation, provenance and incident workflow.',
    licenses: [{ license: { id: 'Apache-2.0' } }],
    hashes: [{ alg: 'SHA-256', content: engineSha256 }],
    externalReferences: [{ type: 'vcs', url: repositoryUrl }, { type: 'website', url: repositoryUrl }],
    properties: [
      { name: 'miragemesh:source-identity', value: source.source_identity },
      { name: 'miragemesh:build-node', value: toolchain.node ?? 'unknown' },
      { name: 'miragemesh:build-go', value: toolchain.go ?? 'unknown' },
    ],
  };
  const bundled = [
    { 'bom-ref': 'pkg:npm/react@19.3.1', type: 'library', name: 'react', version: '19.3.1', purl: 'pkg:npm/react@19.3.1', licenses: [{ license: { id: 'MIT' } }] },
    { 'bom-ref': 'pkg:npm/react-dom@19.3.1', type: 'library', name: 'react-dom', version: '19.3.1', purl: 'pkg:npm/react-dom@19.3.1', licenses: [{ license: { id: 'MIT' } }] },
    { 'bom-ref': 'pkg:npm/scheduler@0.28.0', type: 'library', name: 'scheduler', version: '0.28.0', purl: 'pkg:npm/scheduler@0.28.0', licenses: [{ license: { id: 'MIT' } }] },
    { 'bom-ref': 'go-stdlib-1.27.2', type: 'library', name: 'go-stdlib', version: '1.27.2', licenses: [{ license: { id: 'BSD-3-Clause' } }], properties: [{ name: 'miragemesh:included-in', value: 'dist/engine/miragemesh' }] },
  ];
  const host = lock.resources.map(resource => {
    const names = { 'node-runtime': 'node-runtime', 'npm-cli': 'npm-cli', 'go-toolchain': 'go-toolchain', 'podman-provider': 'podman-provider', 'decoy-image': 'alpine' };
    return {
      'bom-ref': `host:${resource.id}@${resource.version}`,
      type: resource.id === 'decoy-image' ? 'container' : 'platform',
      name: names[resource.id] ?? resource.id,
      version: resource.id === 'decoy-image' ? resource.version : (resource.package_version ?? resource.version),
      scope: 'excluded',
      licenses: [licenseObject(resource.license)],
      properties: [
        { name: 'miragemesh:host-prerequisite', value: 'true' },
        { name: 'miragemesh:artifact-url', value: resource.artifact_url ?? '' },
        { name: 'miragemesh:license-url', value: resource.license_url ?? '' },
        { name: 'miragemesh:source-url', value: resource.source_url ?? '' },
        { name: 'miragemesh:integrity', value: `${resource.integrity.algorithm}:${resource.integrity.expected}` },
      ],
    };
  });
  const components = [...bundled, ...host].sort((a, b) => a.name.localeCompare(b.name, 'en'));
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { component: rootComponent, properties: [{ name: 'miragemesh:artifact', value: `miragemesh-${version}-linux-amd64` }] },
    components,
    dependencies: [
      { ref: rootRef, dependsOn: bundled.filter(item => ['react', 'react-dom', 'scheduler', 'go-stdlib'].includes(item.name)).map(item => item['bom-ref']) },
      { ref: 'pkg:npm/react-dom@19.3.1', dependsOn: ['pkg:npm/react@19.3.1', 'pkg:npm/scheduler@0.28.0'] },
    ],
  };
}

function artifactReadme({ version, source }) {
  return `# MirageMesh ${version} — complete local artifact

This artifact contains the real Go engine, built web workspace, contracts and offline
fixtures, shipped license texts, a CycloneDX SBOM, a full source archive, and SHA-256
checksums. It is the complete locally runnable product, not a web-only shell.

- Platform: linux-amd64
- Source commit: ${source.head_commit}
- Source tree: ${source.tree}
- Source identity: ${source.source_identity}
- Working tree clean: ${source.staged_snapshot.clean ? 'yes' : 'no'}
- License: Apache-2.0 (project); see NOTICE and THIRD_PARTY_NOTICES.md

## Run

Node 24.19.0 is required. No npm dependencies are needed to start the packaged runtime.

\`\`\`sh
sha256sum -c SHA256SUMS.txt
node scripts/start-local.mjs --port 4307
\`\`\`

Open http://127.0.0.1:4307. The supervisory process starts the bundled engine on owned
loopback. The public engineEnabled flag remains false; domain routes stay unavailable
until an operator explicitly configures a supported private workflow. Rootless Podman
4.9.3 and the pinned Alpine digest are host prerequisites for the full decoy workflow
and are not redistributed here.

## Verify

\`\`\`sh
sha256sum -c SHA256SUMS.txt
dist/engine/miragemesh --version
\`\`\`

The checksum manifest covers every regular file except itself. Provenance records the
source commit, tree, source identity, dirty-state sample, toolchain and archive digest.
The complete source and build recipe are in \`source/miragemesh-${version}-source.tar.gz\`
with its own provenance at \`source/provenance.json\`. Offline resources and their hashes
are listed in \`offline/resources.json\`.

This is a locally verified build, not a published release. C40 remains the authorized
published-artifact and installed full-workflow gate. No hosted service, public domain,
login service or telemetry is included.
`;
}

function offlineReadme() {
  return `# Offline resources

The local reference workflow runs without network egress. Contracts, fixtures and the
example scenario are bundled here; the engine and web assets are in \`../dist\`. No
remote rule bundle or grammar is required, and none is downloaded. Every bundled
resource is checksummed in \`resources.json\` and by the artifact-level
\`SHA256SUMS.txt\`.
`;
}

async function recoverOutput(output) {
  const parent = dirname(output);
  const prefix = `.${basename(output)}.previous-`;
  let entries;
  try { entries = await readdir(parent); } catch { return; }
  const backups = entries.filter(name => name.startsWith(prefix)).sort();
  if (backups.length === 0) return;
  let outputExists = false;
  try { outputExists = (await stat(output)).isDirectory(); } catch { /* missing output */ }
  if (!outputExists) await rename(join(parent, backups.pop()), output);
  for (const backup of backups) await rm(join(parent, backup), { recursive: true, force: true });
}

async function commitOutput(stage, output) {
  const backup = join(dirname(output), `.${basename(output)}.previous-${randomUUID()}`);
  let movedPrevious = false;
  try {
    try { await rename(output, backup); movedPrevious = true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    await rename(stage, output);
    if (movedPrevious) await rm(backup, { recursive: true, force: true });
  } catch (error) {
    if (movedPrevious) await rename(backup, output).catch(() => {});
    throw error;
  }
}

export async function packageWeb({ output: destination = defaultOutput, build = true } = {}) {
  assertSafeOutput(destination);
  await recoverOutput(destination);
  if (build) run('npm', ['run', 'build']);
  for (const required of ['dist/web/index.html', 'dist/engine/miragemesh']) {
    try { if (!(await stat(join(repository, ...required.split('/')))).isFile()) throw new Error('not a file'); }
    catch { throw new Error(`Missing build output: ${required}. Run npm run build or omit --no-build.`); }
  }
  const stage = join(dirname(destination), `.${basename(destination)}.staging-${process.pid}-${randomUUID()}`);
  await rm(stage, { recursive: true, force: true });
  await mkdir(stage, { recursive: true });
  const output = stage;
  let committed = false;
  try {
  for (const entry of copyEntries) await copyEntry(output, entry);
  await cp(join(repository, 'dist/web'), join(output, 'dist/web'), { recursive: true, force: true });
  await mkdir(join(output, 'dist/engine'), { recursive: true });
  await cp(join(repository, 'dist/engine/miragemesh'), join(output, 'dist/engine/miragemesh'), { force: true });

  const packageJson = JSON.parse(await readFile(join(repository, 'package.json'), 'utf8'));
  const version = packageJson.version;
  const source = await getSourceInfo();
  const toolchain = toolVersions();
  const lock = JSON.parse(await readFile(join(repository, 'docs/engineering/toolchain-lock.json'), 'utf8'));
  const files = await normalizeModes(output);

  const offline = [];
  for (const name of offlineResources) {
    if (!files.includes(name)) throw new Error(`Missing offline resource: ${name}`);
    offline.push({ path: name, sha256: await sha256File(join(output, ...name.split('/'))) });
  }
  await mkdir(join(output, 'offline'), { recursive: true });
  await writeFile(join(output, 'offline/resources.json'), JSON.stringify({
    schema_version: 1,
    project,
    network_egress_required: false,
    rules: [],
    grammars: [],
    resources: offline,
  }, null, 2) + '\n');
  await writeFile(join(output, 'offline/README.md'), offlineReadme());

  const sourceBuild = await buildSourceArchive({ version, output: join(output, ...sourceArchivePath(version).split('/')) });
  const sourceArchive = { path: sourceArchivePath(version), sha256: sourceBuild.sha256, files: sourceBuild.files, prefix: sourceBuild.prefix };
  const engineSha256 = await sha256File(join(output, 'dist/engine/miragemesh'));
  const webIndexSha256 = await sha256File(join(output, 'dist/web/index.html'));
  const sbom = createSbom({ version, source, engineSha256, toolchain, lock });
  await writeFile(join(output, 'sbom.cdx.json'), JSON.stringify(sbom, null, 2) + '\n');
  const sbomSha256 = await sha256File(join(output, 'sbom.cdx.json'));

  let provenance = {
    schema_version: 1,
    project,
    version,
    artifact: {
      name: `miragemesh-${version}-linux-amd64`,
      platform: 'linux-amd64',
      license: 'Apache-2.0',
      runtime_requirements: 'ops/runtime-requirements.json',
    },
    license: 'Apache-2.0',
    source: { ...source, archive: sourceArchive },
    build: {
      generated_by: 'scripts/package.sh',
      command: ['scripts/package.sh'],
      platform: 'linux-amd64',
      toolchain,
      complete_product: true,
      web_only: false,
      reproducible: true,
      reproducibility_scope: 'Same source tree, GNU tar/gzip, Node/Go/npm versions and UTC locale produce identical source-archive and manifest bytes; no timestamps are embedded.',
    },
    contents: {
      complete_product: true,
      web_only: false,
      engine_sha256: engineSha256,
      web_index_sha256: webIndexSha256,
      checksum_manifest: 'SHA256SUMS.txt',
      checksum_algorithm: 'sha256',
      offline_resources: 'offline/resources.json',
      file_count: 0,
    },
    sbom: { path: 'sbom.cdx.json', format: 'CycloneDX', spec_version: '1.5', sha256: sbomSha256, components: sbom.components.map(component => component.name) },
    notes: 'Locally built complete product; not a published release. See docs/release/ARTIFACTS.md and C40 for publication gates.',
  };
  await writeFile(join(output, 'README.md'), artifactReadme({ version, source }));
  await writeFile(join(output, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  await mkdir(join(output, 'source'), { recursive: true });
  await writeFile(join(output, 'source/provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  const finalFiles = (await listDirectoryFiles(output)).filter(name => name !== 'SHA256SUMS.txt');
  provenance = { ...provenance, contents: { ...provenance.contents, file_count: finalFiles.length } };
  await writeFile(join(output, 'provenance.json'), JSON.stringify(provenance, null, 2) + '\n');
  await writeFile(join(output, 'source/provenance.json'), JSON.stringify(provenance, null, 2) + '\n');

  const checksumTargets = await listDirectoryFiles(output);
  const checksumLines = [];
  for (const name of checksumTargets.sort()) checksumLines.push(`${await sha256File(join(output, ...name.split('/')))}  ${name}`);
  await writeFile(join(output, 'SHA256SUMS.txt'), checksumLines.join('\n') + '\n');

  const verification = await verifyArtifact(output);
  if (!verification.passed) {
    const details = verification.errors.map(error => `${error.code}: ${error.detail}`).join('\n');
    throw new Error(`Artifact verification failed:\n${details}`);
  }
  await commitOutput(output, destination);
  committed = true;
  return {
    status: 'ok',
    output: destination,
    artifact: verification.artifact,
    version,
    files: verification.files,
    source_identity: source.source_identity,
    dirty: source.dirty,
    source_archive: sourceBuild.sha256,
    sbom: sbomSha256,
    checksums: await sha256File(join(destination, 'SHA256SUMS.txt')),
    verification,
  };
  } finally {
    if (!committed) await rm(stage, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await packageWeb(parseArguments(process.argv.slice(2)));
    console.log(JSON.stringify(result));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
