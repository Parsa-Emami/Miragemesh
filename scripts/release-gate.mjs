import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, rename, lstat, realpath, mkdtemp, rm, readdir } from 'node:fs/promises';
import { resolve, relative, dirname, join, isAbsolute, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync, gunzipSync } from 'node:zlib';
import { isDeepStrictEqual } from 'node:util';
import { verifyArtifact } from './verify-artifact.mjs';
import { validateResources } from './verify-resources.mjs';
import { isExcludedSourcePath } from './package-source.mjs';

const cards = Array.from({ length: 38 }, (_, i) => 'C' + String(i + 1).padStart(2, '0'));
const bookkeeping = new Set(['plans/progress.json', 'plans/project-state.json', 'docs/agents/SESSION_HANDOFF.json']);
const compatible = new Set(['Apache-2.0', 'MIT', 'BSD-3-Clause', 'ISC', 'MPL-2.0', 'Artistic-2.0', 'Zlib', 'GPL-2.0-only']);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = (code, detail) => { throw Object.assign(new Error(detail), { code }); };
const safe = path => typeof path === 'string' && path.length > 0 && !isAbsolute(path) && !/[\\\0\r\n]/.test(path) && !path.split('/').some(p => !p || p === '.' || p === '..');
const json = async (root, path) => JSON.parse((await bytes(root, path)).toString('utf8'));

async function bytes(root, path, limit = 4 * 1024 * 1024) {
  if (!safe(path)) fail('unsafe_path', 'Proof and source paths must stay inside their root.');
  const base = await realpath(root);
  const target = resolve(base, path);
  const info = await lstat(target);
  if (!info.isFile() || info.size > limit || await realpath(target) !== target) fail('unsafe_path', 'Proof must be a bounded regular file without symlink components.');
  return readFile(target);
}

function git(root, args, binary = false) {
  const result = spawnSync('git', args, { cwd: root, encoding: binary ? undefined : 'utf8', timeout: 30000, maxBuffer: 128 * 1024 * 1024 });
  if (result.error || result.status !== 0) fail('history_missing', 'Required full Git source/history is unavailable.');
  return result.stdout;
}

async function files(root, revision) {
  const output = new Map();
  if (!revision) {
    const names = new Set(git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean));
    for (const name of names) {
      if (name === 'SHA256SUMS.txt' || name.startsWith('docs/evidence/')) continue;
      const data = await bytes(root, name, 32 * 1024 * 1024);
      const info = await lstat(resolve(root, name));
      output.set(name, { data, mode: info.mode & 0o111 ? '100755' : '100644' });
    }
    return output;
  }
  if (!/^[a-f0-9]{40}$/.test(revision)) fail('wrong_source', 'Source commit must be an exact Git SHA.');
  const entries = git(root, ['ls-tree', '-r', '-z', revision]).split('\0').filter(Boolean).map(line => {
    const [header, name] = line.split('\t');
    const [mode, type, oid] = header.split(' ');
    if (!safe(name) || type !== 'blob' || !['100644', '100755'].includes(mode)) fail('unsafe_source', 'Unsupported Git source entry.');
    return { name, mode, oid };
  }).filter(({ name }) => !name.startsWith('docs/evidence/'));
  const result = spawnSync('git', ['cat-file', '--batch'], { cwd: root, input: entries.map(e => e.oid).join('\n') + '\n', timeout: 30000, maxBuffer: 128 * 1024 * 1024 });
  if (result.status !== 0) fail('history_missing', 'Git source blobs cannot be read.');
  let cursor = 0;
  for (const entry of entries) {
    const end = result.stdout.indexOf(10, cursor);
    const [oid, type, count] = result.stdout.subarray(cursor, end).toString().split(' ');
    if (oid !== entry.oid || type !== 'blob') fail('wrong_source', 'Unexpected Git source blob.');
    cursor = end + 1;
    const data = result.stdout.subarray(cursor, cursor + Number(count));
    cursor += Number(count) + 1;
    output.set(entry.name, { data, mode: entry.mode });
  }
  return output;
}

function identity(entries, releaseInputs = false) {
  const digest = createHash('sha256');
  for (const [name, entry] of [...entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    if (name === 'SHA256SUMS.txt') continue;
    if (releaseInputs && bookkeeping.has(name)) continue;
    let data = entry.data;
    if (releaseInputs && name === 'apps/web/src/generated/project.json') {
      const value = JSON.parse(data.toString());
      for (const task of value.tasks) task.status = 'certification-status';
      data = Buffer.from(JSON.stringify(value));
    }
    digest.update(name + '\0');
    if (releaseInputs) digest.update(entry.mode + '\0');
    digest.update(createHash('sha256').update(data).digest());
  }
  return 'sha256:' + digest.digest('hex');
}

export async function releaseInputIdentity(root) { return identity(await files(root), true); }

export async function auditHistoricalEvidence(root, baseline) {
  if (!/^[a-f0-9]{40}$/.test(baseline ?? '')) fail('history_missing', 'An immutable C38 evidence baseline is required.');
  git(root, ['merge-base', '--is-ancestor', baseline, 'HEAD']);
  const progress = await json(root, 'plans/progress.json');
  const records = [];
  const snapshots = new Map();
  const snapshot = async revision => {
    if (!snapshots.has(revision)) snapshots.set(revision, await files(root, revision));
    return snapshots.get(revision);
  };
  for (const id of cards) {
    const path = `docs/evidence/${id}.json`;
    const original = git(root, ['show', baseline + ':' + path], true);
    const current = await bytes(root, path);
    if (!current.equals(original)) fail('changed_historical_evidence', id + ' differs from its immutable historical record; do not relabel old proof.');
    const proof = JSON.parse(current.toString());
    const state = progress.commits.find(row => row.id === id);
    if (!state || state.status !== 'verified' || proof.passed !== true || proof.planning_template || proof.commit_id !== id || !/^sha256:[a-f0-9]{64}$/.test(proof.source_identity ?? '') || state.source_identity !== proof.source_identity || !proof.commands?.length || proof.commands.some(row => row.exit_code !== 0 || !(row.command ?? row.argv)?.length)) fail('template_evidence', id + ' requires real source-bound successful evidence.');
    let sourceBasis = { kind: 'retained_precommit_receipts', note: 'Historical staged-source identities are retained, not relabelled as current proof; this gate freshly reexecutes the supported capabilities.' };
    const inventoryPath = `docs/evidence/${id}/source-files.json`;
    const exists = spawnSync('git', ['cat-file', '-e', baseline + ':' + inventoryPath], { cwd: root, encoding: 'utf8' }).status === 0;
    if (exists) {
      const originalInventory = git(root, ['show', baseline + ':' + inventoryPath], true);
      if (!(await bytes(root, inventoryPath)).equals(originalInventory)) fail('changed_historical_evidence', id + ' historical source inventory changed.');
      const inventory = JSON.parse(originalInventory.toString());
      const entries = Array.isArray(inventory.files) ? inventory.files.map(row => [row.path, row.sha256]) : Object.entries(inventory.files);
      const revision = git(root, ['log', '-1', '--format=%H', baseline, '--', inventoryPath]).trim();
      const sourceFiles = await snapshot(revision);
      const digest = createHash('sha256');
      for (const [name, value] of entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
        const expected = typeof value === 'string' ? value : value.sha256;
        if (!safe(name) || !/^[a-f0-9]{64}$/.test(expected) || !sourceFiles.has(name) || sha(sourceFiles.get(name).data) !== expected) fail('wrong_source', id + ' inventory does not match its historical Git source.');
        digest.update(name + '\0');
        digest.update(Buffer.from(expected, 'hex'));
      }
      if ('sha256:' + digest.digest('hex') !== proof.source_identity) fail('wrong_source', id + ' source identity does not match its file inventory.');
      sourceBasis = { kind: 'historical_source_inventory', commit: revision, files: entries.length };
    } else if (proof.source_paths?.length) {
      const revision = git(root, ['log', '-1', '--format=%H', baseline, '--', path]).trim();
      const sourceFiles = await snapshot(revision);
      const selected = new Map(proof.source_paths.map(name => [name, sourceFiles.get(name)]));
      if ([...selected.values()].some(v => !v) || identity(selected) !== proof.source_identity) fail('wrong_source', id + ' owned-source identity does not match its historical Git source.');
      sourceBasis = { kind: 'historical_owned_paths', commit: revision, files: selected.size };
    } else if (proof.implementation_commit) {
      const sourceFiles = new Map(await snapshot(proof.implementation_commit));
      if (id === 'C26') for (const path of ['plans/progress.json', 'docs/agents/SESSION_HANDOFF.json']) sourceFiles.delete(path);
      if (identity(sourceFiles) !== proof.source_identity) fail('wrong_source', id + ' source identity does not match its implementation commit.');
      sourceBasis = { kind: 'historical_implementation_commit', commit: proof.implementation_commit, files: sourceFiles.size };
    }
    records.push({ id, path, record_sha256: sha(current), source_identity: proof.source_identity, source_basis: sourceBasis });
  }
  return records;
}

export async function inventoryLicenses(root) {
  const lock = await json(root, 'package-lock.json');
  const dependencies = Object.entries(lock.packages).map(([path, value]) => {
    if (!compatible.has(value.license)) fail('unlicensed_dependency', 'Missing or unreviewed dependency license: ' + path);
    return { path, version: value.version, license: value.license };
  });
  const manifest = await json(root, 'docs/engineering/toolchain-lock.json');
  if ((await validateResources(root, manifest)).length) fail('unlicensed_resource', 'Pinned resource provenance, license or fixture integrity is invalid.');
  for (const resource of manifest.resources) {
    if (resource.id === 'decoy-image') {
      if (!resource.component_licenses?.length || resource.component_licenses.some(item => !compatible.has(item.license))) fail('unlicensed_resource', 'The OCI image requires its compatible component license inventory.');
    } else if (!compatible.has(resource.license)) fail('unlicensed_resource', 'A required resource license has not been reviewed.');
  }
  const current = await files(root);
  const fixtures = [];
  for (const [path, { data }] of current) {
    if (!/^tests\/fixtures\/miragemesh\/C\d\d\//.test(path)) continue;
    if (/^tests\/fixtures\/miragemesh\/C\d\d\/[^/]+\.json$/.test(path)) {
      const value = JSON.parse(data.toString());
      if (!compatible.has(value.license) || typeof value.provenance !== 'string' || !value.provenance.trim()) fail('unlicensed_fixture', 'Fixture license/provenance is missing or unreviewed: ' + path);
    }
    fixtures.push({ path, sha256: sha(data), license: 'Apache-2.0', provenance: 'Repository-authored fixture payload/helper under the parent card and project license; JSON metadata is independently validated.' });
  }
  for (const name of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) if (!(await bytes(root, name)).length) fail('unlicensed_resource', 'Required distribution license/notice is missing.');
  return { dependencies, fixtures: fixtures.sort((a, b) => a.path.localeCompare(b.path)), resources: manifest.resources.map(({ id, version, license, integrity }) => ({ id, version, license, integrity })) };
}

export async function verifyEngineLog(root, raw) {
  const work = await mkdtemp(join(tmpdir(), 'c39-engine-proof-'));
  try {
    const path = join(work, 'engine.jsonl');
    await writeFile(path, raw);
    const result = spawnSync(process.execPath, [join(root, 'scripts/verify-engine-tests.mjs'), path], { encoding: 'utf8', timeout: 30000 });
    const counts = result.stdout?.match(/Verified (\d+) engine suites and (\d+) required test anchors/);
    if (result.status !== 0 || !counts || Number(counts[2]) < 209) fail('failed_required_test', 'Executed engine suites and crash/ACK/quota/egress anchors are missing, failed or skipped.');
    const events = raw.split('\n').filter(Boolean).map(line => JSON.parse(line));
    return { suites: Number(counts[1]), required_anchors: Number(counts[2]), top_level_passed: events.filter(e => e.Action === 'pass' && e.Test && !e.Test.includes('/')).length, subtests_passed: events.filter(e => e.Action === 'pass' && e.Test?.includes('/')).length };
  } finally { await rm(work, { recursive: true, force: true }); }
}

export function verifyOnboarding(proof, source) {
  if (proof.source_identity !== source.identity || proof.staged_tree !== source.tree) fail('wrong_source', 'Clean-clone proof belongs to another source.');
  if (proof.passed !== true || proof.failures?.length || !proof.isolation?.transport_clone || proof.isolation.reused_parent_builds !== false || proof.isolation.reused_parent_modules !== false || !proof.commands?.length || proof.commands.some(c => c.exit_code !== c.expected_exit || c.timed_out || c.signal) || proof.runs?.length !== 2 || proof.runs.some(r => !r.passed || !r.coreWorkflow?.passed || !r.coreWorkflow.restart || !r.coreWorkflow.restoreEquivalent || !r.coreWorkflow.readiness.engineReady || !r.coreWorkflow.readiness.storageReady || !r.coreWorkflow.readiness.providersReady || r.coreWorkflow.negativeCases < 6 || r.provider_failure !== 'onboarding.provider_unavailable') || proof.runs[0].state_manifest_sha256 === proof.runs[1].state_manifest_sha256) fail('incomplete_clone', 'Two independent clean-clone workflows, negatives, readiness, restart and restore are required.');
  return { independent_runs: 2, restart_restore: true, duration_ms: proof.duration_ms };
}

async function executionPlan(root) {
  const testFiles = [];
  for (const directory of ['tests/web', 'tests/contracts', 'tests/engineering', 'tests/release']) {
    for (const file of (await readdir(resolve(root, directory))).sort()) if ((directory === 'tests/release' && file.endsWith('.mjs')) || file.endsWith('.test.mjs')) testFiles.push(directory + '/' + file);
  }
  return [
    ['plan', ['npm', 'run', 'validate:plan']],
    ['repository', ['python3', 'scripts/validate_repo.py']],
    ['resources', ['node', 'scripts/verify-resources.mjs']],
    ['reference', ['node', 'scripts/verify-reference.mjs']],
    ['source', ['python3', 'scripts/verify_ci_source.py']],
    ['build', ['npm', 'run', 'build']],
    ['vet', ['go', 'vet', './...']],
    ['engine', ['go', 'test', '-race', '-count=1', '-json', './...']],
    ['node', ['node', '--test', '--test-reporter=tap', ...testFiles]],
    ['browser', ['node', 'node_modules/@playwright/test/cli.js', 'test', '--reporter=json']],
    ['clone', ['npm', 'run', 'test:clone']],
    ['package', ['npm', 'run', 'package']],
    ['artifact', ['npm', 'run', 'verify:artifact']],
  ];
}

export function verifyNodeLog(raw) {
  const number = name => Number(raw.match(new RegExp('^# ' + name + ' (\\d+)$', 'm'))?.[1] ?? -1);
  const result = { total: number('tests'), passed: number('pass'), failed: number('fail'), skipped: number('skipped') };
  const executed = [...raw.matchAll(/^\s*ok \d+ - (.+)$/gm)].map(match => match[1]);
  const required = ['runtime makes no internet connection by default', 'two builds from one source and toolchain are byte-identical', 'real engine and authoritative store report ready, survive restart and reset diagnostics', 'C35 verifies the real artifact against an independently trusted key', 'C35 rejects modified bytes, expired manifests, missing evidence and untrusted signers', 'C35 installs the verified release without touching accepted data', 'C35 rolls back to the recorded release and can upgrade again without data loss', 'C37 repeated install and upgrade reject modified installed bytes without changing accepted data'];
  if (result.passed < 151 || result.failed !== 0 || result.skipped < 0 || result.skipped > 1 || result.total !== result.passed + result.skipped || executed.length < result.passed || required.some(name => !executed.some(row => row === name))) fail('failed_required_test', 'Complete executed Node TAP proof, including unskipped egress, packaging, readiness and signed upgrade checks, is required.');
  return result;
}

export function verifyBrowserLog(raw) {
  const proof = JSON.parse(raw);
  if (proof.stats?.expected < 24 || proof.stats.unexpected !== 0 || proof.stats.skipped !== 0 || proof.stats.flaky !== 0 || proof.errors?.length) fail('failed_required_test', 'Complete real-browser success without skips/flakes is required.');
  const paths = [];
  let passed = 0;
  const visit = suite => {
    if (suite.file) paths.push(suite.file);
    for (const spec of suite.specs ?? []) for (const test of spec.tests ?? []) {
      if (!spec.ok || test.expectedStatus !== 'passed' || test.status !== 'expected' || !test.results?.length || test.results.some(result => result.status !== 'passed')) fail('failed_required_test', 'Browser cases must actually complete without skipped or failed results.');
      passed++;
    }
    for (const child of suite.suites ?? []) visit(child);
  };
  for (const suite of proof.suites ?? []) visit(suite);
  for (const name of ['security.spec.ts', 'full-workflow-accessibility.spec.ts', 'clone-to-value.spec.ts']) if (!paths.some(path => path.endsWith(name))) fail('failed_required_test', 'Browser security, accessibility or full-workflow suite is missing.');
  if (passed !== proof.stats.expected) fail('failed_required_test', 'Browser case results do not match the reported total.');
  return { passed: proof.stats.expected };
}

async function sourceInventory(root, entries) {
  const wanted = {};
  for (const [path, { data }] of entries) if (!isExcludedSourcePath(path)) wanted[path] = sha(data);
  return wanted;
}

export async function verifySourceArchive(root, artifact) {
  const provenance = await json(artifact, 'provenance.json');
  const prefix = provenance.source.archive.prefix;
  if (!safe(provenance.source.archive.path) || prefix !== `miragemesh-${provenance.version}/`) fail('unsafe_path', 'Source archive location or prefix is unsafe.');
  const archive = resolve(artifact, provenance.source.archive.path);
  const listing = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8', timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
  if (listing.status !== 0) fail('wrong_source', 'Packaged source archive cannot be inspected.');
  const names = listing.stdout.split('\n').filter(name => name && !name.endsWith('/'));
  const expected = await sourceInventory(root, await files(root));
  if (new Set(names).size !== names.length || names.length !== Object.keys(expected).length) fail('wrong_source', 'Packaged source archive has missing or duplicate files.');
  for (const name of names) {
    if (!name.startsWith(prefix) || !safe(name)) fail('unsafe_path', 'Unsafe source archive path.');
    const path = name.slice(prefix.length);
    const result = spawnSync('tar', ['-xOzf', archive, '--', name], { timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
    if (result.status !== 0 || expected[path] !== sha(result.stdout)) fail('wrong_source', 'Packaged source bytes differ from the verified checkout: ' + path);
  }
  return expected;
}

export async function readProof(proofRoot, item) {
  if (!item || !/^[a-f0-9]{64}$/.test(item.sha256 ?? '')) fail('missing_proof', 'A named, hashed proof file is required.');
  let raw;
  try { raw = await bytes(proofRoot, item.path, 16 * 1024 * 1024); }
  catch (error) { if (error.code === 'unsafe_path') throw error; fail('missing_proof', 'A required proof file is missing.'); }
  if (sha(raw) !== item.sha256) fail('proof_digest_mismatch', 'Proof file bytes changed.');
  try { return item.path.endsWith('.gz') ? gunzipSync(raw, { maxOutputLength: 32 * 1024 * 1024 }).toString('utf8') : raw.toString('utf8'); }
  catch { fail('invalid_report', 'Proof compression is invalid or over bound.'); }
}

async function validateReport(root, report, proofRoot) {
  if (report.schema_version !== 1 || report.project !== 'MirageMesh' || report.kind !== 'local-oss-v1-readiness' || report.passed !== true || report.planning_template || report.published !== false) fail('incomplete_proof', 'A real completed C39 local-readiness report is required; publication is separate.');
  const gates = await json(root, 'plans/release-gates.json');
  if (!gates.core_ready) fail('core_not_ready', 'Core readiness is not enabled by the verified local workflow.');
  const history = await auditHistoricalEvidence(root, gates.verification?.evidence_baseline);
  if (!isDeepStrictEqual(history, report.history)) fail('changed_historical_evidence', 'Historical record/source digests do not match the verified baseline.');
  const source = report.source;
  const snapshot = await files(root, source?.commit);
  git(root, ['merge-base', '--is-ancestor', source.commit, 'HEAD']);
  if (git(root, ['rev-parse', source.commit + '^{tree}']).trim() !== source.tree || identity(snapshot) !== source.identity || identity(snapshot, true) !== source.release_inputs || await releaseInputIdentity(root) !== source.release_inputs) fail('wrong_source', 'Verification is bound to another source; rerun the complete gate.');
  const licenses = await inventoryLicenses(root);
  if (!isDeepStrictEqual(licenses, report.licenses)) fail('unlicensed_fixture', 'Current dependency/resource/fixture inventory differs from its verified bytes.');
  const environment = report.environment;
  const lock = await json(root, 'docs/engineering/toolchain-lock.json');
  const pins = Object.fromEntries(lock.resources.map(r => [r.id, r.version]));
  if (environment?.os !== 'linux' || environment.architecture !== 'x64' || environment.node !== 'v' + pins['node-runtime'] || environment.npm !== pins['npm-cli'] || environment.go !== 'go version go' + pins['go-toolchain'] + ' linux/amd64' || environment.podman !== 'podman version ' + pins['podman-provider'] || environment.rootless !== 'true') fail('unsupported_profile', 'The recorded supported host/tool/provider profile is required.');
  const plan = await executionPlan(root);
  if (report.steps?.length !== plan.length) fail('missing_proof', 'Every required verification command must be present.');
  const logs = {};
  for (let i = 0; i < plan.length; i++) {
    const [id, command] = plan[i];
    const step = report.steps[i];
    if (step.id !== id || !isDeepStrictEqual(step.command, command) || step.exit_code !== 0 || step.signal || step.timed_out || !Number.isFinite(step.duration_ms) || step.duration_ms < 0) fail('failed_required_test', 'Missing, changed, unsuccessful or unbounded verification command: ' + id);
    logs[id] = await readProof(proofRoot, step.stdout);
    await readProof(proofRoot, step.stderr);
    if (id !== 'vet' && !logs[id].trim()) fail('missing_proof', 'A successful exit without actual command output is not proof: ' + id);
  }
  const engine = await verifyEngineLog(root, logs.engine);
  const node = verifyNodeLog(logs.node);
  const browser = verifyBrowserLog(logs.browser);
  const onboarding = JSON.parse(await readProof(proofRoot, report.attachments?.onboarding));
  const clone = verifyOnboarding(onboarding, source);
  for (const fixture of onboarding.fixture_hashes ?? []) if (sha(await bytes(root, fixture.path)) !== fixture.sha256) fail('wrong_source', 'Onboarding fixture bytes changed.');
  const provenance = JSON.parse(await readProof(proofRoot, report.attachments?.provenance));
  const sbomRaw = await readProof(proofRoot, report.attachments?.sbom);
  const sbom = JSON.parse(sbomRaw);
  const checksums = await readProof(proofRoot, report.attachments?.checksums);
  const inventory = JSON.parse(await readProof(proofRoot, report.attachments?.source_inventory));
  if (provenance.build?.complete_product !== true || provenance.build.web_only !== false || provenance.contents?.complete_product !== true || provenance.contents.web_only !== false || provenance.source?.dirty !== false || !/^[a-f0-9]{64}$/.test(provenance.contents.engine_sha256 ?? '') || !checksums.includes(provenance.contents.engine_sha256 + '  dist/engine/miragemesh') || !checksums.includes('  dist/web/index.html')) fail('web_only_artifact', 'Complete native engine/web/source packaging is required.');
  if (provenance.source.source_identity !== source.identity || provenance.source.tree !== source.tree || !isDeepStrictEqual(inventory, await sourceInventory(root, snapshot))) fail('wrong_source', 'Packaged source/engine provenance is not bound to the verified snapshot.');
  if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.5' || sha(Buffer.from(sbomRaw)) !== provenance.sbom?.sha256 || !sbom.components?.length || sbom.components.some(c => !c.licenses?.length || c.licenses.some(l => !(l.license?.id || l.license?.name || l.expression)))) fail('unlicensed_dependency', 'Complete shipped dependency SBOM/licenses are required.');
  const artifactResult = JSON.parse(logs.artifact.slice(logs.artifact.indexOf('{')));
  if (!artifactResult.passed || artifactResult.errors?.length || artifactResult.clean_source !== true || artifactResult.source_identity !== source.identity) fail('web_only_artifact', 'Actual complete-artifact verification did not pass.');
  return { schema_version: 1, passed: true, release_ready: true, published: false, source, historical_cards: history.length, engine, node, browser, clone, errors: [] };
}

export async function verifyReleaseGate({ root, reportPath = 'docs/evidence/v1-gate.json' }) {
  try {
    let report;
    try { report = await json(root, reportPath); }
    catch (error) { if (error.code === 'unsafe_path') throw error; fail('missing_report', 'Run the full supported-host gate before certifying readiness.'); }
    return await validateReport(root, report, dirname(resolve(root, reportPath)));
  } catch (error) { return { schema_version: 1, passed: false, release_ready: false, published: false, errors: [{ code: error.code ?? 'invalid_report', detail: error.message }] }; }
}

export async function runReleaseGate({ root, output = 'dist/ci/v1-gate.json' }) {
  if (!safe(output) || !output.startsWith('dist/')) fail('usage', 'The generated report must be an ignored dist/ output.');
  const proofRoot = dirname(resolve(root, output));
  const proofDirectory = 'C39/verification';
  await mkdir(resolve(proofRoot, proofDirectory), { recursive: true });
  const report = { schema_version: 1, project: 'MirageMesh', kind: 'local-oss-v1-readiness', passed: false, planning_template: false, published: false, steps: [], attachments: {}, started_at: new Date().toISOString() };
  const publish = async () => { const path = resolve(root, output); await writeFile(path + '.tmp', JSON.stringify(report, null, 2) + '\n'); await rename(path + '.tmp', path); };
  const keep = async (name, data) => { const raw = gzipSync(Buffer.from(data), { mtime: 0 }); const path = proofDirectory + '/' + name + '.gz'; await writeFile(resolve(proofRoot, path), raw); return { path, sha256: sha(raw) }; };
  const probe = (command, args) => { const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 30000 }); if (result.status !== 0) fail('unsupported_profile', 'Required tool/provider is unavailable: ' + command); return result.stdout.trim(); };
  await publish();
  try {
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const commit = process.env.C39_SOURCE_COMMIT || head;
    const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
    if (git(root, ['rev-parse', commit + '^{tree}']).trim() !== tree || git(root, ['status', '--porcelain', '--untracked-files=normal']).trim()) fail('dirty_source', 'Commit all inputs and update the branch before full verification; source/head trees must match.');
    const snapshot = await files(root, commit);
    report.source = { commit, tree, identity: identity(snapshot), release_inputs: identity(snapshot, true) };
    const gates = await json(root, 'plans/release-gates.json');
    report.history = await auditHistoricalEvidence(root, gates.verification?.evidence_baseline);
    report.licenses = await inventoryLicenses(root);
    report.environment = { os: process.platform, architecture: process.arch, node: process.version, npm: probe('npm', ['--version']), go: probe('go', ['version']), podman: probe('podman', ['--version']), rootless: probe('podman', ['info', '--format', '{{.Host.Security.Rootless}}']) };
    for (const [id, command] of await executionPlan(root)) {
      const start = performance.now();
      const [executable, ...args] = command;
      const result = spawnSync(executable === 'node' ? process.execPath : executable, args, { cwd: root, encoding: 'utf8', timeout: 300000, maxBuffer: 64 * 1024 * 1024 });
      const step = { id, command, exit_code: result.status, signal: result.signal, timed_out: result.error?.code === 'ETIMEDOUT', duration_ms: Math.round(performance.now() - start), stdout: await keep(id + '.stdout.log', result.stdout ?? ''), stderr: await keep(id + '.stderr.log', result.stderr ?? '') };
      report.steps.push(step);
      console.log(JSON.stringify({ stage: id, exit_code: step.exit_code, duration_ms: step.duration_ms }));
      if (result.error || result.status !== 0) fail('failed_required_test', 'Required verification failed: ' + id + '; inspect the retained command output.');
    }
    const artifact = resolve(root, 'dist/release');
    const checked = await verifyArtifact(artifact);
    if (!checked.passed) fail('web_only_artifact', 'Actual complete artifact verification failed.');
    const inventory = await verifySourceArchive(root, artifact);
    for (const [name, path] of Object.entries({ onboarding: 'dist/ci/onboarding.json', provenance: 'dist/release/provenance.json', sbom: 'dist/release/sbom.cdx.json', checksums: 'dist/release/SHA256SUMS.txt' })) report.attachments[name] = await keep(name + '.json', await readFile(resolve(root, path)));
    report.attachments.source_inventory = await keep('source-inventory.json', JSON.stringify(inventory));
    report.passed = true;
    report.completed_at = new Date().toISOString();
    const result = await validateReport(root, report, proofRoot);
    report.results = result;
    await publish();
    return result;
  } catch (error) {
    report.passed = false;
    report.errors = [{ code: error.code ?? 'invalid_report', detail: error.message }];
    report.completed_at = new Date().toISOString();
    await publish();
    return { schema_version: 1, passed: false, release_ready: false, published: false, errors: report.errors };
  }
}

export async function releaseGateCommand(root, args) {
  try {
    if (args.length === 0) return verifyReleaseGate({ root });
    if (args.length === 2 && args[0] === '--report' && safe(args[1])) return verifyReleaseGate({ root, reportPath: args[1] });
    if (args[0] === '--run' && (args.length === 1 || (args.length === 3 && args[1] === '--output'))) return await runReleaseGate({ root, output: args[2] });
    fail('usage', 'Usage: npm run release:check [-- --run [--output dist/ci/v1-gate.json] | --report path]');
  } catch (error) { return { passed: false, release_ready: false, published: false, errors: [{ code: error.code ?? 'invalid_report', detail: error.message }] }; }
}
