import { mkdtemp, mkdir, rm, writeFile, readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir, platform, arch, cpus, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { goEnvironment } from './oss-bootstrap.mjs';
import { loadOnboarding, runCommand, OnboardingError } from './onboarding-contract.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const reportPath = join(root, 'dist/ci/onboarding.json');
const logDirectory = join(root, 'dist/ci/onboarding-logs');
const report = {
  schema_version: 1, task: 'C36', passed: false, started_at: new Date().toISOString(),
  environment: { os: platform(), architecture: arch(), logical_cpus: cpus().length, ram_mib: Math.round(totalmem() / 1048576), node: process.version },
  isolation: { transport_clone: true, reused_parent_builds: false, reused_parent_modules: false, prepared_host_caches: ['Go compiler/toolchain', 'rootless Podman and digest-pinned image', 'Playwright Chromium'], independent_human_contributor: false },
  commands: [], runs: [], failures: [],
};
const began = performance.now();
let temp;
await mkdir(logDirectory, { recursive: true });
const log = async (row, stdout, stderr) => {
  const name = String(report.commands.length).padStart(2, '0') + '-' + row.stage + '.log';
  await writeFile(join(logDirectory, name), stdout + stderr);
  row.log = 'dist/ci/onboarding-logs/' + name;
  console.log(JSON.stringify({ stage: row.stage, exit_code: row.exit_code, duration_ms: row.duration_ms }));
};
const run = (stage, command, args, cwd, options = {}) => runCommand(report.commands, stage, command, args, { cwd, log, ...options });
try {
  if (process.argv.length !== 2) throw new OnboardingError('onboarding.invalid_options', 'Usage: npm run test:clone; report: dist/ci/onboarding.json');
  const { scenario } = await loadOnboarding(root);
  if (!process.env.npm_execpath) throw new OnboardingError('onboarding.missing_prerequisite', 'Invoke through npm run test:clone');
  temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
  const tree = (await run('staged-source', 'git', ['write-tree'], root)).trim();
  const identity = { ...process.env, GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid', GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid' };
  const commit = (await run('snapshot', 'git', ['commit-tree', tree, '-p', 'HEAD', '-m', 'temporary staged source proof'], root, { env: identity })).trim();
  report.staged_tree = tree;
  report.base_commit = (await run('base-source', 'git', ['rev-parse', 'HEAD'], root)).trim();
  const source = join(temp, 'source.git');
  await run('isolated-source', 'git', ['init', '--bare', '--quiet', source], temp);
  const objects = resolve(root, (await run('source-objects', 'git', ['rev-parse', '--git-path', 'objects'], root)).trim());
  await mkdir(join(source, 'objects/info'), { recursive: true });
  await writeFile(join(source, 'objects/info/alternates'), objects + '\n');
  await run('advertise-snapshot', 'git', ['--git-dir=' + source, 'update-ref', 'refs/heads/snapshot', commit], temp);
  const checkout = join(temp, 'checkout');
  await run('transport-clone', 'git', ['clone', '--quiet', '--no-local', '--branch', 'snapshot', source, checkout], temp);
  const clonedTree = (await run('cloned-source', 'git', ['rev-parse', 'HEAD^{tree}'], checkout)).trim();
  if (clonedTree !== tree) throw new OnboardingError('onboarding.source_mismatch', 'Cloned tree differs from index');
  for (const name of ['node_modules', 'dist']) {
    if (await stat(join(checkout, name)).then(() => true, () => false)) throw new OnboardingError('onboarding.dirty_environment', 'Fresh clone unexpectedly contains ' + name);
  }
  const sourceProof = JSON.parse(await run('source-integrity', 'python3', ['scripts/verify_ci_source.py'], checkout));
  report.source_identity = sourceProof.current_source_identity;
  report.guides = [];
  for (const path of scenario.onboarding.guides) report.guides.push({ path, sha256: createHash('sha256').update(await readFile(join(checkout, path))).digest('hex') });
  report.fixture_hashes = [];
  for (const path of [...scenario.fixtures, ...['positive', 'negative', 'expected-output'].map(name => scenario.onboarding.fixture_directory + '/' + name + '.json')]) report.fixture_hashes.push({ path, license: 'Apache-2.0', sha256: createHash('sha256').update(await readFile(join(checkout, path))).digest('hex') });
  const missingPath = join(temp, 'empty-path');
  await mkdir(missingPath);
  await run('missing-prerequisite', process.execPath, ['scripts/oss-bootstrap.mjs', 'setup'], checkout, { env: { ...process.env, PATH: missingPath }, expectedExit: 1, expectedStderr: 'prerequisite failed' });
  report.negative_prerequisite = { passed: true, exit_code: 1, code: 'onboarding.missing_prerequisite' };
  await run('guide-setup', process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout, { timeout: 240000 });
  report.tools = {
    go: (await run('go-version', 'go', ['version'], checkout, { env: goEnvironment })).trim(),
    podman: (await run('provider-version', 'podman', ['--version'], checkout)).trim(),
    rootless: (await run('rootless-provider', 'podman', ['info', '--format', '{{.Host.Security.Rootless}}'], checkout)).trim(),
    npm: (await run('npm-version', process.execPath, [process.env.npm_execpath, '--version'], checkout)).trim(),
  };
  await run('engine-vet', 'go', ['vet', './...'], checkout, { env: goEnvironment });
  const engineTests = await run('engine-race-tests', 'go', ['test', '-race', '-count=1', '-json', './...'], checkout, { env: goEnvironment, timeout: 240000 });
  await mkdir(join(checkout, 'dist/ci'), { recursive: true });
  await writeFile(join(checkout, 'dist/ci/engine-tests.jsonl'), engineTests);
  await run('required-engine-tests', process.execPath, ['scripts/verify-engine-tests.mjs', 'dist/ci/engine-tests.jsonl'], checkout);
  await run('malformed-fixture', 'go', ['run', './tests/fixtures/miragemesh/C30/seed', join(temp, 'invalid-state')], checkout, { env: { ...goEnvironment, MIRAGEMESH_C30_FIXTURES: join(temp, 'missing-fixtures') }, expectedExit: 1, expectedStderr: 'acceptance: missing or malformed fixture' });
  if (await stat(join(temp, 'invalid-state/state')).then(() => true, () => false)) throw new OnboardingError('onboarding.placeholder_state', 'Missing fixtures created state');
  for (let iteration = 1; iteration <= scenario.onboarding.independent_runs; iteration++) {
    const resultFile = join(temp, 'result-' + iteration + '.json');
    await run('reference-workflow-' + iteration, process.execPath, ['scripts/onboarding-workflow.mjs', join(temp, 'state-' + iteration), resultFile], checkout, { timeout: 240000 });
    const result = JSON.parse(await readFile(resultFile, 'utf8'));
    if (!result.passed || resolve(result.implementation_root) !== resolve(checkout) || !result.coreWorkflow.passed || !result.coreWorkflow.restoreEquivalent || result.provider_failure !== 'onboarding.provider_unavailable') throw new OnboardingError('onboarding.incomplete_workflow', 'Clone-owned workflow did not complete');
    if (report.runs.some(previous => previous.state_manifest_sha256 === result.state_manifest_sha256)) throw new OnboardingError('onboarding.shared_state', 'Independent runs reused an accepted manifest');
    delete result.implementation_root;
    report.runs.push({ iteration, ...result });
  }
  report.passed = true;
  report.proof = 'fresh transport clone -> public guide setup -> real Go vet/race/required anchors -> two fresh-state reference workflows -> clone-owned engine/storage/provider readiness -> restart/restore -> Chromium domain views';
} catch (error) {
  report.failures.push({ code: error.code ?? 'onboarding.failed', message: error.message });
  console.error(error.message);
  process.exitCode = 1;
} finally {
  report.completed_at = new Date().toISOString();
  report.duration_ms = Math.round(performance.now() - began);
  try { if (temp) await rm(temp, { recursive: true, force: true }); }
  catch (error) { report.passed = false; report.failures.push({ code: 'onboarding.cleanup_failed', message: error.message }); process.exitCode = 1; }
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ passed: report.passed, report: 'dist/ci/onboarding.json', duration_ms: report.duration_ms, runs: report.runs.length }));
}
