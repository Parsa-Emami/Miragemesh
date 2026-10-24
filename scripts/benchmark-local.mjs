import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { access, mkdir, readFile, readdir, rename, rm, stat, statfs, writeFile } from 'node:fs/promises';
import { constants as fsConstants, readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { cpus, loadavg, platform, release, totalmem } from 'node:os';
import { performance } from 'node:perf_hooks';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildEngine } from './build-engine.mjs';
import { goEnvironment } from './oss-bootstrap.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const scenarioPath = 'tests/scenarios/target-workload.json';
const fixturePaths = [
  'tests/fixtures/miragemesh/C28/positive.json',
  'tests/fixtures/miragemesh/C28/negative.json',
  'tests/fixtures/miragemesh/C28/expected-output.json',
];
const clockTicks = 100;

const digest = value => createHash('sha256').update(value).digest('hex');

export function percentile(values, fraction) {
  if (!Array.isArray(values) || values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const position = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1));
  return sorted[position];
}

export function summarizeLatency(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return { count: 0, min_ms: 0, mean_ms: 0, p50_ms: 0, p95_ms: 0, p99_ms: 0, max_ms: 0 };
  }
  const total = values.reduce((sum, value) => sum + value, 0);
  return {
    count: values.length,
    min_ms: Math.min(...values),
    mean_ms: total / values.length,
    p50_ms: percentile(values, 0.5),
    p95_ms: percentile(values, 0.95),
    p99_ms: percentile(values, 0.99),
    max_ms: Math.max(...values),
  };
}

function summarizeProjection(outcome) {
  return {
    scope: outcome.scope,
    status: outcome.status,
    appended: outcome.appended,
    skipped: outcome.skipped,
    retained: outcome.retained,
    already_projected: outcome.already_projected,
    segments: outcome.segments,
    segments_known: outcome.segments_known,
    incomplete_segments: outcome.incomplete_segments,
    index_known: outcome.index_known,
    index_records: outcome.index_records,
    index_sensors: outcome.index_sensors,
    index_complete: outcome.index_complete,
    index_duplicates: outcome.index_duplicates,
    deduplicated: outcome.deduplicated,
    alerts: {
      coverage_complete: outcome.alerts?.coverage_complete ?? null,
      interactions: outcome.alerts?.interactions?.length ?? 0,
      rates: outcome.alerts?.rates?.length ?? 0,
      sensor_health: outcome.alerts?.sensor_health?.length ?? 0,
    },
  };
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

export function validateWorkload(scenario, fixtures) {
  const errors = [];
  const { positive, negative, expected } = fixtures ?? {};
  if (!scenario || typeof scenario !== 'object') return ['scenario is missing'];
  if (scenario.schema_version !== 1 || scenario.fixture_version !== 1) errors.push('scenario version must be 1');
  if (scenario.task !== 'C28' || scenario.status !== 'defined') errors.push('scenario task/status is not C28');
  if (scenario.license !== 'Apache-2.0' || !scenario.provenance || !scenario.title) errors.push('scenario license/provenance/title is missing');
  const hardware = scenario.hardware_target ?? {};
  if (!positiveInteger(hardware.vcpu) || !positiveInteger(hardware.memory_mib) || !positiveInteger(hardware.free_disk_mib)) errors.push('hardware target must be positive');
  const target = scenario.target ?? {};
  if (!positiveInteger(target.sensors) || target.sensors !== scenario.published_capacity?.sensors) errors.push('target sensors must match the published cap');
  if (target.steady_phase?.duration_seconds !== 30 || target.steady_phase?.batch_size !== 1) errors.push('steady phase must be 30s with batch size 1');
  if (target.steady_phase?.events_per_second !== scenario.published_capacity?.events_per_second) errors.push('steady phase must exercise the published rate');
  if (!positiveInteger(scenario.over_limit?.rate_probe?.events_per_second) || !positiveInteger(scenario.over_limit.rate_probe.duration_seconds) || scenario.over_limit.rate_probe.batch_size !== 1) errors.push('rate probe is incomplete');
  if (scenario.over_limit?.rate_probe?.events_per_second <= scenario.published_capacity?.events_per_second) errors.push('rate probe must exceed the published rate');
  if (!positiveInteger(target.backlog_phase?.events) || !positiveInteger(target.backlog_phase?.batch_size) || target.backlog_phase.events % target.sensors !== 0) errors.push('backlog must be positive and divisible by sensors');
  if (target.backlog_phase?.batch_size > target.config?.settings?.event_batch_limit) errors.push('backlog batch exceeds the signed limit');
  if (!positiveInteger(target.storage_limits?.max_operations) || !positiveInteger(target.storage_limits?.max_bytes) || !positiveInteger(target.storage_limits?.max_manifest_bytes)) errors.push('target storage limits are incomplete');
  if (!positiveInteger(target.segment_limits?.max_segments) || !positiveInteger(target.segment_limits?.max_records_per_segment) || !positiveInteger(target.segment_limits?.max_bytes_per_segment)) errors.push('target segment limits are incomplete');
  if (!positiveInteger(target.alerts?.rate_limit) || !positiveInteger(target.alerts?.window_seconds)) errors.push('projection alert policy is incomplete');
  if (!Array.isArray(target.http?.endpoints) || target.http.endpoints.length === 0) errors.push('HTTP endpoints are missing');
  for (const endpoint of target.http?.endpoints ?? []) {
    if (typeof endpoint !== 'string' || !endpoint.startsWith('/') || endpoint.includes('..')) errors.push(`endpoint is not a local path: ${endpoint}`);
  }
  if (!Array.isArray(target.http?.levels) || target.http.levels.length === 0 || !positiveInteger(target.http?.requests_per_level) || !positiveInteger(target.http?.saturation_level)) errors.push('HTTP policy is incomplete');
  if (!positiveInteger(target.regression?.events_per_sensor) || !positiveInteger(target.regression?.batch_size)) errors.push('regression policy is incomplete');
  if (!positiveInteger(scenario.over_limit?.batch_probe?.batch_size) || scenario.over_limit.batch_probe.batch_size <= target.config?.settings?.event_batch_limit) errors.push('batch probe must exceed the signed limit');
  if (!positiveInteger(scenario.over_limit?.storage_probe?.events) || !positiveInteger(scenario.over_limit?.storage_probe?.batch_size) || !positiveInteger(scenario.over_limit?.storage_probe?.storage_limits?.max_bytes)) errors.push('storage probe is incomplete');
  if (!positiveInteger(scenario.cancellation?.batch_size) || !positiveInteger(scenario.cancellation?.cancel_after_checks) || scenario.cancellation?.retry !== true) errors.push('cancellation policy is incomplete');
  if (!Array.isArray(scenario.restart?.checks) || scenario.restart.checks.length === 0) errors.push('restart checks are missing');
  if (!Array.isArray(scenario.fixtures) || scenario.fixtures.length !== 3 || scenario.fixtures.some(path => !fixturePaths.includes(path))) errors.push('scenario must reference the three C28 fixtures');
  if (!positive || !negative || !expected) {
    errors.push('fixture documents are missing');
    return errors;
  }
  for (const [name, fixture] of Object.entries({ positive, negative, expected })) {
    if (fixture.fixture_version !== 1 || fixture.license !== 'Apache-2.0' || !fixture.provenance) errors.push(`${name} fixture metadata is invalid`);
  }
  if (!Array.isArray(positive.sensors) || positive.sensors.length !== target.sensors) errors.push('positive sensor list does not match the target');
  if (!Array.isArray(positive.samples) || positive.samples.length !== positive.expected?.samples_accepted) errors.push('positive samples are inconsistent');
  if (!Array.isArray(negative.cases) || negative.cases.length !== expected.negatives?.count) errors.push('negative case count is inconsistent');
  if (!positiveInteger(negative.sensor_count) || negative.sensor_count > positive.sensors?.length) errors.push('negative sensor count is invalid');
  const names = new Set();
  for (const testCase of negative.cases ?? []) {
    if (!testCase?.name || names.has(testCase.name)) errors.push(`negative case name is missing or duplicated: ${testCase?.name}`);
    names.add(testCase?.name);
    if (!['event', 'batch', 'storage_quota'].includes(testCase?.kind)) errors.push(`negative case ${testCase?.name} has an unknown kind`);
  }
  const steady = (target.steady_phase?.duration_seconds ?? 0) * (target.steady_phase?.events_per_second ?? 0);
  const total = steady + (target.backlog_phase?.events ?? 0);
  if (expected.target?.total_events !== total || expected.target?.steady_events !== steady || expected.target?.backlog_events !== target.backlog_phase?.events) errors.push('expected target counts do not match the scenario');
  if (expected.target?.total_acks !== total || expected.target?.per_sensor_sequences !== total / target.sensors) errors.push('expected acknowledgement counts do not match the scenario');
  if (expected.cancellation?.batch_size !== scenario.cancellation?.batch_size || expected.cancellation?.retry_events !== scenario.cancellation?.batch_size || expected.cancellation?.retry_acks !== scenario.cancellation?.batch_size) errors.push('expected cancellation count does not match the scenario');
  if (expected.over_limit?.rate_probe?.planned_events !== scenario.over_limit?.rate_probe?.events_per_second * scenario.over_limit?.rate_probe?.duration_seconds || expected.over_limit?.rate_probe?.completed_max >= expected.over_limit?.rate_probe?.planned_events) errors.push('expected rate probe does not match the scenario');
  return errors;
}

export function selectConstraint({ requested = 'auto', requireConstraints = false, systemd = false, taskset = false } = {}) {
  if (!['auto', 'systemd', 'taskset', 'none'].includes(requested)) return { error: `unknown constraint mode ${requested}` };
  let mode = requested;
  if (mode === 'auto') mode = systemd ? 'systemd' : taskset ? 'taskset' : 'none';
  if (mode === 'systemd' && !systemd) return { error: 'systemd user-scope enforcement is unavailable' };
  if (mode === 'taskset' && !taskset) return { error: 'taskset CPU affinity is unavailable' };
  if (requireConstraints && mode !== 'systemd') return { error: 'full 2 vCPU / 2048 MiB enforcement requires an available systemd user scope' };
  const wrapper = mode === 'systemd'
    ? ['systemd-run', '--user', '--scope', '--quiet', '--collect', '-p', 'MemoryMax=2147483648', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=200%', '--']
    : mode === 'taskset' ? ['taskset', '-c', '0,1', '--'] : [];
  return {
    mode,
    wrapper,
    enforced: mode === 'systemd'
      ? { vcpu: 2, memory_mib: 2048, cpu: 'CPUQuota=200% in an owned user scope', memory: 'MemoryMax=2147483648 MemorySwapMax=0 in the same scope' }
      : mode === 'taskset'
        ? { vcpu: 2, memory_mib: null, cpu: 'taskset -c 0,1', memory: 'measured only' }
        : { vcpu: null, memory_mib: null, cpu: 'unconstrained', memory: 'unconstrained' },
  };
}

export function validateObservation(observation, scenario, expected) {
  const errors = [];
  if (!observation || observation.schema_version !== 1 || observation.task !== 'C28') errors.push('observation identity is invalid');
  if (!/^sha256:[a-f0-9]{64}$/.test(observation?.source_identity ?? '')) errors.push('source identity is missing');
  if (!observation?.environment?.os || !observation?.environment?.go || !observation?.environment?.engine_sha256) errors.push('environment identity is incomplete');
  if (!observation?.constraints?.mode) errors.push('constraint mode is missing');
  if (!Array.isArray(observation?.fixtures) || observation.fixtures.length !== 3 || observation.fixtures.some(item => !/^[a-f0-9]{64}$/.test(item?.sha256 ?? ''))) errors.push('fixture identities are incomplete');
  if (!Array.isArray(observation?.assertions) || observation.assertions.length === 0) errors.push('assertions are missing');
  if ((observation?.assertions ?? []).some(item => !item.passed)) errors.push('a measured assertion failed');
  if (!observation?.limits_published || typeof observation.limits_published !== 'object') errors.push('published limits are missing');
  const measured = observation?.target?.ingest?.steady?.events_per_second;
  if (!Number.isFinite(measured) || measured < (scenario?.published_capacity?.events_per_second ?? 20)) errors.push('measured steady rate does not support the published capacity');
  if ((observation?.limits_published?.sustained_events_per_second ?? 0) > measured) errors.push('published rate exceeds the measured rate');
  if (observation?.target?.ingest?.events !== expected?.target?.total_events) errors.push('measured target event count does not match the expected workload');
  if (observation?.target?.ingest?.acks !== expected?.target?.total_acks) errors.push('measured acknowledgement count does not match the expected workload');
  if (!observation?.over_limit?.rate_probe || observation.over_limit.rate_probe.completed_events >= observation.over_limit.rate_probe.planned_events) errors.push('the over-limit rate probe did not demonstrate saturation');
  return errors;
}

function sha256File(path) {
  return readFile(path).then(digest);
}

function runSync(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: repository, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 300000, ...options });
  if (result.error) throw new Error(`${command} failed: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${command} failed (${result.status}): ${(result.stderr ?? '').trim() || (result.stdout ?? '').trim()}`);
  return result.stdout;
}

function parseArgs(argv) {
  const options = { output: 'docs/evidence/performance.json', workdir: null, constraint: 'auto', requireConstraints: false, keep: false };
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === '--require-constraints') options.requireConstraints = true;
    else if (argument === '--keep') options.keep = true;
    else if (argument === '--help') options.help = true;
    else if (['--output', '--workdir', '--constraint'].includes(argument)) {
      const value = argv[++index];
      if (!value) throw new Error(`${argument} requires a value`);
      options[argument.slice(2)] = value;
    } else throw new Error(`unknown option: ${argument}`);
  }
  if (!['auto', 'systemd', 'taskset', 'none'].includes(options.constraint)) throw new Error('unknown constraint mode');
  return options;
}

function insideRepository(path) {
  const difference = relative(repository, resolve(repository, path));
  return difference === '' || (!difference.startsWith('..') && !isAbsolute(difference));
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function directoryBytes(directory) {
  let bytes = 0;
  let files = 0;
  async function visit(path) {
    let entries;
    try {
      entries = await readdir(path, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const entry of entries) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) await visit(full);
      else if (entry.isFile()) {
        bytes += (await stat(full)).size;
        files++;
      }
    }
  }
  await visit(directory);
  return { bytes, files };
}

async function directoryDigest(directory) {
  const entries = [];
  async function visit(path) {
    let children;
    try {
      children = await readdir(path, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const child of children) {
      const full = join(path, child.name);
      if (child.isDirectory()) await visit(full);
      else if (child.isFile()) entries.push([relative(directory, full), await sha256File(full)]);
    }
  }
  await visit(directory);
  entries.sort((left, right) => left[0].localeCompare(right[0]));
  return digest(entries.map(([name, hash]) => `${name}\0${hash}`).join('\n'));
}

async function freeDiskMiB(path) {
  const stats = await statfs(path);
  return Math.floor((stats.bavail * stats.bsize) / (1024 * 1024));
}

function readCpu(pid) {
  try {
    const raw = requireRead(`/proc/${pid}/stat`);
    const close = raw.lastIndexOf(')');
    if (close < 0) return null;
    const fields = raw.slice(close + 2).trim().split(/\s+/);
    return (Number(fields[11]) + Number(fields[12])) / clockTicks;
  } catch {
    return null;
  }
}

function requireRead(path) {
  return readFileSync(path, 'utf8');
}

function readRssMiB(pid) {
  try {
    const raw = requireRead(`/proc/${pid}/status`);
    const high = /VmHWM:\s+(\d+) kB/.exec(raw);
    const resident = /VmRSS:\s+(\d+) kB/.exec(raw);
    const kib = Number(high?.[1] ?? resident?.[1] ?? 0);
    return kib / 1024;
  } catch {
    return null;
  }
}

function startSampler(pids) {
  let peakRss = 0;
  let lastCpu = 0;
  const read = () => {
    let rss = 0;
    let cpu = 0;
    for (const pid of pids.filter(Boolean)) {
      rss += readRssMiB(pid) ?? 0;
      cpu += readCpu(pid) ?? 0;
    }
    peakRss = Math.max(peakRss, rss);
    if (cpu > lastCpu) lastCpu = cpu;
  };
  read();
  const timer = setInterval(read, 25);
  return {
    stop() {
      clearInterval(timer);
      read();
      return { peak_rss_mib: peakRss, cpu_seconds: lastCpu };
    },
  };
}

function runSampled(command, args, { cwd = repository, env = {}, timeoutMs = 900000 } = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const sampler = startSampler([child.pid]);
    const started = performance.now();
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`command timed out after ${timeoutMs}ms: ${command}`));
    }, timeoutMs);
    child.once('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      const sample = sampler.stop();
      const result = {
        code,
        signal,
        stdout,
        stderr,
        wall_ms: performance.now() - started,
        cpu_seconds: sample.cpu_seconds,
        peak_rss_mib: sample.peak_rss_mib,
      };
      if (code !== 0) {
        reject(new Error(`${command} exited ${code ?? signal}: ${stderr.trim() || stdout.trim()}`));
        return;
      }
      resolvePromise(result);
    });
  });
}

async function pathExists(path) {
  try {
    await access(path, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function detectConstraints(requested, requireConstraints) {
  const systemd = spawnSync('systemd-run', ['--user', '--scope', '--quiet', '--collect', '-p', 'MemoryMax=2147483648', '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=200%', '--', 'true'], { encoding: 'utf8', timeout: 10000 }).status === 0;
  const taskset = spawnSync('taskset', ['-c', '0,1', 'true'], { encoding: 'utf8', timeout: 10000 }).status === 0;
  const selection = selectConstraint({ requested, requireConstraints, systemd, taskset });
  if (selection.error) throw new Error(selection.error);
  return { ...selection, systemd_available: systemd, taskset_available: taskset };
}

function wrappedCommand(constraint, command, args) {
  return constraint.wrapper.length ? [constraint.wrapper[0], [...constraint.wrapper.slice(1), command, ...args]] : [command, args];
}

function wait(ms) {
  return new Promise(resolvePromise => setTimeout(resolvePromise, ms));
}

async function waitHttp(port, path, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(2000) });
      if (response.ok) return response;
    } catch {}
    await wait(100);
  }
  throw new Error(`local stack did not answer ${path}`);
}

async function startStack(constraint) {
  const [command, args] = wrappedCommand(constraint, process.execPath, ['scripts/start-local.mjs', '--port', '0']);
  const child = spawn(command, args, { cwd: repository, env: { ...process.env, GOMAXPROCS: '2' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let buffer = '';
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const info = await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`local stack startup timed out: ${stderr}`)), 20000);
    child.stdout.on('data', chunk => {
      buffer += chunk;
      if (!buffer.includes('\n')) return;
      clearTimeout(timer);
      try {
        resolvePromise(JSON.parse(buffer.split('\n')[0]));
      } catch (error) {
        reject(error);
      }
    });
    child.once('exit', code => {
      clearTimeout(timer);
      reject(new Error(`local stack exited before readiness (${code}): ${stderr}`));
    });
  });
  const started = performance.now();
  await waitHttp(info.port, '/readyz');
  return {
    child,
    info,
    port: info.port,
    startup_ms: performance.now() - started,
    close: async () => {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
      await once(child, 'exit');
      clearTimeout(timer);
    },
  };
}

function request(port, path) {
  return new Promise((resolvePromise, reject) => {
    const started = performance.now();
    const call = httpRequest({ host: '127.0.0.1', port, path, method: 'GET', agent: false }, response => {
      response.resume();
      response.on('end', () => resolvePromise({ status: response.statusCode, ms: performance.now() - started }));
      response.on('error', reject);
    });
    call.on('error', reject);
    call.end();
  });
}

async function runHttpLevel(port, endpoints, concurrency, requests) {
  let next = 0;
  const latencies = [];
  const statuses = {};
  let errors = 0;
  const started = performance.now();
  async function worker() {
    while (true) {
      const index = next++;
      if (index >= requests) return;
      const endpoint = endpoints[index % endpoints.length];
      try {
        const result = await request(port, endpoint);
        latencies.push(result.ms);
        statuses[result.status] = (statuses[result.status] ?? 0) + 1;
        if (result.status !== 200) errors++;
      } catch {
        errors++;
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const elapsed = performance.now() - started;
  return {
    concurrency,
    requests,
    completed: latencies.length,
    errors,
    statuses,
    elapsed_ms: elapsed,
    requests_per_second: elapsed > 0 ? latencies.length / (elapsed / 1000) : 0,
    latency: summarizeLatency(latencies),
  };
}

async function measureHttp(constraint, scenario, workdir, httpLevel) {
  const target = scenario.target.http;
  const levels = [...target.levels, target.saturation_level, httpLevel].filter((value, index, all) => value > 0 && all.indexOf(value) === index);
  let stack = await startStack(constraint);
  const sampler = startSampler([stack.child.pid, stack.info.enginePid]);
  try {
    for (let index = 0; index < target.warmup_requests; index++) await request(stack.port, target.endpoints[index % target.endpoints.length]);
    const results = [];
    for (const concurrency of levels) {
      const requests = concurrency === target.saturation_level || concurrency === httpLevel ? scenario.over_limit.http_saturation.requests : target.requests_per_level;
      results.push(await runHttpLevel(stack.port, target.endpoints, concurrency, requests));
    }
    const aborted = [];
    for (let index = 0; index < 10; index++) {
      const controller = new AbortController();
      const pending = fetch(`http://127.0.0.1:${stack.port}/api/engine/health`, { signal: controller.signal }).catch(() => {});
      controller.abort();
      await pending;
      aborted.push(true);
    }
    const healthy = await waitHttp(stack.port, '/readyz', 20);
    const sample = sampler.stop();
    await stack.close();
    const restarted = await startStack(constraint);
    const restartHealthy = await waitHttp(restarted.port, '/readyz', 20);
    const restartStartup = restarted.startup_ms;
    await restarted.close();
    return {
      levels: results,
      cancellation: { aborted: aborted.length, healthy_after: healthy.ok, restart_ready: restartHealthy.ok },
      stack: { peak_rss_mib: sample.peak_rss_mib, cpu_seconds: sample.cpu_seconds, startup_ms: stack.startup_ms, restart_startup_ms: restartStartup },
    };
  } finally {
    sampler.stop();
    await stack.close();
  }
}

async function measureProjection(constraint, scenario, workdir) {
  const target = scenario.target;
  const segmentsDirectory = join(workdir, 'segments');
  const storageDirectory = join(workdir, 'state');
  const beforeManifest = await sha256File(join(storageDirectory, 'manifest.json'));
  const beforeSegments = await directoryDigest(segmentsDirectory);
  const args = [
    '--project-segments',
    `--storage-dir=${storageDirectory}`,
    `--segments-dir=${segmentsDirectory}`,
    `--storage-max-operations=${target.storage_limits.max_operations}`,
    `--storage-max-bytes=${target.storage_limits.max_bytes}`,
    `--storage-max-manifest-bytes=${target.storage_limits.max_manifest_bytes}`,
    `--segments-max-count=${target.segment_limits.max_segments}`,
    `--segments-max-records=${target.segment_limits.max_records_per_segment}`,
    `--segments-max-bytes=${target.segment_limits.max_bytes_per_segment}`,
    `--alerts-rate-limit=${target.alerts.rate_limit}`,
    `--alerts-window-seconds=${target.alerts.window_seconds}`,
  ];
  const [command, commandArgs] = wrappedCommand(constraint, join(repository, 'dist/engine/miragemesh'), args);
  const result = await runSampled(command, commandArgs, { env: { GOMAXPROCS: '2' }, timeoutMs: 900000 });
  const outcome = JSON.parse(result.stdout.trim().split('\n').filter(Boolean).pop());
  const afterManifest = await sha256File(join(storageDirectory, 'manifest.json'));
  const afterSegments = await directoryDigest(segmentsDirectory);
  const bytes = await directoryBytes(segmentsDirectory);
  return {
    outcome,
    wall_ms: result.wall_ms,
    cpu_seconds: result.cpu_seconds,
    peak_rss_mib: result.peak_rss_mib,
    storage_manifest_unchanged: beforeManifest === afterManifest,
    segments_unchanged: beforeSegments === afterSegments,
    segment_bytes: bytes.bytes,
    segment_files: bytes.files,
  };
}

async function measureWithTestBinary(constraint, testBinary, phase, directory, resultPath) {
  const [command, args] = wrappedCommand(constraint, testBinary, ['-test.run', '^TestC28TargetWorkloadMeasurement$', '-test.v', '-test.count=1']);
  const result = await runSampled(command, args, {
    cwd: join(repository, 'tests'),
    env: { ...goEnvironment, GOMAXPROCS: '2', C28_MEASURE: '1', C28_PHASE: phase, C28_WORKLOAD_DIR: directory, C28_RESULT: resultPath },
    timeoutMs: 900000,
  });
  return { ...result, document: await readJson(resultPath) };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log('Usage: node scripts/benchmark-local.mjs [--output path] [--workdir path] [--constraint auto|systemd|taskset|none] [--require-constraints] [--keep]');
    return;
  }
  if (platform() !== 'linux') throw new Error('C28 measures the supported Linux amd64 local profile only.');
  if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error(`Node 24 is required, found ${process.version}`);
  if (!insideRepository(options.output) || !insideRepository(options.workdir ?? 'dist/bench')) throw new Error('C28 output and work directories must stay inside the repository.');

  const scenario = await readJson(join(repository, scenarioPath));
  const fixtures = {
    positive: await readJson(join(repository, fixturePaths[0])),
    negative: await readJson(join(repository, fixturePaths[1])),
    expected: await readJson(join(repository, fixturePaths[2])),
  };
  const fixtureErrors = validateWorkload(scenario, fixtures);
  if (fixtureErrors.length) throw new Error(`malformed C28 workload: ${fixtureErrors.join('; ')}`);
  const expected = fixtures.expected;
  const freeDisk = await freeDiskMiB(repository);
  if (freeDisk < scenario.hardware_target.free_disk_mib) throw new Error(`C28 requires ${scenario.hardware_target.free_disk_mib} MiB free disk; found ${freeDisk} MiB`);

  const goVersion = runSync('go', ['version'], { env: goEnvironment }).trim();
  if (!goVersion.includes('go1.27.2')) throw new Error(`unexpected Go toolchain: ${goVersion}`);
  runSync('python3', ['--version']);

  const engineBinary = join(repository, 'dist/engine/miragemesh');
  if (!(await pathExists(engineBinary))) buildEngine(repository);
  if (!(await pathExists(join(repository, 'dist/web/index.html')))) throw new Error('dist/web is missing; run npm run build before benchmarking.');
  const engineVersion = JSON.parse(runSync(engineBinary, ['--version'])).version;
  const engineSHA256 = await sha256File(engineBinary);

  const workdir = options.workdir ? resolve(repository, options.workdir) : join(repository, 'dist/bench', `c28-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  if (await pathExists(workdir)) {
    const entries = await readdir(workdir);
    if (entries.length) throw new Error(`C28 work directory is not empty: ${workdir}`);
  }
  await mkdir(workdir, { recursive: true, mode: 0o700 });

  const constraint = await detectConstraints(options.constraint, options.requireConstraints);
  const testBinary = join(workdir, 'c28.test');
  const buildStarted = performance.now();
  runSync('go', ['test', '-c', '-o', testBinary, './tests'], { env: goEnvironment, timeout: 300000 });
  const buildMs = performance.now() - buildStarted;

  const sourceIdentity = runSync('python3', ['scripts/source_identity.py']).trim();
  const baseCommit = runSync('git', ['rev-parse', 'HEAD']).trim();
  const workingTree = runSync('git', ['status', '--porcelain']).trim();
  const fixtureIdentity = [];
  for (const path of fixturePaths) {
    const fixture = await readJson(join(repository, path));
    fixtureIdentity.push({ path, sha256: await sha256File(join(repository, path)), license: fixture.license, provenance: fixture.provenance });
  }
  const scenarioSHA256 = await sha256File(join(repository, scenarioPath));

  const targetDirectory = join(workdir, 'target');
  const targetRun = await measureWithTestBinary(constraint, testBinary, 'target', targetDirectory, join(workdir, 'target.json'));
  const target = targetRun.document;
  const targetBytes = await directoryBytes(targetDirectory);
  const targetManifest = await sha256File(join(targetDirectory, 'state/manifest.json'));

  const firstProjection = await measureProjection(constraint, scenario, targetDirectory);
  const restartRun = await measureWithTestBinary(constraint, testBinary, 'restart', targetDirectory, join(workdir, 'restart.json'));
  const restart = restartRun.document;
  const restartManifest = await sha256File(join(targetDirectory, 'state/manifest.json'));
  const secondProjection = await measureProjection(constraint, scenario, targetDirectory);

  const overLimitRun = await measureWithTestBinary(constraint, testBinary, 'over-limit', join(workdir, 'over-limit'), join(workdir, 'over-limit.json'));
  const overLimit = overLimitRun.document;
  const http = await measureHttp(constraint, scenario, workdir, scenario.over_limit.http_saturation.concurrency);

  const steady = target.steady ?? {};
  const assertions = [];
  const check = (name, passed, observed, limit) => assertions.push({ name, passed, observed, limit });
  check('steady_completed', steady.completed_events === expected.target.steady_events, steady.completed_events, expected.target.steady_events);
  check('steady_rate', steady.events_per_second >= scenario.published_capacity.events_per_second * 0.95, steady.events_per_second, scenario.published_capacity.events_per_second);
  check('target_events', target.events === expected.target.total_events, target.events, expected.target.total_events);
  check('target_acks', target.acks === expected.target.total_acks, target.acks, expected.target.total_acks);
  check('target_configs', target.configs === expected.target.configs, target.configs, expected.target.configs);
  check('target_revision', target.applied_revision === expected.target.applied_revision, target.applied_revision, expected.target.applied_revision);
  check('rate_probe_saturated', overLimit.rate_probe?.completed_events < overLimit.rate_probe?.planned_events && overLimit.rate_probe?.events_per_second < scenario.over_limit.rate_probe.events_per_second, overLimit.rate_probe, scenario.over_limit.rate_probe);
  check('batch_probe', target.batch_probe?.matched === true && target.batch_probe?.observed === expected.over_limit.batch_probe.error, target.batch_probe?.observed, expected.over_limit.batch_probe.error);
  check('projection_status', firstProjection.outcome.status === 'projected', firstProjection.outcome.status, 'projected');
  check('projection_appended', firstProjection.outcome.appended === expected.target.appended, firstProjection.outcome.appended, expected.target.appended);
  check('projection_skipped', firstProjection.outcome.skipped === expected.target.skipped_non_events, firstProjection.outcome.skipped, expected.target.skipped_non_events);
  check('projection_first_index', firstProjection.outcome.index_records === expected.target.index_records_first_projection, firstProjection.outcome.index_records, expected.target.index_records_first_projection);
  check('projection_segments', firstProjection.outcome.segments === expected.target.segments, firstProjection.outcome.segments, expected.target.segments);
  check('projection_complete', firstProjection.outcome.index_complete === true, firstProjection.outcome.index_complete, true);
  check('projection_deduplicated', firstProjection.outcome.deduplicated === true, firstProjection.outcome.deduplicated, true);
  check('projection_storage_unchanged', firstProjection.storage_manifest_unchanged === true, firstProjection.storage_manifest_unchanged, true);
  check('restart_events', restart.restart?.events === target.events, restart.restart?.events, target.events);
  check('restart_acks', restart.restart?.acks === target.acks, restart.restart?.acks, target.acks);
  check('restart_revision', restart.restart?.applied_revision === target.applied_revision, restart.restart?.applied_revision, target.applied_revision);
  check('restart_manifest', restart.restart?.manifest_sha256 === target.manifest_sha256, restart.restart?.manifest_sha256, target.manifest_sha256);
  check('restart_manifest_unchanged', restartManifest === targetManifest, restartManifest === targetManifest, true);
  check('second_projection_appended', secondProjection.outcome.appended === expected.target.appended_after_restart, secondProjection.outcome.appended, expected.target.appended_after_restart);
  check('second_projection_already', secondProjection.outcome.already_projected === expected.target.already_projected_after_restart, secondProjection.outcome.already_projected, expected.target.already_projected_after_restart);
  check('second_projection_index', secondProjection.outcome.index_records === expected.target.index_records_after_restart, secondProjection.outcome.index_records, expected.target.index_records_after_restart);
  check('second_projection_sensors', secondProjection.outcome.index_sensors === expected.target.index_sensors_after_restart, secondProjection.outcome.index_sensors, expected.target.index_sensors_after_restart);
  check('second_projection_segments_unchanged', secondProjection.segments_unchanged === true, secondProjection.segments_unchanged, true);
  check('cancellation', overLimit.cancellation?.matched === true && overLimit.cancellation?.acks_before_retry === 0, overLimit.cancellation, expected.cancellation);
  check('cancellation_retry', overLimit.cancellation?.retry_events === expected.cancellation.retry_events && overLimit.cancellation?.retry_acks === expected.cancellation.retry_acks, overLimit.cancellation?.retry_events, expected.cancellation.retry_events);
  check('storage_quota', overLimit.storage_probe?.matched === true && overLimit.storage_probe?.accepted >= expected.over_limit.storage_probe.accepted_between[0] && overLimit.storage_probe?.accepted <= expected.over_limit.storage_probe.accepted_between[1], overLimit.storage_probe, expected.over_limit.storage_probe);
  check('target_rss', targetRun.peak_rss_mib <= scenario.hardware_target.memory_mib, targetRun.peak_rss_mib, scenario.hardware_target.memory_mib);
  check('projection_rss', firstProjection.peak_rss_mib <= scenario.hardware_target.memory_mib, firstProjection.peak_rss_mib, scenario.hardware_target.memory_mib);
  check('stack_rss', http.stack.peak_rss_mib <= scenario.hardware_target.memory_mib, http.stack.peak_rss_mib, scenario.hardware_target.memory_mib);
  check('free_disk', freeDisk >= scenario.hardware_target.free_disk_mib, freeDisk, scenario.hardware_target.free_disk_mib);
  check('disk_delta', targetBytes.bytes + firstProjection.segment_bytes <= scenario.hardware_target.free_disk_mib * 1024 * 1024, targetBytes.bytes + firstProjection.segment_bytes, scenario.hardware_target.free_disk_mib * 1024 * 1024);
  const targetLevels = http.levels.filter(level => scenario.target.http.levels.includes(level.concurrency));
  check('http_target_levels', targetLevels.length === scenario.target.http.levels.length && targetLevels.every(level => level.errors === 0), targetLevels.map(level => ({ concurrency: level.concurrency, errors: level.errors, p99_ms: level.latency.p99_ms })), scenario.target.http.levels);
  check('http_saturation', http.levels.some(level => level.concurrency === scenario.over_limit.http_saturation.concurrency), http.levels.map(level => level.concurrency), scenario.over_limit.http_saturation.concurrency);
  check('http_cancellation', http.cancellation.aborted === 10 && http.cancellation.healthy_after === true, http.cancellation, { aborted: 10, healthy_after: true });
  check('stack_restart', http.cancellation.restart_ready === true, http.cancellation.restart_ready, true);

  const observation = {
    schema_version: 1,
    task: 'C28',
    status: 'measured',
    measurement_date: new Date().toISOString(),
    source_identity: sourceIdentity,
    source_identity_algorithm: 'scripts/source_identity.py: sorted tracked/untracked non-ignored paths excluding SHA256SUMS.txt and docs/evidence/',
    base_commit: baseCommit,
    working_tree_dirty: workingTree.length > 0,
    working_tree_changes: workingTree.length ? workingTree.split('\n').length : 0,
    environment: {
      os: `${platform()} ${release()}`,
      distribution: await (async () => {
        try {
          const raw = await readFile('/etc/os-release', 'utf8');
          return /^PRETTY_NAME="?([^"\n]+)"?$/m.exec(raw)?.[1] ?? 'unknown';
        } catch {
          return 'unknown';
        }
      })(),
      cpu_model: await (async () => {
        try {
          return /^model name\s*:\s*(.+)$/m.exec(await readFile('/proc/cpuinfo', 'utf8'))?.[1]?.trim() ?? 'unknown';
        } catch {
          return 'unknown';
        }
      })(),
      cpu_count: cpus().length,
      memory_mib: Math.floor(totalmem() / (1024 * 1024)),
      free_disk_mib: freeDisk,
      load_average: loadavg().map(value => Number(value.toFixed(2))),
      node: process.version,
      npm: runSync('npm', ['--version'], { env: goEnvironment }).trim(),
      go: goVersion,
      engine_version: engineVersion,
      engine_sha256: engineSHA256,
      test_binary_sha256: await sha256File(testBinary),
      test_binary_build_ms: buildMs,
    },
    constraints: {
      requested: options.constraint,
      require_constraints: options.requireConstraints,
      mode: constraint.mode,
      enforced: constraint.enforced,
      limitations: constraint.mode === 'systemd'
        ? ['The 2 vCPU/2048 MiB target is enforced with a user-scope cgroup on the measured host; it is not a capacity guarantee for other hardware.']
        : ['The 2 vCPU/2048 MiB target was not fully enforced; memory is measured only.'],
    },
    fixtures: fixtureIdentity,
    workload: {
      scenario: scenarioPath,
      scenario_sha256: scenarioSHA256,
      sensors: scenario.target.sensors,
      steady: scenario.target.steady_phase,
      backlog: scenario.target.backlog_phase,
      total_events: expected.target.total_events,
      storage_limits: scenario.target.storage_limits,
      segment_limits: scenario.target.segment_limits,
    },
    target: {
      ingest: {
        steady,
        backlog: target.backlog,
        events: target.events,
        acks: target.acks,
        configs: target.configs,
        ingest_calls: target.ingest_calls,
        applied_revision: target.applied_revision,
        wall_ms: targetRun.wall_ms,
        cpu_seconds: targetRun.cpu_seconds,
        peak_rss_mib: targetRun.peak_rss_mib,
        disk_bytes: targetBytes.bytes,
        disk_files: targetBytes.files,
        disk_bytes_per_event: target.events ? targetBytes.bytes / target.events : 0,
        manifest_sha256: target.manifest_sha256,
      },
      projection: {
        outcome: summarizeProjection(firstProjection.outcome),
        wall_ms: firstProjection.wall_ms,
        cpu_seconds: firstProjection.cpu_seconds,
        peak_rss_mib: firstProjection.peak_rss_mib,
        storage_manifest_unchanged: firstProjection.storage_manifest_unchanged,
        segment_bytes: firstProjection.segment_bytes,
        segment_files: firstProjection.segment_files,
      },
      restart: {
        document: restart,
        wall_ms: restartRun.wall_ms,
        cpu_seconds: restartRun.cpu_seconds,
        peak_rss_mib: restartRun.peak_rss_mib,
        manifest_unchanged: restartManifest === targetManifest,
      },
      projection_after_restart: {
        outcome: summarizeProjection(secondProjection.outcome),
        wall_ms: secondProjection.wall_ms,
        cpu_seconds: secondProjection.cpu_seconds,
        peak_rss_mib: secondProjection.peak_rss_mib,
        segments_unchanged: secondProjection.segments_unchanged,
      },
      http,
    },
    over_limit: {
      rate_probe: overLimit.rate_probe,
      batch_probe: target.batch_probe,
      storage_probe: overLimit.storage_probe,
      cancellation: overLimit.cancellation,
      wall_ms: overLimitRun.wall_ms,
      cpu_seconds: overLimitRun.cpu_seconds,
      peak_rss_mib: overLimitRun.peak_rss_mib,
    },
    assertions,
    limits_published: {
      sustained_events_per_second: Math.floor((steady.events_per_second ?? 0) * 100) / 100,
      steady_window_seconds: scenario.target.steady_phase.duration_seconds,
      sensors: scenario.target.sensors,
      accepted_batch_size: scenario.target.backlog_phase.batch_size,
      max_applied_batch_limit: scenario.target.config.settings.event_batch_limit,
      peak_rss_mib: Math.max(targetRun.peak_rss_mib, firstProjection.peak_rss_mib, http.stack.peak_rss_mib),
      target_state_bytes: targetBytes.bytes,
      segment_bytes: firstProjection.segment_bytes,
      free_disk_mib_at_start: freeDisk,
      http: http.levels.map(level => ({ concurrency: level.concurrency, p50_ms: level.latency.p50_ms, p95_ms: level.latency.p95_ms, p99_ms: level.latency.p99_ms, errors: level.errors })),
      saturation: {
        concurrency: scenario.over_limit.http_saturation.concurrency,
        p99_ms: http.levels.find(level => level.concurrency === scenario.over_limit.http_saturation.concurrency)?.latency.p99_ms ?? null,
        errors: http.levels.find(level => level.concurrency === scenario.over_limit.http_saturation.concurrency)?.errors ?? null,
        threshold_ms: scenario.target.http.saturation_p99_ms,
      },
    },
    negatives_executed: [
      'batch over applied limit returns a typed error without a write',
      'storage quota saturates with a typed error and a readable accepted prefix',
      'cancellation returns context.Canceled with no acknowledgement before retry',
      'restart preserves counts, revision and manifest bytes',
      'second projection is idempotent and does not rewrite segments',
      'HTTP saturation sweep records latency and errors without crashing',
      'aborted HTTP requests leave the stack healthy',
      'local stack restart returns to readiness',
      'loopback-only harness guard',
    ],
    observed_limitations: [
      'Local Linux single-operator profile only; no hosted Actions or release claim.',
      'The workload is a 30-second published-capacity window plus a bounded batch backlog, not a multi-day retention or unbounded-volume claim.',
      'Browser rendering and perceived latency are not measured; C27 covers rendered correctness.',
      'The benchmark used the existing local synthetic fixtures and an ephemeral in-memory signing key; no real traffic or credentials were used.',
      'The evidence is generated on a dirty working tree because no commit was authorized for this session.',
    ],
  };

  const observationErrors = validateObservation(observation, scenario, expected);
  if (observationErrors.length) throw new Error(`C28 observation is incomplete: ${observationErrors.join('; ')}`);
  const failures = assertions.filter(assertion => !assertion.passed);
  const outputPath = resolve(repository, options.output);
  await mkdir(dirname(outputPath), { recursive: true });
  if (failures.length) {
    await writeAtomic(`${outputPath}.failed.json`, { ...observation, status: 'failed', failed_assertions: failures });
    throw new Error(`C28 assertions failed: ${failures.map(failure => `${failure.name}=${failure.observed} (want ${failure.limit})`).join('; ')}`);
  }
  await writeAtomic(outputPath, observation);
  console.log(JSON.stringify({
    status: 'passed',
    output: relative(repository, outputPath),
    source_identity: sourceIdentity,
    constraints: constraint.mode,
    target: {
      steady_events: steady.completed_events,
      steady_events_per_second: steady.events_per_second,
      events: target.events,
      acks: target.acks,
      peak_rss_mib: targetRun.peak_rss_mib,
      disk_bytes: targetBytes.bytes,
    },
    projection: { appended: firstProjection.outcome.appended, segments: firstProjection.outcome.segments, p99_ms: null },
    http: http.levels.map(level => ({ concurrency: level.concurrency, p99_ms: level.latency.p99_ms, errors: level.errors })),
    assertions: assertions.length,
  }, null, 2));
  if (!options.keep) await rm(workdir, { recursive: true, force: true });
}

async function writeAtomic(path, value) {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  await rename(temporary, path);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
