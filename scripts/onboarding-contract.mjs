import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { validateReference } from './verify-reference.mjs';

export class OnboardingError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export async function loadOnboarding(root) {
  try {
    const scenario = JSON.parse(await readFile(resolve(root, 'tests/scenarios/clone-to-value.json'), 'utf8'));
    const errors = await validateReference(root, scenario);
    const config = scenario.onboarding;
    if (errors.length || config?.schema_version !== 1 || config.independent_runs !== 2 || config.restart_cycles !== 2 || config.fixture_directory !== 'tests/fixtures/miragemesh/C36') throw new Error('Invalid versioned onboarding scenario');
    const canonicalRoot = await realpath(root);
    const fixtures = {};
    for (const name of ['positive', 'negative', 'expected-output']) {
      const path = resolve(canonicalRoot, config.fixture_directory, name + '.json');
      const canonical = await realpath(path);
      const rel = relative(canonicalRoot, canonical);
      if (isAbsolute(rel) || rel === '..' || rel.startsWith('..' + sep)) throw new Error('Unconfined fixture');
      const raw = await readFile(canonical, 'utf8');
      const data = JSON.parse(raw);
      if (data.fixture_version !== 1 || data.license !== 'Apache-2.0' || !/repository-authored synthetic/i.test(data.provenance ?? '')) throw new Error('Missing fixture version, license or synthetic provenance');
      fixtures[name === 'expected-output' ? 'expected' : name] = data;
    }
    if (!fixtures.positive.event || !fixtures.negative.event || fixtures.expected.event?.exit_code !== 0 || fixtures.expected.invalid_event?.exit_code !== 1 || fixtures.expected.invalid_event?.code !== 'INVALID_INPUT') throw new Error('Missing event outcome semantics');
    return { scenario, ...fixtures };
  } catch (error) { throw new OnboardingError('onboarding.invalid_fixture', error.message); }
}

export function runCommand(commands, stage, command, args, { cwd, timeout = 120000, env = process.env, input, expectedExit = 0, expectedStderr, log } = {}) {
  const started = new Date().toISOString();
  const before = performance.now();
  return new Promise((accept, reject) => {
    const child = execFile(command, args, { cwd, timeout, env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, killSignal: 'SIGKILL', shell: false }, async (error, stdout, stderr) => {
      const exitCode = error ? (typeof error.code === 'number' ? error.code : null) : 0;
      const row = { stage, command: [command, ...args], started_at: started, duration_ms: Math.round(performance.now() - before), exit_code: exitCode, expected_exit: expectedExit, signal: error?.signal ?? null, timed_out: Boolean(error?.killed), stdout_sha256: createHash('sha256').update(stdout ?? '').digest('hex') };
      commands.push(row);
      try {
        if (log) await log(row, stdout ?? '', stderr ?? '');
        if (error?.killed || exitCode !== expectedExit) throw new OnboardingError('onboarding.command_failed', `${stage}: exit ${exitCode ?? error?.code}, signal ${error?.signal ?? 'none'}\n${(stderr || stdout || error?.message || '').slice(-2000)}`);
        if (expectedStderr && !stderr.includes(expectedStderr)) throw new OnboardingError('onboarding.unexpected_failure', stage + ': expected error was not observed');
        accept(stdout);
      } catch (failure) { reject(failure); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}
