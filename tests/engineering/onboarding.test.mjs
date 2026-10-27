import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const api = await import('../../scripts/onboarding-contract.mjs').catch(() => ({}));

test('C36 loads the versioned scenario and licensed sensor-event outcomes', async () => {
  assert.equal(typeof api.loadOnboarding, 'function', 'C36 onboarding contract must exist');
  const fixtures = await api.loadOnboarding(root);
  assert.equal(fixtures.positive.event.sensor_id, 'onboarding-01');
  assert.equal(fixtures.expected.event.result.valid, true);
});

test('C36 refuses missing, unlicensed, unsupported and malformed fixtures', async t => {
  assert.equal(typeof api.loadOnboarding, 'function');
  for (const change of ['missing', 'license', 'version', 'json', 'escape']) {
    await t.test(change, async () => {
      const directory = await mkdtemp(join(tmpdir(), 'onboarding-fixture-'));
      try {
        await cp(join(root, 'tests'), join(directory, 'tests'), { recursive: true });
        const path = join(directory, 'tests/fixtures/miragemesh/C36/positive.json');
        if (change === 'missing') await rm(path);
        else if (change === 'escape') {
          const scenarioPath = join(directory, 'tests/scenarios/clone-to-value.json');
          const scenario = JSON.parse(await readFile(scenarioPath, 'utf8'));
          scenario.onboarding.fixture_directory = '../outside';
          await writeFile(scenarioPath, JSON.stringify(scenario));
        } else {
          const data = JSON.parse(await readFile(path, 'utf8'));
          if (change === 'license') data.license = 'unknown';
          if (change === 'version') data.fixture_version = 99;
          await writeFile(path, change === 'json' ? '{' : JSON.stringify(data));
        }
        await assert.rejects(api.loadOnboarding(directory), { code: 'onboarding.invalid_fixture' });
      } finally { await rm(directory, { recursive: true, force: true }); }
    });
  }
});

test('C36 command journal records real exits and refuses failed or timed-out commands', async () => {
  assert.equal(typeof api.runCommand, 'function');
  const commands = [];
  const output = await api.runCommand(commands, 'node-version', process.execPath, ['--version'], { cwd: root });
  assert.equal(output.trim(), process.version);
  assert.equal(commands[0].exit_code, 0);
  assert.ok(commands[0].duration_ms >= 0);
  await assert.rejects(api.runCommand(commands, 'failure', process.execPath, ['-e', 'process.exit(7)'], { cwd: root }), { code: 'onboarding.command_failed' });
  assert.equal(commands[1].exit_code, 7);
  await assert.rejects(api.runCommand([], 'wrong-failure', process.execPath, ['-e', 'process.exit(1)'], { cwd: root, expectedExit: 1, expectedStderr: 'required prerequisite failed' }), { code: 'onboarding.unexpected_failure' });
  await assert.rejects(api.runCommand(commands, 'timeout', process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { cwd: root, timeout: 100 }), { code: 'onboarding.command_failed' });
  assert.equal(commands[2].timed_out, true);
  assert.notEqual(commands[2].exit_code, 0);
});
