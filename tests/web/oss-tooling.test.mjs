import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setup, supportedNode } from '../../scripts/oss-bootstrap.mjs';
import { validate } from '../../scripts/roadmap.mjs';
test('setup validates toolchain/options and stops at the first failed install', () => {
  assert.equal(supportedNode('v24.19.0'), true); assert.equal(supportedNode('v25.1.0'), false);
  assert.throws(() => setup(['--unknown']), /options/);
  const prior = process.env.npm_execpath; process.env.npm_execpath ??= 'test-npm';
  let calls = 0; assert.throws(() => setup([], () => { calls++; return { status: 1 }; }), /failed/); assert.equal(calls, 1);
  assert.equal(setup(['--check'], () => { throw new Error('must not execute'); }).executed, false);
  if (prior === undefined) delete process.env.npm_execpath; else process.env.npm_execpath = prior;
});
test('setup rejects missing tools, wrong pins and a non-rootless provider before building', () => {
  const prior = process.env.npm_execpath; process.env.npm_execpath ??= 'test-npm';
  try {
    for (const broken of ['go', 'podman-version', 'podman-rootless']) {
      let build = false;
      const run = (command, args) => {
        if (command === 'go') return { status: broken === 'go' ? 127 : 0, stdout: 'go version go1.27.2 linux/amd64\n' };
        if (command === 'podman') return { status: 0, stdout: args[0] === '--version' ? (broken === 'podman-version' ? 'podman version 1.0.0' : 'podman version 4.9.3') : (broken === 'podman-rootless' ? 'false' : 'true') };
        build = true; return { status: 0 };
      };
      assert.throws(() => setup([], run), /Go|Podman/);
      assert.equal(build, false);
    }
    let calls = 0;
    assert.throws(() => setup([], command => {
      calls++;
      if (command === 'go') return { status: 0, stdout: 'go version go1.27.2 linux/amd64' };
      if (command === 'podman') return { status: 0, stdout: calls === 2 ? 'podman version 4.9.3' : 'true' };
      return { status: 1 };
    }), /failed/);
    assert.equal(calls, 4, 'failed installation must prevent build');
  } finally { if (prior === undefined) delete process.env.npm_execpath; else process.env.npm_execpath = prior; }
});
test('roadmap rejects absent resources, escaping paths and unproved completion', async () => {
  const read = async path => JSON.parse(await readFile(new URL('../../' + path, import.meta.url), 'utf8'));
  const values = await Promise.all(['plans/roadmap.json', 'plans/progress.json', 'plans/requirements.json', 'plans/release-gates.json'].map(read));
  assert.deepEqual(validate(...values), []);
  const missing = structuredClone(values); delete missing[0].commits[6].resources.fixture;
  assert.ok(validate(...missing).some(e => e.includes('resources')));
  const unsafe = structuredClone(values); unsafe[0].commits[6].deliverables.push('../escape'); assert.ok(validate(...unsafe).some(e => e.includes('unsafe')));
  const circular = structuredClone(values); circular[0].commits[0].verification_commands[1].introduced_by = 'C06'; assert.ok(validate(...circular).some(e => e.includes('future task')));
  const unsafeFixture = structuredClone(values); unsafeFixture[0].commits[6].resources.fixture.path = '../escape'; assert.ok(validate(...unsafeFixture).some(e => e.includes('unsafe')));
  const pending = values[1].commits.findIndex(t => t.status !== 'verified');
  assert.ok(pending >= 0, 'a pending unverified task must exist while the roadmap is incomplete');
  const fake = structuredClone(values); fake[1].commits[pending].status = 'verified'; assert.ok(validate(...fake).some(e => e.includes('unproved')));
});
