import test from 'node:test';
import assert from 'node:assert/strict';
import { installRelease, upgradeRelease } from '../../scripts/install-release.mjs';

test('C37 release APIs reject missing options with a typed usage error', async () => {
  for (const action of [installRelease, upgradeRelease]) {
    for (const options of [{}, null, { prefix: '/tmp/c37-unused', trustedKey: 'missing.pub' }, { prefix: '/tmp/c37-unused', trustedKey: 'missing.pub', now: 'invalid' }]) await assert.rejects(action(options), { code: 'usage' });
  }
});
