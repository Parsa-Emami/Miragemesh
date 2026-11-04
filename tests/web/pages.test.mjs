import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRuntimeConfig } from '../../apps/web/src/lib/runtime-config.mjs';

const local = { projectId: 'miragemesh', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

test('C40 static publication is explicit and never enables engine integration', () => {
  assert.equal(validateRuntimeConfig({ ...local, deployment: 'static-public' }, 'miragemesh').deployment, 'static-public');
  assert.equal(validateRuntimeConfig(local, 'miragemesh').engineEnabled, false);
  for (const deployment of ['remote', '', true, null]) assert.throws(() => validateRuntimeConfig({ ...local, deployment }, 'miragemesh'));
  assert.throws(() => validateRuntimeConfig({ ...local, deployment: 'static-public', engineEnabled: true }, 'miragemesh'));
});
