import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('C40 publication refuses a dirty source, wrong repository and an unapproved version', async () => {
  const { validatePublication } = await import('../../scripts/publication-contract.mjs');
  const plan = JSON.parse(await readFile(new URL('../../docs/release/RELEASE_MANIFEST.json', import.meta.url), 'utf8'));
  const source = { clean: true, repository: 'Parsa-Emami/Miragemesh', commit: 'a'.repeat(40), version: '0.0.1' };
  assert.equal(validatePublication(plan, source).tag, 'v0.0.1');
  for (const patch of [{ clean: false }, { repository: 'other/project' }, { commit: 'main' }, { version: '9.9.9' }]) assert.throws(() => validatePublication(plan, { ...source, ...patch }));
  for (const patch of [{ publication_authorized: false }, { tag: 'main' }, { version: 'latest' }, { platform: 'windows-amd64' }]) assert.throws(() => validatePublication({ ...plan, ...patch }, source));
});
