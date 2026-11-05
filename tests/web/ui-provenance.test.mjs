import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const root = new URL('../../', import.meta.url);

test('shipped UI assets match pinned provenance and retain upstream notices', async () => {
  const provenance = JSON.parse(await readFile(new URL('docs/design/UI_PROVENANCE.json', root), 'utf8'));
  assert.match(provenance.components.revision, /^[a-f0-9]{40}$/);
  assert.match(provenance.icons.revision, /^[a-f0-9]{40}$/);
  for (const group of [provenance.components, provenance.icons]) {
    const license = await readFile(new URL(group.license_path, root), 'utf8');
    assert.match(license, /Permission/);
  }
  for (const file of provenance.icons.files) {
    assert.ok(file.path.startsWith('apps/web/public/assets/icons/'));
    const bytes = await readFile(new URL(file.path, root));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
    assert.match(file.url, new RegExp(provenance.icons.revision));
  }
  const notice = await readFile(new URL('THIRD_PARTY_NOTICES.md', root), 'utf8');
  assert.ok(notice.includes(provenance.icons.revision));
  assert.ok(notice.includes(provenance.components.revision));
});
