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

test('all literal UI icons and navigation icons resolve to shipped local assets', async () => {
  const { readdir, access } = await import('node:fs/promises');
  async function inspect(directory) {
    const names = new Set();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = new URL(entry.name + (entry.isDirectory() ? '/' : ''), directory);
      if (entry.isDirectory()) for (const name of await inspect(path)) names.add(name);
      else if (entry.name.endsWith('.tsx')) {
        const source = await readFile(path, 'utf8');
        for (const match of source.matchAll(/<Icon\s+name="([a-z0-9-]+)"|icon:\s*'([a-z0-9-]+)'/g)) names.add(match[1] ?? match[2]);
      }
    }
    return names;
  }
  for (const name of await inspect(new URL('apps/web/src/', root))) {
    await assert.doesNotReject(access(new URL(`apps/web/public/assets/icons/${name}.svg`, root)), name);
  }
});
