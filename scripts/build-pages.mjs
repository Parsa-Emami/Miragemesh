import { spawnSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
for (const args of [['scripts/generate-web-data.mjs'], ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], ['node_modules/vite/bin/vite.js', 'build', '--config', 'apps/web/vite.config.ts', '--mode', 'pages']]) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit', timeout: 120000 });
  if (result.error || result.status !== 0) throw new Error('Pages build failed.');
}
const output = new URL('../dist/pages/', import.meta.url);
const config = JSON.parse(await readFile(new URL('runtime-config.json', output), 'utf8'));
await writeFile(new URL('runtime-config.json', output), JSON.stringify({ ...config, deployment: 'static-public' }, null, 2) + '\n');
const manifest = JSON.parse(await readFile(new URL('manifest.webmanifest', output), 'utf8'));
await writeFile(new URL('manifest.webmanifest', output), JSON.stringify({ ...manifest, id: './', start_url: './', scope: './', icons: manifest.icons.map(icon => ({ ...icon, src: './icon.svg' })) }, null, 2) + '\n');
const index = await readFile(new URL('index.html', output), 'utf8');
await writeFile(new URL('index.html', output), index.replace('noindex,nofollow', 'index,follow'));
await writeFile(new URL('robots.txt', output), 'User-agent: *\nAllow: /\n');
await writeFile(new URL('.nojekyll', output), '');
console.log('Built public static workspace at /Miragemesh/; engine integration remains disabled.');
