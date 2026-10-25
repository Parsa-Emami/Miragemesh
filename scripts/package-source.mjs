import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { goEnvironment } from './oss-bootstrap.mjs';

export const repository = resolve(fileURLToPath(new URL('../', import.meta.url)));
export const project = 'MirageMesh';
export const repositoryUrl = 'https://github.com/Parsa-Emami/Miragemesh';
export const sourceArchivePath = version => `source/miragemesh-${version}-source.tar.gz`;

const archiveExcludedPrefixes = [
  '.cache/', '.git/', '.local-data/', 'coverage/', 'data/', 'dist/', 'docs/evidence/',
  'legacy/', 'node_modules/', 'playwright-report/', 'target/', 'test-results/', 'vendor/',
];
const archiveExcludedExact = new Set(['SHA256SUMS.txt', 'review.md']);

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export async function sha256File(path) {
  return sha256(await readFile(path));
}

export function isSafeRelativePath(name) {
  if (typeof name !== 'string' || !name || name.includes('\0') || name.includes('\n') || name.includes('\r') || name.includes('\\')) return false;
  if (isAbsolute(name)) return false;
  return !name.split('/').some(part => part === '..' || part === '');
}

export function isExcludedSourcePath(name) {
  if (archiveExcludedExact.has(name)) return true;
  if (archiveExcludedPrefixes.some(prefix => name === prefix.slice(0, -1) || name.startsWith(prefix))) return true;
  if (/^\.env(?:\.|$)/.test(name) && name !== '.env.example') return true;
  if (/\.(?:pem|key|p12|pfx)$/i.test(name) || /(?:^|\/)secrets?\//.test(name)) return true;
  return /\.sqlite(?:3)?(?:-|$)/.test(name);
}

export function git(args, options = {}) {
  const result = spawnSync('git', args, { cwd: repository, encoding: options.encoding ?? 'utf8', input: options.input, timeout: 60000, maxBuffer: 64 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`git ${args[0]} failed: ${(result.stderr || result.error?.message || '').toString().trim()}`);
  return result.stdout;
}

export async function listSourceFiles({ includeExcluded = false } = {}) {
  const names = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean);
  const unique = [...new Set(names)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  const existing = [];
  for (const name of unique) {
    if (!isSafeRelativePath(name)) throw new Error(`Unsafe source path: ${name}`);
    if (includeExcluded || !isExcludedSourcePath(name)) {
      try { if ((await stat(resolve(repository, name))).isFile()) existing.push(name); } catch { /* tracked deletion in the working tree */ }
    }
  }
  return existing;
}

export async function getSourceIdentity() {
  const names = await listSourceFiles({ includeExcluded: true });
  const digest = createHash('sha256');
  for (const name of names) {
    if (name === 'SHA256SUMS.txt' || name.startsWith('docs/evidence/')) continue;
    const target = resolve(repository, name);
    const info = await stat(target);
    if (!info.isFile()) continue;
    digest.update(Buffer.from(name + '\0'));
    digest.update(createHash('sha256').update(await readFile(target)).digest());
  }
  return 'sha256:' + digest.digest('hex');
}

export async function getSourceInfo() {
  const status = git(['status', '--porcelain=v1', '--untracked-files=normal']).trim();
  const changed = status ? status.split('\n').map(line => line.slice(2).trimStart()) : [];
  const sourceIdentity = await getSourceIdentity();
  const headCommit = git(['rev-parse', 'HEAD']).trim();
  const tree = git(['rev-parse', 'HEAD^{tree}']).trim();
  return {
    repository: repositoryUrl,
    head_commit: headCommit,
    tree,
    dirty: changed.length !== 0,
    source_identity: sourceIdentity,
    staged_snapshot: {
      clean: changed.length === 0,
      changed_paths_count: changed.length,
      changed_paths_sample: changed.slice(0, 20),
    },
  };
}

export function toolVersions() {
  const probe = (command, args, env) => {
    const result = spawnSync(command, args, { encoding: 'utf8', env, timeout: 30000 });
    return result.status === 0 ? result.stdout.trim() : null;
  };
  return {
    node: probe(process.execPath, ['--version']),
    npm: probe('npm', ['--version'], process.env),
    go: probe('go', ['version'], goEnvironment),
    podman: probe('podman', ['--version'], process.env),
  };
}

async function assertRegularSourceFile(root, name) {
  const target = resolve(root, name);
  const base = await realpath(root);
  const actual = await realpath(target);
  if (actual !== base && !actual.startsWith(base + sep)) throw new Error(`Source path escapes repository: ${name}`);
  const info = await stat(actual);
  if (!info.isFile()) throw new Error(`Source path is not a regular file: ${name}`);
  return { actual, executable: (info.mode & 0o111) !== 0 };
}

async function spawnPipeline(tar, gzip, output) {
  const errors = [];
  const tarExit = new Promise((accept, reject) => {
    tar.once('error', reject);
    tar.once('close', code => code === 0 ? accept() : reject(new Error(`tar failed (${code}): ${errors.join('')}`)));
  });
  const gzipExit = new Promise((accept, reject) => {
    gzip.once('error', reject);
    gzip.once('close', code => code === 0 ? accept() : reject(new Error(`gzip failed (${code}): ${errors.join('')}`)));
  });
  const finished = new Promise((accept, reject) => {
    output.once('error', reject);
    output.once('finish', accept);
  });
  tar.stderr.on('data', chunk => { if (errors.length < 4096) errors.push(chunk.toString('utf8')); });
  gzip.stderr.on('data', chunk => { if (errors.length < 4096) errors.push(chunk.toString('utf8')); });
  tar.stdout.pipe(gzip.stdin);
  gzip.stdout.pipe(output);
  await Promise.all([tarExit, gzipExit, finished]);
}

export async function buildSourceArchive({ version, output }) {
  const files = await listSourceFiles();
  const staging = await mkdtemp(join(tmpdir(), 'miragemesh-source-'));
  const folder = `miragemesh-${version}`;
  try {
    const destination = join(staging, folder);
    for (const name of files) {
      const { actual, executable } = await assertRegularSourceFile(repository, name);
      const target = join(destination, ...name.split('/'));
      await mkdir(dirname(target), { recursive: true });
      await copyFile(actual, target);
      await chmod(target, executable ? 0o755 : 0o644);
    }
    const directories = new Set([destination]);
    for (const name of files) {
      let current = dirname(join(destination, ...name.split('/')));
      while (current.startsWith(destination) && !directories.has(current)) {
        directories.add(current);
        current = dirname(current);
      }
    }
    for (const directory of directories) await chmod(directory, 0o755);
    await mkdir(dirname(output), { recursive: true });
    const tar = spawn('tar', ['-C', staging, '--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner', '--format=gnu', '-cf', '-', folder], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, LC_ALL: 'C', TZ: 'UTC' } });
    const gzip = spawn('gzip', ['-n', '-9', '-c'], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, LC_ALL: 'C', TZ: 'UTC' } });
    await spawnPipeline(tar, gzip, createWriteStream(output, { mode: 0o644 }));
    return { archive: output, sha256: await sha256File(output), files: files.length, prefix: folder + '/', version };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

export async function listArchive(path) {
  // GNU tar reads "D:..." as a remote host on Windows. A relative archive
  // name with an explicit cwd is portable and adds no network behavior.
  const result = spawnSync('tar', ['-tzf', basename(path)], { cwd: dirname(path), encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) throw new Error('Source archive is unreadable.');
  return result.stdout.split('\n').filter(Boolean);
}

export async function listDirectoryFiles(root) {
  const files = [];
  async function walk(directory, prefix = '') {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`Artifact contains a symbolic link: ${name}`);
      if (entry.isDirectory()) await walk(join(directory, entry.name), name);
      else if (entry.isFile()) files.push(name);
      else throw new Error(`Artifact contains an unsupported entry: ${name}`);
    }
  }
  await walk(root);
  return files;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const packageJson = JSON.parse(await readFile(join(repository, 'package.json'), 'utf8'));
    const output = resolve(repository, process.argv[2] ?? 'dist/source.tar.gz');
    const result = await buildSourceArchive({ version: packageJson.version, output });
    console.log(JSON.stringify({ status: 'ok', ...result, source: await getSourceInfo() }));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
