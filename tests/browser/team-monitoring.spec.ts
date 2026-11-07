import { expect, test } from '@playwright/test';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type AddressInfo, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

async function ports(count: number) {
  const servers: Server[] = [];
  try {
    for (let i = 0; i < count; i++) {
      const server = createServer().listen(0, '127.0.0.1');
      servers.push(server);
      await once(server, 'listening');
    }
    return servers.map(server => (server.address() as AddressInfo).port);
  } finally {
    await Promise.all(servers.map(server => new Promise<void>(done => server.close(() => done()))));
  }
}

async function stop(child: ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  const kill = setTimeout(() => child.kill('SIGKILL'), 6000);
  try {
    await exited;
  } finally {
    clearTimeout(kill);
  }
}

test('an analyst can inspect sensor evidence and record an attributable decision on mobile', async ({ browser }) => {
  const temporary = await mkdtemp(join(tmpdir(), 'miragemesh-browser-'));
  const processes: ChildProcess[] = [];
  try {
    const [collector, workspace, sensor, health] = await ports(4);
    const output = execFileSync('bash', ['scripts/monitor-lab.sh'], {
      encoding: 'utf8',
      env: {
        ...process.env, TMPDIR: temporary,
        MIRAGEMESH_LAB_COLLECTOR_PORT: String(collector), MIRAGEMESH_LAB_TEAM_PORT: String(workspace),
        MIRAGEMESH_LAB_SENSOR_PORT: String(sensor), MIRAGEMESH_LAB_HEALTH_PORT: String(health),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const lab = /^Lab directory: (.+)$/m.exec(output)?.[1];
    if (!lab) throw new Error('Monitor lab did not print its state directory.');
    const binary = resolve('dist/engine/miragemesh');
    processes.push(spawn(binary, ['--monitor-config', join(lab, 'monitor.json')], { stdio: 'ignore' }));
    processes.push(spawn(binary, ['--monitor-sensor-config', join(lab, 'sensor.json')], { stdio: 'ignore' }));
    await expect.poll(async () => {
      try {
        return (await fetch(`http://127.0.0.1:${health}/healthz`, { signal: AbortSignal.timeout(500) })).status;
      } catch { return 0; }
    }).toBe(200);
    const observation = await fetch(`http://127.0.0.1:${sensor}/review-this?discard=private`);
    expect(observation.status).toBe(200);
    expect(await observation.json()).toEqual({ status: 'ok' });

    const origin = `https://127.0.0.1:${workspace}`;
    const context = await browser.newContext({
      viewport: { width: 360, height: 820 },
      ignoreHTTPSErrors: true,
      clientCertificates: [{ origin, certPath: join(lab, 'operator/client.crt'), keyPath: join(lab, 'operator/client.key') }],
    });
    try {
      const page = await context.newPage();
      await page.goto(origin);
      await expect(page.getByRole('heading', { name: 'Sensor activity and incident review.' })).toBeVisible();
      const evidence = page.getByRole('button', { name: 'Open evidence lab-decoy sequence 1' });
      await evidence.click({ timeout: 10000 });
      await expect(page.getByText('/review-this', { exact: true })).toBeVisible();
      await page.getByLabel('Reason').fill('Reviewed the lab observation.');
      await page.getByRole('button', { name: 'Save decision' }).click();
      await expect(page.getByText('investigating · lab-analyst', { exact: true })).toBeVisible();
      await page.reload();
      await evidence.click();
      await expect(page.getByText('Reviewed the lab observation.', { exact: true })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
    } finally {
      await context.close();
    }
  } finally {
    await Promise.all(processes.map(stop));
    await rm(temporary, { recursive: true, force: true });
  }
});
