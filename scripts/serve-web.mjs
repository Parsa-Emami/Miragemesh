import { validateUpdateSnapshot } from '../apps/web/src/lib/updates.mjs';
import http from 'node:http';
import { validateCertificateSnapshot } from '../apps/web/src/lib/certificates.mjs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateRuntimeConfig, validateHealth } from '../apps/web/src/lib/runtime-config.mjs';
import { validateSensorSnapshot } from '../apps/web/src/lib/sensor-status.mjs';
import { validateIncidentSnapshot, validateTriageResult } from '../apps/web/src/lib/incidents.mjs';

const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
export const readinessLimits = Object.freeze({ probe_timeout_ms: 1500, max_log_entries: 32, max_log_bytes: 8192, max_message_chars: 256 });

export function redactDiagnosticMessage(value, maxChars = readinessLimits.max_message_chars) {
  return String(value ?? '')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(/(authorization|token|secret|password|api[_-]?key|cookie)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxChars);
}

export function createDiagnosticLog(limits = readinessLimits) {
  const entries = [];
  const sizes = [];
  let bytes = 0;
  let dropped = 0;
  return {
    add(level, code, message) {
      const entry = { at: new Date().toISOString(), level, code, message: redactDiagnosticMessage(message ?? code, limits.max_message_chars) };
      const size = Buffer.byteLength(JSON.stringify(entry));
      while (entries.length > 0 && (entries.length >= limits.max_log_entries || bytes + size > limits.max_log_bytes)) {
        entries.shift();
        bytes -= sizes.shift();
        dropped += 1;
      }
      if (size > limits.max_log_bytes) return;
      entries.push(entry);
      sizes.push(size);
      bytes += size;
    },
    snapshot() {
      return {
        entries: entries.map(entry => ({ ...entry })),
        dropped,
        max_entries: limits.max_log_entries,
        max_bytes: limits.max_log_bytes,
        max_message_chars: limits.max_message_chars,
      };
    },
  };
}

const storageProbes = {
  sensors: (address, signal) => readEngineSensors(address, signal),
  incidents: (address, signal) => readEngineIncidents(address, { signal }),
  certificates: (address, signal) => readEngineCertificates(address, signal),
  updates: (address, signal) => readEngineUpdates(address, signal),
};
const providerProbes = { certificates: (address, signal) => readEngineCertificates(address, signal), updates: (address, signal) => readEngineUpdates(address, signal) };
const failureMessages = {
  web: 'Web shell assets are unavailable.',
  engine: 'Engine runtime readiness probe failed.',
  storage: 'Authoritative storage readiness probe failed.',
  certificates: 'Required certificate provider readiness probe failed.',
  updates: 'Required update provider readiness probe failed.',
};


export function readEngineHealth(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) return Promise.reject(new Error('Invalid loopback engine address.'));
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/healthz`, { agent: false, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000) }, response => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error('Engine unavailable.')); return; }
      let body = '';
      response.on('data', chunk => {
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body) > 4096) response.destroy(new Error('Engine health exceeds limit.'));
      });
      response.on('error', reject);
      response.on('end', () => { try { accept(validateHealth(JSON.parse(body))); } catch (error) { reject(error); } });
    });
    request.on('error', reject);
  });
}

export function readEngineSensors(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) return Promise.reject(new Error('Invalid loopback engine address.'));
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/api/v1/sensors`, { agent: false, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000) }, response => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error('Sensor status unavailable.')); return; }
      let body = '';
      response.on('data', chunk => {
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body) > 1048576) response.destroy(new Error('Sensor status exceeds the response limit.'));
      });
      response.on('error', reject);
      response.on('end', () => { try { accept(validateSensorSnapshot(JSON.parse(body))); } catch (error) { reject(error); } });
    });
    request.on('error', reject);
  });
}

export function readEngineCertificates(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) return Promise.reject(new Error('Invalid loopback engine address.'));
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/api/v1/certificates`, { agent: false, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000) }, response => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error('Certificate status unavailable.')); return; }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 1048576) response.destroy(new Error('Certificate response exceeds limit.')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => { try { accept(validateCertificateSnapshot(JSON.parse(Buffer.concat(chunks).toString('utf8')))); } catch (error) { reject(error); } });
    });
    request.on('error', reject);
  });
}

export function readEngineUpdates(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) return Promise.reject(new Error('Invalid loopback engine address.'));
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/api/v1/updates`, { agent: false, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000) }, response => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error('Update status unavailable.')); return; }
      const chunks = []; let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 1048576) response.destroy(new Error('Update response exceeds limit.')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => { try { accept(validateUpdateSnapshot(JSON.parse(Buffer.concat(chunks).toString('utf8')))); } catch (error) { reject(error); } });
    });
    request.on('error', reject);
  });
}

export function requestEngineIncidents(address, { id, body, key, signal } = {}) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535 || id !== undefined && !/^incident-[a-f0-9]{64}$/.test(id)) return Promise.reject(new Error('Invalid local incident request.'));
  return new Promise((accept, reject) => {
    const path = id ? `/api/v1/incidents/${id}/triage` : '/api/v1/incidents';
    const headers = id ? { 'Content-Type': 'application/json', 'Content-Length': body.length, 'Idempotency-Key': key, Origin: `http://${address}` } : {};
    const request = http.request(`http://${address}${path}`, { method: id ? 'POST' : 'GET', headers, agent: false, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000) }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => { size += chunk.length; if (size > 1048576) response.destroy(new Error('Incident response exceeds limit.')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => {
        try {
          const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!id && response.statusCode === 200) accept({ status: 200, value: validateIncidentSnapshot(value) });
          else if (id && response.statusCode === 202) accept({ status: 202, value: validateTriageResult(value, id) });
          else if ([403, 404, 409, 413, 415, 422, 503].includes(response.statusCode) && ['incidents_unavailable', 'triage_unavailable', 'incident_not_found', 'idempotency_conflict', 'invalid_triage', 'request_too_large', 'json_required', 'forbidden_origin'].includes(value.error)) accept({ status: response.statusCode, value: { error: value.error } });
          else reject(new Error('Invalid incident response.'));
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.end(id ? body : undefined);
  });
}

export function createWebServer({ root, config, projectId, engineAddress, readiness = {}, allowedHosts = [] }) {
  const valid = validateRuntimeConfig(config, projectId);
  const publicRoot = resolve(root);
  const policy = {
    engine: Boolean(engineAddress),
    storage: readiness.storage ?? null,
    providers: Array.isArray(readiness.providers) ? [...readiness.providers] : [],
    optionalProviders: Array.isArray(readiness.optionalProviders) ? [...readiness.optionalProviders] : [],
  };
  if (policy.storage !== null && !Object.hasOwn(storageProbes, policy.storage)) throw new Error('Invalid storage readiness surface.');
  if (policy.providers.some(name => !Object.hasOwn(providerProbes, name)) || policy.optionalProviders.some(name => !Object.hasOwn(providerProbes, name))) throw new Error('Invalid readiness provider.');
  const diagnostics = createDiagnosticLog();
  const previousReadiness = new Map();
  const within = path => { const diff = relative(publicRoot, path); return diff !== '..' && !diff.startsWith('../') && !isAbsolute(diff); };
  const probe = async (name, required, read, message) => {
    if (!engineAddress) return { name, required, ready: false, code: 'not_configured' };
    try {
      await read(engineAddress, AbortSignal.timeout(readinessLimits.probe_timeout_ms));
      return { name, required, ready: true, code: null };
    } catch {
      const suffix = name.startsWith('provider:') ? `provider_${name.slice('provider:'.length)}` : name;
      return { name, required, ready: false, code: `${suffix}_unavailable` };
    }
  };
  const record = components => {
    for (const component of components) {
      const prior = previousReadiness.get(component.name);
      const key = component.name.startsWith('provider:') ? component.name.slice('provider:'.length) : component.name;
      if (!component.ready && component.code !== 'not_configured' && prior !== false) diagnostics.add(component.required ? 'error' : 'warn', component.code, failureMessages[key]);
      else if (component.ready && prior === false) diagnostics.add('info', 'component_recovered', `${component.name} readiness recovered.`);
      previousReadiness.set(component.name, component.ready);
    }
  };
  const readReadiness = async () => {
    let indexReady = false;
    try { indexReady = (await stat(resolve(publicRoot, 'index.html'))).isFile(); } catch { indexReady = false; }
    const checks = [Promise.resolve({ name: 'web', required: true, ready: indexReady, code: indexReady ? null : 'web_assets_unavailable' })];
    checks.push(probe('engine', policy.engine, readEngineHealth, failureMessages.engine));
    checks.push(policy.storage
      ? probe('storage', true, storageProbes[policy.storage], failureMessages.storage)
      : Promise.resolve({ name: 'storage', required: false, ready: false, code: 'not_configured' }));
    for (const name of policy.providers) checks.push(probe(`provider:${name}`, true, providerProbes[name], failureMessages[name]));
    for (const name of policy.optionalProviders) checks.push(probe(`provider:${name}`, false, providerProbes[name], failureMessages[name]));
    const components = await Promise.all(checks);
    record(components);
    const requiredFailed = components.some(component => component.required && !component.ready);
    const optionalFailed = components.some(component => !component.required && !component.ready);
    return { status: requiredFailed ? 'not_ready' : optionalFailed ? 'degraded' : 'ready', components };
  };
  const readinessBody = result => {
    const component = name => result.components.find(item => item.name === name)?.ready ?? false;
    const providers = result.components.filter(item => item.name.startsWith('provider:'));
    return {
      status: result.status,
      scope: 'web-shell',
      engineReady: component('engine'),
      storageReady: component('storage'),
      providersReady: providers.every(item => item.ready),
      components: result.components,
    };
  };
  const permittedHosts = new Set(['127.0.0.1', 'localhost', '[::1]', ...allowedHosts]);
  const server = http.createServer({ requestTimeout: 15000, headersTimeout: 10000, keepAliveTimeout: 5000, maxHeaderSize: 16384 }, async (req, res) => {
    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, body, type = 'application/json; charset=utf-8') => {
      res.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    const authority = req.headers.host;
    const port = server.address()?.port;
    const allowed = typeof authority === 'string' && Array.from(permittedHosts).some(host => authority === `${host}:${port}` || (port === 80 || port === 443) && authority === host);
    const origin = req.headers.origin;
    const originMatch = origin === undefined || origin === `http://${authority}` || origin === `https://${authority}`;
    if (!allowed || !originMatch) {
      send(403, '{"error":"forbidden_origin"}'); return;
    }
    const triagePath = /^\/api\/v1\/incidents\/(incident-[a-f0-9]{64})\/triage$/.exec((req.url ?? '').split('?')[0]);
    if (!['GET', 'HEAD'].includes(req.method ?? '') && !(req.method === 'POST' && triagePath)) { res.setHeader('Allow', (req.url ?? '').split('?')[0] === '/api/v1/sensors' || (req.url ?? '').split('?')[0] === '/api/v1/certificates' || (req.url ?? '').split('?')[0] === '/api/v1/updates' || (req.url ?? '').split('?')[0] === '/api/v1/incidents' ? 'GET' : triagePath ? 'POST' : 'GET, HEAD'); send(405, '{"error":"method_not_allowed"}'); return; }
    let path;
    try {
      path = decodeURIComponent((req.url ?? '/').split('?')[0]);
      if (!path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some(part => part.startsWith('.'))) throw new Error();
    } catch { send(400, '{"error":"invalid_path"}'); return; }
    if (path === '/api/v1/incidents' || triagePath) {
      const method = triagePath ? 'POST' : 'GET';
      if (req.method !== method) { res.setHeader('Allow', method); send(405, '{"error":"method_not_allowed"}'); return; }
      if (!engineAddress) { send(503, '{"error":"incidents_unavailable"}'); return; }
      const controller = new AbortController();
      res.once('close', () => controller.abort());
      try {
        let body;
        if (triagePath) {
          if (req.headers.origin !== `http://${authority}` && req.headers.origin !== `https://${authority}`) { send(403, '{"error":"forbidden_origin"}'); return; }
          if ((req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json') { send(415, '{"error":"json_required"}'); return; }
          if (typeof req.headers['idempotency-key'] !== 'string' || req.headers['idempotency-key'].length < 16 || req.headers['idempotency-key'].length > 128) { send(422, '{"error":"invalid_triage"}'); return; }
          const chunks = [];
          let size = 0;
          for await (const chunk of req) { size += chunk.length; if (size > 16384) { send(413, '{"error":"request_too_large"}'); req.resume(); return; } chunks.push(chunk); }
          body = Buffer.concat(chunks);
        }
        const result = await requestEngineIncidents(engineAddress, { id: triagePath?.[1], body, key: req.headers['idempotency-key'], signal: controller.signal });
        send(result.status, JSON.stringify(result.value));
      } catch { if (!res.destroyed) send(503, JSON.stringify({ error: triagePath ? 'triage_unavailable' : 'incidents_unavailable' })); }
      return;
    }
    if (path === '/healthz') { send(200, '{"status":"ok","scope":"web-shell"}'); return; }
    if (path === '/readyz') {
      const result = await readReadiness();
      send(result.status === 'not_ready' ? 503 : 200, JSON.stringify(readinessBody(result)));
      return;
    }
    if (path === '/api/diagnostics') {
      const result = await readReadiness();
      const body = readinessBody(result);
      send(200, JSON.stringify({
        schema_version: 1,
        scope: 'web-shell',
        generated_at: new Date().toISOString(),
        status: body.status,
        components: body.components,
        logs: diagnostics.snapshot(),
        limits: { ...readinessLimits },
      }));
      return;
    }
    if (path === '/api/engine/health' && engineAddress) {
      try { send(200, JSON.stringify(await readEngineHealth(engineAddress))); }
      catch { send(503, '{"error":"engine_unavailable"}'); }
      return;
    }
    if (path === '/api/v1/certificates') {
      if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); send(405, '{"error":"method_not_allowed"}'); return; }
      if (!engineAddress) { send(503, '{"error":"certificate_status_unavailable"}'); return; }
      const controller = new AbortController(); res.once('close', () => controller.abort());
      try { send(200, JSON.stringify(await readEngineCertificates(engineAddress, controller.signal))); }
      catch { if (!res.destroyed) send(503, '{"error":"certificate_status_unavailable"}'); }
      return;
    }
    if (path === '/api/v1/updates') {
      if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); send(405, '{"error":"method_not_allowed"}'); return; }
      if (!engineAddress) { send(503, '{"error":"update_status_unavailable"}'); return; }
      const controller = new AbortController(); res.once('close', () => controller.abort());
      try { send(200, JSON.stringify(await readEngineUpdates(engineAddress, controller.signal))); }
      catch { if (!res.destroyed) send(503, '{"error":"update_status_unavailable"}'); }
      return;
    }
    if (path === '/api/v1/sensors') {
      if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); send(405, '{"error":"method_not_allowed"}'); return; }
      if (!engineAddress) { send(503, '{"error":"sensor_status_unavailable"}'); return; }
      try { send(200, JSON.stringify(await readEngineSensors(engineAddress))); }
      catch { send(503, '{"error":"sensor_status_unavailable"}'); }
      return;
    }
    if (path === '/api' || path.startsWith('/api/')) { send(503, '{"error":"engine_not_integrated"}'); return; }
    if (path === '/runtime-config.json') { send(200, JSON.stringify(valid)); return; }
    const asset = path.startsWith('/assets/');
    if (!(asset || ['/', '/index.html', '/icon.svg', '/manifest.webmanifest', '/robots.txt'].includes(path))) { send(404, '{"error":"not_found"}'); return; }
    try {
      const filename = await realpath(resolve(publicRoot, '.' + (path === '/' ? '/index.html' : path)));
      if (!within(filename) || !(await stat(filename)).isFile()) { send(404, '{"error":"not_found"}'); return; }
      const bytes = await readFile(filename);
      res.writeHead(200, { 'Content-Type': types[extname(filename)] ?? 'application/octet-stream', 'Content-Length': bytes.length, 'Cache-Control': asset ? 'public, max-age=31536000, immutable' : 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : bytes);
    } catch { send(404, '{"error":"not_found"}'); }
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const options = { host: '127.0.0.1', port: '4173', root: 'dist/web', config: 'ops/web/runtime-config.json' };
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) throw new Error('Usage: node scripts/serve-web.mjs [--host 127.0.0.1] [--port 4173] [--root dist/web] [--config path]');
    options[key] = args[i + 1];
  }
  if (!['127.0.0.1', '::1'].includes(options.host)) throw new Error('Bind to loopback and use the documented TLS proxy.');
  if (!/^\d+$/.test(options.port) || +options.port < 1 || +options.port > 65535) throw new Error('Invalid port.');
  const product = JSON.parse(await readFile(new URL('../ops/web/brand.json', import.meta.url), 'utf8'));
  const config = JSON.parse(await readFile(resolve(options.config), 'utf8'));
  await stat(resolve(options.root, 'index.html'));
  const server = createWebServer({ root: options.root, config, projectId: product.slug });
  server.maxRequestsPerSocket = 1000;
  server.on('error', error => { console.error(error.message); process.exitCode = 1; });
  server.listen(+options.port, options.host, () => console.log(JSON.stringify({ service: product.slug + '-web', host: options.host, port: +options.port, engineReady: false })));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 10000).unref();
  });
}
