import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import project from './generated/project.json';
import { validateRuntimeConfig, validateHealth } from './lib/runtime-config.mjs';
import { inspectJson } from './lib/preview.mjs';
import Sensors from './pages/Sensors';
import PublicWorkspace from './pages/PublicWorkspace';
import Certificates from './pages/Certificates';
import Updates from './pages/Updates';
import Incidents from './pages/Incidents';
import AppShell, { type Route } from './components/AppShell';
import OperationalOverview from './components/OperationalOverview';
import './styles.css';

type Runtime = { projectId: string; apiBasePath: string; engineEnabled: false; maxPreviewBytes: number; deployment?: 'local' | 'static-public' };
function route(): Route { return location.hash === '#updates' ? 'updates' : location.hash === '#certificates' ? 'certificates' : location.hash === '#roadmap' ? 'roadmap' : location.hash === '#sensors' ? 'sensors' : location.hash === '#incidents' ? 'incidents' : 'workspace'; }

function App({ config }: { config: Runtime }) {
  const [page, setPage] = useState<Route>(route);
  const [query, setQuery] = useState('');
  const [stage, setStage] = useState('all');
  const [preview, setPreview] = useState<{ name: string; bytes: number; fields: string[] } | null>(null);
  const [error, setError] = useState('');
  const [engine, setEngine] = useState('Checking engine runtime…');
  const publicMode = config.deployment === 'static-public';
  const busy = useRef(false);
  const generation = useRef(0);
  useEffect(() => {
    const onRoute = () => { setPage(route()); document.getElementById('content')?.focus(); };
    addEventListener('hashchange', onRoute);
    return () => removeEventListener('hashchange', onRoute);
  }, []);
  useEffect(() => {
    if (publicMode) return;
    const controller = new AbortController();
    async function check() {
      try {
        const response = await fetch('/api/engine/health', { cache: 'no-store', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(2000)]) });
        if (!response.ok) throw new Error('Engine unavailable');
        const health = validateHealth(await response.json());
        if (!controller.signal.aborted) setEngine(`Engine runtime ${health.version} is running (${health.toolchain}).`);
      } catch { if (!controller.signal.aborted) setEngine('Engine runtime unavailable.'); }
    }
    void check();
    const timer = setInterval(() => { void check(); }, 5000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);
  async function importFile(file: File | undefined) {
    if (!file || busy.current) return;
    const current = ++generation.current;
    setError(''); setPreview(null);
    if (file.size > config.maxPreviewBytes) { setError('File exceeds the preview limit.'); return; }
    busy.current = true;
    try {
      const result = inspectJson(await file.text(), config.maxPreviewBytes);
      if (current === generation.current) setPreview({ name: file.name, fields: result.fields, bytes: result.bytes });
    } catch (reason) {
      if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Unable to read this file.');
    } finally { busy.current = false; }
  }
  const tasks = project.tasks.filter(task => (stage === 'all' || task.stage === stage) && `${task.id} ${task.title}`.toLowerCase().includes(query.toLowerCase()));
  return <AppShell page={page} publicMode={publicMode}>
      <div className="page-heading"><div><p className="page-context">{publicMode ? 'Explore MirageMesh' : 'Local operations'}</p><h1>{page === 'workspace' ? 'Workspace overview' : page === 'sensors' ? 'Sensor health and spool pressure.' : page === 'incidents' ? 'Incident replay and triage.' : page === 'updates' ? 'Signed sensor updates.' : page === 'certificates' ? 'Certificate rotation and recovery.' : 'A clear path to release.'}</h1><p className="intro">{page === 'workspace' ? 'Understand your signals. Keep the evidence close.' : page === 'sensors' ? 'Review sensor activity, applied configuration and durable delivery gaps.' : page === 'incidents' ? 'Replay source events, inspect coverage and record a reason for each decision.' : page === 'updates' ? 'Review publisher authority and verification of local candidate files.' : page === 'certificates' ? 'Review sensor identities, validity windows and recovery options.' : 'Forty source-backed delivery steps. Product adoption and hosted readiness are separate.'}</p></div><span className="badge">{publicMode ? 'Public workspace · 0.0.1' : 'Local workspace · 0.0.1'}</span></div>
      {publicMode && page !== 'roadmap' ? <PublicWorkspace section={page}/> : page === 'workspace' ? <>
        <section className="notice" aria-label="Availability" aria-live="polite"><span className="dot"/>{engine} This is a liveness check. Each enabled read surface reports its own readiness.</section>
        <OperationalOverview/><div className="grid"><section className="panel"><div className="eyebrow">Local file preview</div><h2>Inspect a document</h2><p>Choose a JSON file to inspect its top-level fields. The file stays in memory in this tab and is not uploaded or saved.</p><label className="file-button">Choose JSON file<input aria-label="Choose JSON file" type="file" accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ''; }}/></label><p className="muted">Maximum {Math.round(config.maxPreviewBytes / 1024)} KiB · JSON structure only</p>
          {error && <p role="alert" className="error">{error}</p>}
          {preview && <div className="preview" role="status"><h3>{preview.name}</h3><p>{preview.bytes} bytes · {preview.fields.length} top-level fields</p><ul>{preview.fields.slice(0, 30).map(field => <li key={field}><code>{field}</code></li>)}</ul><p className="muted">JSON structure checked. Domain validation requires the engine.</p><button onClick={() => { generation.current++; setPreview(null); }}>Clear preview</button></div>}
        </section><section className="panel"><div className="eyebrow">Operator guide</div><h2>Keep the next step clear</h2><p>Read surfaces use explicitly configured local engine state. Starting the workspace alone does not enroll sensors or create observations.</p><div className="resource-links"><a href="#sensors">Review sensor activity and delivery gaps</a><a href="#incidents">Investigate observations and evidence coverage</a><a href="#certificates">Review certificate validity and rotation</a><a href="#updates">Inspect signed update authority</a><a href="https://github.com/Parsa-Emami/Miragemesh/blob/main/docs/release/USER_GUIDE.md">Open the installation and operations guide</a></div></section></div>
      </> : page === 'sensors' ? <Sensors/> : page === 'incidents' ? <Incidents/> : page === 'certificates' ? <Certificates/> : page === 'updates' ? <Updates/> : <section className="panel"><div className="filters"><label>Search tasks<input value={query} onChange={event => setQuery(event.target.value)} placeholder="ID or task title" type="search"/></label><label>Stage<select value={stage} onChange={event => setStage(event.target.value)}><option value="all">All stages</option>{[...new Set(project.tasks.map(task => task.stage))].map(value => <option key={value} value={value}>{value}</option>)}</select></label></div><p aria-live="polite" className="muted">{tasks.length} of {project.tasks.length} product tasks</p><ol className="tasks">{tasks.map(task => <li key={task.id}><div className="task-line"><span className="task-id">{task.id}</span><h2>{task.title}</h2><span className="state">{task.status.replaceAll('_', ' ')}</span></div><p>{task.acceptance.join(' ')}</p><p className="muted">Stage: {task.stage} · Prerequisites: {task.dependsOn.join(', ') || 'None'}</p></li>)}</ol>{tasks.length === 0 && <p>No matching tasks.</p>}</section>}
  </AppShell>;
}

const root = createRoot(document.getElementById('root')!);
fetch(new URL('runtime-config.json', document.baseURI), { cache: 'no-store', credentials: 'omit' }).then(async response => {
  if (!response.ok) throw new Error('Workspace configuration is unavailable.');
  return validateRuntimeConfig(await response.json(), project.slug) as Runtime;
}).then(config => root.render(<StrictMode><App config={config}/></StrictMode>)).catch(() => {
  root.render(<main className="startup-error"><h1>Workspace unavailable</h1><p>The workspace configuration could not be loaded. Reload the page or contact the operator.</p></main>);
});
