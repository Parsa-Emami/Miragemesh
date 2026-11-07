import { useEffect, useRef, useState } from 'react';
import './team.css';

const api = '/api/team/v1';

type Session = { id: string; role: 'viewer' | 'analyst'; sensors: string[] };
type Sensor = {
  id: string; last_received_hour?: string; events_this_hour: number; rate_signal: boolean;
  online: boolean; last_heartbeat?: string; spool_pending: number; spool_held: number;
};
type Incident = { id: string; sensor_id: string; event_id: string; sequence: number; received_hour: string; rate_signal: boolean; coverage_complete: boolean };
type Page = { items: Incident[]; next_cursor?: string };
type Decision = { status: string; reason: string; actor: string; triaged_at: string };
type Evidence = {
  event: { sensor_id: string; event_id: string; sequence: number; observed_at: string; metadata: { path: string } };
  sha256: string;
  history: Decision[];
};

async function get<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(api + path, {
    cache: 'no-store', credentials: 'same-origin',
    signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]),
  });
  if (!response.ok) throw new Error(`Request failed (${response.status}).`);
  return response.json();
}

export default function Team() {
  const [session, setSession] = useState<Session | null>(null);
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [sensor, setSensor] = useState('');
  const [cursors, setCursors] = useState(['']);
  const [page, setPage] = useState<Page | null>(null);
  const [selected, setSelected] = useState('');
  const [updated, setUpdated] = useState('');
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [triagePending, setTriagePending] = useState(false);
  const before = cursors.at(-1) ?? '';
  const detailPanel = useRef<HTMLElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    let running = false;
    async function refresh() {
      if (running) return;
      running = true;
      const query = new URLSearchParams({ limit: '20' });
      if (sensor) query.set('sensor', sensor);
      if (before) query.set('before', before);
      try {
        const [current, status, incidents] = await Promise.all([
          get<Session>('/session', controller.signal),
          get<Sensor[]>('/sensors', controller.signal),
          get<Page>('/incidents?' + query, controller.signal),
        ]);
        if (!controller.signal.aborted) {
          setSession(current);
          setSensors(status);
          setPage(incidents);
          setUpdated(new Date().toISOString());
          setError('');
        }
      } catch {
        if (!controller.signal.aborted) setError('Workspace refresh failed. Check your client certificate and the monitoring service.');
      } finally {
        running = false;
      }
    }
    void refresh();
    const timer = before ? undefined : setInterval(() => void refresh(), 5000);
    return () => {
      controller.abort();
      if (timer !== undefined) clearInterval(timer);
    };
  }, [sensor, before, retry]);

  function navigate(next: string[]) {
    setCursors(next);
    setPage(null);
    setSelected('');
  }

  function openEvidence(id: string) {
    setSelected(id);
    requestAnimationFrame(() => detailPanel.current?.focus());
  }

  return <div className="app team-workspace">
    <a className="skip" href="#team-content">Skip to content</a>
    <header><a className="brand" href="/"><span className="mark" aria-hidden="true">M</span>MirageMesh</a>
      <span className="team-identity">{session ? `${session.id} · ${session.role}` : 'Client certificate session'}</span></header>
    <main id="team-content" tabIndex={-1}>
      <div className="eyebrow">Private monitoring workspace</div>
      <h1>Sensor activity and incident review.</h1>
      <p className="intro">Review observations from your assigned sensors, inspect the recorded evidence and keep a durable decision history.</p>
      <section className="panel" aria-label="Sensor activity">
        <h2>Sensor activity</h2>
        {sensors.length === 0 ? <p>Sensor activity will appear when the workspace connects.</p> :
          <ul className="team-sensors">{sensors.map(item => <li key={item.id}>
            <strong>{item.id}</strong>
            <span className={item.online ? 'muted' : 'team-signal'}>{item.online ? 'Sensor connected' : item.last_heartbeat ? 'Heartbeat overdue' : 'Awaiting heartbeat'}</span>
            <span>{item.events_this_hour} this UTC hour</span>
            {item.last_heartbeat && <span className="muted">Reported spool {item.spool_pending} pending · {item.spool_held} held</span>}
            <span className={item.rate_signal ? 'team-signal' : 'muted'}>{item.rate_signal ? 'Rate threshold reached' : 'Within hourly threshold'}</span>
            <span className="muted">{item.last_received_hour ? `Last received hour ${item.last_received_hour}` : 'Awaiting first observation'}</span>
          </li>)}</ul>}
      </section>
      <section className="panel" aria-label="Incident timeline">
        <h2>Incident timeline</h2>
        <div className="incident-toolbar">
          <div className="filters"><label>Sensor<select value={sensor} disabled={triagePending} onChange={event => {
            setSensor(event.target.value);
            navigate(['']);
          }}>
            <option value="">All assigned sensors</option>
            {session?.sensors.map(id => <option key={id} value={id}>{id}</option>)}
          </select></label></div>
          <p className="muted">{before ? 'History page · automatic refresh paused' : 'Latest page · refreshes every 5 seconds'}</p>
          <button onClick={() => setRetry(value => value + 1)}>Refresh</button>
        </div>
        {updated && <p className="muted">Last update <time dateTime={updated}>{updated}</time></p>}
        {error && <p role="alert" className="error">{page && 'Showing previously loaded results. '}{error}</p>}
        {!page && !error && <p role="status">Loading observations…</p>}
        {page && (page.items.length === 0 ? <p>No retained observations in this view.</p> :
          <div className="sensor-table-wrap" tabIndex={0} role="region" aria-label="Observations">
            <table className="sensor-table team-table"><thead><tr>
              <th scope="col">Sensor</th><th scope="col">Received hour (UTC)</th><th scope="col">Sequence</th>
              <th scope="col">Finding</th><th scope="col">Evidence</th>
            </tr></thead><tbody>{page.items.map(item => <tr key={item.id}>
              <th scope="row">{item.sensor_id}</th><td><time dateTime={item.received_hour}>{item.received_hour}</time></td>
              <td>{item.sequence}</td><td>{item.rate_signal ? <span className="team-signal">Rate signal</span> : 'Interaction'}
                {!item.coverage_complete && <div className="muted">Incomplete partition</div>}</td>
              <td><button disabled={triagePending} aria-label={`Open evidence ${item.sensor_id} sequence ${item.sequence}`} onClick={() => openEvidence(item.id)}>Open</button></td>
            </tr>)}</tbody></table>
          </div>)}
        <div className="incident-toolbar"><span className="muted">Page {cursors.length}</span><div className="replay-controls">
          <button disabled={triagePending || cursors.length === 1} onClick={() => navigate(cursors.slice(0, -1))}>Newer</button>
          <button disabled={triagePending || !page?.next_cursor} onClick={() => { if (page?.next_cursor) navigate([...cursors, page.next_cursor]); }}>Older</button>
        </div></div>
      </section>
      {selected && <section className="panel" ref={detailPanel} tabIndex={-1} aria-label="Selected evidence">
        <EvidencePanel key={selected} id={selected} canTriage={session?.role === 'analyst'} lockNavigation={setTriagePending}/>
      </section>}
    </main>
  </div>;
}

function EvidencePanel({ id, canTriage, lockNavigation }: { id: string; canTriage: boolean; lockNavigation: (value: boolean) => void }) {
  const [detail, setDetail] = useState<Evidence | null>(null);
  const [readError, setReadError] = useState('');
  const [readRevision, refresh] = useState(0);
  const [status, setStatus] = useState('investigating');
  const [reason, setReason] = useState('');
  const [pending, setPending] = useState<{ key: string; body: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const savingRef = useRef(false);
  const reasonBytes = new TextEncoder().encode(reason).length;

  useEffect(() => {
    const controller = new AbortController();
    void get<Evidence>('/incidents/' + id, controller.signal)
      .then(value => { if (!controller.signal.aborted) { setDetail(value); setReadError(''); } })
      .catch(() => { if (!controller.signal.aborted) setReadError('Evidence is unavailable. The record may have expired.'); });
    return () => controller.abort();
  }, [id, readRevision]);

  async function save() {
    if (!canTriage || savingRef.current || !pending && (!reason.trim() || reasonBytes > 1024)) return;
    const operation = pending ?? { key: crypto.randomUUID(), body: JSON.stringify({ status, reason }) };
    savingRef.current = true;
    setPending(operation);
    lockNavigation(true);
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const response = await fetch(api + '/incidents/' + id + '/triage', {
        method: 'POST', cache: 'no-store', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': operation.key },
        body: operation.body, signal: AbortSignal.timeout(5000),
      });
      if (response.status >= 400 && response.status < 500) {
        setPending(null);
        lockNavigation(false);
        setError(`The server rejected this decision (${response.status}). Check the evidence and your permissions.`);
        return;
      }
      if (response.status !== 202) throw new Error('Ambiguous save result.');
      setPending(null);
      lockNavigation(false);
      setReason('');
      setMessage('Decision saved.');
      refresh(value => value + 1);
    } catch {
      setError('Save outcome is unknown. Retry the same decision to recover its result.');
    } finally {
      savingRef.current = false;
      setSaving(false);
    }
  }

  return <>
    <h2>Recorded evidence</h2>
    {readError && <p role="alert" className="error">{readError}</p>}
    {!detail && !readError && <p role="status">Loading evidence…</p>}
    {detail && <>
      <dl className="source-trace"><dt>Event</dt><dd>{detail.event.event_id} · sequence {detail.event.sequence}</dd>
        <dt>Sensor</dt><dd>{detail.event.sensor_id}</dd>
        <dt>Observed at</dt><dd><time dateTime={detail.event.observed_at}>{detail.event.observed_at}</time></dd>
        <dt>Request path</dt><dd><code>{detail.event.metadata.path}</code></dd>
        <dt>Payload SHA-256</dt><dd><code>{detail.sha256}</code></dd>
      </dl>
      {canTriage && <form className="triage-form" onSubmit={event => { event.preventDefault(); void save(); }}>
        <h3>Record a decision</h3>
        <label>Status<select value={status} disabled={pending !== null} onChange={event => setStatus(event.target.value)}>
          <option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="dismissed">Dismissed</option>
        </select></label>
        <label>Reason<textarea required maxLength={1024} disabled={pending !== null} value={reason} onChange={event => setReason(event.target.value)}/></label>
        <p className="muted">{reasonBytes} / 1024 bytes</p>
        <button type="submit" disabled={saving || !pending && (!!readError || !reason.trim() || reasonBytes > 1024)}>
          {saving ? 'Saving…' : pending ? 'Retry same decision' : 'Save decision'}
        </button>
      </form>}
      {message && <p role="status">{message}</p>}
      {error && <p role="alert" className="error">{error}</p>}
      <h3>Decision history</h3>
      {detail.history.length === 0 ? <p>No decisions recorded.</p> : <ol className="triage-history">{detail.history.map((decision, index) =>
        <li key={index}><strong>{decision.status} · {decision.actor}</strong><p>{decision.reason}</p>
          <time dateTime={decision.triaged_at}>{decision.triaged_at}</time></li>)}</ol>}
    </>}
  </>;
}
