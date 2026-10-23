import { useCallback, useEffect, useRef, useState } from 'react';
import { validateIncidentSnapshot, validateTriageResult } from '../lib/incidents.mjs';

type Source = { sensor_id: string; event_id: string; sequence: number; segment: string; record: number; digest: string };
type Replay = { source: Source; event: { observed_at: string; metadata: { path: string } } };
type Incident = { id: string; finding: { class: string; sensor_id: string; explanation: string }; events: Replay[]; history: { status: string; reason: string; triaged_at: string }[] };
type Retention = { segment: string; records: number; bytes: number; digest: string; before: string; expired_at: string; reason: string };
type Snapshot = { retained_events?: number; coverage: { retention_gaps?: Retention[]; complete: boolean; incomplete_segments: number; missing_ordinals: { after: number; before: number }[] }; unprojected_events: number; rate_limit: number; window_seconds: number; incidents: Incident[] };
type Pending = { id: string; key: string; status: string; reason: string };

export default function Incidents() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [selected, setSelected] = useState('');
  const [position, setPosition] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState('');
  const [status, setStatus] = useState('investigating');
  const [reason, setReason] = useState('');
  const [pending, setPending] = useState<Pending | null>(null);
  const [saving, setSaving] = useState(false);
  const [writeError, setWriteError] = useState('');
  const [message, setMessage] = useState('');
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const inFlight = useRef(false);
  const detail = useRef<HTMLElement | null>(null);

  const refresh = useCallback(async () => {
    read.current?.abort();
    const controller = new AbortController();
    read.current = controller;
    setLoading(true);
    try {
      const response = await fetch('/api/v1/incidents', { cache: 'no-store', credentials: 'omit', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(3000)]) });
      if (!response.ok) throw new Error('Incidents are unavailable. Check the local engine, segment store and explicit incident policy.');
      let value: Snapshot;
      try { value = validateIncidentSnapshot(await response.json()) as Snapshot; }
      catch { throw new Error('Incident response is invalid. No new snapshot was accepted.'); }
      if (!controller.signal.aborted) { setSnapshot(value); setUpdated(new Date().toISOString()); setError(''); setSelected(current => value.incidents.some(item => item.id === current) ? current : value.incidents[0]?.id ?? ''); }
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error && cause.name === 'Error' ? cause.message : 'Incident request was interrupted or timed out. Retry the read.');
    } finally { if (!controller.signal.aborted) setLoading(false); }
  }, []);

  useEffect(() => { void refresh(); return () => { read.current?.abort(); write.current?.abort(); }; }, [refresh]);
  const incident = snapshot?.incidents.find(item => item.id === selected);
  const replay = incident?.events[Math.min(position, incident.events.length - 1)];

  function choose(id: string) {
    setSelected(id); setPosition(0); setReason(''); setWriteError(''); setMessage('');
    requestAnimationFrame(() => detail.current?.focus());
  }

  async function triage() {
    if (!incident || inFlight.current || !pending && (!reason.trim() || Array.from(reason).length > 4096)) return;
    const operation = pending ?? { id: incident.id, key: crypto.randomUUID(), status, reason };
    const controller = new AbortController();
    write.current = controller;
    inFlight.current = true;
    setPending(operation); setSaving(true); setWriteError(''); setMessage('');
    try {
      const response = await fetch(`/api/v1/incidents/${operation.id}/triage`, { method: 'POST', cache: 'no-store', credentials: 'omit', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': operation.key }, body: JSON.stringify({ status: operation.status, reason: operation.reason }), signal: AbortSignal.any([controller.signal, AbortSignal.timeout(4000)]) });
      if ([403, 404, 409, 413, 415, 422].includes(response.status)) {
        setPending(null);
        throw new Error(response.status === 409 ? 'The idempotency key conflicts with an earlier request. Refresh the history before submitting again.' : response.status === 422 || response.status === 413 ? 'Triage was rejected. Check the status, reason and storage byte limit.' : 'Triage was rejected. Refresh the incident and check local access.');
      }
      if (response.status !== 202) throw new Error('Save outcome is unknown. Retry the same triage to recover its durable result.');
      try { validateTriageResult(await response.json(), operation.id); }
      catch { throw new Error('Save response is invalid. Retry the same triage to recover its durable result.'); }
      if (controller.signal.aborted) return;
      setPending(null); setReason(''); setMessage('Triage saved to local durable history.');
      await refresh();
    } catch (cause) {
      if (!controller.signal.aborted) setWriteError(cause instanceof Error && cause.name === 'Error' ? cause.message : 'Save was interrupted. Its outcome is unknown. Retry the same triage.');
    } finally { inFlight.current = false; if (!controller.signal.aborted) setSaving(false); }
  }

  return <section aria-label="Incident workspace" className="incident-workspace">
    <div className="incident-toolbar"><p className="muted">{updated ? <>Last updated: <time dateTime={updated}>{updated}</time>{error ? ' · Stale snapshot' : ''}</> : 'Local immutable event segments'}</p><button onClick={() => void refresh()} disabled={loading}>{loading ? 'Loading incidents…' : 'Refresh incidents'}</button></div>
    {error && <p role="alert" className="error">{snapshot ? 'Displayed incident data is stale. ' : ''}{error}</p>}
    {!snapshot && loading && <p role="status">Loading local incident replay…</p>}
    {snapshot && <>
      <section className="panel" aria-label="Evidence coverage"><h2>Evidence coverage</h2><p>{snapshot.coverage.complete ? 'Available segment coverage is complete.' : 'Evidence coverage is incomplete. Missing evidence does not prove that an event never occurred.'}</p><p className="muted">{snapshot.retained_events ?? 0} deliberately expired event sources · {snapshot.unprojected_events} unprojected events · {snapshot.coverage.incomplete_segments} incomplete segments · {snapshot.coverage.missing_ordinals.length} missing ordinal ranges</p>{snapshot.coverage.missing_ordinals.map(gap => <p key={gap.after}>Missing ordinals strictly between {gap.after} and {gap.before}.</p>)}{snapshot.coverage.retention_gaps && snapshot.coverage.retention_gaps.length > 0 && <details><summary>Retention audit ({snapshot.coverage.retention_gaps.length} segments)</summary><ol className="triage-history">{snapshot.coverage.retention_gaps.map(gap => <li key={gap.segment}><code>{gap.segment}</code><p>{gap.records} records · {gap.bytes} bytes</p><p>Observed before <time dateTime={gap.before}>{gap.before}</time></p><p>Expired at <time dateTime={gap.expired_at}>{gap.expired_at}</time></p><p>{gap.reason}</p><p>Segment SHA-256: <code>{gap.digest}</code></p></li>)}</ol></details>}<p className="muted">Rate policy: {snapshot.rate_limit} requests within {snapshot.window_seconds} seconds. Signals require review. Spool loss findings are shown on Sensors.</p></section>
      <section className="panel"><h2>Incidents</h2>{snapshot.incidents.length === 0 ? <p>No incidents in the projected segments.</p> : <div className="sensor-table-wrap" tabIndex={0} role="region" aria-label="Incident table"><table className="sensor-table"><thead><tr><th scope="col">Finding</th><th scope="col">Sensor</th><th scope="col">Triage status</th><th scope="col">Source events</th><th scope="col">Replay</th></tr></thead><tbody>{snapshot.incidents.map((item, index) => <tr key={item.id} aria-selected={item.id === selected}><th scope="row">{item.finding.class === 'attack_signal' ? 'Rate signal' : 'Interaction'}</th><td><code>{item.finding.sensor_id}</code></td><td>{item.history.at(-1)?.status ?? 'Unreviewed'}</td><td>{item.events.length}</td><td><button aria-label={`Open incident ${index + 1}`} disabled={pending !== null} onClick={() => choose(item.id)}>Open replay</button></td></tr>)}</tbody></table></div>}</section>
      {incident && replay && <section className="panel incident-detail" ref={detail} tabIndex={-1} aria-label="Selected incident"><div className="eyebrow">{incident.finding.class === 'attack_signal' ? 'Rate signal for review' : 'Observed interaction'}</div><h2>Replay and source trace</h2><p>{incident.finding.explanation}</p><p className="muted incident-id">Incident: <code>{incident.id}</code></p>
        <div className="incident-toolbar"><h3>Event {Math.min(position + 1, incident.events.length)} of {incident.events.length}</h3><div className="replay-controls"><button disabled={position === 0} onClick={() => setPosition(value => value - 1)}>Previous event</button><button disabled={position >= incident.events.length - 1} onClick={() => setPosition(value => value + 1)}>Next event</button></div></div>
        <dl className="source-trace"><dt>Event</dt><dd><code>{replay.source.event_id}</code> · sequence {replay.source.sequence}</dd><dt>Observed</dt><dd><time dateTime={replay.event.observed_at}>{replay.event.observed_at}</time></dd><dt>Request path</dt><dd><code data-testid="event-path">{replay.event.metadata.path}</code></dd><dt>Source segment</dt><dd><code>{replay.source.segment}</code> · record {replay.source.record}</dd><dt>Exact payload SHA-256</dt><dd><code>{replay.source.digest}</code></dd></dl>
        <div className="sensor-table-wrap" tabIndex={0} role="region" aria-label="Source event table"><table className="sensor-table"><thead><tr><th scope="col">Event</th><th scope="col">Time</th><th scope="col">Segment / record</th><th scope="col">Select</th></tr></thead><tbody>{incident.events.map((event, index) => <tr key={event.source.event_id}><th scope="row">{event.source.event_id}</th><td>{event.event.observed_at}</td><td><code>{event.source.segment}</code> / {event.source.record}</td><td><button onClick={() => setPosition(index)} aria-label={`Replay event ${index + 1}`}>Replay</button></td></tr>)}</tbody></table></div>
        <form className="triage-form" onSubmit={event => { event.preventDefault(); void triage(); }}><h3>Record triage</h3><label>Status<select aria-label="Triage status" value={pending?.status ?? status} disabled={pending !== null} onChange={event => setStatus(event.target.value)}><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label><label>Reason<textarea aria-label="Triage reason" value={pending?.reason ?? reason} required maxLength={4096} disabled={pending !== null} onChange={event => setReason(event.target.value)}/></label><p className="muted">Status and reason append to history. Source event bytes remain immutable.</p><button disabled={saving || !!error || !pending && !reason.trim()} type="submit">{saving ? 'Saving triage…' : pending ? 'Retry same triage' : 'Save triage'}</button></form>
        {writeError && <p className="error" role="alert">{writeError}</p>}{message && <p role="status">{message}</p>}
        <section aria-label="Triage history"><h3>Triage history</h3>{incident.history.length === 0 ? <p>No triage history yet.</p> : <ol className="triage-history">{incident.history.map((entry, index) => <li key={index}><strong>{entry.status}</strong><p>{entry.reason}</p><time dateTime={entry.triaged_at}>{entry.triaged_at}</time></li>)}</ol>}</section>
      </section>}
    </>}
  </section>;
}
