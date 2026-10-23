import { useCallback, useEffect, useRef, useState } from 'react';
import { validateCertificateSnapshot } from '../lib/certificates.mjs';

type Certificate = { sensor_id: string; revision: number; fingerprint: string; previous_fingerprint?: string; overlap_until?: string; not_after: string; status: 'current' | 'overlap' | 'expired'; recovery_available: boolean };
type Snapshot = { observed_at: string; issuer_fingerprint: string; sensors: Certificate[] };

export default function Certificates() {
 const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');
 const active = useRef<AbortController | null>(null);
 const refresh = useCallback(async () => {
  active.current?.abort(); const controller = new AbortController(); active.current = controller; setLoading(true);
  try {
   const response = await fetch('/api/v1/certificates', { cache: 'no-store', credentials: 'omit', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(3000)]) });
   if (!response.ok) throw new Error('Certificate status is unavailable. Check the local engine and certificate configuration.');
   let value: Snapshot;
   try { value = validateCertificateSnapshot(await response.json()) as Snapshot; }
   catch { throw new Error('Certificate response is invalid. No new snapshot was accepted.'); }
   if (!controller.signal.aborted) { setSnapshot(value); setError(''); }
  } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof Error && cause.name === 'Error' ? cause.message : 'Certificate status request was interrupted or timed out. Retry the read.'); }
  finally { if (!controller.signal.aborted) setLoading(false); }
 }, []);
 useEffect(() => { void refresh(); return () => active.current?.abort(); }, [refresh]);
 return <div className="certificate-workspace">
  <div className="incident-toolbar"><p className="muted">{snapshot ? <>Last checked: <time dateTime={snapshot.observed_at}>{snapshot.observed_at}</time>{error ? ' · Stale snapshot' : ''}</> : 'Local certificate lifecycle'}</p><button onClick={() => void refresh()} disabled={loading}>{loading ? 'Loading certificates…' : 'Refresh certificates'}</button></div>
  {error && <p role="alert" className="error">{snapshot ? 'Displayed certificate data is stale. ' : ''}{error}</p>}
  {!snapshot && loading && <p role="status">Loading certificate status…</p>}
  {snapshot && <section aria-label="Certificate status">
   <h2>Managed certificates</h2>
   <p className="muted certificate-sensor">Issuer SHA-256: <code>{snapshot.issuer_fingerprint}</code></p>
   <p>Certificate status does not confirm a live sensor connection.</p>
   {snapshot.sensors.length === 0 ? <div className="panel"><p>No sensor certificates have been registered.</p></div> : snapshot.sensors.map(sensor => <article key={sensor.sensor_id} className="panel certificate-sensor">
    <div className="eyebrow">Revision {sensor.revision}</div><h3><code>{sensor.sensor_id}</code></h3>
    <span className={'state ' + sensor.status}>{sensor.status === 'overlap' ? 'Overlap active' : sensor.status === 'expired' ? 'Expired' : 'Current certificate'}</span>
    <p>Valid until <time dateTime={sensor.not_after}>{sensor.not_after}</time>.</p>
    {sensor.overlap_until && <p>Old certificate rejected from <time dateTime={sensor.overlap_until}>{sensor.overlap_until}</time>.{sensor.status === 'overlap' ? ' Both certificates are within the rotation window.' : ''}</p>}
    {sensor.recovery_available ? <p>Recovery is available. If the sensor missed its replacement, ask the local operator for a short-lived recovery token and submit a new key request. Recovery immediately replaces the current credential.</p> : <p>{sensor.status === 'overlap' ? 'Install the replacement before the overlap window ends.' : 'The current certificate remains active. Plan its replacement before expiry.'}</p>}
    <details><summary>Certificate details</summary><dl className="source-trace"><dt>Current SHA-256</dt><dd><code>{sensor.fingerprint}</code></dd>{sensor.previous_fingerprint && <><dt>Previous SHA-256</dt><dd><code>{sensor.previous_fingerprint}</code></dd></>}</dl></details>
   </article>)}
  </section>}
 </div>;
}
