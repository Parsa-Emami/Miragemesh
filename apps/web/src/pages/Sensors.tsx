import { useEffect, useState } from 'react';
import { validateSensorSnapshot } from '../lib/sensor-status.mjs';

type SensorStatus = {
  sensor_id: string;
  last_event_at: string | null;
  offline: boolean;
  config_status: 'missing' | 'expired' | 'current';
  dropped_event_count: number;
};

type SensorSnapshot = { offline_after_seconds: number; sensors: SensorStatus[] };

export default function Sensors() {
  const [snapshot, setSnapshot] = useState<SensorSnapshot | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function refresh() {
      try {
        const response = await fetch('/api/v1/sensors', {
          cache: 'no-store',
          credentials: 'omit',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(2000)]),
        });
        if (!response.ok) throw new Error(response.status === 503 ? 'Sensor status is unavailable. Check the local engine and its storage or verification policy.' : response.status === 403 ? 'Sensor status access was denied.' : 'Sensor status request failed.');
        let value: SensorSnapshot;
        try { value = validateSensorSnapshot(await response.json()) as SensorSnapshot; }
        catch { throw new Error('Sensor status is unavailable because the engine response is invalid.'); }
        if (!controller.signal.aborted) { setSnapshot(value); setUpdatedAt(new Date().toISOString()); setError(''); }
      } catch (reason) {
        if (!controller.signal.aborted) setError(reason instanceof Error && reason.name === 'Error' ? reason.message : 'Sensor status is unavailable. The local engine could not be reached; retrying automatically.');
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void refresh();
    const timer = setInterval(() => { void refresh(); }, 5000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);

  if (loading) return <section className="panel" aria-live="polite"><h2>Loading sensor status…</h2></section>;
  if (error && !snapshot) return <section className="panel"><h2>Sensor status unavailable</h2><p role="alert" className="error">{error}</p></section>;
  const sensors = snapshot?.sensors ?? [];
  const offline = sensors.filter(sensor => sensor.offline).length;
  const stale = sensors.filter(sensor => sensor.config_status !== 'current').length;
  const dropped = sensors.reduce((total, sensor) => total + sensor.dropped_event_count, 0);
  return <section aria-label="Sensor summary">
    {error && <p role="alert" className="error">Displayed sensor data is stale. {error} Retrying automatically.</p>}
    {updatedAt && <p className="muted">Last updated: <time dateTime={updatedAt}>{updatedAt}</time>{error ? ' · Stale snapshot' : ''}</p>}
    <div className="sensor-metrics">
      <article className="panel"><span className="eyebrow">Offline</span><strong>{offline}</strong><p>Last event older than {Math.round((snapshot?.offline_after_seconds ?? 300) / 60)} minutes</p></article>
      <article className="panel"><span className="eyebrow">Stale configuration</span><strong>{stale}</strong><p>Missing or expired applied configuration</p></article>
      <article className="panel"><span className="eyebrow">Dropped events</span><strong>{dropped}</strong><p>Durable spool gaps across listed sensors</p></article>
    </div>
    <section className="panel"><div className="eyebrow">Local C05 snapshot</div><h2>Sensor status</h2>
      {sensors.length === 0 ? <p>No sensor records are available in local storage.</p> : <div className="sensor-table-wrap"><table className="sensor-table"><thead><tr><th scope="col">Sensor</th><th scope="col">Connection</th><th scope="col">Applied config</th><th scope="col">Dropped events</th><th scope="col">Last event</th></tr></thead><tbody>
        {sensors.map(sensor => <tr key={sensor.sensor_id}><th scope="row"><code>{sensor.sensor_id}</code></th><td><span className={sensor.offline ? 'state offline' : 'state current'}>{sensor.offline ? 'Offline' : 'Online by recent event'}</span></td><td><span className={'state ' + sensor.config_status}>{sensor.config_status}</span></td><td>{sensor.dropped_event_count}</td><td>{sensor.last_event_at ?? 'No events recorded'}</td></tr>)}
      </tbody></table></div>}
      <p className="muted">Offline is based on the last stored event. It does not confirm a live network connection.</p>
    </section>
  </section>;
}
