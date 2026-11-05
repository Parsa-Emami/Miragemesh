import { useEffect, useState } from 'react';
import { validateSensorSnapshot } from '../lib/sensor-status.mjs';
import { validateIncidentSnapshot } from '../lib/incidents.mjs';
import { Card, Icon } from './ui/primitives';

type SensorsView = { sensors: { offline: boolean }[] };
type IncidentsView = { coverage: { complete: boolean }; incidents: { history: { status: string }[] }[] };
type Reading = { total: number; needsReview: number; coverage: boolean };
export default function OperationalOverview() {
  const [sensors, setSensors] = useState<{ total: number; offline: number } | null>(null);
  const [incidents, setIncidents] = useState<Reading | null>(null);
  const [failures, setFailures] = useState<string[]>([]);
  useEffect(() => {
    const controller = new AbortController();
    async function read<T>(path: string, validate: (value: unknown) => T): Promise<T> {
      const response = await fetch(path, { cache: 'no-store', credentials: 'omit', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(3000)]) });
      if (!response.ok) throw new Error('Read unavailable');
      return validate(await response.json());
    }
    void Promise.allSettled([read<SensorsView>('/api/v1/sensors', validateSensorSnapshot), read<IncidentsView>('/api/v1/incidents', validateIncidentSnapshot)]).then(results => {
      if (controller.signal.aborted) return;
      const [sensorResult, incidentResult] = results;
      if (sensorResult.status === 'fulfilled') setSensors({ total: sensorResult.value.sensors.length, offline: sensorResult.value.sensors.filter((item: { offline: boolean }) => item.offline).length });
      if (incidentResult.status === 'fulfilled') setIncidents({ total: incidentResult.value.incidents.length, needsReview: incidentResult.value.incidents.filter((item: { history: { status: string }[] }) => !['resolved', 'false_positive'].includes(item.history.at(-1)?.status ?? '')).length, coverage: incidentResult.value.coverage.complete });
      setFailures(results.flatMap((result, index) => result.status === 'rejected' ? [index === 0 ? 'sensor' : 'incident'] : []));
    });
    return () => controller.abort();
  }, []);
  return <section aria-label="Local operational overview"><div className="overview-metrics">
    <Card><Icon name="radio"/><span>Stored sensors</span><strong>{sensors?.total ?? '—'}</strong><small>{sensors ? `${sensors.offline} offline by event age` : 'Awaiting a valid local snapshot'}</small><a href="#sensors">Review sensors <Icon name="arrow-up-right"/></a></Card>
    <Card><Icon name="activity"/><span>Findings to review</span><strong>{incidents?.needsReview ?? '—'}</strong><small>{incidents ? `${incidents.total} findings in projected segments` : 'Awaiting a valid local snapshot'}</small><a href="#incidents">Review incidents <Icon name="arrow-up-right"/></a></Card>
    <Card><Icon name="shield-check"/><span>Evidence coverage</span><strong className="text-value">{incidents ? incidents.coverage ? 'Complete' : 'Incomplete' : 'Unknown'}</strong><small>Missing data never counts as a clean result.</small><a href="#incidents">Inspect coverage <Icon name="arrow-up-right"/></a></Card>
  </div>{failures.length > 0 && <p className="muted">The {failures.join(' and ')} read surface is unavailable. Open its page to inspect the error and retry. This summary is a point-in-time snapshot.</p>}</section>;
}
