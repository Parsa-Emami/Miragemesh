const digest = /^[a-f0-9]{64}$/;
const incidentID = /^incident-[a-f0-9]{64}$/;
const segmentID = /^segment-[0-9]{20}$/;
const date = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max) => typeof value === 'string' && value.isWellFormed() && Array.from(value).length > 0 && Array.from(value).length <= max;
const integer = (value, min = 0) => Number.isSafeInteger(value) && value >= min;
const fail = () => { throw new Error('Incident response is invalid.'); };

export function validateIncidentSnapshot(value) {
  if (!object(value) || value.schema_version !== '1' || !integer(value.rate_limit, 1) || !integer(value.window_seconds, 1) ||
      !integer(value.unprojected_events) || !object(value.coverage) || typeof value.coverage.complete !== 'boolean' ||
      !integer(value.coverage.incomplete_segments) || !Array.isArray(value.coverage.missing_ordinals) || !Array.isArray(value.incidents) || value.incidents.length > 512) fail();
  for (const gap of value.coverage.missing_ordinals) if (!object(gap) || !integer(gap.after, 1) || !integer(gap.before, 1) || gap.before <= gap.after + 1) fail();
  if (value.coverage.complete && (value.unprojected_events || value.coverage.incomplete_segments || value.coverage.missing_ordinals.length)) fail();
  const ids = new Set();
  const identities = new Map();
  for (const incident of value.incidents) {
    if (!object(incident) || !incidentID.test(incident.id) || ids.has(incident.id) || !object(incident.finding) || !Array.isArray(incident.events) || incident.events.length < 1 || incident.events.length > 256 || !Array.isArray(incident.history)) fail();
    ids.add(incident.id);
    const finding = incident.finding;
    if (!['interaction', 'attack_signal'].includes(finding.class) || !text(finding.sensor_id, 128) || !text(finding.explanation, 4096) || !Array.isArray(finding.sources) || finding.sources.length !== incident.events.length) fail();
    if (finding.class === 'interaction' && incident.events.length !== 1) fail();
    if (finding.class === 'attack_signal' && (finding.count !== incident.events.length || finding.count < value.rate_limit || finding.window_seconds !== value.window_seconds || !date(finding.observed_from) || !date(finding.observed_to))) fail();
    const seen = new Set();
    for (const [index, replay] of incident.events.entries()) {
      if (!object(replay) || !object(replay.source) || !object(replay.event)) fail();
      const { source, event } = replay;
      const ref = finding.sources[index];
      if (!object(ref) || !text(source.sensor_id, 128) || !text(source.event_id, 128) || !integer(source.sequence, 1) || !integer(source.record, 1) || !segmentID.test(source.segment) || /^segment-0{20}$/.test(source.segment) || !digest.test(source.digest)) fail();
      if (['sensor_id', 'event_id', 'sequence', 'segment', 'record', 'digest'].some(key => source[key] !== ref[key]) || source.sensor_id !== finding.sensor_id) fail();
      if (event.schema_version !== '1' || event.kind !== 'http.request' || event.sensor_id !== source.sensor_id || event.event_id !== source.event_id || event.sequence !== source.sequence || !date(event.observed_at) || !object(event.metadata) || !text(event.metadata.path, 8192)) fail();
      const key = JSON.stringify([source.sensor_id, source.event_id]);
      const identity = JSON.stringify([source.sequence, source.segment, source.record, source.digest, event]);
      if (seen.has(key) || identities.has(key) && identities.get(key) !== identity) fail();
      seen.add(key); identities.set(key, identity);
    }
    for (const entry of incident.history) if (!object(entry) || !text(entry.status, 4096) || !text(entry.reason, 4096) || !date(entry.triaged_at)) fail();
  }
  return value;
}

export function validateTriageResult(value, id) {
  if (!object(value) || value.status !== 'accepted' || value.resource_id !== id || !text(value.request_id, 255) || value.operation_id !== value.request_id || !object(value.data) || typeof value.data.replayed !== 'boolean') fail();
  return value;
}
