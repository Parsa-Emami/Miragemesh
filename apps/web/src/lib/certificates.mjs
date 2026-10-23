const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value > 0;
const text = value => typeof value === 'string' && value.isWellFormed() && Array.from(value).length > 0 && Array.from(value).length <= 128;
const fields = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key));
const fail = () => { throw new Error('Certificate response is invalid.'); };

function instant(value) {
 if (typeof value !== 'string') return null;
 const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
 if (!match || Number(value.slice(0, 4)) < 1000) return null;
 const milliseconds = Date.parse(match[1] + 'Z');
 if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 19) !== match[1]) return null;
 return BigInt(milliseconds) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0'));
}

export function validateCertificateSnapshot(value) {
 if (!fields(value, ['schema_version', 'issuer_fingerprint', 'observed_at', 'sensors']) || value.schema_version !== '1' || !digest(value.issuer_fingerprint) || !Array.isArray(value.sensors) || value.sensors.length > 8192) fail();
 const now = instant(value.observed_at); if (now === null) fail();
 const sensors = new Set(), identities = new Set();
 for (const sensor of value.sensors) {
  if (!fields(sensor, ['sensor_id', 'revision', 'fingerprint', 'previous_fingerprint', 'overlap_until', 'not_after', 'status', 'recovery_available']) || !text(sensor.sensor_id) || sensors.has(sensor.sensor_id) || !integer(sensor.revision) || !digest(sensor.fingerprint) || identities.has(sensor.fingerprint) || typeof sensor.recovery_available !== 'boolean') fail();
  sensors.add(sensor.sensor_id); identities.add(sensor.fingerprint);
  const expiry = instant(sensor.not_after), deadline = sensor.overlap_until === undefined ? null : instant(sensor.overlap_until);
  if (expiry === null) fail();
  const previous = sensor.previous_fingerprint !== undefined;
  if (previous !== (sensor.overlap_until !== undefined) || sensor.revision === 1 && previous || sensor.revision > 1 && !previous || previous && (!digest(sensor.previous_fingerprint) || sensor.fingerprint === sensor.previous_fingerprint || identities.has(sensor.previous_fingerprint) || deadline === null || deadline >= expiry)) fail();
  if (previous) identities.add(sensor.previous_fingerprint);
  const expired = now >= expiry, overlap = previous && now < deadline;
  if (sensor.status !== (expired ? 'expired' : overlap ? 'overlap' : 'current') || sensor.recovery_available !== (expired || previous && now >= deadline)) fail();
 }
 return value;
}
