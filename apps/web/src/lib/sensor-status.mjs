const timestamp = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$/;

export function validateSensorSnapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema_version !== '1' ||
      !Number.isSafeInteger(value.offline_after_seconds) || value.offline_after_seconds <= 0 || !Array.isArray(value.sensors)) {
    throw new Error('Invalid sensor status response.');
  }
  const seen = new Set();
  for (const sensor of value.sensors) {
    const validId = typeof sensor?.sensor_id === 'string' && Array.from(sensor.sensor_id).length > 0 && Array.from(sensor.sensor_id).length <= 128;
    if (!sensor || typeof sensor !== 'object' || Array.isArray(sensor) || !validId || seen.has(sensor.sensor_id) ||
        !(sensor.last_event_at === null || typeof sensor.last_event_at === 'string' && timestamp.test(sensor.last_event_at) && Number.isFinite(Date.parse(sensor.last_event_at))) ||
        typeof sensor.offline !== 'boolean' || !['missing', 'expired', 'current'].includes(sensor.config_status) ||
        !Number.isSafeInteger(sensor.dropped_event_count) || sensor.dropped_event_count < 0) {
      throw new Error(seen.has(sensor?.sensor_id) ? 'Duplicate sensor in status response.' : 'Invalid sensor status response.');
    }
    seen.add(sensor.sensor_id);
  }
  return value;
}
