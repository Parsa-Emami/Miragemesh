#!/usr/bin/env bash
set -euo pipefail
umask 077
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ ! -x "$repo/dist/engine/miragemesh" || ! -f "$repo/dist/web/index.html" ]]; then
  printf '%s\n' 'Run npm ci --ignore-scripts and npm run build before creating the lab.' >&2
  exit 1
fi
lab="$(mktemp -d "${TMPDIR:-/tmp}/miragemesh-lab.XXXXXXXX")"
lab="$(cd "$lab" && pwd -P)"
collector_port="${MIRAGEMESH_LAB_COLLECTOR_PORT:-9443}"
team_port="${MIRAGEMESH_LAB_TEAM_PORT:-9444}"
sensor_port="${MIRAGEMESH_LAB_SENSOR_PORT:-9080}"
health_port="${MIRAGEMESH_LAB_HEALTH_PORT:-9081}"
for port in "$collector_port" "$team_port" "$sensor_port" "$health_port"; do
  if [[ ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || ((port < 1024 || port > 65535)); then
    printf '%s\n' 'Choose unprivileged TCP ports from 1024 through 65535.' >&2
    exit 2
  fi
done
if [[ "$(printf '%s\n' "$collector_port" "$team_port" "$sensor_port" "$health_port" | sort -u | wc -l)" -ne 4 ]]; then
  printf '%s\n' 'Choose four distinct ports.' >&2
  exit 2
fi

issue() {
  local identity="$1" usage="$2" serial="$3" authority="$4"
  local destination="$authority/$identity"
  openssl genpkey -algorithm ED25519 -out "$destination.key"
  openssl req -new -key "$destination.key" -subj "/CN=$identity" -out "$destination.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$usage" > "$destination.ext"
  if [[ "$usage" == serverAuth ]]; then
    printf 'subjectAltName=IP:127.0.0.1\n' >> "$destination.ext"
  fi
  openssl x509 -req -in "$destination.csr" -CA "$authority/ca.crt" -CAkey "$authority/ca.key" \
    -set_serial "$serial" -days 3 -extfile "$destination.ext" -out "$destination.crt"
}

authority() {
  local name="$1" dir="$lab/$1"
  mkdir "$dir"
  openssl genpkey -algorithm ED25519 -out "$dir/ca.key"
  openssl req -new -x509 -key "$dir/ca.key" -subj "/CN=MirageMesh $name local lab CA" -days 4 \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$dir/ca.crt"
  : > "$dir/index.txt"
  printf '01\n' > "$dir/crlnumber"
  cat > "$dir/ca.cnf" <<EOF
[ca]
default_ca=issuer
[issuer]
database="$dir/index.txt"
crlnumber="$dir/crlnumber"
certificate="$dir/ca.crt"
private_key="$dir/ca.key"
default_md=default
default_crl_days=3
EOF
  openssl ca -gencrl -config "$dir/ca.cnf" -out "$dir/ca.crl"
  issue server serverAuth 2 "$dir"
  issue client clientAuth 3 "$dir"
}

authority collector
authority operator
openssl pkcs12 -export -inkey "$lab/operator/client.key" -in "$lab/operator/client.crt" \
  -certfile "$lab/operator/ca.crt" -name 'MirageMesh Lab Analyst' -passout pass: -out "$lab/operator/analyst.p12"

node --input-type=module - "$lab" "$repo/dist/web" "$collector_port" "$team_port" "$sensor_port" "$health_port" <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
const [lab, web, collectorPort, teamPort, sensorPort, healthPort] = process.argv.slice(2);
const listener = (group, port) => ({
  listen: '127.0.0.1:' + port,
  certificate: lab + '/' + group + '/server.crt',
  key: lab + '/' + group + '/server.key',
  ca: lab + '/' + group + '/ca.crt',
  crl: lab + '/' + group + '/ca.crl',
});
const fingerprint = group => new X509Certificate(readFileSync(lab + '/' + group + '/client.crt')).fingerprint256.replaceAll(':', '').toLowerCase();
const write = (name, value) => writeFileSync(lab + '/' + name, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
write('monitor.json', {
  state_dir: lab + '/state', web_dir: web, retention_hours: 24,
  max_events_per_hour: 400, max_event_age_minutes: 60, requests_per_hour_alert: 5,
  workspace_origin: 'https://127.0.0.1:' + teamPort,
  collector: listener('collector', collectorPort), workspace: listener('operator', teamPort),
  sensors: { [fingerprint('collector')]: ['lab-decoy'] },
  operators: { [fingerprint('operator')]: { id: 'lab-analyst', role: 'analyst', sensors: ['lab-decoy'] } },
});
write('sensor.json', {
  sensor_id: 'lab-decoy', listen: '127.0.0.1:' + sensorPort, health_listen: '127.0.0.1:' + healthPort,
  spool_dir: lab + '/spool', queue_limit: 100, collector_origin: 'https://127.0.0.1:' + collectorPort,
  ca: lab + '/collector/ca.crt', certificate: lab + '/collector/client.crt', key: lab + '/collector/client.key',
});
JS

printf '\nLab directory: %s\n' "$lab"
printf 'Collector and workspace: %q --monitor-config %q\n' "$repo/dist/engine/miragemesh" "$lab/monitor.json"
printf 'HTTP sensor: %q --monitor-sensor-config %q\n' "$repo/dist/engine/miragemesh" "$lab/sensor.json"
printf 'Observation: curl -fsS %q\n' "http://127.0.0.1:$sensor_port/example"
printf 'Inspect: curl -fsS --cacert %q --cert %q --key %q %q\n' \
  "$lab/operator/ca.crt" "$lab/operator/client.crt" "$lab/operator/client.key" "https://127.0.0.1:$team_port/api/team/v1/incidents"
printf 'Workspace: https://127.0.0.1:%s/\n' "$team_port"
printf 'Browser lab certificate: %s\n' "$lab/operator/analyst.p12"
