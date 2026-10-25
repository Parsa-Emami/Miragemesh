# MirageMesh Deployment & Network Boundaries

## 1. Local-First & Zero Public Domain Architecture

MirageMesh is designed and implemented strictly in accordance with [ADR-0003](../docs/architecture/ADR-0003-open-source-local-first.md):
- **No Owned Public Domain Requirement**: Operating MirageMesh locally or within private networks requires zero public domain ownership, zero public DNS records, and zero external SaaS dependencies.
- **Strict Loopback Binding**: The web shell (`scripts/serve-web.mjs`) and the core Go engine bind exclusively to local loopback addresses (`127.0.0.1` and `::1`). Attempts to bind directly to non-loopback interfaces (such as `0.0.0.0`) are rejected at startup.
- **Loopback Isolation**: The Go engine listens on an ephemeral loopback port (`127.0.0.1:<port>`) and communicates exclusively with the local supervisor via HTTP loopback calls. Engine API endpoints are never exposed to external networks by default.

```
+---------------------------------------------------------------------------------+
|                                Host Boundary                                    |
|                                                                                 |
|  [ Optional Reverse Proxy ]           [ MirageMesh Web Shell ]                  |
|  Nginx / Caddy                       scripts/serve-web.mjs                      |
|  (TLS 1.2/1.3, Deny-All by Default)  (Port 4173 / 4307)                         |
|           |                                    |                                |
|           | proxy_pass http://127.0.0.1:4307   | Loopback IPC                   |
|           +----------------------------------->+                                |
|                                                | http://127.0.0.1:<engine-port> |
|                                                v                                |
|                                      [ MirageMesh Engine ]                      |
|                                      Go runtime (Core Engine)                   |
+---------------------------------------------------------------------------------+
```

---

## 2. Ingress & Origin Boundaries

### 2.1 Host and Origin Header Validation
The web shell verifies the incoming `Host` and `Origin` headers on every request:
1. **Allowed Host Invariant**: The `Host` header must match a permitted loopback authority (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, or port 80/443 without suffix). When running behind a private reverse proxy, explicitly allowed private hostnames can be supplied via configuration. Foreign hosts (e.g. `attacker.example` or subdomain spoofing `127.0.0.1.attacker.example`) immediately receive `403 {"error":"forbidden_origin"}`.
2. **Origin Verification**: When an `Origin` header is present (CORS or state-modifying requests such as incident triage), it must match the server's own origin (`http://<host>` or `https://<host>`). Cross-origin requests or `null` origins are rejected with `403 {"error":"forbidden_origin"}`.

### 2.2 Security Headers
Every HTTP response from the web shell carries defense-in-depth security headers:
- `Content-Security-Policy`: `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`
- `X-Content-Type-Options`: `nosniff`
- `Referrer-Policy`: `no-referrer`
- `Permissions-Policy`: `camera=(), microphone=(), geolocation=()`
- `X-Frame-Options`: `DENY`

---

## 3. Cache Boundaries

To eliminate information leaks and cache poisoning:
- **Dynamic Content & APIs**: `Cache-Control: no-store` is enforced on:
  - Application entry points (`/`, `/index.html`)
  - Runtime configuration (`/runtime-config.json`)
  - Health and readiness probes (`/healthz`, `/readyz`, `/api/diagnostics`, `/api/engine/health`)
  - Sensor, certificate, update, and incident data (`/api/v1/*`)
- **Static Fingerprinted Assets**: `Cache-Control: public, max-age=31536000, immutable` is applied strictly to build artifacts under `/assets/` that contain cryptographic content hashes in their file names.
- **Path Confinement**: Directory traversal attempts (`../`, `%2e%2e/`, Windows backslashes `\`, null bytes `\0`) are intercepted and rejected with `400 {"error":"invalid_path"}`.

---

## 4. Optional Private Hosting with TLS

When private remote access is required by an organization (e.g. over a private VPN or LAN), use a reverse proxy rather than exposing Node.js or the Go engine directly.

### 4.1 Systemd Service
Install the supervised process under `/etc/systemd/system/miragemesh-web.service` using `ops/web/service.systemd`:
```sh
sudo systemctl daemon-reload
sudo systemctl enable --now miragemesh-web
```

### 4.2 Nginx Configuration
Render `ops/web/nginx.conf.template` with local certificates and private IP restrictions:
```nginx
server {
    listen 443 ssl;
    server_name miragemesh.internal; # Or private IP / local name

    ssl_certificate /etc/ssl/certs/miragemesh.crt;
    ssl_certificate_key /etc/ssl/private/miragemesh.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Deny all external traffic by default; permit only reviewed operator ranges
    allow 127.0.0.1;
    allow ::1;
    allow 10.0.0.0/8; # Example trusted operator CIDR
    deny all;

    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:4307;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 20s;
    }
}
```

Validate and reload:
```sh
sudo nginx -t
sudo systemctl reload nginx
```

---

## 5. Verification Commands

Verify network boundaries locally:
```sh
npm run validate:plan
node --test tests/web/network-boundaries.test.mjs
```
