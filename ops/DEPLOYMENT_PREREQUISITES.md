# MirageMesh operational prerequisites

Selected mode: embedded-private. No deployment has been performed.

- collector هدف 2 vCPU / 2 GiB RAM / 20 GiB SSD؛ sensor روی host مجزا یا segment ایزوله آزمون شود.
- نرخ پایدار منتشرشده ۸ رویداد بر ثانیه با ۵ sensor است و در C28 روی همان ۲ vCPU / ۲۰۴۸ MiB با cgroup محدودکننده اندازه‌گیری شد؛ هدف پیشین ۲۰ رویداد بر ثانیه پشتیبانی نشد و کاهش یافت. جزئیات و host در docs/evidence/performance.json آمده است.
- Runtime dependencies: Go sensor and collector, rootless Podman optional decoy adapter, SQLite metadata/spool, Segmented JSONL events. Exact supported pins are resolved at C02; no version assumptions from v7.
- DNS/subdomain and HTTPS for a web app. Private access for stateful modes. Static mode needs no server project-data DB.
- Persistent local volumes for embedded stores; independent consistent backup and sufficient disk for raw data, derived files and temporary staging.
- No exposed DB/engine socket. Runtime secret references via platform injection, never committed env values. Identity provider trust and TLS expiry monitored where used.
- Static demo data only in public profile. Private sensors/labs/provider/evidence workers remain separate from public demo.
- Document export/restore and data portability; run UAT on target host before real sensitive data.

Capacity settings are in product/project.json and reflect the C28 measurement; a host with different resources needs its own benchmark before it publishes these numbers. Ephemeral/serverless deployments of stateful profiles require separate persistent storage architecture and are not the default.

Costs: estimate domain + compute-hours + persistent GiB + backup GiB + egress + provider/support cost from chosen vendor at deployment time. No current hosting quote or paid plan is assumed. Online third-party management reduces administration, not necessarily cost or storage use.
