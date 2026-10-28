# Security Policy

## 1. Supported Versions

`main` is the active maintenance line for the local profile. Historical commits
and `v0.x` tags have no blanket backport or lifetime guarantee. Support for a
future published release must be declared in its release notes. See
[MAINTENANCE.md](docs/release/MAINTENANCE.md) for versions, platforms, dependency
review and source-bound checks; C40 publication remains a separate gate.

## 2. Reporting a Vulnerability

For security vulnerabilities, **do not open a public GitHub issue**, public pull
request or discussion containing exploit details or sensitive data.

Use **GitHub Private Vulnerability Reporting** if the repository's Security tab
offers **Report a vulnerability**:
[private report form](https://github.com/Parsa-Emami/Miragemesh/security/advisories/new).
The presence of that form is conditional; this document does not confirm that
the repository setting is enabled. No alternate private mailbox is currently
confirmed. The former `.local` address was a placeholder and is not a contact
channel. If the private form is unavailable, retain the report privately;
do not work around it by publishing an exploit or secrets in an ordinary issue.

Include affected commit/version, platform and tool versions, impact, and a
minimal synthetic reproduction. Omit production keys, raw tokens, host secrets,
private network details, accepted ledgers and customer traffic.

## 3. Scope and Trust Boundaries

The supported single-operator Linux profile covers engine lifecycle, loopback
Host/Origin guards, event/config validation, mTLS identity and revocation,
rootless decoy isolation, local file-store durability, signed update authority
and inert browser rendering. See [THREAT_MODEL.md](docs/security/THREAT_MODEL.md)
and the [executable security matrix](tests/release/security-matrix.md).

Public multi-tenancy, OS/root/same-UID compromise, physical storage access and
unsupported platforms are not certified trust boundaries. Third-party defects
should also be reported through that upstream's private process where
available; a MirageMesh configuration or integration defect remains relevant
here. MirageMesh does not encrypt stored files or guarantee secure erasure.
[SERVICE_POLICY.md](docs/release/SERVICE_POLICY.md) documents retained data,
backup/restore, deletion limits and prepared-runtime no-egress behavior.

## 4. Response and Disclosure Timeline

Community security work is best effort. There is no guaranteed 48-hour
acknowledgment, five-business-day triage, fixed disclosure deadline, on-call
coverage or remediation SLA. When a private reporting route is available,
coordinate disclosure with the maintainer. Record actual affected/fixed source,
verified regressions and release information with any eventual advisory; do not
announce a patch or release before it has been tested and published.

## 5. Security Principles and Limitations

All core source is Apache-2.0 with inventoried compatible upstream notices.
There is no required hosted subscription, paid core feature or cloud entitlement.
The prepared local runtime sends no telemetry or automatic update request;
dependency/image preparation can download pinned resources explicitly.
The software is provided as is under [LICENSE](LICENSE). No commercial
certification, uptime, zero-vulnerability or zero-loss guarantee is made.
