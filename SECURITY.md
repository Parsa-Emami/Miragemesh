# Security Policy

MirageMesh takes the security and integrity of its open-source, local-first software seriously. This document defines our security policy, supported versions, confirmed vulnerability reporting procedures, and disclosure timeline.

---

## 1. Supported Versions

Security updates and patches are provided for the following releases:

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `main` branch | **Yes** | Active development; receives immediate patches. |
| `v0.x` releases | **Yes** | Tagged release artifacts and release branches. |
| Older revisions | No | Users are advised to upgrade to the latest release or `main`. |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or suspect an integrity issue in MirageMesh, **do not open a public GitHub issue, pull request, or forum discussion.** Public disclosure exposes users before a fix can be verified.

### Confirmed Reporting Channels

Please report vulnerabilities through one of our private channels:

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   - Navigate to the repository's **Security** tab.
   - Click **Report a vulnerability** under the Advisories section.
   - Provide a detailed description, reproduction steps, affected versions, and potential impact.

2. **Direct Security Contact (Encrypted Email)**:
   - If GitHub Private Reporting is unavailable, send an email to:
     ```
     security@miragemesh.local
     ```
   - Please include:
     - Clear description of the vulnerability.
     - Minimal proof-of-concept (PoC) or reproduction script.
     - Any proposed remediation or patches.

> [!CAUTION]
> Never include real production secrets, private encryption keys, internal network configurations, or customer data in vulnerability reports. Use synthetic or redacted identifiers.

---

## 3. Scope and Trust Boundaries

### In Scope
- **Go Supervisor & Engine**: Process isolation, loopback enforcement, signal handling, and resource quota management.
- **Sensor Communications**: mTLS validation, certificate parsing, signature verification, and replay protection.
- **Decoy Isolation**: Rootless Podman container constraints, capability dropping, read-only root filesystems, and network confinement (`--network=none`).
- **Data Durability**: Local store permissions (`mode 0700`), atomic manifest publishing, and immutable segment protections.
- **Web Client**: Origin validation, CSP headers, XSS sanitization, and clickjacking defenses.

### Out of Scope
- Attacks requiring prior `root` or administrator access on the operator's host.
- Denial of Service caused by the local operator deliberately exhausting local disk or memory.
- Vulnerabilities in third-party software (e.g. Node.js, Go compiler, Linux kernel) unless caused by a specific MirageMesh misconfiguration.
- Social engineering or physical access attacks.

---

## 4. Response and Disclosure Timeline

We adhere to a standard 90-day responsible disclosure process:

1. **Initial Acknowledgment**: Within **48 hours** of receiving a report.
2. **Triage & Assessment**: Within **5 business days**, the maintainer will validate the issue, determine its severity, and establish a remediation plan.
3. **Fix & Verification**: A patch will be developed and tested privately against acceptance and negative regression suites.
4. **Coordinated Disclosure**: The fix will be tagged, packaged, and published alongside a Security Advisory crediting the finder (unless anonymity is requested).

---

## 5. Security Principles and Limitations

- **Local-First & No Egress**: MirageMesh requires no external cloud connection, telemetry, or remote entitlement servers. The core software operates entirely within the operator's trusted perimeter.
- **Open-Source Guarantee**: All code is available under the [Apache-2.0](LICENSE) license.
- **No Certification Claim**: MirageMesh is provided "as is" under the Apache-2.0 license. No formal commercial certification, warranty, or guarantee of zero vulnerabilities is made.
