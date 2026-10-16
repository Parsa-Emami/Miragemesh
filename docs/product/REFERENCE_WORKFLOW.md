# MirageMesh: reference workflow

Status: planned domain acceptance; the current JSON structure preview does not implement this workflow.

Enroll sensor -> apply signed config -> isolated decoy event -> disconnect -> spool -> reconnect with duplicate ACK test -> triage and retention gap check.

Required invariants:

- No egress by default
- Signed desired state and monotonic apply
- Replay-safe bounded spool with explicit loss accounting

Required UAT:

- sensor معتبر enroll شود؛ token replay و certificate نامعتبر رد شوند
- قطع شبکه و پرشدن spool رفتار مشخص دهد؛ reconnect داده را dedup کند
- decoy به Internet و شبکهٔ داخلی عملیاتی دسترسی نداشته باشد

Machine contract: tests/scenarios/clone-to-value.json. C01/C04 create and freeze the actual synthetic positive/negative fixture formats; no real secrets, user source/traffic/case data or unlicensed corpus. A clean source clone must reproduce the entire workflow with restart and restore at C30.
