# MirageMesh product requirements v0

Status: planning; application source not implemented. English-facing app/docs are the release default. See Persian assessment for commercial hypotheses.

Target user: اپراتور lab و مدیر شبکهٔ کوچک

Job to complete: sensor کم‌مصرف با مشاهدهٔ وضعیت و replay امن

Differentiation hypothesis: یک decoy محدود و no-egress، صف آفلاین و alert قابل‌توضیح

## MVP acceptance scope

- یک sensor مجاز و یک HTTP decoy ساده
- کنترل‌پنل خصوصی و هویت mTLS
- desired/applied state امضاشده
- رویداد offline spool، dedup و triage

## Excluded until another decision

- ده‌ها protocol decoy
- fleet جهانی
- دریافت خودکار malware
- public decoy hosting چند مشتری

## End-to-end outcomes

1. sensor معتبر enroll شود؛ token replay و certificate نامعتبر رد شوند
2. قطع شبکه و پرشدن spool رفتار مشخص دهد؛ reconnect داده را dedup کند
3. decoy به Internet و شبکهٔ داخلی عملیاتی دسترسی نداشته باشد

Functional requirements F01–F20 and nonfunctional/release requirements are mapped one-to-one in `plans/requirements.json`. Tests belong with their feature commit, not postponed until launch. Success: a clean installed selected profile performs the core task and recovers from documented failures. Public demand remains unvalidated until real trials are recorded.

## UI flow

Select/import scoped input -> validate limits and permission -> show actual processing state -> explain result and confidence -> review/triage where appropriate -> export -> recover in clean environment. Loading, empty, stale, partial, unauthorized, rejected input, timeout/cancel and permanent failure are explicit. Provide table/keyboard alternatives to canvas, charts and graph paths. No sensitive content in page telemetry.
