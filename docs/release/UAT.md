# MirageMesh acceptance gate

All scenarios are unexecuted in v0. Use synthetic or explicitly authorized owned data.

1. sensor معتبر enroll شود؛ token replay و certificate نامعتبر رد شوند
2. قطع شبکه و پرشدن spool رفتار مشخص دهد؛ reconnect داده را dedup کند
3. decoy به Internet و شبکهٔ داخلی عملیاتی دسترسی نداشته باشد

Also require negative input/auth tests, crash or interrupted operation, clean install/upgrade, export/restore and workload bounds. Claims must match selected private/public distribution profile.
