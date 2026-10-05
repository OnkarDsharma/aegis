# AEGIS Results Artifacts

Place generated tool reports here for the dashboard to ingest:

- `zap-scan-SC-series.json` from OWASP ZAP
- `caldera-op-SC-series.json` from MITRE Caldera

The dashboard intentionally falls back to the checked-in manual scenario files
when no automated reports exist yet, so the UI can still be smoke-tested before
the first range run.
