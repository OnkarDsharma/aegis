# AEGIS: RedBlue Loop

Research prototype of the *Autonomous Red-Blue AI Defense Platform* PRD:
observe, discover, attack, detect, respond, verify, learn, all inside an isolated cyber range.

**Status: Phases 1–3 are done.** Discovery, the temporal attack graph and path scoring (Phase 1); a safety-gated
non-destructive red agent (Phase 2); and a blue agent with a remediation proof engine and a tamper-evident evidence
ledger (Phase 3). Phase 4 (pilot metrics) is next. See [the runbook](docs/midsem-runbook.md).

## Layout

```
aegis/                 Python package
  model.py             vendor-neutral node/edge model (FR-2)
  store.py             temporal SQLite graph store, valid_from/valid_to versions (FR-5)
  graph.py             attack-graph compiler, path finding and scoring (FR-6, FR-7, FR-9)
  collectors/          inventory (compose / docker inspect), Keycloak, ZAP, Caldera, scenarios (FR-1, FR-33)
  blue.py              rule-based remediation advice (FR-14, fallback)
  safety.py            policy-as-code, independent safety agent, kill switch (FR-17/18/19)
  environments.py      twin/canary/range routing, fidelity, availability (FR-23/24/22)
  redteam.py           bounded non-destructive validation actions (FR-9/10/11)
  cleanup.py           cleanup + residual-artifact scan (FR-20)
  detection.py         Sigma-style detection over telemetry (FR-13)
  blueteam.py          fix proposals + remediation proof engine (FR-14/25/26/27)
  ledger.py            hash-chained append-only evidence ledger (FR-28/29/30)
  loop.py              observe->attack->detect->respond->verify->learn orchestrator
  api.py               FastAPI service + dashboard
cyber_range/           the range: Juice Shop, MySQL, workstation, Keycloak, ZAP, Caldera
experiments/scenarios  manually validated exploit scenarios (SC-*.yaml)
experiments/results    tool reports dropped here are ingested (git-ignored)
frontend/              dashboard (static HTML/JS)
tests/                 pytest suite
```

## Quick start (no containers needed)

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'
```

```bash
.venv/bin/python -m aegis collect      # run collectors, write var/aegis.db
```

```bash
.venv/bin/python -m aegis paths        # print ranked attack paths
```

```bash
.venv/bin/python -m aegis serve        # dashboard + API on http://127.0.0.1:8000
```

```bash
.venv/bin/python -m pytest
```

Without a running range, inventory comes from `cyber_range/docker-compose.yml` and identities come from
`cyber_range/keycloak/aegis-realm.json`. When containers are running, inventory comes from `docker`/`podman inspect`.
Keycloak is read through its admin API when `AEGIS_KEYCLOAK_URL` is set.

## How the attack graph works

Collectors write **observations** into the temporal store. Each collector owns a *scope*. Re-collecting closes
anything the collector no longer sees, so a fixed vulnerability or revoked role drops out of the graph from that
moment on, and the past state is still queryable (`?at=<ISO time>`).

The knowledge graph is compiled into an **attack graph** of attacker privilege states:
`pos:` (foothold), `app:` (app admin), `data:`, `id:` (identity) and `vuln:` (exploit step). Paths run from entry
points (the internet, and assets labelled `aegis.entry_point`) to objectives (crown jewels, assets with
criticality ≥ 0.7, and privileged identities). Each path is scored as:

```
security_value = impact × reachability × confidence − 0.25 × operational_risk
```

Each path also gets a status (FR-7):
- **validated**: every exploit step has recorded evidence
- **exploitable**: reachable, with confidence ≥ 0.3
- **theoretical**: everything else

Vulnerabilities that no entry point can reach are listed separately.

On the current range the engine finds, among others:

- internet → SQL injection on Juice Shop → webapp admin (**validated** by SC-001)
- workstation → bob's cached credentials → `db-admin` role → database (weak signals composed into one path, FR-8)
- internet → weak Keycloak bootstrap password → IdP admin → any identity → database (trust-boundary abuse, FR-6)
- workstation → MySQL on the flat `data_net` → weak root password → database

## The red-blue loop (Phases 2-3)

`POST /api/engage` (or `python -m aegis engage`) runs one safety-constrained pass:

1. **Attack** - the red agent plans bounded, **non-destructive** validation actions for the exploit steps on the
   top attack paths. Each action is grounded in the graph: it "succeeds" only if its target is genuinely reachable,
   so a finding is marked *validated* only on real evidence, never a guess.
2. **Safety gate** - an independent safety agent evaluates every action against [`policy.yaml`](policy.yaml) (default
   deny: technique, target and environment must all be allowed), estimates blast radius, enforces rate limits and
   approval thresholds, and honours a **kill switch** that fails closed. The planner cannot bypass it.
3. **Route** - the environment router sends each action to the twin, a canary, or the range by operational risk, and
   blocks production changes when twin fidelity is below threshold.
4. **Detect** - a Sigma-style engine records whether each validation was detected, missed, or detected late.
5. **Respond** - the blue agent proposes fixes (WAF virtual patch, secret rotation, segmentation, identity hygiene,
   detection rules), each with predicted impact, a rollback plan and an approval tier.
6. **Verify (proof engine)** - for each fix it re-runs *the exact validated attack* against the post-fix graph and
   records pass/fail, and runs regression checks so a fix that breaks a legitimate workflow is rejected.
7. **Learn** - every step is written to a hash-chained evidence ledger. A success/closure claim with no attached
   evidence is refused (FR-29), and the chain is verifiable (FR-30).

Applying a proven fix to the live range stays a human step (edit compose/realm, then re-collect); the proof shows it
will work first. On the current range the loop validates 3 paths, proves 4 fixes, and cuts the exposure score by
roughly two thirds.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness |
| POST | `/api/collect` | run all collectors now |
| GET | `/api/paths?at=` | ranked attack paths + summary |
| GET | `/api/paths/diff?before=&after=` | paths opened/closed between two instants, exposure delta |
| GET | `/api/findings?at=` | vulnerabilities and attack steps with reachability + Blue AI advice |
| GET | `/api/graph?at=` | the knowledge graph |
| GET | `/api/timeline` | instants at which the graph changed |
| GET | `/api/runs`, `/api/runs/{id}/evidence` | collector runs and their source hashes |
| GET | `/api/nodes/{id}/history` | every version of a node |
| POST | `/api/engage` | run one safety-gated red-blue loop; returns the engagement report |
| GET | `/api/policy` | the active policy and kill-switch state |
| POST | `/api/kill-switch?engage=` | trip or reset the kill switch |
| GET | `/api/ledger`, `/api/ledger/verify` | the evidence ledger and its integrity check |

## Configuration

All settings are `AEGIS_*` environment variables (see `aegis/config.py`): `AEGIS_DB`, `AEGIS_RESULTS_DIR`,
`AEGIS_SCENARIOS_DIR`, `AEGIS_COMPOSE_FILE`, `AEGIS_REALM_FILE`, `AEGIS_INVENTORY` (`auto|compose|runtime`),
`AEGIS_KEYCLOAK_URL`/`_REALM`/`_ADMIN`/`_PASSWORD`, `AEGIS_POLICY_FILE`, `AEGIS_LEDGER`, `AEGIS_KILL_SWITCH`,
`AEGIS_HOST`, `AEGIS_PORT`.

All passwords in `cyber_range/` are lab-only test values for the isolated range.
