# AEGIS: RedBlue Loop

Research prototype of the *Autonomous Red-Blue AI Defense Platform* PRD:
observe, discover, attack, detect, respond, verify, learn, all inside an isolated cyber range.

**Status: Phases 1–7 are done.** Discovery, the temporal attack graph and path scoring (Phase 1); a safety-gated
non-destructive red agent (Phase 2); a blue agent with a remediation proof engine and a tamper-evident evidence
ledger (Phase 3); a pilot metrics + reporting layer that quantifies the Success Metrics against targets (Phase 4);
an adaptive, multi-round red-blue campaign with a learned planner and tiered auto-remediation (Phase 5); broader
coverage collectors for multi-cloud, Kubernetes and OT/endpoints (Phase 6); and a cross-tool control compiler that
turns a proven fix into concrete per-tool controls plus a change ticket / CMDB record (Phase 7).
See [the runbook](docs/midsem-runbook.md).

## Layout

```
aegis/                 Python package
  model.py             vendor-neutral node/edge model (FR-2)
  store.py             temporal SQLite graph store, valid_from/valid_to versions (FR-5)
  graph.py             attack-graph compiler, path finding and scoring (FR-6, FR-7, FR-9)
  collectors/          inventory (compose / docker inspect), Keycloak, ZAP, Caldera, scenarios (FR-1, FR-33)
  collectors/cloud.py  multi-cloud inventory export -> assets/identities/misconfigs (Phase 6, FR-4)
  collectors/kubernetes.py  k8s cluster export -> workloads/RBAC/netpol (Phase 6, FR-4)
  collectors/ot.py     OT/ICS asset register + remote endpoints (Phase 6, FR-4)
  blue.py              rule-based remediation advice (FR-14, fallback)
  safety.py            policy-as-code, independent safety agent, kill switch (FR-17/18/19)
  environments.py      twin/canary/range routing, fidelity, availability (FR-23/24/22)
  redteam.py           bounded non-destructive validation actions (FR-9/10/11)
  cleanup.py           cleanup + residual-artifact scan (FR-20)
  detection.py         Sigma-style detection over telemetry (FR-13)
  blueteam.py          fix proposals + remediation proof engine (FR-14/25/26/27)
  ledger.py            hash-chained append-only evidence ledger (FR-28/29/30)
  loop.py              observe->attack->detect->respond->verify->learn orchestrator
  metrics.py           pilot Success Metrics + executive report (Phase 4, FR-36/37)
  adaptive.py          multi-round red-blue co-learning + tiered auto-remediation (Phase 5, FR-11/15/16/27)
  compiler.py          cross-tool security control compiler (Phase 7, FR-35)
  integrations.py      ticketing / CMDB change records (Phase 7, FR-34)
  api.py               FastAPI service + dashboard
cyber_range/coverage/  example cloud / kubernetes / OT exports the coverage collectors ingest (Phase 6)
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

## Pilot metrics (Phase 4)

`POST /api/pilot` (or `python -m aegis pilot`) measures the PRD Success Metrics from the recorded evidence and scores
them against pilot targets, producing an exportable executive report (FR-36/37). It runs the loop several times to
prove the results are **repeatable** (the engagement is deterministic, so the score is 100%). Categories: speed,
exposure (% paths closed, exposure reduction, exploit-success drop), detection (false-negative rate, latency), safety
(blocked-action rate, verified-cleanup rate, zero outages), business impact (availability, regression rate), learning
(novel paths, repeatability) and efficiency (proven fixes, analyst hours saved). On the current range it reports 100%
path-closure, ~68% exposure reduction and all targets met.

## Adaptive campaign (Phase 5)

`POST /api/campaign` (or `python -m aegis campaign`) runs several rounds of red-blue **co-adaptation**:

- The red planner is a UCB bandit over *path arms* (objective + technique). A path that gets blocked, detected, or is
  already closed earns a low reward, so the planner stops re-picking easy, low-impact wins (FR-11). The reward follows
  the PRD's closed-loop formula: exposure reduction + detection quality − operational risk − availability penalty.
- Proven fixes pass through a **tiered gate**: the low-risk tiers auto-apply, higher tiers are staged for a human
  (FR-15). Applying a fix is a pure graph transform, so each round's graph is the previous one with the applied fixes
  composed on. A conflict resolver keeps the least-disruptive fix when two touch the same element (FR-16), and a
  regression monitor flags any path that was closed earlier but is reachable again (FR-27).

On the current range the campaign converges in a few rounds, auto-applying the proven low-risk fixes and driving the
exposure score from ~7.2 down to ~0.8 with no regressions, every step backed by the hash-chained ledger.

## Broader coverage (Phase 6)

The discovery layer extends past the Docker range to a hybrid estate (FR-4). Three collectors read declarative exports
under `cyber_range/coverage/` and normalize them into the same vendor-neutral model, so the attack graph, red/blue
agents and proof engine work on them unchanged:

- **Multi-cloud** (`cloud-*.json`) - AWS/GCP compute, managed databases, object storage, IAM identities and
  federation. Misconfigurations (public buckets, wide-open security groups, token-reachable metadata) become
  attack-path steps, and identity federation is modelled as a trust boundary (FR-6).
- **Kubernetes** (`k8s-*.json`) - namespaces as zones, workloads as assets, a missing NetworkPolicy as flat
  reachability, and over-broad RBAC / privileged pods as weaknesses reaching the crown-jewel workload.
- **OT / endpoints** (`ot-*.json`) - Purdue-style zones, PLCs/HMIs/historians (a safety-critical PLC is a crown
  jewel), remote laptops as assumed-breach entry points, and unauthenticated field protocols as weaknesses.

With the examples enabled, the estate grows to 25 attack paths spanning on-prem, cloud, Kubernetes and OT, and a full
engagement validates and proves fixes across all four domains. Point `AEGIS_COVERAGE_DIR` elsewhere (or at a missing
dir) to turn the extra coverage off.

## Cross-tool control compiler (Phase 7)

`POST /api/compile` (or `python -m aegis compile`) takes every **proven** fix and compiles it into the concrete,
tool-specific controls that realize it on the stack the asset actually lives on (FR-35, Differentiation #7), instead
of leaving an operator to translate a recommendation by hand:

- segmentation -> an AWS security-group edit, a Kubernetes `NetworkPolicy`, an OT protocol gateway, or an iptables
  rule, chosen from the target's type; WAF -> a ModSecurity virtual patch; weak secret -> a secrets-manager rotation;
  RBAC -> a least-privilege binding; plus a SIEM detection for the behaviour the fix just closed.
- Each change ships the rendered artifact (the actual rule / manifest / command) and a rollback, and every
  remediation also produces a change **ticket** (Jira / ServiceNow shape) and a **CMDB** record referencing the proof
  and the ledger (FR-34). Nothing is pushed to a live system - compilation produces the reviewable change set.

On the hybrid estate this compiles 13 proven fixes into controls across ten tools (ModSecurity, Vault, iptables,
Kubernetes, kubernetes-rbac, aws-s3, aws-security-group, cloud-compute, ot-firewall, sigma-siem).

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
| POST | `/api/pilot?repeat=` | measure pilot Success Metrics + executive report, scored against targets (Phase 4) |
| POST | `/api/campaign?rounds=&paths_per_round=` | run the adaptive multi-round red-blue campaign (Phase 5) |
| POST | `/api/compile?top_paths=` | compile proven fixes into cross-tool controls + change tickets / CMDB (Phase 7) |
| GET | `/api/policy` | the active policy and kill-switch state |
| POST | `/api/kill-switch?engage=` | trip or reset the kill switch |
| GET | `/api/ledger`, `/api/ledger/verify` | the evidence ledger and its integrity check |

## Configuration

All settings are `AEGIS_*` environment variables (see `aegis/config.py`): `AEGIS_DB`, `AEGIS_RESULTS_DIR`,
`AEGIS_SCENARIOS_DIR`, `AEGIS_COMPOSE_FILE`, `AEGIS_REALM_FILE`, `AEGIS_INVENTORY` (`auto|compose|runtime`),
`AEGIS_KEYCLOAK_URL`/`_REALM`/`_ADMIN`/`_PASSWORD`, `AEGIS_POLICY_FILE`, `AEGIS_LEDGER`, `AEGIS_KILL_SWITCH`,
`AEGIS_HOST`, `AEGIS_PORT`.

All passwords in `cyber_range/` are lab-only test values for the isolated range.
