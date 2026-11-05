# SC-001 — Manual Graph Representation

> Superseded by the generated graph: `python -m aegis paths` / `GET /api/graph`. Kept as the original hand-drawn reference.

## Nodes
- employee (asset, type: workstation)
- webapp (asset, type: server, image: juice-shop:v14.0.0)
- database (asset, type: database)
- CWE-89 (vulnerability, class: SQL Injection)
- admin_account (identity)
- ZAP (tool, type: application_scanner)

## Edges
(employee) --REACHABLE_VIA--> (range_net) --CONNECTS_TO--> (webapp)
(webapp) --HAS_VULNERABILITY--> (CWE-89)
(ZAP) --DISCOVERED_BY_AUTOMATION--> (CWE-89)
(CWE-89) --LOCATED_AT--> ("POST /rest/user/login")
(CWE-89) --ENABLES--> (authenticate_as: admin_account, no_credentials_required: true)
# Note: Juice Shop stores its data in its own SQLite file, not the range MySQL, so there is
# no admin_account -> database edge. The generated graph (GET /api/graph) reaches the
# database only through the workstation, bob's db-admin role, or the IdP.

## Evidence
- Juice Shop challenge tracker log: "Solved 2-star loginAdminChallenge (Login Admin)"
- Source: `docker logs webapp --since 10m`
- Timestamp: 2026-09-17 (session date)
- Automation status: pending ZAP confirmation in `experiments/results/zap-scan-SC-series.json`
