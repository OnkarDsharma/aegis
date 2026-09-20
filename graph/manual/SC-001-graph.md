# SC-001 — Manual Graph Representation

## Nodes
- employee (asset, type: workstation)
- webapp (asset, type: server, image: juice-shop:v14.0.0)
- database (asset, type: database)
- CWE-89 (vulnerability, class: SQL Injection)
- admin_account (identity)

## Edges
(employee) --REACHABLE_VIA--> (range_net) --CONNECTS_TO--> (webapp)
(webapp) --HAS_VULNERABILITY--> (CWE-89)
(CWE-89) --LOCATED_AT--> ("POST /rest/user/login")
(CWE-89) --ENABLES--> (authenticate_as: admin_account, no_credentials_required: true)
(admin_account) --HAS_ACCESS--> (database)   # implied next attack hop, not yet exploited

## Evidence
- Juice Shop challenge tracker log: "Solved 2-star loginAdminChallenge (Login Admin)"
- Source: `docker logs webapp --since 10m`
- Timestamp: 2026-09-17 (session date)