"""Phase 1 tests: collectors, temporal store, attack graph, API."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.blue import recommend_blue_ai
from aegis.collectors import collect
from aegis.collectors import identity, inventory, scanners, scenarios
from aegis.config import ROOT, Settings
from aegis.graph import AttackGraph, diff_paths
from aegis.model import EdgeKind, Node, NodeKind, Observation
from aegis.store import GraphStore

FIXTURES = Path(__file__).parent / "fixtures"
COMPOSE = ROOT / "cyber_range" / "docker-compose.yml"
REALM = ROOT / "cyber_range" / "keycloak" / "aegis-realm.json"
SCENARIOS = ROOT / "experiments" / "scenarios"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    results = tmp_path / "results"
    results.mkdir()
    return Settings(
        db_path=tmp_path / "aegis.db",
        results_dir=results,
        scenarios_dir=SCENARIOS,
        compose_file=COMPOSE,
        realm_file=REALM,
        inventory_mode="compose",
        keycloak_url="",
        frontend_dir=ROOT / "frontend",
    )


def graph_from(store: GraphStore, at: str | None = None) -> AttackGraph:
    return AttackGraph(*store.snapshot(at))


def states(paths) -> list[list[str]]:
    return [p.states for p in paths]


# ----------------------------------------------------------------- collectors
def test_compose_inventory_models_zones_reachability_and_weak_secrets():
    services, evidence = inventory.from_compose(COMPOSE)
    obs = inventory.build_observation(services, "compose", evidence)
    ids = {n.id for n in obs.nodes}

    assert "asset:dashboard" not in ids and "asset:aegis-dashboard" not in ids  # aegis.ignore
    assert "asset:caldera" not in ids  # inactive profile
    assert "control:zap" in ids and "asset:zap" not in ids
    reach = {(e.src, e.dst) for e in obs.edges if e.kind == EdgeKind.CAN_REACH}
    assert ("asset:employee", "asset:database") in reach  # flat-network misconfiguration
    assert ("asset:webapp", "asset:database") not in reach  # segmented
    assert ("asset:internet", "asset:webapp") in reach and ("asset:internet", "asset:keycloak") in reach
    weak = [n for n in obs.nodes if n.kind == NodeKind.VULNERABILITY]
    assert {n.props["location"] for n in weak} == {"database environment", "keycloak environment"}
    assert all("rootpass123" not in json.dumps(n.props) for n in obs.nodes)  # secret values never stored


def test_runtime_inventory_parses_inspect_output():
    container = {
        "Name": "/database",
        "Config": {
            "Image": "mysql:5.7.31",
            "Labels": {"aegis.asset_type": "database", "aegis.crown_jewel": "true", "com.docker.compose.project": "cyber_range"},
            "ExposedPorts": {"3306/tcp": {}},
            "Env": ["MYSQL_ROOT_PASSWORD=rootpass123"],
        },
        "NetworkSettings": {"Networks": {"cyber_range_data_net": {}}},
        "HostConfig": {"PortBindings": {}},
        "State": {"Running": True},
    }
    unrelated = {"Name": "/other", "Config": {"Labels": {}}}
    services, _ = inventory.from_runtime([container, unrelated])
    assert len(services) == 1
    svc = services[0]
    assert svc.networks == ["data_net"] and svc.ports == [3306] and svc.running
    assert svc.secret_findings[0]["variable"] == "MYSQL_ROOT_PASSWORD"


def test_identity_collector_links_roles_sessions_and_idp_trust():
    realm, evidence = identity.realm_from_file(REALM)
    obs = identity.identity_observation(realm, evidence)
    edges = {(e.src, e.kind, e.dst) for e in obs.edges}
    assert ("identity:aegis/bob", EdgeKind.ADMIN_OF, "asset:database") in edges
    assert ("identity:aegis/bob", EdgeKind.SESSION_ON, "asset:employee") in edges
    assert ("identity:aegis/alice", EdgeKind.CAN_LOGIN, "asset:employee") in edges
    assert ("identity:aegis/carol", EdgeKind.TRUSTS, "asset:keycloak") in edges
    bob = next(n for n in obs.nodes if n.id == "identity:aegis/bob")
    assert bob.props["privileged"] is True


def test_zap_collector_normalizes_alerts_and_grants():
    obs = scanners.zap_observation(FIXTURES / "zap-sample.json")
    vulns = {n.props["name"]: n for n in obs.nodes if n.kind == NodeKind.VULNERABILITY}
    sqli = vulns["SQL Injection"]
    assert sqli.props["severity"] == "high" and sqli.props["port"] == 3000 and sqli.props["confidence"] == 0.6
    assert "CWE-89" in sqli.props["classification"]
    grants = [e for e in obs.edges if e.kind == EdgeKind.GRANTS]
    assert [(e.src, e.props["level"]) for e in grants] == [(sqli.id, "app_admin")]  # CSP alert grants nothing


def test_caldera_collector_extracts_attack_technique(tmp_path: Path):
    report = tmp_path / "caldera-op.json"
    report.write_text(json.dumps({
        "steps": {"employee-paw": {"ability": {
            "name": "System Information Discovery", "technique_id": "T1082", "tactic": "discovery", "command": "uname -a"}}}
    }))
    obs = scanners.caldera_observation([report])
    steps = [n for n in obs.nodes if n.kind == NodeKind.ATTACK_STEP]
    assert len(steps) == 1 and steps[0].props["technique"] == "T1082"
    assert (steps[0].id, "asset:employee") in {(e.src, e.dst) for e in obs.edges}


def test_scenarios_only_promote_exploited_ones():
    obs = scenarios.scenario_observation(SCENARIOS)
    vulns = [n for n in obs.nodes if n.kind == NodeKind.VULNERABILITY]
    assert [v.props["scenario"] for v in vulns] == ["SC-001"]  # SC-002 is still pending a scan
    assert vulns[0].props["validated"] and vulns[0].props["attack_steps"]


def test_blue_ai_recommendations():
    assert "parameterized" in " ".join(recommend_blue_ai("SQL Injection", "high", "webapp", "CWE-89").fix_steps).lower()
    headers = recommend_blue_ai("Content Security Policy Header Not Set", "medium", "webapp", "ZAP-10038")
    assert headers.priority == "fix-next" and "Content-Security-Policy" in " ".join(headers.fix_steps)
    assert "Rotate" in recommend_blue_ai("Weak credential", "high", "database", "CWE-521").fix_steps[0]


# --------------------------------------------------------------- temporal store
def _obs(scope: str, *nodes: Node) -> Observation:
    return Observation(collector="test", scope=scope, nodes=list(nodes))


def test_store_versions_changes_and_closes_missing_items():
    store = GraphStore()
    a1 = Node("asset:a", NodeKind.ASSET, {"name": "a", "image": "v1"})
    b = Node("asset:b", NodeKind.ASSET, {"name": "b"})
    store.ingest(_obs("s", a1, b), at="2026-01-01T00:00:00Z")
    stats = store.ingest(_obs("s", Node("asset:a", NodeKind.ASSET, {"name": "a", "image": "v2"})), at="2026-01-02T00:00:00Z")
    assert stats["changed"] == 1 and stats["closed"] == 1

    past, _ = store.snapshot("2026-01-01T12:00:00Z")
    now, _ = store.snapshot("2026-01-03T00:00:00Z")
    assert past["asset:a"].props["image"] == "v1" and "asset:b" in past
    assert now["asset:a"].props["image"] == "v2" and "asset:b" not in now
    assert len(store.history("asset:a")) == 2
    # Re-ingesting identical state is a no-op and does not create a timeline point.
    assert store.ingest(_obs("s", Node("asset:a", NodeKind.ASSET, {"name": "a", "image": "v2"})), at="2026-01-04T00:00:00Z")["unchanged"] == 1
    assert store.change_times()[-1].startswith("2026-01-02")


def test_store_scopes_are_independent_and_props_merge():
    store = GraphStore()
    store.ingest(_obs("inventory", Node("asset:w", NodeKind.ASSET, {"name": "w", "criticality": 0.7})), at="2026-01-01T00:00:00Z")
    store.ingest(_obs("zap", Node("asset:w", NodeKind.ASSET, {"name": "w"})), at="2026-01-01T00:00:01Z")
    store.ingest(_obs("zap"), at="2026-01-01T00:00:02Z")  # zap stops reporting; inventory still does
    nodes, _ = store.snapshot()
    assert nodes["asset:w"].props["criticality"] == 0.7


def test_store_rejects_out_of_order_observations():
    store = GraphStore()
    store.ingest(_obs("s"), at="2026-01-02T00:00:00Z")
    with pytest.raises(ValueError):
        store.ingest(_obs("s"), at="2026-01-01T00:00:00Z")


# --------------------------------------------------------------- attack graph
def test_attack_paths_on_the_range(settings: Settings):
    shutil.copy(FIXTURES / "zap-sample.json", settings.results_dir / "zap-scan.json")
    store = GraphStore(settings.db_path)
    collect(store, settings)
    g = graph_from(store)
    paths = g.attack_paths(limit=100)
    chains = states(paths)

    # Weak signals compose into a multi-step path: cached creds -> privileged identity -> crown jewel.
    assert ["pos:asset:employee", "id:identity:aegis/bob", "app:asset:database"] in chains
    # Trust boundary: compromising the internet-exposed IdP yields every identity it issues.
    assert any(c[0] == "pos:asset:internet" and "app:asset:keycloak" in c and c[-1] == "app:asset:database" for c in chains)
    # The manually exploited SQLi path is the only fully validated kind.
    validated = [p for p in paths if p.status == "validated"]
    assert validated and all(any("scenario/SC-001" in v for v in p.vulnerabilities) for p in validated)
    # Ranked by security value.
    assert [p.security_value for p in paths] == sorted((p.security_value for p in paths), reverse=True)
    # Nothing from the internet reaches the database directly - it is segmented.
    assert ["pos:asset:internet", "vuln:vulnerability:database/weak-credential/mysql_root_password", "app:asset:database"] not in chains


def test_unreachable_vulnerability_is_theoretical():
    nodes = {
        "asset:internet": Node("asset:internet", NodeKind.ASSET, {"entry_point": True, "asset_type": "external"}),
        "asset:island": Node("asset:island", NodeKind.ASSET, {"criticality": 1.0, "crown_jewel": True}),
        "vulnerability:x": Node("vulnerability:x", NodeKind.VULNERABILITY, {"confidence": 0.9}),
    }
    from aegis.model import Edge

    edges = [Edge("asset:island", "vulnerability:x", EdgeKind.HAS_VULNERABILITY),
             Edge("vulnerability:x", "asset:island", EdgeKind.GRANTS, {"level": "app_admin"})]
    g = AttackGraph(nodes, edges)
    assert g.attack_paths() == []
    assert g.unreachable_vulnerabilities() == ["vulnerability:x"]


def test_remediation_closes_path_in_temporal_graph(settings: Settings, tmp_path: Path):
    store = GraphStore(settings.db_path)
    collect(store, settings, at="2026-03-01T00:00:00Z")

    # Remediation: bob no longer leaves credentials on the shared workstation.
    realm = json.loads(REALM.read_text())
    fixed = copy.deepcopy(realm)
    for user in fixed["users"]:
        if user["username"] == "bob":
            user["attributes"] = {}
    fixed_file = tmp_path / "realm-fixed.json"
    fixed_file.write_text(json.dumps(fixed))
    settings.realm_file = fixed_file
    collect(store, settings, at="2026-03-02T00:00:00Z")

    before = graph_from(store, "2026-03-01T12:00:00Z").attack_paths(500)
    after = graph_from(store, "2026-03-02T12:00:00Z").attack_paths(500)
    diff = diff_paths(before, after)
    closed = [p["states"] for p in diff["closed"]]
    assert ["pos:asset:employee", "id:identity:aegis/bob", "app:asset:database"] in closed
    assert diff["exposure_after"] < diff["exposure_before"]


# ------------------------------------------------------------------------ API
def test_api_end_to_end(settings: Settings):
    shutil.copy(FIXTURES / "zap-sample.json", settings.results_dir / "zap-scan.json")
    client = TestClient(create_app(settings))

    assert client.get("/api/health").json()["status"] == "ok"
    paths = client.get("/api/paths").json()
    assert paths["summary"]["paths"] > 0 and paths["summary"]["validated"] >= 1
    assert "pos:asset:employee" in paths["summary"]["entry_points"]

    findings = client.get("/api/findings").json()["findings"]
    sqli = next(f for f in findings if f["name"] == "SQL Injection" and f["source_tool"] == "zap")
    assert sqli["reachability"] == "on_attack_path" and sqli["blue_ai"]["priority"] == "fix-now"
    csp = next(f for f in findings if "Content Security Policy" in f["name"])
    assert csp["reachability"] == "reachable" and csp["attack_paths"] == 0

    graph = client.get("/api/graph").json()
    assert any(n["id"] == "asset:database" for n in graph["nodes"])
    runs = client.get("/api/runs").json()["runs"]
    assert client.get(f"/api/runs/{runs[0]['id']}/evidence").json()
    assert client.post("/api/collect").status_code == 200
    assert client.get("/api/paths", params={"at": "not-a-time"}).status_code == 400
    assert "Attack paths" in client.get("/").text
    assert client.get("/app.js").status_code == 200
