"""Phase 6 (broader coverage: cloud / kubernetes / OT collectors, FR-4) and
Phase 7 (cross-tool control compiler + ticketing/CMDB, FR-34/35) tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.blueteam import BlueAgent, Fix, ProofEngine
from aegis.collectors import cloud, collect, kubernetes, ot
from aegis.compiler import ControlCompiler
from aegis.config import ROOT, Settings
from aegis.detection import DetectionEngine
from aegis.graph import AttackGraph
from aegis.integrations import TicketingAdapter
from aegis.model import EdgeKind, Node, NodeKind, node_id
from aegis.redteam import RedAgent
from aegis.store import GraphStore

COVERAGE = ROOT / "cyber_range" / "coverage"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    results = tmp_path / "results"
    results.mkdir()
    return Settings(
        db_path=tmp_path / "aegis.db",
        results_dir=results,
        scenarios_dir=ROOT / "experiments" / "scenarios",
        compose_file=ROOT / "cyber_range" / "docker-compose.yml",
        realm_file=ROOT / "cyber_range" / "keycloak" / "aegis-realm.json",
        policy_file=ROOT / "policy.yaml",
        ledger_path=tmp_path / "ledger.jsonl",
        kill_switch_file=tmp_path / "KILL",
        coverage_dir=COVERAGE,
        inventory_mode="compose",
        keycloak_url="",
        frontend_dir=ROOT / "frontend",
    )


@pytest.fixture
def graph(settings: Settings) -> AttackGraph:
    store = GraphStore(settings.db_path)
    collect(store, settings)
    return AttackGraph(*store.snapshot())


# ============================================================ Phase 6: collectors
def test_cloud_collector_normalizes_estate_and_misconfigs():
    data, ev = cloud.from_file(COVERAGE / "cloud-estate.json")
    obs = cloud.cloud_observation(data, ev)
    ids = {n.id for n in obs.nodes}
    assert "asset:cloud-orders-db" in ids and "asset:cloud-backups" in ids
    # a public bucket is a vulnerability granting data read
    vulns = [n for n in obs.nodes if n.kind == NodeKind.VULNERABILITY]
    assert any("publicly readable" in n.name for n in vulns)
    assert all(n.props.get("remediation") for n in vulns)       # every finding has a fix hint
    # identity federation is modelled as a TRUSTS edge (FR-6)
    assert any(e.kind == EdgeKind.TRUSTS for e in obs.edges)
    # no secret values, only metadata
    assert ev["sha256"] and obs.scope == "cloud"


def test_kubernetes_collector_models_rbac_and_flat_reachability():
    data, ev = kubernetes.from_file(COVERAGE / "k8s-cluster.json")
    obs = kubernetes.kubernetes_observation(data, ev)
    ids = {n.id for n in obs.nodes}
    assert "asset:payments-db" in ids and "network:ns/payments" in ids
    assert any(n.props.get("crown_jewel") for n in obs.nodes if n.kind == NodeKind.ASSET)
    # a segmentable (missing-NetworkPolicy) reachability edge exists
    assert any(e.kind == EdgeKind.CAN_REACH and e.props.get("segmentable") for e in obs.edges)
    # cluster-admin RBAC becomes a vulnerability granting app admin
    assert any("ClusterRole" in n.name or "cluster-admin" in n.name.lower()
               for n in obs.nodes if n.kind == NodeKind.VULNERABILITY)


def test_ot_collector_models_zones_plc_and_entry_endpoint():
    data, ev = ot.from_file(COVERAGE / "ot-assets.json")
    obs = ot.ot_observation(data, ev)
    plc = next(n for n in obs.nodes if n.id == "asset:plc-line-1")
    assert plc.props["crown_jewel"] and plc.props["asset_type"] == "ot-plc"
    laptop = next(n for n in obs.nodes if n.id == "asset:engineer-laptop")
    assert laptop.props["entry_point"] and laptop.props["asset_type"] == "endpoint"
    # the unauthenticated field protocol grants app admin on the PLC
    assert any(e.kind == EdgeKind.GRANTS for e in obs.edges
               if e.src.startswith("vulnerability:") and e.dst == "asset:plc-line-1")


def test_coverage_produces_cross_domain_attack_paths(graph: AttackGraph):
    objectives = set(graph.objectives())
    assert any("cloud-orders-db" in o for o in objectives)
    assert any("payments-db" in o for o in objectives)
    assert any("plc-line-1" in o for o in objectives)
    on_path = {v for p in graph.attack_paths(500) for v in p.vulnerabilities}
    by_tool = {graph.nodes[v].props.get("source_tool") for v in on_path if v in graph.nodes}
    assert {"cloud", "kubernetes", "ot"} <= by_tool          # each domain reaches an objective


def test_coverage_probes_are_detected(graph: AttackGraph):
    red, engine = RedAgent(), DetectionEngine()
    actions = red.plan(graph, top_paths=40, max_actions=60)
    cloud_action = next(a for a in actions if a.technique == "cloud-misconfig-probe")
    result = red.execute(cloud_action, graph, "twin")
    det = engine.evaluate(result)
    assert det.detected and det.rule_id == "SIGMA-CLOUD-1"


# ====================================================== Phase 7: control compiler
def _asset_graph(name: str, asset_type: str) -> AttackGraph:
    aid = node_id(NodeKind.ASSET, name)
    return AttackGraph({aid: Node(aid, NodeKind.ASSET, {"name": name, "asset_type": asset_type})}, [])


def _fix(fix_type: str, target: str, tier: str = "low-risk") -> Fix:
    return Fix(fix_id=f"fix-{fix_type}", title=f"{fix_type} on {target}", fix_type=fix_type, target=target,
               addresses="x", predicted_impact="impact", rollback="rollback", approval_tier=tier, blast_radius=0.3)


def test_compiler_chooses_platform_from_asset_type():
    comp = ControlCompiler()
    aws = comp.compile(_fix("segmentation", "cloud-db"), _asset_graph("cloud-db", "aws-rds"))
    k8s = comp.compile(_fix("segmentation", "pod-x"), _asset_graph("pod-x", "pod"))
    ics = comp.compile(_fix("segmentation", "plc-1"), _asset_graph("plc-1", "ot-plc"))
    onprem = comp.compile(_fix("segmentation", "db"), _asset_graph("db", "database"))
    assert "aws-security-group" in aws.tools
    assert "kubernetes" in k8s.tools
    assert "ot-firewall" in ics.tools
    assert "iptables" in onprem.tools
    # every compiled remediation also ships a detection for the closed behaviour
    for cr in (aws, k8s, ics, onprem):
        assert "sigma-siem" in cr.tools
        assert all(c.artifact and c.rollback for c in cr.changes)


def test_compiler_covers_every_platform_on_the_hybrid_estate(graph: AttackGraph):
    red, blue, proof, comp = RedAgent(), BlueAgent(), ProofEngine(), ControlCompiler()
    platforms, seen = set(), set()
    for action in red.plan(graph, top_paths=40, max_actions=60):
        result = red.execute(action, graph, "twin")
        if not result.succeeded:
            continue
        for fix in blue.propose(graph, result):
            pr = proof.prove(graph, fix, action, "twin")
            if pr.verdict != "proven" or fix.fix_id in seen:
                continue
            seen.add(fix.fix_id)
            for change in comp.compile(fix, graph).changes:
                platforms.add(change.platform)
    # a proven fix on the hybrid estate compiles to controls on all of these
    assert {"cloud", "kubernetes", "ot", "waf", "firewall", "secrets", "identity", "siem"} <= platforms


def test_ticketing_builds_change_ticket_and_cmdb_record():
    comp, tickets = ControlCompiler(), TicketingAdapter(system="servicenow")
    compiled = comp.compile(_fix("bucket-policy", "cloud-backups", tier="auto"),
                            _asset_graph("cloud-backups", "aws-s3"))
    ticket = tickets.create_change_ticket(compiled, {"closed": True, "regression_ok": True, "ledger_head": "abc123"})
    assert ticket.system == "servicenow" and ticket.priority == "P4-routine"  # auto tier -> routine
    assert ticket.steps and ticket.rollback and ticket.evidence_ref["closed"] is True
    md = ticket.as_markdown()
    assert "Implementation steps" in md and "Rollback" in md and "Evidence" in md
    cmdb = tickets.create_cmdb_record(compiled, ticket)
    assert cmdb.ci_name == "cloud-backups" and cmdb.linked_ticket == ticket.ticket_id and cmdb.reversible


def test_api_compile_endpoint(settings: Settings):
    client = TestClient(create_app(settings))
    out = client.post("/api/compile", params={"top_paths": 40}).json()
    assert out["count"] > 0
    # cross-tool: cloud + kubernetes + OT + on-prem controls all show up
    assert {"aws-security-group", "kubernetes", "ot-firewall"} & set(out["tools"])
    first = out["remediations"][0]
    assert first["ticket"]["ticket_id"].startswith("CHG-")
    assert first["cmdb"]["change_id"].startswith("CMDB-")
    assert "Implementation steps" in first["ticket_markdown"]
