"""Phase 2 (safe red + safety) and Phase 3 (blue + proof) tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.blueteam import BlueAgent, ProofEngine
from aegis.cleanup import CleanupEngine
from aegis.collectors import collect
from aegis.config import ROOT, Settings
from aegis.detection import DetectionEngine
from aegis.environments import Environment, EnvironmentRouter
from aegis.graph import AttackGraph
from aegis.ledger import EvidenceLedger, MissingEvidenceError
from aegis.loop import LoopConfig, RedBlueLoop
from aegis.redteam import RedAgent, ValidationAction
from aegis.safety import KillSwitch, Policy, SafetyAgent
from aegis.store import GraphStore

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    results = tmp_path / "results"
    results.mkdir()
    shutil.copy(FIXTURES / "zap-sample.json", results / "zap-scan.json")
    return Settings(
        db_path=tmp_path / "aegis.db",
        results_dir=results,
        scenarios_dir=ROOT / "experiments" / "scenarios",
        compose_file=ROOT / "cyber_range" / "docker-compose.yml",
        realm_file=ROOT / "cyber_range" / "keycloak" / "aegis-realm.json",
        policy_file=ROOT / "policy.yaml",
        ledger_path=tmp_path / "ledger.jsonl",
        kill_switch_file=tmp_path / "KILL",
        coverage_dir=tmp_path / "nocov",  # pin to the core range; coverage has its own tests
        inventory_mode="compose",
        keycloak_url="",
        frontend_dir=ROOT / "frontend",
    )


@pytest.fixture
def graph(settings: Settings) -> AttackGraph:
    store = GraphStore(settings.db_path)
    collect(store, settings)
    return AttackGraph(*store.snapshot())


def _action(technique="sqli-login-probe", target="webapp", non_destructive=True, blast=0.1) -> ValidationAction:
    return ValidationAction("act-x", "probe", technique, target, "vulnerability:v", "path-1",
                            non_destructive=non_destructive, blast_radius=blast, operational_risk=0.2)


# ----------------------------------------------------------------- safety (FR-17/18/19)
def test_safety_default_deny_unknown_technique_and_target():
    agent = SafetyAgent(Policy(), KillSwitch(None))
    assert not agent.evaluate(_action(technique="made-up"), "range").allowed
    assert not agent.evaluate(_action(target="prod-crm"), "range").allowed
    assert agent.evaluate(_action(), "range").allowed


def test_safety_blocks_prohibited_and_destructive_and_bad_env():
    agent = SafetyAgent(Policy(), KillSwitch(None))
    assert not agent.evaluate(_action(technique="T1486"), "twin").allowed          # ransomware
    assert not agent.evaluate(_action(non_destructive=False), "range").allowed     # destructive
    assert not agent.evaluate(_action(), "production").allowed                     # env not allowed


def test_safety_requires_approval_for_high_blast_radius():
    agent = SafetyAgent(Policy(), KillSwitch(None))
    d1 = agent.evaluate(_action(blast=0.9), "range", approved=False)
    assert not d1.allowed and d1.requires_approval
    assert agent.evaluate(_action(blast=0.9), "range", approved=True).allowed
    # twin auto-approves
    assert agent.evaluate(_action(blast=0.9), "twin").allowed


def test_safety_kill_switch_fails_closed(tmp_path: Path):
    ks = KillSwitch(tmp_path / "KILL")
    agent = SafetyAgent(Policy(), ks)
    assert agent.evaluate(_action(), "range").allowed
    ks.trip("test")
    assert (tmp_path / "KILL").exists()
    assert not agent.evaluate(_action(), "range").allowed
    ks.reset()
    assert agent.evaluate(_action(), "range").allowed


def test_safety_rate_limit_per_target():
    agent = SafetyAgent(Policy({"rate_limits": {"per_run": 100, "per_target": 2}}), KillSwitch(None))
    assert agent.evaluate(_action(), "range").allowed
    assert agent.evaluate(_action(), "range").allowed
    assert not agent.evaluate(_action(), "range").allowed  # third hits per-target limit


# -------------------------------------------------------------- environments (FR-23/24)
def test_environment_routing_by_risk():
    router = EnvironmentRouter()
    assert router.route(0.1).environment == Environment.RANGE
    assert router.route(0.4).environment == Environment.CANARY
    assert router.route(0.8).environment == Environment.TWIN


def test_low_twin_fidelity_blocks_production_change():
    ok, _ = EnvironmentRouter(twin_fidelity=0.9, fidelity_threshold=0.8).guard_production_change()
    blocked, reason = EnvironmentRouter(twin_fidelity=0.5, fidelity_threshold=0.8).guard_production_change()
    assert ok and not blocked and "fidelity" in reason


# ------------------------------------------------------------------- ledger (FR-28/29/30)
def test_ledger_hash_chain_and_tamper_detection(tmp_path: Path):
    ledger = EvidenceLedger(tmp_path / "l.jsonl")
    ledger.record("safety", {"a": 1})
    ledger.record("validation", {"b": 2}, evidence={"telemetry": "x"})
    ok, broken = ledger.verify()
    assert ok and broken is None and len(ledger) == 2
    # tamper with a persisted record
    ledger._records[0].payload["a"] = 999
    bad, where = ledger.verify()
    assert not bad and where is not None


def test_ledger_refuses_unsupported_finding():
    ledger = EvidenceLedger(None)
    with pytest.raises(MissingEvidenceError):
        ledger.record("validation", {"claim": "exploited"})  # no evidence
    with pytest.raises(MissingEvidenceError):
        ledger.record("remediation", {"fixed": True}, asserts_success=True)
    assert ledger.record("safety", {"decision": "allow"})  # non-evidence kinds are fine


def test_ledger_persists_and_reloads(tmp_path: Path):
    path = tmp_path / "l.jsonl"
    led = EvidenceLedger(path)
    led.record("safety", {"a": 1})
    led.record("engagement", {"summary": {}})
    reloaded = EvidenceLedger(path)
    assert len(reloaded) == 2 and reloaded.verify()[0]


# --------------------------------------------------------------------- detection (FR-13)
def test_detection_matches_and_misses():
    engine = DetectionEngine()
    red = RedAgent()
    sqli = _action("sqli-login-probe", "webapp")
    sqli.signature = "sqli:login:or-1-1"
    from aegis.graph import AttackGraph as AG
    g = AG({}, [])
    detected = engine.evaluate(red._simulate(sqli, g, "range"))
    assert detected.detected and detected.rule_id == "SIGMA-SQLI-1"

    recon = _action("reachability-probe", "database")
    recon.signature = "net:connect"
    missed = engine.evaluate(red._simulate(recon, g, "range"))
    assert not missed.detected and missed.quality == "missed"


# ------------------------------------------------------------- red agent (FR-9/10)
def test_red_plans_nondestructive_actions_grounded_in_graph(graph: AttackGraph):
    red = RedAgent()
    actions = red.plan(graph, top_paths=5, max_actions=10)
    assert actions and all(a.non_destructive for a in actions)
    # a validated/reachable vuln yields a successful, access-proving result
    hit = next(a for a in actions if "scenario/SC-001" in a.vuln_id)
    result = red.execute(hit, graph, "twin")
    assert result.succeeded and result.outcome == "access-proven"
    assert result.evidence["marker"] and result.evidence["reachable_in_graph"]
    assert result.telemetry[0].signature


def test_cleanup_reports_clean_for_nondestructive_action():
    result = CleanupEngine().run(_action())
    assert result.clean and result.steps_run


# ------------------------------------------------- blue agent + proof engine (FR-14/25/26)
def test_proof_engine_closes_sqli_path_with_waf(graph: AttackGraph):
    red, blue, proof = RedAgent(), BlueAgent(), ProofEngine()
    action = next(a for a in red.plan(graph) if a.technique == "sqli-login-probe")
    result = red.execute(action, graph, "twin")
    fixes = blue.propose(graph, result)
    waf = next(f for f in fixes if f.fix_type == "web-firewall")
    pr = proof.prove(graph, waf, action, "twin")
    assert pr.verdict == "proven" and pr.closed and pr.regression_ok
    assert pr.exposure_after < pr.exposure_before


def test_proof_rejects_fix_that_breaks_a_legitimate_workflow(graph: AttackGraph):
    from aegis.blueteam import Fix, _drop_edges
    from aegis.model import EdgeKind

    # A deliberately over-broad fix: revoke svc-backup's legitimate DB admin role.
    bad = Fix(
        fix_id="fix-bad", title="Revoke all db-admin roles", fix_type="identity", target="database",
        addresses="identity:aegis/svc-backup", predicted_impact="", rollback="", approval_tier="high-risk",
        blast_radius=0.5,
        _transform=_drop_edges(lambda e: e.kind == EdgeKind.ADMIN_OF and e.dst == "asset:database"),
    )
    red, proof = RedAgent(), ProofEngine()
    action = next(a for a in red.plan(graph) if a.target == "database")
    pr = proof.prove(graph, bad, action, "twin")
    assert pr.verdict == "rejected-regression" and not pr.regression_ok and pr.broken_workflows


# ----------------------------------------------------------------------- full loop
def test_redblue_loop_end_to_end(graph: AttackGraph, settings: Settings):
    ledger = EvidenceLedger(settings.ledger_path)
    safety = SafetyAgent(Policy.load(settings.policy_file), KillSwitch(settings.kill_switch_file))
    report = RedBlueLoop(safety, ledger).run(graph, LoopConfig(top_paths=5))

    assert report.attack_paths > 0
    assert report.validated >= 3
    assert report.fixes_proven >= 3
    assert report.exposure_after_if_applied < report.exposure_before
    assert report.ledger_ok
    # every validation and remediation in the ledger carries evidence (FR-29)
    for entry in ledger.entries("validation"):
        assert "evidence" in entry["payload"]
    assert ledger.verify()[0]


# ------------------------------------------------------------------------ API
def test_api_phase23_endpoints(settings: Settings):
    client = TestClient(create_app(settings))
    report = client.post("/api/engage").json()
    assert report["validated"] >= 3 and report["fixes_proven"] >= 3
    assert report["exposure_after_if_applied"] < report["exposure_before"]

    ledger = client.get("/api/ledger").json()
    assert ledger["integrity_ok"] and ledger["count"] > 0
    assert client.get("/api/ledger/verify").json()["integrity_ok"]

    policy = client.get("/api/policy").json()
    assert "sqli-login-probe" in policy["policy"]["allowed_techniques"]

    assert client.post("/api/kill-switch", params={"engage": True}).json()["kill_switch_engaged"]
    blocked = client.post("/api/engage").json()
    assert blocked["validated"] == 0 and blocked["blocked_by_safety"] > 0  # fails closed
    assert not client.post("/api/kill-switch", params={"engage": False}).json()["kill_switch_engaged"]
