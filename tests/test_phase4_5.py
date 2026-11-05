"""Phase 4 (pilot metrics + reporting) and Phase 5 (adaptive co-learning) tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.adaptive import (
    AdaptiveCampaign,
    AdaptivePlanner,
    CampaignConfig,
    ConflictResolver,
    ProvenFix,
    RegressionMonitor,
    RemediationGate,
    arm_of,
    reward,
)
from aegis.api import create_app
from aegis.blueteam import TIER_AUTO, TIER_HIGH, TIER_LOW, BlueAgent, Fix, ProofEngine, ProofResult
from aegis.collectors import collect
from aegis.config import ROOT, Settings
from aegis.graph import AttackGraph
from aegis.ledger import EvidenceLedger
from aegis.loop import LoopConfig
from aegis.metrics import MetricsEngine, PilotReport, PilotTargets
from aegis.redteam import RedAgent
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


# ================================================================ Phase 4: metrics
def test_metrics_measure_exposure_and_closure(graph: AttackGraph):
    m = MetricsEngine(Policy()).measure(graph, LoopConfig(top_paths=5), repeat=2)
    exp = m.metrics.exposure
    assert exp["attack_paths"] > 0
    assert exp["validated_paths"] >= 3
    assert exp["paths_closed"] >= 3
    assert exp["path_closure_rate"] >= 0.75
    assert exp["exposure_after"] < exp["exposure_before"]
    assert exp["exposure_reduction"] > 0
    # proving fixes drives exploit success rate down
    assert exp["exploit_success_rate_after"] < exp["exploit_success_rate_before"]


def test_metrics_repeatability_is_deterministic(graph: AttackGraph):
    m = MetricsEngine(Policy()).measure(graph, LoopConfig(top_paths=5), repeat=3)
    assert m.repeatability == 1.0
    assert m.metrics.learning["deterministic"] is True
    assert m.metrics.learning["repeatability_score"] == 1.0


def test_metrics_safety_and_detection_quality(graph: AttackGraph):
    m = MetricsEngine(Policy()).measure(graph, LoopConfig(top_paths=5), repeat=1)
    # no benign traffic is simulated -> no false positives; cleanup verified; no outages
    assert m.metrics.detection["false_positive_rate"] == 0.0
    assert m.metrics.safety["verified_cleanup_rate"] == 1.0
    assert m.metrics.safety["unplanned_outages"] == 0
    assert m.metrics.business_impact["availability_ok_rate"] == 1.0
    assert m.metrics.efficiency["ledger_integrity_ok"] is True


def test_pilot_report_scorecard_and_executive_export(graph: AttackGraph):
    m = MetricsEngine(Policy()).measure(graph, LoopConfig(top_paths=5), repeat=2)
    report = PilotReport(m, PilotTargets())
    sc = report.scorecard()
    assert sc["targets_met"] is True
    assert sc["checks"]["path_closure_rate"]["met"] is True
    text = report.executive_report()
    assert "AEGIS Pilot Report" in text and "Exposure" in text and "Target scorecard" in text
    assert "PASS" in text


def test_pilot_targets_can_fail(graph: AttackGraph):
    m = MetricsEngine(Policy()).measure(graph, LoopConfig(top_paths=5), repeat=1)
    # an impossible closure target must be reported as not met
    strict = PilotReport(m, PilotTargets(path_closure_rate=1.1))
    assert strict.scorecard()["targets_met"] is False


# ================================================================ Phase 5: reward
def test_reward_rewards_closure_and_penalizes_risk_and_outage():
    closed = reward(exposure_before=10.0, exposure_after=2.0, detected=True,
                    operational_risk=0.1, availability_ok=True)
    nothing = reward(exposure_before=10.0, exposure_after=10.0, detected=False,
                     operational_risk=0.1, availability_ok=True)
    risky = reward(exposure_before=10.0, exposure_after=2.0, detected=True,
                   operational_risk=0.9, availability_ok=True)
    outage = reward(exposure_before=10.0, exposure_after=2.0, detected=True,
                    operational_risk=0.1, availability_ok=False)
    assert closed > nothing          # reducing exposure is rewarded
    assert closed > risky            # higher operational risk is penalized
    assert outage < closed           # breaking availability is penalized


def test_adaptive_planner_explores_then_exploits_deterministically(graph: AttackGraph):
    paths = graph.attack_paths(500)
    p1, p2 = AdaptivePlanner(), AdaptivePlanner()
    # same update sequence -> same selection order (repeatability)
    for p in (paths[0], paths[1]):
        p1.update(p, 0.5)
        p2.update(p, 0.5)
    assert [x.path_id for x in p1.select(paths, 5)] == [x.path_id for x in p2.select(paths, 5)]
    # a punished arm sinks below an equal-value unpunished one
    planner = AdaptivePlanner(exploration=0.0)
    before = planner.select(paths, len(paths))
    planner.update(before[0], -5.0)
    after_rank = {pth.path_id: i for i, pth in enumerate(planner.select(paths, len(paths)))}
    assert after_rank[before[0].path_id] > 0  # no longer first after being punished


def _fix(fix_id: str, tier: str, blast: float, addresses: str = "vulnerability:v") -> Fix:
    return Fix(fix_id=fix_id, title=fix_id, fix_type="t", target="webapp", addresses=addresses,
               predicted_impact="", rollback="", approval_tier=tier, blast_radius=blast)


def _proven(fix: Fix, verdict: str = "proven") -> ProvenFix:
    pr = ProofResult(fix.fix_id, "act", "path", closed=True, regression_ok=True, broken_workflows=[],
                     paths_before=1, paths_after=0, exposure_before=1.0, exposure_after=0.0,
                     verdict=verdict, evidence={"ok": True})
    return ProvenFix(fix, pr)


def test_remediation_gate_auto_applies_low_tiers_and_stages_high(graph: AttackGraph):
    gate = RemediationGate(auto_apply_tier=TIER_LOW)
    proven = [_proven(_fix("f-auto", TIER_AUTO, 0.1)),
              _proven(_fix("f-low", TIER_LOW, 0.3)),
              _proven(_fix("f-high", TIER_HIGH, 0.5)),
              _proven(_fix("f-big", TIER_LOW, 0.9))]  # over blast threshold -> staged
    apply, staged = gate.partition(proven)
    assert {pf.fix.fix_id for pf in apply} == {"f-auto", "f-low"}
    assert {pf.fix.fix_id for pf in staged} == {"f-high", "f-big"}
    # a not-proven fix is never auto-applied
    assert not gate.eligible(_proven(_fix("f-x", TIER_AUTO, 0.1), verdict="failed-still-open"))


def test_conflict_resolver_keeps_least_disruptive(graph: AttackGraph):
    a = _proven(_fix("keep", TIER_LOW, 0.2, addresses="edge:X"))
    b = _proven(_fix("drop", TIER_LOW, 0.8, addresses="edge:X"))  # same target element
    c = _proven(_fix("other", TIER_AUTO, 0.3, addresses="edge:Y"))
    resolved, conflicts = ConflictResolver().resolve([a, b, c])
    ids = {pf.fix.fix_id for pf in resolved}
    assert ids == {"keep", "other"}
    assert len(conflicts) == 1 and conflicts[0]["kept"] == "keep" and conflicts[0]["dropped"] == "drop"


def test_regression_monitor_detects_reopened_path(graph: AttackGraph):
    red, blue = RedAgent(), BlueAgent()
    action = next(a for a in red.plan(graph) if a.technique == "sqli-login-probe")
    result = red.execute(action, graph, "twin")
    waf = next(f for f in blue.propose(graph, result) if f.fix_type == "web-firewall")
    closed_graph = AttackGraph(*waf.apply_to(graph.nodes, graph.edges))

    monitor = RegressionMonitor()
    newly_closed, reopened = monitor.observe(graph, closed_graph)
    assert newly_closed and not reopened       # a path was closed
    # rolling the fix back (closed -> open) reopens that exact path (FR-27)
    _, reopened2 = monitor.observe(closed_graph, graph)
    assert reopened2


def test_adaptive_campaign_converges_and_reduces_exposure(graph: AttackGraph, settings: Settings):
    safety = SafetyAgent(Policy.load(settings.policy_file), KillSwitch(None))
    ledger = EvidenceLedger(None)
    report = AdaptiveCampaign(safety, ledger).run(graph, CampaignConfig(rounds=5, paths_per_round=3))

    assert report.rounds_run >= 2
    assert report.exposure_trajectory[-1] < report.exposure_trajectory[0]  # exposure fell
    assert report.total_applied > 0
    assert report.converged is True
    assert report.regressions == []            # auto-applied fixes do not reopen paths
    assert report.ledger_ok is True
    # every remediation recorded in the campaign carries evidence (FR-29)
    for entry in ledger.entries("remediation"):
        assert "evidence" in entry["payload"]
    assert ledger.verify()[0]


# ================================================================ API (Phase 4/5)
def test_api_pilot_and_campaign_endpoints(settings: Settings):
    client = TestClient(create_app(settings))

    pilot = client.post("/api/pilot", params={"repeat": 2}).json()
    assert pilot["scorecard"]["targets_met"] is True
    assert pilot["metrics"]["exposure"]["exposure_after"] < pilot["metrics"]["exposure"]["exposure_before"]
    assert "AEGIS Pilot Report" in pilot["executive_report"]

    campaign = client.post("/api/campaign", params={"rounds": 5, "paths_per_round": 3}).json()
    assert campaign["rounds_run"] >= 2
    assert campaign["exposure_trajectory"][-1] < campaign["exposure_trajectory"][0]
    assert campaign["total_applied"] > 0
    assert campaign["ledger_ok"] is True
