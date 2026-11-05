"""Adaptive red-blue co-learning and tiered auto-remediation
(PRD Phase 5; FR-11, FR-15, FR-16, FR-27; Differentiation #2).

Phases 2-3 run one pass of the loop. Phase 5 runs a **campaign**: several rounds
in which the red agent learns which paths are worth validating and the blue agent
keeps closing them, so the two co-adapt.

The feedback protocol uses the PRD's reward (Differentiation #2):

    reward = w_exposure * exposure_reduction_fraction
           + w_detection * detection_quality
           - w_risk     * operational_risk
           - w_avail    * availability_penalty

The red planner is a UCB bandit over *path arms* (keyed by objective + technique).
A path that gets blocked, detected, or is already closed yields low reward, so the
planner stops re-picking easy, low-impact wins (FR-11). Proven fixes are applied
through a tiered gate: the lowest approval tier auto-applies, higher tiers are
staged for a human (FR-15). When two fixes touch the same graph element a conflict
resolver keeps the least-disruptive one (FR-16). A regression monitor flags any
attack path that was closed in an earlier round but is reachable again (FR-27).

As in Phase 3, applying a fix is a *pure graph transform*: each round's graph is
the previous graph with the applied fixes' transforms composed onto it, so the
whole campaign runs deterministically offline and every claim is backed by a
re-run against the transformed graph.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .blueteam import TIER_AUTO, TIER_HIGH, TIER_LOW, BlueAgent, Fix, ProofEngine, ProofResult
from .detection import DetectionEngine, detection_rule_for
from .graph import AttackGraph, AttackPath
from .ledger import EvidenceLedger
from .redteam import RedAgent, ValidationAction
from .safety import SafetyAgent

TIER_RANK = {TIER_AUTO: 0, TIER_LOW: 1, TIER_HIGH: 2}


# ----------------------------------------------------------------------- reward
@dataclass
class RewardWeights:
    exposure: float = 1.0
    detection: float = 0.3
    op_risk: float = 0.5
    availability: float = 0.5


def reward(exposure_before: float, exposure_after: float, detected: bool,
           operational_risk: float, availability_ok: bool,
           w: RewardWeights | None = None) -> float:
    """Closed-loop reward (Differentiation #2). Higher is better for the defender."""
    w = w or RewardWeights()
    reduction = (exposure_before - exposure_after) / exposure_before if exposure_before else 0.0
    detection_quality = 1.0 if detected else 0.0
    avail_penalty = 0.0 if availability_ok else 1.0
    return round(
        w.exposure * reduction
        + w.detection * detection_quality
        - w.op_risk * operational_risk
        - w.availability * avail_penalty,
        4,
    )


# --------------------------------------------------------------- bandit planner
def arm_of(path: AttackPath) -> str:
    """A stable 'arm' key: what objective this path reaches, by what kind of step."""
    objective = path.target.split(":", 1)[0] if ":" in path.target else path.target
    technique = "chain"
    if path.vulnerabilities:
        technique = path.vulnerabilities[0].split(":", 1)[0]
    return f"{objective}->{technique}"


class AdaptivePlanner:
    """UCB bandit over path arms (FR-11): learn which paths are worth validating.

    Deterministic: ties break on the path's own security value and id, so a
    campaign is reproducible (Success Metric: repeatability).
    """

    def __init__(self, exploration: float = 0.7) -> None:
        self.exploration = exploration
        self.values: dict[str, float] = {}
        self.counts: dict[str, int] = {}
        self.total = 0

    def _ucb(self, path: AttackPath) -> float:
        arm = arm_of(path)
        value = self.values.get(arm, 0.0)
        count = self.counts.get(arm, 0)
        if count == 0:
            bonus = 1.0  # always explore an unseen arm at least once
        else:
            bonus = self.exploration * math.sqrt(math.log(self.total + 1) / count)
        # base priority is the path's own security value, nudged by what we learned
        return path.security_value + value + bonus

    def select(self, paths: list[AttackPath], k: int) -> list[AttackPath]:
        ranked = sorted(paths, key=lambda p: (-self._ucb(p), -p.security_value, p.path_id))
        return ranked[:k]

    def update(self, path: AttackPath, observed_reward: float) -> None:
        arm = arm_of(path)
        self.counts[arm] = self.counts.get(arm, 0) + 1
        self.total += 1
        n = self.counts[arm]
        prev = self.values.get(arm, 0.0)
        self.values[arm] = round(prev + (observed_reward - prev) / n, 4)  # running mean

    def learned(self) -> dict[str, dict[str, Any]]:
        return {arm: {"value": self.values.get(arm, 0.0), "count": self.counts.get(arm, 0)}
                for arm in sorted(self.values)}


# --------------------------------------------------------- tiered remediation
@dataclass
class ProvenFix:
    fix: Fix
    proof: ProofResult


class RemediationGate:
    """Tiered auto-apply (FR-15): apply the lowest tier, stage the rest."""

    def __init__(self, auto_apply_tier: str = TIER_AUTO, blast_threshold: float = 0.6) -> None:
        self.auto_rank = TIER_RANK.get(auto_apply_tier, 0)
        self.blast_threshold = blast_threshold

    def eligible(self, pf: ProvenFix) -> bool:
        return (
            pf.proof.verdict == "proven"
            and TIER_RANK.get(pf.fix.approval_tier, 2) <= self.auto_rank
            and pf.fix.blast_radius < self.blast_threshold
        )

    def partition(self, proven: list[ProvenFix]) -> tuple[list[ProvenFix], list[ProvenFix]]:
        apply, staged = [], []
        for pf in proven:
            (apply if self.eligible(pf) else staged).append(pf)
        return apply, staged


class ConflictResolver:
    """Resolve fixes that touch the same graph element (FR-16).

    Keep the least-disruptive fix (lowest blast radius, then lowest tier rank) per
    addressed element; report the ones dropped so the decision is auditable.
    """

    def resolve(self, fixes: list[ProvenFix]) -> tuple[list[ProvenFix], list[dict[str, Any]]]:
        best: dict[str, ProvenFix] = {}
        conflicts: list[dict[str, Any]] = []
        for pf in fixes:
            key = pf.fix.addresses
            incumbent = best.get(key)
            if incumbent is None:
                best[key] = pf
                continue
            keep, drop = self._prefer(incumbent, pf)
            best[key] = keep
            conflicts.append({
                "addresses": key,
                "kept": keep.fix.fix_id,
                "dropped": drop.fix.fix_id,
                "reason": "lower blast radius / tier",
            })
        # stable, deterministic order
        resolved = sorted(best.values(), key=lambda pf: (pf.fix.blast_radius, pf.fix.fix_id))
        return resolved, conflicts

    @staticmethod
    def _prefer(a: ProvenFix, b: ProvenFix) -> tuple[ProvenFix, ProvenFix]:
        ka = (a.fix.blast_radius, TIER_RANK.get(a.fix.approval_tier, 2), a.fix.fix_id)
        kb = (b.fix.blast_radius, TIER_RANK.get(b.fix.approval_tier, 2), b.fix.fix_id)
        return (a, b) if ka <= kb else (b, a)


# --------------------------------------------------------- regression monitor
def path_signature(path: AttackPath) -> str:
    return f"{path.entry}|{path.target}|{','.join(path.vulnerabilities)}"


def exploitable_signatures(graph: AttackGraph) -> set[str]:
    return {path_signature(p) for p in graph.attack_paths(500)
            if p.status in ("validated", "exploitable")}


class RegressionMonitor:
    """FR-27: detect a previously-closed attack path that is reachable again."""

    def __init__(self) -> None:
        self.closed: set[str] = set()

    def observe(self, before: AttackGraph, after: AttackGraph) -> tuple[set[str], list[str]]:
        before_sigs = exploitable_signatures(before)
        after_sigs = exploitable_signatures(after)
        newly_closed = before_sigs - after_sigs
        reopened = sorted(self.closed & after_sigs)  # were closed, exploitable again
        self.closed = (self.closed | newly_closed) - after_sigs
        return newly_closed, reopened


# --------------------------------------------------------------- the campaign
@dataclass
class CampaignConfig:
    rounds: int = 4
    paths_per_round: int = 3
    max_actions: int = 12
    auto_apply_tier: str = TIER_LOW  # FR-15: auto-apply low-risk tiers, stage high-risk
    exploration: float = 0.7


@dataclass
class CampaignReport:
    rounds_run: int
    exposure_trajectory: list[float]
    total_applied: int
    total_staged: int
    converged: bool
    regressions: list[str]
    learned_arms: dict[str, dict[str, Any]]
    rounds: list[dict[str, Any]] = field(default_factory=list)
    ledger_ok: bool = True

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class AdaptiveCampaign:
    """Multi-round red-blue co-adaptation with tiered auto-remediation."""

    def __init__(self, safety: SafetyAgent, ledger: EvidenceLedger,
                 weights: RewardWeights | None = None,
                 red: RedAgent | None = None, blue: BlueAgent | None = None,
                 detection: DetectionEngine | None = None, proof: ProofEngine | None = None) -> None:
        self.safety = safety
        self.ledger = ledger
        self.weights = weights or RewardWeights()
        self.red = red or RedAgent()
        self.blue = blue or BlueAgent()
        self.detection = detection or DetectionEngine()
        self.proof = proof or ProofEngine(self.red)

    def run(self, graph: AttackGraph, config: CampaignConfig | None = None) -> CampaignReport:
        config = config or CampaignConfig()
        planner = AdaptivePlanner(exploration=config.exploration)
        gate = RemediationGate(config.auto_apply_tier)
        resolver = ConflictResolver()
        monitor = RegressionMonitor()

        current = graph
        trajectory: list[float] = []
        rounds_rows: list[dict[str, Any]] = []
        total_applied = total_staged = 0
        all_reopened: list[str] = []

        for rnd in range(config.rounds):
            self.safety.reset_counters()
            paths = current.attack_paths(500)
            exposure_before = round(sum(max(p.security_value, 0) for p in paths), 3)
            trajectory.append(exposure_before)
            if not paths:
                rounds_rows.append({"round": rnd, "exposure_before": exposure_before,
                                    "note": "no reachable attack paths; fully remediated"})
                break

            selected = planner.select(paths, config.paths_per_round)
            actions = self.red.plan_paths(current, selected, max_actions=config.max_actions)

            proven: list[ProvenFix] = []
            detected_count = blocked = validated = 0
            path_by_id = {p.path_id: p for p in selected}
            for action in actions:
                decision = self.safety.evaluate(action, "twin", approved=True)
                self.ledger.record("safety", {"action_id": action.action_id,
                                               "round": rnd, **decision.as_dict()})
                path = path_by_id.get(action.path_id)
                if not decision.allowed:
                    blocked += 1
                    if path:
                        planner.update(path, -0.5)  # blocked -> discourage this arm
                    continue
                result = self.red.execute(action, current, "twin")
                detect = self.detection.evaluate(result)
                detected_count += int(detect.detected)
                self.ledger.record(
                    "validation",
                    {"action_id": action.action_id, "round": rnd, "succeeded": result.succeeded,
                     "outcome": result.outcome, "detection": detect.as_dict()},
                    evidence=result.evidence if result.succeeded
                    else {"outcome": result.outcome, "telemetry": [e.as_dict() for e in result.telemetry]},
                )
                if not detect.detected:
                    self.detection.add_rule(detection_rule_for(action.technique, action.signature))
                if not result.succeeded:
                    if path:
                        planner.update(path, -0.2)  # already closed / unreachable
                    continue
                validated += 1

                best_after = exposure_before
                for fix in self.blue.propose(current, result):
                    pr = self.proof.prove(current, fix, action, environment="twin")
                    self.ledger.record("remediation", {"round": rnd, "fix": fix.as_dict(),
                                                        "proof": pr.as_dict()},
                                       evidence=pr.evidence, asserts_success=(pr.verdict == "proven"))
                    if pr.verdict == "proven":
                        proven.append(ProvenFix(fix, pr))
                        best_after = min(best_after, pr.exposure_after)
                if path:
                    r = reward(exposure_before, best_after, detect.detected,
                               action.operational_risk, availability_ok=True, w=self.weights)
                    planner.update(path, r)

            # tiered auto-remediation + conflict resolution
            to_apply, staged = gate.partition(proven)
            resolved, conflicts = resolver.resolve(to_apply)
            nodes, edges = current.nodes, current.edges
            for pf in resolved:
                nodes, edges = pf.fix.apply_to(nodes, edges)
            next_graph = AttackGraph(nodes, edges)

            newly_closed, reopened = monitor.observe(current, next_graph)
            all_reopened.extend(reopened)
            exposure_after = round(sum(max(p.security_value, 0) for p in next_graph.attack_paths(500)), 3)
            total_applied += len(resolved)
            total_staged += len(staged)

            rounds_rows.append({
                "round": rnd,
                "exposure_before": exposure_before,
                "exposure_after": exposure_after,
                "paths_available": len(paths),
                "paths_selected": len(selected),
                "validated": validated,
                "blocked": blocked,
                "detected": detected_count,
                "fixes_proven": len(proven),
                "fixes_applied": len(resolved),
                "fixes_staged": len(staged),
                "paths_closed": len(newly_closed),
                "reopened": reopened,
                "conflicts_resolved": conflicts,
                "staged_for_approval": [pf.fix.as_dict() for pf in staged],
            })
            self.ledger.record("campaign-round", {"round": rnd, "exposure_before": exposure_before,
                                                  "exposure_after": exposure_after,
                                                  "applied": len(resolved), "staged": len(staged)})
            current = next_graph
            # Stop when fully remediated, or when a round reaches a stable state
            # (nothing left to validate and nothing applied) - the loop converged.
            if exposure_after <= 0 or not next_graph.attack_paths(1) or (validated == 0 and not resolved):
                trajectory.append(exposure_after)
                break

        ledger_ok, _ = self.ledger.verify()
        converged = len(trajectory) >= 2 and trajectory[-1] <= trajectory[0]
        report = CampaignReport(
            rounds_run=len(rounds_rows),
            exposure_trajectory=trajectory,
            total_applied=total_applied,
            total_staged=total_staged,
            converged=converged,
            regressions=all_reopened,
            learned_arms=planner.learned(),
            rounds=rounds_rows,
            ledger_ok=ledger_ok,
        )
        self.ledger.record("campaign", {"summary": {k: v for k, v in report.as_dict().items()
                                                    if k != "rounds"}})
        return report
