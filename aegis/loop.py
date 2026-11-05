"""RedBlue Loop orchestrator (PRD core loop + FR-28/29).

Ties the pieces into one safety-constrained pass:

    observe/discover  -> attack graph from the temporal store (Phase 1)
    attack            -> red agent plans bounded actions, safety gates each,
                         environment router picks where they run, cleanup scans
    detect            -> detection engine scores each validation
    respond           -> blue agent proposes fixes with impact + rollback
    verify            -> proof engine re-runs the attack and checks regressions
    learn             -> everything is written to the hash-chained ledger

Nothing here executes a destructive action or changes production: fixes are
*proven* against the graph and staged for approval. Applying a staged fix to the
real range stays a human step (edit compose/realm, re-collect).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .blueteam import BlueAgent, Fix, ProofEngine, ProofResult
from .cleanup import CleanupEngine
from .detection import DetectionEngine, detection_rule_for
from .environments import EnvironmentRouter
from .graph import AttackGraph
from .ledger import EvidenceLedger
from .redteam import ActionResult, RedAgent
from .safety import SafetyAgent


@dataclass
class LoopConfig:
    top_paths: int = 5
    max_actions: int = 8
    auto_apply_tier: str = "auto"  # tiers at/below this may be auto-approved (FR-15)


@dataclass
class EngagementReport:
    attack_paths: int
    validated: int
    blocked_by_safety: int
    detections: dict[str, int]
    fixes_proposed: int
    fixes_proven: int
    exposure_before: float
    exposure_after_if_applied: float
    actions: list[dict[str, Any]] = field(default_factory=list)
    ledger_ok: bool = True

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class RedBlueLoop:
    def __init__(
        self,
        safety: SafetyAgent,
        ledger: EvidenceLedger,
        router: EnvironmentRouter | None = None,
        red: RedAgent | None = None,
        blue: BlueAgent | None = None,
        detection: DetectionEngine | None = None,
        cleanup: CleanupEngine | None = None,
        proof: ProofEngine | None = None,
    ) -> None:
        self.safety = safety
        self.ledger = ledger
        self.router = router or EnvironmentRouter()
        self.red = red or RedAgent()
        self.blue = blue or BlueAgent()
        self.detection = detection or DetectionEngine()
        self.cleanup = cleanup or CleanupEngine()
        self.proof = proof or ProofEngine(self.red)

    def run(self, graph: AttackGraph, config: LoopConfig | None = None) -> EngagementReport:
        config = config or LoopConfig()
        self.safety.reset_counters()
        before_paths = graph.attack_paths(500)
        exposure_before = round(sum(max(p.security_value, 0) for p in before_paths), 3)

        validated = blocked = proven = proposed = 0
        detections = {"detected": 0, "missed": 0, "detected-late": 0}
        exposure_after = exposure_before
        rows: list[dict[str, Any]] = []

        for action in self.red.plan(graph, top_paths=config.top_paths, max_actions=config.max_actions):
            route = self.router.route(action.operational_risk)
            auto_ok = self._auto_approved(config, route.environment)
            decision = self.safety.evaluate(action, route.environment, approved=auto_ok)
            self.ledger.record("safety", {"action_id": action.action_id, "environment": route.environment,
                                          "route": route.as_dict(), **decision.as_dict()})
            if not decision.allowed:
                blocked += 1
                rows.append({"action": action.as_dict(), "safety": decision.as_dict(), "status": "blocked"})
                continue

            # availability before/during/after (FR-22)
            avail_before = self.router.availability([action.target], "before")
            result = self.red.execute(action, graph, route.environment)
            avail_after = self.router.availability([action.target], "after")
            clean = self.cleanup.run(action)
            if not clean.clean:
                self.safety.kill_switch.trip(f"residual artifacts after {action.action_id}")

            detect = self.detection.evaluate(result)
            detections[detect.quality] = detections.get(detect.quality, 0) + 1

            self.ledger.record(
                "validation",
                {"action_id": action.action_id, "succeeded": result.succeeded, "outcome": result.outcome,
                 "detection": detect.as_dict(), "cleanup": clean.as_dict(),
                 "availability": {"before": [a.as_dict() for a in avail_before], "after": [a.as_dict() for a in avail_after]}},
                evidence=result.evidence if result.succeeded else {"outcome": result.outcome, "telemetry": [e.as_dict() for e in result.telemetry]},
            )

            row: dict[str, Any] = {"action": action.as_dict(), "safety": decision.as_dict(), "route": route.as_dict(),
                                   "result": result.as_dict(), "detection": detect.as_dict(), "cleanup": clean.as_dict(),
                                   "status": result.outcome, "fixes": []}
            if not result.succeeded:
                rows.append(row)
                continue
            validated += 1

            fixes = self.blue.propose(graph, result)
            # If the validation was missed, also propose a detection rule (FR-14).
            if not detect.detected:
                self.detection.add_rule(detection_rule_for(action.technique, action.signature))

            best_after = exposure_before
            for fix in fixes:
                proposed += 1
                proof = self.proof.prove(graph, fix, action, environment="twin")
                self.ledger.record(
                    "remediation",
                    {"fix": fix.as_dict(), "proof": proof.as_dict()},
                    evidence=proof.evidence,
                    asserts_success=(proof.verdict == "proven"),
                )
                if proof.verdict == "proven":
                    proven += 1
                    best_after = min(best_after, proof.exposure_after)
                row["fixes"].append({"fix": fix.as_dict(), "proof": proof.as_dict()})
            if row["fixes"]:
                exposure_after = min(exposure_after, best_after)
            rows.append(row)

        ledger_ok, _ = self.ledger.verify()
        report = EngagementReport(
            attack_paths=len(before_paths), validated=validated, blocked_by_safety=blocked,
            detections=detections, fixes_proposed=proposed, fixes_proven=proven,
            exposure_before=exposure_before, exposure_after_if_applied=round(exposure_after, 3),
            actions=rows, ledger_ok=ledger_ok,
        )
        self.ledger.record("engagement", {"summary": {k: v for k, v in report.as_dict().items() if k != "actions"}})
        return report

    def _auto_approved(self, config: LoopConfig, environment: str) -> bool:
        # The twin auto-approves validation; this models tiered auto-approval.
        return environment == "twin" or config.auto_apply_tier == "all"
