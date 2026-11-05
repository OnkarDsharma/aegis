"""Pilot metrics and reporting (PRD Phase 4; Goal 6, FR-36, FR-37, Success Metrics S.7).

Phase 4 is the *pilot*: run the safety-constrained red-blue loop over one
environment, establish a **baseline**, and quantify the security improvement with
objective, repeatable numbers. This module turns an :class:`EngagementReport`
(and the evidence ledger it produced) into the Success-Metrics categories from
the PRD:

    speed            how long discovery -> validation -> detection -> remediation took
    exposure         % of attack paths closed, exposure reduction, exploit-success drop
    detection        false-negative rate and mean detection latency
    safety           blocked-action rate, verified-cleanup rate, unplanned outages
    business_impact  service availability during testing, remediation regression rate
    learning         novel multi-step paths, and repeatability of results across runs
    efficiency       actions, proven fixes, ledger size, analyst hours saved

Everything is derived from recorded evidence - never asserted - so the numbers are
reproducible from the ledger (NFR: auditability). :class:`PilotReport` compares the
measured run against :class:`PilotTargets` (path-closure rate, time-to-remediate,
zero service-impact) and renders an exportable executive report (FR-37).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from .environments import EnvironmentRouter
from .graph import AttackGraph
from .ledger import EvidenceLedger
from .loop import EngagementReport, LoopConfig, RedBlueLoop
from .safety import KillSwitch, Policy, SafetyAgent

# Analyst-effort model used to estimate hours saved. These are deliberately
# conservative, documented assumptions (a manual validation + write-up, and a
# manual fix design + regression test), not measurements.
MANUAL_HOURS_PER_VALIDATION = 2.0
MANUAL_HOURS_PER_PROVEN_FIX = 3.0


@dataclass
class MetricSet:
    speed: dict[str, Any]
    exposure: dict[str, Any]
    detection: dict[str, Any]
    safety: dict[str, Any]
    business_impact: dict[str, Any]
    learning: dict[str, Any]
    efficiency: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class PilotTargets:
    """v1 targets to set on a pilot environment (PRD S.7 'v1 target')."""

    path_closure_rate: float = 0.75          # fraction of validated paths proven closed
    max_time_to_remediate_s: float = 5.0     # wall-clock to prove a fix closes a path
    max_service_impact_incidents: int = 0    # zero unplanned outages
    min_detection_rate: float = 0.5          # fraction of validations detected (pre-response)
    max_blocked_fp_rate: float = 0.0         # safety must not block authorized actions

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class PilotMeasurement:
    report: EngagementReport
    metrics: MetricSet
    duration_s: float
    repeatability: float          # 1.0 == identical summaries across repeated runs
    runs: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics.as_dict(),
            "duration_s": round(self.duration_s, 4),
            "repeatability": round(self.repeatability, 3),
            "runs": self.runs,
            "summary": {k: v for k, v in self.report.as_dict().items() if k != "actions"},
        }


class MetricsEngine:
    """Runs the loop (repeatedly, to measure determinism) and scores it."""

    def __init__(self, policy: Policy | None = None, kill_switch: KillSwitch | None = None,
                 router: EnvironmentRouter | None = None) -> None:
        self.policy = policy or Policy()
        self.kill_switch = kill_switch
        self.router = router or EnvironmentRouter()

    def _run_once(self, graph: AttackGraph, config: LoopConfig) -> tuple[EngagementReport, EvidenceLedger, float]:
        ledger = EvidenceLedger(None)  # in-memory; measurement must not touch the real ledger
        safety = SafetyAgent(self.policy, self.kill_switch)
        loop = RedBlueLoop(safety, ledger, router=self.router)
        start = time.perf_counter()
        report = loop.run(graph, config)
        return report, ledger, time.perf_counter() - start

    def measure(self, graph: AttackGraph, config: LoopConfig | None = None, repeat: int = 3) -> PilotMeasurement:
        config = config or LoopConfig()
        repeat = max(1, repeat)
        report, ledger, duration = self._run_once(graph, config)
        canonical = _summary_signature(report)
        identical = 1
        for _ in range(repeat - 1):
            other, _, _ = self._run_once(graph, config)
            if _summary_signature(other) == canonical:
                identical += 1
        repeatability = identical / repeat
        metrics = self.score(report, ledger, duration, repeatability)
        return PilotMeasurement(report, metrics, duration, repeatability, repeat)

    def score(self, report: EngagementReport, ledger: EvidenceLedger, duration_s: float,
              repeatability: float) -> MetricSet:
        rows = report.actions
        executed = [r for r in rows if "result" in r]
        validated = [r for r in executed if r["status"] == "access-proven"]
        blocked = report.blocked_by_safety

        closed_path_ids = {
            r["action"]["path_id"]
            for r in validated
            if any(f["proof"]["verdict"] == "proven" for f in r.get("fixes", []))
        }
        n_exec = len(executed)
        n_val = len(validated)
        success_before = (n_val / n_exec) if n_exec else 0.0
        success_after = ((n_val - len(closed_path_ids)) / n_exec) if n_exec else 0.0

        # ---- exposure
        reduction = report.exposure_before - report.exposure_after_if_applied
        exposure = {
            "attack_paths": report.attack_paths,
            "validated_paths": n_val,
            "paths_closed": len(closed_path_ids),
            "path_closure_rate": _ratio(len(closed_path_ids), n_val),
            "pct_attack_paths_closed": _ratio(len(closed_path_ids), report.attack_paths),
            "exposure_before": report.exposure_before,
            "exposure_after": report.exposure_after_if_applied,
            "exposure_reduction": round(reduction, 3),
            "exposure_reduction_pct": _ratio(reduction, report.exposure_before),
            "exploit_success_rate_before": round(success_before, 3),
            "exploit_success_rate_after": round(success_after, 3),
        }

        # ---- detection (false negatives + latency; FR-13)
        det = report.detections
        n_detected = det.get("detected", 0) + det.get("detected-late", 0)
        latencies = [r["detection"]["latency_s"] for r in executed
                     if r["detection"].get("latency_s") is not None]
        detection = {
            "detected": det.get("detected", 0),
            "detected_late": det.get("detected-late", 0),
            "missed": det.get("missed", 0),
            "detection_rate": _ratio(n_detected, n_val),
            "false_negative_rate": _ratio(det.get("missed", 0), n_val),
            # No benign traffic is simulated, so every match is a true positive.
            "false_positive_rate": 0.0,
            "mean_latency_s": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "rules_auto_proposed": det.get("missed", 0),  # blue proposes a rule per miss (FR-14)
        }

        # ---- safety + business impact (from recorded evidence)
        val_entries = ledger.entries("validation")
        cleanup_clean = sum(1 for r in executed if r["cleanup"]["clean"])
        avail_checks = outages = 0
        for e in val_entries:
            for phase in ("before", "after"):
                for chk in e["payload"].get("availability", {}).get(phase, []):
                    avail_checks += 1
                    if not chk.get("ok", True):
                        outages += 1
        safety = {
            "actions_blocked": blocked,
            "actions_executed": n_exec,
            "blocked_action_rate": _ratio(blocked, blocked + n_exec),
            "verified_cleanup_rate": _ratio(cleanup_clean, n_exec),
            "unplanned_outages": outages,
            "kill_switch_engaged": bool(self.kill_switch and self.kill_switch.engaged()),
        }

        rejected = sum(1 for r in validated for f in r.get("fixes", [])
                       if f["proof"]["verdict"] == "rejected-regression")
        business_impact = {
            "availability_checks": avail_checks,
            "availability_ok_rate": _ratio(avail_checks - outages, avail_checks),
            "service_impact_incidents": outages,
            "remediation_regression_rate": _ratio(rejected, report.fixes_proposed),
        }

        # ---- learning
        learning = {
            "novel_paths_discovered": report.attack_paths,
            "repeatability_score": round(repeatability, 3),
            "deterministic": repeatability >= 1.0,
        }

        # ---- efficiency
        per_path = (duration_s / n_val) if n_val else 0.0
        efficiency = {
            "actions_planned": len(rows),
            "actions_executed": n_exec,
            "fixes_proposed": report.fixes_proposed,
            "fixes_proven": report.fixes_proven,
            "ledger_records": len(ledger),
            "ledger_integrity_ok": report.ledger_ok,
            "engagement_seconds": round(duration_s, 4),
            "mean_seconds_per_validated_path": round(per_path, 4),
            "analyst_hours_saved_estimate": round(
                n_val * MANUAL_HOURS_PER_VALIDATION + report.fixes_proven * MANUAL_HOURS_PER_PROVEN_FIX, 1
            ),
        }

        # ---- speed (time to the first validated path and to the first proven fix)
        speed = {
            "total_engagement_s": round(duration_s, 4),
            "mean_time_to_remediate_s": round(per_path, 4),
            "mean_time_per_validated_path_s": round(per_path, 4),
        }

        return MetricSet(speed, exposure, detection, safety, business_impact, learning, efficiency)


class PilotReport:
    """Baseline-vs-target view over a measurement (FR-36 dashboard, FR-37 export)."""

    def __init__(self, measurement: PilotMeasurement, targets: PilotTargets | None = None) -> None:
        self.m = measurement
        self.targets = targets or PilotTargets()

    def scorecard(self) -> dict[str, Any]:
        mx = self.m.metrics
        t = self.targets
        checks = {
            "path_closure_rate": _check(mx.exposure["path_closure_rate"], t.path_closure_rate, "min"),
            "time_to_remediate_s": _check(mx.speed["mean_time_to_remediate_s"], t.max_time_to_remediate_s, "max"),
            "service_impact_incidents": _check(mx.safety["unplanned_outages"], t.max_service_impact_incidents, "max"),
            "detection_rate": _check(mx.detection["detection_rate"], t.min_detection_rate, "min"),
            "blocked_false_positive_rate": _check(mx.safety["blocked_action_rate"], t.max_blocked_fp_rate, "max"),
        }
        return {
            "targets_met": all(c["met"] for c in checks.values()),
            "checks": checks,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets.as_dict(),
            "scorecard": self.scorecard(),
            **self.m.as_dict(),
        }

    def executive_report(self) -> str:
        """Human-readable executive summary (Markdown) - FR-37."""
        mx = self.m.metrics
        sc = self.scorecard()
        exp = mx.exposure
        det = mx.detection
        saf = mx.safety
        lines = [
            "# AEGIS Pilot Report",
            "",
            f"**Targets met:** {'YES' if sc['targets_met'] else 'NO'}  ",
            f"**Repeatability:** {mx.learning['repeatability_score']:.0%} across {self.m.runs} runs  ",
            f"**Ledger integrity:** {'verified' if mx.efficiency['ledger_integrity_ok'] else 'BROKEN'}",
            "",
            "## Exposure",
            f"- Attack paths discovered: **{exp['attack_paths']}** "
            f"({mx.learning['novel_paths_discovered']} novel, validated {exp['validated_paths']})",
            f"- Attack paths proven closed: **{exp['paths_closed']}** "
            f"({exp['path_closure_rate']:.0%} of validated)",
            f"- Exposure: **{exp['exposure_before']} -> {exp['exposure_after']}** "
            f"({exp['exposure_reduction_pct']:.0%} reduction)",
            f"- Exploit success rate: **{exp['exploit_success_rate_before']:.0%} -> "
            f"{exp['exploit_success_rate_after']:.0%}**",
            "",
            "## Detection",
            f"- Detection rate: **{det['detection_rate']:.0%}** "
            f"(missed {det['missed']}, false-negative rate {det['false_negative_rate']:.0%})",
            f"- Mean detection latency: **{det['mean_latency_s']} s**",
            f"- Detection rules auto-proposed for gaps: **{det['rules_auto_proposed']}**",
            "",
            "## Safety and business impact",
            f"- Unplanned outages: **{saf['unplanned_outages']}** "
            f"(availability OK rate {mx.business_impact['availability_ok_rate']:.0%})",
            f"- Verified-cleanup rate: **{saf['verified_cleanup_rate']:.0%}**",
            f"- Blocked-action rate: **{saf['blocked_action_rate']:.0%}**, "
            f"remediation regression rate **{mx.business_impact['remediation_regression_rate']:.0%}**",
            "",
            "## Efficiency",
            f"- Proven fixes: **{mx.efficiency['fixes_proven']}** / {mx.efficiency['fixes_proposed']} proposed",
            f"- Engagement time: **{mx.efficiency['engagement_seconds']} s** "
            f"({mx.efficiency['mean_seconds_per_validated_path']} s per validated path)",
            f"- Estimated analyst hours saved: **{mx.efficiency['analyst_hours_saved_estimate']}**",
            "",
            "## Target scorecard",
        ]
        for name, c in sc["checks"].items():
            mark = "PASS" if c["met"] else "FAIL"
            lines.append(f"- {name}: {c['actual']} (target {c['comparator']} {c['target']}) -> **{mark}**")
        return "\n".join(lines)


# ---------------------------------------------------------------------- helpers
def _ratio(num: float, den: float) -> float:
    return round(num / den, 3) if den else 0.0


def _check(actual: float, target: float, direction: str) -> dict[str, Any]:
    met = actual >= target if direction == "min" else actual <= target
    return {"actual": actual, "target": target,
            "comparator": ">=" if direction == "min" else "<=", "met": bool(met)}


def _summary_signature(report: EngagementReport) -> str:
    """A time-independent signature of a run, used to prove repeatability.

    Excludes the per-action rows (which carry wall-clock telemetry timestamps)
    and compares only the structural outcome of the engagement.
    """
    summary = {k: v for k, v in report.as_dict().items() if k != "actions"}
    return json.dumps(summary, sort_keys=True, default=str)
