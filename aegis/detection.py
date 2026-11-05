"""Detection engine (PRD FR-13).

Sigma-style rules match the telemetry the red agent emits. For every validation
action we record whether it was detected, missed, or detected late, plus the
latency. "Missed" validations are exactly the gaps the blue agent should close
with a new detection rule, so this feeds Phase 3's response step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .redteam import ActionResult, TelemetryEvent

# A rule matches on technique and/or a telemetry signature substring.
DEFAULT_RULES: list[dict[str, Any]] = [
    {"id": "SIGMA-SQLI-1", "name": "SQL injection login attempt", "technique": "sqli-login-probe",
     "contains": "sqli:", "latency_s": 4, "severity": "high"},
    {"id": "SIGMA-CRED-1", "name": "Default / weak credential use", "technique": "weak-credential-check",
     "contains": "auth:default-credentials", "latency_s": 12, "severity": "medium"},
    {"id": "SIGMA-DISCO-1", "name": "Host discovery command", "technique": "T1082",
     "contains": "", "latency_s": 30, "severity": "low"},
    # Phase 6 broader-coverage detections (cloud / kubernetes / OT).
    {"id": "SIGMA-CLOUD-1", "name": "Cloud misconfiguration access", "technique": "cloud-misconfig-probe",
     "contains": "cloud:", "latency_s": 8, "severity": "high"},
    {"id": "SIGMA-K8S-1", "name": "Excessive Kubernetes RBAC / privileged pod", "technique": "k8s-rbac-probe",
     "contains": "k8s:", "latency_s": 10, "severity": "high"},
    {"id": "SIGMA-OT-1", "name": "Unauthenticated OT protocol access", "technique": "ot-protocol-probe",
     "contains": "ot:", "latency_s": 15, "severity": "critical"},
    # Note: there is deliberately no rule for "net:connect" (reachability-probe),
    # so plain reachability validation is MISSED until the blue agent adds one.
]


@dataclass
class DetectionResult:
    action_id: str
    target: str
    technique: str
    detected: bool
    rule_id: str | None
    latency_s: float | None
    quality: str  # detected | missed | detected-late

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class DetectionEngine:
    def __init__(self, rules: list[dict[str, Any]] | None = None, late_threshold_s: float = 20.0) -> None:
        self.rules = list(rules if rules is not None else DEFAULT_RULES)
        self.late_threshold_s = late_threshold_s

    def add_rule(self, rule: dict[str, Any]) -> None:
        self.rules.append(rule)

    def evaluate(self, result: ActionResult) -> DetectionResult:
        for event in result.telemetry:
            rule = self._match(event)
            if rule:
                latency = float(rule.get("latency_s", 0))
                quality = "detected-late" if latency > self.late_threshold_s else "detected"
                return DetectionResult(result.action.action_id, event.target, event.technique, True, rule["id"], latency, quality)
        tech = result.action.technique
        return DetectionResult(result.action.action_id, result.action.target, tech, False, None, None, "missed")

    def _match(self, event: TelemetryEvent) -> dict[str, Any] | None:
        for rule in self.rules:
            if rule.get("technique") and rule["technique"] != event.technique:
                continue
            needle = rule.get("contains", "")
            if needle and needle not in event.signature:
                continue
            return rule
        return None


def detection_rule_for(technique: str, signature: str) -> dict[str, Any]:
    """A proposed Sigma rule that would catch a currently-missed technique."""
    return {
        "id": f"SIGMA-AEGIS-{technique.upper()}",
        "name": f"AEGIS auto-proposed rule for {technique}",
        "technique": technique,
        "contains": signature.split(":")[0] + ":" if ":" in signature else signature,
        "latency_s": 5,
        "severity": "medium",
    }
