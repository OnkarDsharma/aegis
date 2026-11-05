"""Safety, authorization and governance (PRD FR-17, FR-18, FR-19, FR-20).

The :class:`SafetyAgent` is an *independent* gate: every planned red or blue
action is evaluated against policy-as-code before it may run, and the planner
cannot bypass it. The default is deny - an action is allowed only when the
policy explicitly permits its technique, target and environment.

It enforces:
* an allow-list of assets and techniques (anything else is denied),
* per-run and per-target rate limits,
* human-approval thresholds by blast radius and environment,
* a blast-radius estimate attached to every decision (FR-19),
* a kill switch (a file on disk and/or an in-process flag) that fails closed.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("aegis.safety")

DEFAULT_POLICY = {
    "version": 1,
    # Assets the platform is authorized to touch. "*" is never implied.
    "authorized_assets": ["webapp", "database", "employee", "keycloak", "internet"],
    # ATT&CK-style technique ids / action kinds the red agent may perform.
    "allowed_techniques": [
        "sqli-login-probe",
        "weak-credential-check",
        "reachability-probe",
        "T1082",  # System Information Discovery
        "T1046",  # Network Service Discovery
    ],
    # Techniques that are always denied even if listed above.
    "prohibited_techniques": [
        "T1486",  # Data Encrypted for Impact (ransomware)
        "T1485",  # Data Destruction
        "T1490",  # Inhibit System Recovery
        "exploit-write",
        "lateral-persist",
    ],
    # Only non-destructive actions may run without a human (FR-10).
    "require_non_destructive": True,
    "allowed_environments": ["twin", "canary", "range"],
    "rate_limits": {"per_run": 50, "per_target": 10},
    # Human approval required at/above this blast radius, or in these envs.
    "approval": {
        "blast_radius_threshold": 0.6,
        "environments_requiring_approval": ["production"],
        "auto_approve_environments": ["twin"],
    },
    "kill_switch_file": "var/KILL_SWITCH",
}


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    requires_approval: bool
    blast_radius: float
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "blast_radius": round(self.blast_radius, 3),
            "reasons": list(self.reasons),
        }


class Policy:
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        merged = dict(DEFAULT_POLICY)
        merged.update(data or {})
        self.data = merged

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        path = Path(path)
        if not path.exists():
            log.warning("policy file %s not found; using built-in default policy", path)
            return cls()
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


class KillSwitch:
    """Fails closed: if the file exists or the flag is set, nothing runs."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path else None
        self._tripped = threading.Event()

    def engaged(self) -> bool:
        return self._tripped.is_set() or bool(self.path and self.path.exists())

    def trip(self, reason: str = "manual") -> None:
        log.error("KILL SWITCH engaged: %s", reason)
        self._tripped.set()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(f"engaged: {reason}\n", encoding="utf-8")

    def reset(self) -> None:
        self._tripped.clear()
        if self.path and self.path.exists():
            self.path.unlink()


class SafetyAgent:
    def __init__(self, policy: Policy | None = None, kill_switch: KillSwitch | None = None) -> None:
        self.policy = policy or Policy()
        self.kill_switch = kill_switch or KillSwitch(self.policy.get("kill_switch_file"))
        self._run_count = 0
        self._per_target: dict[str, int] = {}
        self._lock = threading.RLock()

    def reset_counters(self) -> None:
        with self._lock:
            self._run_count = 0
            self._per_target.clear()

    def evaluate(self, action: Any, environment: str, approved: bool = False) -> SafetyDecision:
        """Evaluate one action. ``action`` must expose ``technique``, ``target``,
        ``non_destructive`` and ``blast_radius`` attributes (see redteam/blueteam)."""
        reasons: list[str] = []
        technique = getattr(action, "technique", getattr(action, "kind", "unknown"))
        target = getattr(action, "target", "unknown")
        non_destructive = bool(getattr(action, "non_destructive", False))
        blast = float(getattr(action, "blast_radius", 0.5))

        if self.kill_switch.engaged():
            return SafetyDecision(False, False, blast, ["kill switch engaged; failing closed"])

        if technique in self.policy.get("prohibited_techniques", []):
            reasons.append(f"technique {technique} is explicitly prohibited")
        if technique not in self.policy.get("allowed_techniques", []):
            reasons.append(f"technique {technique} is not on the allow-list (default deny)")
        if target not in self.policy.get("authorized_assets", []):
            reasons.append(f"target {target} is not an authorized asset")
        if self.policy.get("require_non_destructive", True) and not non_destructive:
            reasons.append("action is not marked non-destructive")
        if environment not in self.policy.get("allowed_environments", []):
            reasons.append(f"environment {environment} is not permitted")

        limits = self.policy.get("rate_limits", {})
        with self._lock:
            if self._run_count >= int(limits.get("per_run", 10**9)):
                reasons.append("per-run rate limit exceeded")
            if self._per_target.get(target, 0) >= int(limits.get("per_target", 10**9)):
                reasons.append(f"per-target rate limit for {target} exceeded")

        approval_cfg = self.policy.get("approval", {})
        requires_approval = (
            blast >= float(approval_cfg.get("blast_radius_threshold", 0.6))
            or environment in approval_cfg.get("environments_requiring_approval", [])
        ) and environment not in approval_cfg.get("auto_approve_environments", [])

        if reasons:
            return SafetyDecision(False, requires_approval, blast, reasons)
        if requires_approval and not approved:
            return SafetyDecision(False, True, blast, ["human approval required and not granted"])

        with self._lock:
            self._run_count += 1
            self._per_target[target] = self._per_target.get(target, 0) + 1
        return SafetyDecision(True, requires_approval, blast, ["authorized by policy"])
