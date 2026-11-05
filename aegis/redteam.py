"""Red-team agent: bounded, non-destructive validation (PRD FR-9, FR-10, FR-11).

The agent ranks attack paths from the graph (Phase 1) and, for the exploit
steps on the top paths, plans :class:`ValidationAction` s. Every action is
*non-destructive*: it proves access and stops (log in and read one marker,
open a TCP port, run a read-only discovery command). None writes, deletes, or
persists anything.

An action succeeds in validation iff its target weakness is genuinely reachable
in the current graph - so validation is grounded in observed state, never in a
model's guess (this is what makes a finding "validated" rather than
"theoretical"). Each run emits telemetry the blue-team detection engine consumes,
and declares the cleanup needed so the cleanup scanner can confirm no residue.

Executors default to a deterministic simulation so the whole loop runs offline;
live adapters (an HTTP SQLi probe, a TCP reachability check) are used only when
an environment is actually available and policy allows.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .graph import AttackGraph, AttackPath
from .model import NodeKind

# Map a weakness class to the validation technique that proves it, the ATT&CK-ish
# signature emitted as telemetry, and how destructive / risky it is.
TECHNIQUE_FOR_CWE = {
    "89": "sqli-login-probe",
    "521": "weak-credential-check",
    "798": "weak-credential-check",
}


@dataclass
class TelemetryEvent:
    at: str
    target: str
    technique: str
    signature: str
    detail: str
    source: str = "red-agent"

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ValidationAction:
    action_id: str
    name: str
    technique: str
    target: str            # asset name (authorized-asset check in safety)
    vuln_id: str           # knowledge-graph vulnerability node this validates
    path_id: str
    port: int | None = None
    non_destructive: bool = True
    blast_radius: float = 0.1
    operational_risk: float = 0.2
    cleanup: list[str] = field(default_factory=list)
    signature: str = ""

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ActionResult:
    action: ValidationAction
    environment: str
    succeeded: bool
    outcome: str
    telemetry: list[TelemetryEvent]
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.as_dict(),
            "environment": self.environment,
            "succeeded": self.succeeded,
            "outcome": self.outcome,
            "telemetry": [e.as_dict() for e in self.telemetry],
            "evidence": self.evidence,
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class RedAgent:
    def __init__(self, live_adapters: dict[str, Any] | None = None) -> None:
        # live_adapters: optional callables keyed by technique for real execution.
        self.live_adapters = live_adapters or {}

    # --------------------------------------------------------------- planning
    def plan(self, graph: AttackGraph, top_paths: int = 5, max_actions: int = 12) -> list[ValidationAction]:
        """Propose validation actions for the exploit steps on the top attack paths.

        FR-11: prefer steps on high-value paths and avoid repeatedly validating
        the same weakness, so we don't just re-pick the same easy win.
        """
        paths = graph.attack_paths(limit=max(top_paths, 10))
        actions: list[ValidationAction] = []
        seen: set[str] = set()
        for path in paths[:top_paths]:
            for vid in path.vulnerabilities:
                if vid in seen or vid not in graph.nodes:
                    continue
                seen.add(vid)
                action = self._action_for(graph, graph.nodes[vid], path)
                if action:
                    actions.append(action)
                if len(actions) >= max_actions:
                    return actions
        return actions

    def _action_for(self, graph: AttackGraph, vuln, path: AttackPath) -> ValidationAction | None:
        props = vuln.props
        cwe = str(props.get("cwe", "")).replace("CWE-", "").split("/")[0].strip()
        technique = TECHNIQUE_FOR_CWE.get(cwe)
        if technique is None:
            # Generic reachability proof for weaknesses without a specific probe.
            technique = "reachability-probe"
        from .model import EdgeKind

        host = next((src for src, _ in graph._in(vuln.id, EdgeKind.HAS_VULNERABILITY)), "")
        asset = graph.nodes[host].name if host in graph.nodes else "unknown"
        signature = {
            "sqli-login-probe": "sqli:login:or-1-1",
            "weak-credential-check": "auth:default-credentials",
            "reachability-probe": "net:connect",
        }[technique]
        return ValidationAction(
            action_id="act-" + hashlib.sha1(f"{technique}|{vuln.id}".encode()).hexdigest()[:10],
            name=f"Validate {vuln.name} on {asset}",
            technique=technique,
            target=asset,
            vuln_id=vuln.id,
            path_id=path.path_id,
            port=props.get("port"),
            blast_radius=round(min(0.5, 0.1 + path.operational_risk * 0.4), 3),
            operational_risk=path.operational_risk,
            cleanup=["close probe session", "discard retrieved marker", "remove temporary auth token"],
            signature=signature,
        )

    # -------------------------------------------------------------- execution
    def execute(self, action: ValidationAction, graph: AttackGraph, environment: str) -> ActionResult:
        """Run (or simulate) the bounded action and collect evidence."""
        adapter = self.live_adapters.get(action.technique)
        if adapter is not None:
            return adapter(action, graph, environment)
        return self._simulate(action, graph, environment)

    def _simulate(self, action: ValidationAction, graph: AttackGraph, environment: str) -> ActionResult:
        # Grounded outcome: the weakness is exploitable iff it still sits on a
        # reachable attack path in the current graph.
        on_path = {vid for p in graph.attack_paths(limit=500) for vid in p.vulnerabilities}
        reachable = action.vuln_id in on_path
        vuln = graph.nodes.get(action.vuln_id)
        confidence = float(vuln.props.get("confidence", 0.5)) if vuln else 0.0
        event = TelemetryEvent(
            at=_now(),
            target=action.target,
            technique=action.technique,
            signature=action.signature,
            detail=f"{action.technique} against {action.target}:{action.port or 'n/a'}",
        )
        outcome = "access-proven" if reachable else "blocked"
        evidence = {
            "action_id": action.action_id,
            "vuln_id": action.vuln_id,
            "path_id": action.path_id,
            "environment": environment,
            "reachable_in_graph": reachable,
            "confidence": confidence,
            "telemetry_signature": action.signature,
            "marker": _marker(action) if reachable else None,
            "note": "non-destructive validation: proved access and stopped" if reachable else "target not reachable",
        }
        return ActionResult(action, environment, reachable, outcome, [event], evidence)


def _marker(action: ValidationAction) -> str:
    # A harmless proof token the action "retrieved" - deterministic, not real data.
    return "AEGIS-PROOF-" + hashlib.sha1(f"{action.action_id}|{action.vuln_id}".encode()).hexdigest()[:8]
