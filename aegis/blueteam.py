"""Blue-team agent: remediation proposals and the proof engine
(PRD FR-14, FR-15, FR-25, FR-26, FR-27).

A :class:`Fix` is a *pure transform* over the knowledge graph: applying it
returns the graph as it would be once the change lands (an edge removed by
segmentation, a weak-credential node rotated away, a mitigating control added).
That lets the :class:`ProofEngine` do the thing that distinguishes this platform
from a scanner (FR-25): take the exact attack path a red action validated,
re-run that action against the post-fix graph, and record pass/fail with
evidence - *before* anyone touches production.

Every proposal carries predicted impact, a rollback plan and an approval tier
(FR-14). Proof also runs regression checks on legitimate business workflows, so
a fix that would break real access is rejected (FR-26).
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from .graph import AttackGraph
from .model import Edge, EdgeKind, Node, NodeKind, node_id
from .redteam import ActionResult, RedAgent, ValidationAction

# approval tiers (FR-15): auto-apply only the lowest tier, per policy.
TIER_AUTO = "auto"       # reversible, additive, low blast radius
TIER_LOW = "low-risk"    # staged, single approval
TIER_HIGH = "high-risk"  # explicit approval, twin-first


@dataclass
class Fix:
    fix_id: str
    title: str
    fix_type: str
    target: str
    addresses: str           # vuln_id or edge/identity reference it closes
    predicted_impact: str
    rollback: str
    approval_tier: str
    blast_radius: float
    # transform applied to (nodes, edges) -> (nodes, edges)
    _transform: Callable[[dict[str, Node], list[Edge]], tuple[dict[str, Node], list[Edge]]] = field(repr=False, default=None)
    technique: str = "remediation"
    non_destructive: bool = True  # staging the change is itself non-destructive

    def apply_to(self, nodes: dict[str, Node], edges: list[Edge]) -> tuple[dict[str, Node], list[Edge]]:
        nodes2 = copy.deepcopy(nodes)
        edges2 = [Edge(e.src, e.dst, e.kind, dict(e.props)) for e in edges]
        if self._transform is None:
            return nodes2, edges2
        return self._transform(nodes2, edges2)

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


# ------------------------------------------------------------------- transforms
def _drop_edges(pred: Callable[[Edge], bool]):
    def t(nodes, edges):
        return nodes, [e for e in edges if not pred(e)]
    return t


def _drop_node(nid: str):
    def t(nodes, edges):
        nodes.pop(nid, None)
        return nodes, [e for e in edges if e.src != nid and e.dst != nid]
    return t


def _neutralize_vuln(vid: str, control_name: str):
    """Keep the weakness visible but remove the access it grants, and add a
    protecting control (models a WAF / input validation in front of the asset)."""
    def t(nodes, edges):
        cid = node_id(NodeKind.CONTROL, control_name)
        edges2 = [e for e in edges if not (e.src == vid and e.kind == EdgeKind.GRANTS)]
        host = next((e.src for e in edges if e.dst == vid and e.kind == EdgeKind.HAS_VULNERABILITY), None)
        if vid in nodes:
            nodes[vid].props["mitigated_by"] = control_name
        nodes[cid] = Node(cid, NodeKind.CONTROL, {"name": control_name, "control_type": "waf", "enabled": True})
        if host:
            edges2.append(Edge(cid, host, EdgeKind.PROTECTS, {"mitigates": vid}))
        return nodes, edges2
    return t


class BlueAgent:
    """Proposes fixes for a validated finding / attack path."""

    def propose(self, graph: AttackGraph, action_result: ActionResult) -> list[Fix]:
        vid = action_result.action.vuln_id
        vuln = graph.nodes.get(vid)
        fixes: list[Fix] = []
        if vuln is None:
            return fixes
        cls = str(vuln.props.get("classification", "")).lower()
        host = _host_of(graph, vid)

        if "cwe-89" in cls or "injection" in vuln.name.lower():
            fixes.append(self._mk(
                "waf-virtual-patch", f"Deploy a WAF virtual patch in front of {host}", "web-firewall", host, vid,
                predicted_impact="Blocks SQL-injection payloads at the proxy; Juice Shop code unchanged. "
                                 "Adds one hop of latency; no data change.",
                rollback="Remove the ModSecurity sidecar and restore the direct route.",
                tier=TIER_LOW, blast=0.3, transform=_neutralize_vuln(vid, "modsecurity-waf"),
            ))
        if "cwe-521" in cls or "cwe-798" in cls or "weak credential" in vuln.name.lower():
            fixes.append(self._mk(
                "rotate-secret", f"Rotate the weak secret on {host} and move it to a secrets manager", "credential", host, vid,
                predicted_impact="Replaces the guessable secret; dependent services must read the new value. "
                                 "Brief reconnect on rotation.",
                rollback="Restore the previous secret from the sealed backup (not recommended).",
                tier=TIER_LOW, blast=0.35, transform=_drop_node(vid),
            ))
        # Phase 6 coverage findings carry a remediation hint naming the control to
        # apply (cloud-firewall, bucket-policy, k8s-networkpolicy, rbac-tighten,
        # ot-protocol-gateway, ...). Build the matching graph transform.
        hint = vuln.props.get("remediation")
        if hint:
            strategy = str(hint.get("strategy", "neutralize"))
            control = str(hint.get("control", hint.get("fix_type", "mitigating-control")))
            transform = _drop_node(vid) if strategy == "drop" else _neutralize_vuln(vid, control)
            fixes.append(self._mk(
                str(hint.get("fix_type", "harden-config")),
                f"Apply {hint.get('fix_type', 'hardening')} on {host}", str(hint.get("fix_type", "config")), host, vid,
                predicted_impact=f"Closes '{vuln.name}' on {host} by applying {hint.get('fix_type')} "
                                 f"({'removes the weakness' if strategy == 'drop' else 'adds a mitigating control'}). "
                                 f"No legitimate workflow depends on the misconfiguration.",
                rollback=f"Revert the {hint.get('fix_type')} change on {host}.",
                tier=str(hint.get("tier", TIER_LOW)), blast=float(hint.get("blast", 0.3)), transform=transform,
            ))

        # Path-structural fixes derived from how the path reaches its objective.
        for fix in self._path_fixes(graph, action_result):
            fixes.append(fix)
        return _dedupe(fixes)

    def _path_fixes(self, graph: AttackGraph, action_result: ActionResult) -> list[Fix]:
        fixes: list[Fix] = []
        # Only consider edges that lie on the attack path this action validated,
        # so proposals are relevant to the finding rather than the whole estate.
        path = next((p for p in graph.attack_paths(500) if p.path_id == action_result.action.path_id), None)
        on_path = set(path.states) if path else set()

        def in_path(edge: Edge) -> bool:
            if not on_path:
                return True
            refs = {s.split(":", 1)[1] for s in on_path if ":" in s}
            return edge.src in refs and edge.dst in refs

        # Flat reachability into a high-value asset -> segment it off. This covers
        # the on-prem workstation->database flat network and the Phase 6 coverage
        # cases a collector flags as segmentable (a cloud route to a managed DB, a
        # missing k8s NetworkPolicy, a flat OT conduit to a PLC).
        for e in graph.edges:
            if e.kind != EdgeKind.CAN_REACH or not in_path(e):
                continue
            dst = graph.nodes.get(e.dst)
            src = graph.nodes.get(e.src)
            if not (dst and src):
                continue
            high_value = dst.props.get("crown_jewel") or float(dst.props.get("criticality", 0) or 0) >= 0.7
            flat = bool(e.props.get("segmentable")) or src.props.get("asset_type") == "workstation"
            if high_value and flat:
                fixes.append(self._mk(
                    f"segment-{src.name}-{dst.name}", f"Remove {src.name}'s direct network path to {dst.name}", "segmentation",
                    dst.name, f"{e.src}->{e.dst}",
                    predicted_impact=f"{src.name} can no longer reach {dst.name} directly. This path is a "
                                     f"misconfiguration, so no legitimate workflow is affected.",
                    rollback=f"Re-attach the direct route from {src.name} to {dst.name}.",
                    tier=TIER_LOW, blast=0.25,
                    transform=_drop_edges(lambda x, s=e.src, d=e.dst: x.kind == EdgeKind.CAN_REACH and x.src == s and x.dst == d),
                ))
        # Cached-credential exposure on a shared host -> stop caching creds there.
        for e in graph.edges:
            if e.kind == EdgeKind.SESSION_ON and in_path(e):
                ident = graph.nodes.get(e.src)
                host = graph.nodes.get(e.dst)
                if ident and host:
                    fixes.append(self._mk(
                        f"clear-session-{ident.name}", f"Stop {ident.name} caching credentials on {host.name}",
                        "identity-hygiene", host.name, f"{e.src}->{e.dst}",
                        predicted_impact=f"Clears {ident.name}'s cached session on {host.name} and disables credential "
                                         f"caching. {ident.name}'s own legitimate access is unchanged.",
                        rollback="Re-enable credential caching (not recommended).",
                        tier=TIER_AUTO, blast=0.15,
                        transform=_drop_edges(lambda x, s=e.src, d=e.dst: x.kind == EdgeKind.SESSION_ON and x.src == s and x.dst == d),
                    ))
        return fixes

    def _mk(self, slug, title, ftype, target, addresses, predicted_impact, rollback, tier, blast, transform) -> Fix:
        return Fix(
            fix_id="fix-" + hashlib.sha1(f"{slug}|{addresses}".encode()).hexdigest()[:10],
            title=title, fix_type=ftype, target=target, addresses=addresses,
            predicted_impact=predicted_impact, rollback=rollback, approval_tier=tier,
            blast_radius=blast, _transform=transform,
        )


@dataclass
class ProofResult:
    fix_id: str
    action_id: str
    path_id: str
    closed: bool                 # the re-run attack is now blocked (FR-25)
    regression_ok: bool          # legitimate workflows still work (FR-26)
    broken_workflows: list[str]
    paths_before: int
    paths_after: int
    exposure_before: float
    exposure_after: float
    verdict: str                 # proven | failed-still-open | rejected-regression
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class ProofEngine:
    """Re-runs a validated attack after a fix and checks for regressions."""

    def __init__(self, red: RedAgent | None = None) -> None:
        self.red = red or RedAgent()

    def prove(self, graph_before: AttackGraph, fix: Fix, action: ValidationAction, environment: str = "twin") -> ProofResult:
        before_paths = graph_before.attack_paths(500)
        nodes_after, edges_after = fix.apply_to(graph_before.nodes, graph_before.edges)
        graph_after = AttackGraph(nodes_after, edges_after)
        after_paths = graph_after.attack_paths(500)

        rerun = self.red.execute(action, graph_after, environment)
        closed = not rerun.succeeded

        before_access = _legit_access(graph_before)
        after_access = _legit_access(graph_after)
        broken = sorted(f"{i}:{a}" for (i, a, k) in before_access - after_access)
        regression_ok = not broken

        if not regression_ok:
            verdict = "rejected-regression"
        elif closed:
            verdict = "proven"
        else:
            verdict = "failed-still-open"

        evidence = {
            "fix_id": fix.fix_id,
            "action_id": action.action_id,
            "path_id": action.path_id,
            "environment": environment,
            "rerun_outcome": rerun.outcome,
            "rerun_evidence": rerun.evidence,
            "attack_paths_before": len(before_paths),
            "attack_paths_after": len(after_paths),
        }
        return ProofResult(
            fix_id=fix.fix_id, action_id=action.action_id, path_id=action.path_id,
            closed=closed, regression_ok=regression_ok, broken_workflows=broken,
            paths_before=len(before_paths), paths_after=len(after_paths),
            exposure_before=round(sum(max(p.security_value, 0) for p in before_paths), 3),
            exposure_after=round(sum(max(p.security_value, 0) for p in after_paths), 3),
            verdict=verdict, evidence=evidence,
        )


def _legit_access(graph: AttackGraph) -> set[tuple[str, str, str]]:
    """Legitimate, must-not-break access: every enabled identity's admin/login
    rights are a business workflow the proof engine must preserve (FR-26)."""
    out: set[tuple[str, str, str]] = set()
    for nid, node in graph.nodes.items():
        if node.kind != NodeKind.IDENTITY:
            continue
        for kind in (EdgeKind.ADMIN_OF, EdgeKind.CAN_LOGIN):
            for dst, _ in graph._out(nid, kind):
                out.add((nid, dst, str(kind)))
    return out


def _host_of(graph: AttackGraph, vid: str) -> str:
    host = next((src for src, _ in graph._in(vid, EdgeKind.HAS_VULNERABILITY)), "")
    return graph.nodes[host].name if host in graph.nodes else "unknown"


def _dedupe(fixes: list[Fix]) -> list[Fix]:
    seen: dict[str, Fix] = {}
    for f in fixes:
        seen.setdefault(f.fix_id, f)
    return list(seen.values())
