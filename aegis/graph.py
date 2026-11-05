"""Attack-graph engine (PRD FR-6, FR-7, FR-9).

The knowledge graph (assets, identities, vulnerabilities ...) is compiled into
an *attack graph* whose nodes are attacker privilege states:

    pos:<asset>    foothold / code execution / network position on the asset
    app:<asset>    administrative access to the asset's application or data
    data:<asset>   read access to the asset's data
    id:<identity>  control of an identity (its credentials or session)
    vuln:<vuln>    the attacker exploits this weakness (an intermediate step)

Transitions:

    pos:A  -> vuln:V        A can reach V's asset on V's port (or V is local to A)
    vuln:V -> pos/app/data:B   per V's GRANTS edges
    vuln:V -> id:I          V yields an identity
    pos:A  -> id:I          I's credentials are exposed on A (SESSION_ON)
    id:I   -> app:B         I is ADMIN_OF B
    id:I   -> pos:B         I CAN_LOGIN to B
    app:P / pos:P -> id:I   P is the IdP that issues I (trust boundary)

Attack paths run from entry points (the internet and assumed-breach assets)
to objectives (crown-jewel assets and privileged identities) and are scored
with the PRD formula:

    security_value = impact x reachability x confidence - operational_risk
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from .model import Edge, EdgeKind, Level, Node, NodeKind

MAX_HOPS = 8
MAX_PATHS_PER_PAIR = 25   # candidate paths examined per (entry, objective)
BEST_PATHS_PER_PAIR = 3   # paths reported per (entry, objective)
IDP_TYPES = {"idp", "directory"}
LEVEL_PREFIX = {Level.FOOTHOLD: "pos", Level.APP_ADMIN: "app", Level.DATA_READ: "data"}
LEVEL_IMPACT = {"pos": 1.0, "app": 0.9, "data": 0.6, "id": 1.0}
SESSION_CONFIDENCE = 0.5  # cached credentials are a weak signal until validated
OP_RISK_WEIGHT = 0.25
OBJECTIVE_CRITICALITY = 0.7  # assets at or above this criticality are attacker objectives


@dataclass
class AttackPath:
    path_id: str
    entry: str
    target: str
    states: list[str]
    steps: list[dict[str, Any]]
    impact: float
    reachability: float
    confidence: float
    operational_risk: float
    security_value: float
    status: str  # validated | exploitable | theoretical
    vulnerabilities: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class AttackGraph:
    def __init__(self, nodes: dict[str, Node], edges: list[Edge]) -> None:
        self.nodes = nodes
        self.edges = edges
        self.kg = nx.MultiDiGraph()
        for nid, node in nodes.items():
            self.kg.add_node(nid, kind=str(node.kind), **node.props)
        for e in edges:
            self.kg.add_edge(e.src, e.dst, key=str(e.kind), **e.props)
        self.ag = nx.DiGraph()
        self._compile()

    # -------------------------------------------------------------- compile
    def _out(self, src: str, kind: EdgeKind) -> list[tuple[str, dict[str, Any]]]:
        if src not in self.kg:
            return []
        return [(dst, data) for _, dst, k, data in self.kg.out_edges(src, keys=True, data=True) if k == str(kind)]

    def _in(self, dst: str, kind: EdgeKind) -> list[tuple[str, dict[str, Any]]]:
        if dst not in self.kg:
            return []
        return [(src, data) for src, _, k, data in self.kg.in_edges(dst, keys=True, data=True) if k == str(kind)]

    def _add(self, a: str, b: str, **data: Any) -> None:
        data.setdefault("confidence", 1.0)
        data.setdefault("reach", 1.0)
        data.setdefault("op_risk", 0.0)
        if self.ag.has_edge(a, b) and self.ag[a][b]["confidence"] >= data["confidence"]:
            return
        self.ag.add_edge(a, b, **data)

    def _compile(self) -> None:
        assets = {nid: n for nid, n in self.nodes.items() if n.kind == NodeKind.ASSET}
        vulns = {nid: n for nid, n in self.nodes.items() if n.kind == NodeKind.VULNERABILITY}
        identities = {nid: n for nid, n in self.nodes.items() if n.kind == NodeKind.IDENTITY}

        vuln_host: dict[str, str] = {}
        for aid in assets:
            for vid, _ in self._out(aid, EdgeKind.HAS_VULNERABILITY):
                vuln_host[vid] = aid

        # pos:A -> vuln:V when A reaches V's host on V's port
        for vid, host in vuln_host.items():
            v = vulns[vid].props
            conf = float(v.get("confidence", 0.5))
            risk = _op_risk(assets[host].props, v)
            port = v.get("port")
            for src, data in self._in(host, EdgeKind.CAN_REACH):
                ports = data.get("ports") or []
                if v.get("remote", True) and (port is None or not ports or int(port) in ports):
                    self._add(f"pos:{src}", f"vuln:{vid}", kind="exploit", confidence=conf, op_risk=risk,
                              detail=f"reach {assets[host].name}:{port or 'any'} and exploit")
            # local exploitation from a foothold on the host itself
            self._add(f"pos:{host}", f"vuln:{vid}", kind="exploit", confidence=conf, op_risk=risk,
                      detail="exploit locally")
            for dst, data in self._out(vid, EdgeKind.GRANTS):
                level = str(data.get("level", Level.APP_ADMIN))
                if dst.startswith("identity:"):
                    self._add(f"vuln:{vid}", f"id:{dst}", kind="grants", detail="yields identity")
                else:
                    prefix = LEVEL_PREFIX.get(Level(level), "app") if level in {l.value for l in Level} else "app"
                    self._add(f"vuln:{vid}", f"{prefix}:{dst}", kind="grants", detail=f"gain {level}")

        for iid in identities:
            for dst, data in self._out(iid, EdgeKind.ADMIN_OF):
                self._add(f"id:{iid}", f"app:{dst}", kind="admin", detail="use admin role")
            for dst, data in self._out(iid, EdgeKind.CAN_LOGIN):
                self._add(f"id:{iid}", f"pos:{dst}", kind="login", detail="log in")
            for host, data in self._out(iid, EdgeKind.SESSION_ON):
                self._add(f"pos:{host}", f"id:{iid}", kind="credential_access",
                          confidence=float(data.get("confidence", SESSION_CONFIDENCE)),
                          op_risk=0.05, detail="harvest cached credentials")
            for idp, _ in self._out(iid, EdgeKind.TRUSTS):
                if assets.get(idp) and assets[idp].props.get("asset_type") in IDP_TYPES:
                    for prefix in ("app", "pos"):
                        self._add(f"{prefix}:{idp}", f"id:{iid}", kind="trust_abuse", detail="IdP issues this identity")

        # A foothold implies application/data access on the same asset.
        for aid in assets:
            self._add(f"pos:{aid}", f"app:{aid}", kind="implied", detail="foothold implies local admin of app")
            self._add(f"app:{aid}", f"data:{aid}", kind="implied", detail="app admin can read data")

        for node in list(self.ag.nodes):
            self.ag.nodes[node]["label"] = self.describe(node)

    # ---------------------------------------------------------------- query
    def entry_points(self) -> list[str]:
        return [f"pos:{nid}" for nid, n in self.nodes.items()
                if n.kind == NodeKind.ASSET and n.props.get("entry_point") and f"pos:{nid}" in self.ag]

    def objectives(self) -> dict[str, float]:
        """Attack-graph states worth reaching, mapped to their impact (0..1)."""
        out: dict[str, float] = {}
        for nid, n in self.nodes.items():
            if n.kind == NodeKind.ASSET and (n.props.get("crown_jewel") or float(n.props.get("criticality", 0)) >= OBJECTIVE_CRITICALITY):
                crit = float(n.props.get("criticality", 1.0))
                for prefix in ("app", "data"):
                    state = f"{prefix}:{nid}"
                    if state in self.ag:
                        out[state] = round(crit * LEVEL_IMPACT[prefix], 3)
            if n.kind == NodeKind.IDENTITY and n.props.get("privileged") and f"id:{nid}" in self.ag:
                out[f"id:{nid}"] = 0.8
        return out

    def attack_paths(self, limit: int = 50) -> list[AttackPath]:
        objectives = self.objectives()
        entries = self.entry_points()
        found: list[AttackPath] = []
        for entry in entries:
            for target, impact in objectives.items():
                if entry == target or not nx.has_path(self.ag, entry, target):
                    continue
                candidates = []
                for count, states in enumerate(nx.shortest_simple_paths(self.ag, entry, target)):
                    if count >= MAX_PATHS_PER_PAIR or len(states) - 1 > MAX_HOPS:
                        break
                    if target.startswith("data:") and "app:" + target[5:] in states:
                        continue  # data access via admin is implied by the shorter admin path
                    if any(s in entries for s in states[1:]):
                        continue  # covered by the path that starts from that entry point
                    candidates.append(self._score(states, impact))
                candidates.sort(key=lambda p: (-p.security_value, len(p.states)))
                found.extend(candidates[:BEST_PATHS_PER_PAIR])
        ranked = sorted(found, key=lambda p: (-p.security_value, len(p.states)))
        return ranked[:limit]

    def unreachable_vulnerabilities(self) -> list[str]:
        """Vulnerabilities no entry point can reach: theoretical, not exploitable (FR-7)."""
        reachable: set[str] = set()
        for entry in self.entry_points():
            reachable |= nx.descendants(self.ag, entry)
        return sorted(vid for vid, n in self.nodes.items()
                      if n.kind == NodeKind.VULNERABILITY and f"vuln:{vid}" not in reachable)

    def _score(self, states: list[str], impact: float) -> AttackPath:
        steps, conf, reach, risk = [], 1.0, 1.0, 0.0
        vulns: list[str] = []
        validated = True
        for a, b in zip(states, states[1:]):
            data = self.ag[a][b]
            conf *= data["confidence"]
            reach *= data["reach"]
            risk = max(risk, data["op_risk"])
            if b.startswith("vuln:"):
                vid = b[5:]
                vulns.append(vid)
                validated &= bool(self.nodes[vid].props.get("validated"))
            elif data["kind"] == "credential_access":
                validated = False
            steps.append({"from": a, "to": b, "kind": data["kind"], "detail": data.get("detail", ""),
                          "confidence": round(data["confidence"], 3), "label": self.describe(b)})
        # Longer chains are harder to execute: a mild length discount on confidence.
        conf *= math.pow(0.97, max(0, len(steps) - 2))
        value = impact * reach * conf - OP_RISK_WEIGHT * risk
        if validated and vulns:
            status = "validated"
        elif conf >= 0.3:
            status = "exploitable"
        else:
            status = "theoretical"
        pid = "path-" + hashlib.sha1("|".join(states).encode()).hexdigest()[:10]
        return AttackPath(
            path_id=pid, entry=states[0], target=states[-1], states=states, steps=steps,
            impact=round(impact, 3), reachability=round(reach, 3), confidence=round(conf, 3),
            operational_risk=round(risk, 3), security_value=round(value, 3), status=status, vulnerabilities=vulns,
        )

    # -------------------------------------------------------------- display
    def describe(self, state: str) -> str:
        prefix, _, ref = state.partition(":")
        node = self.nodes.get(ref)
        name = node.name if node else ref
        if node is not None and node.props.get("asset_type") == "external":
            return f"attacker on the {name}"
        return {
            "pos": f"foothold on {name}",
            "app": f"admin of {name}",
            "data": f"read data on {name}",
            "id": f"control identity {name}",
            "vuln": f"exploit {name}",
        }.get(prefix, state)

    def knowledge_graph(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": nid, "kind": str(n.kind), "name": n.name, **n.props} for nid, n in self.nodes.items()],
            "edges": [{"src": e.src, "dst": e.dst, "kind": str(e.kind), **e.props} for e in self.edges],
        }


def diff_paths(before: list[AttackPath], after: list[AttackPath]) -> dict[str, Any]:
    b = {p.path_id: p for p in before}
    a = {p.path_id: p for p in after}
    return {
        "opened": [a[k].as_dict() for k in a.keys() - b.keys()],
        "closed": [b[k].as_dict() for k in b.keys() - a.keys()],
        "persisting": sorted(a.keys() & b.keys()),
        "exposure_before": round(sum(max(p.security_value, 0) for p in before), 3),
        "exposure_after": round(sum(max(p.security_value, 0) for p in after), 3),
    }


def _op_risk(asset: dict[str, Any], vuln: dict[str, Any]) -> float:
    """Risk that *validating* this step disrupts the business (0..1)."""
    env_factor = {"twin": 0.1, "canary": 0.3, "range": 0.5, "production": 1.0}.get(str(asset.get("environment", "range")), 0.5)
    crit = float(asset.get("criticality", 0.5))
    severity_factor = {"critical": 1.0, "high": 0.8, "medium": 0.5}.get(str(vuln.get("severity")), 0.3)
    return round(env_factor * crit * severity_factor, 3)
