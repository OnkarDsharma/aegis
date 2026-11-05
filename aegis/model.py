"""Vendor-neutral data model (PRD FR-2).

Everything a collector observes is expressed as ``Node`` and ``Edge`` records.
Nodes have a ``kind`` and a free-form ``props`` dict; the keys each kind is
expected to carry are documented on :class:`NodeKind`.

IDs are stable strings of the form ``<kind>:<natural key>`` so that the same
real-world thing observed by two collectors maps onto one node.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeKind(StrEnum):
    # props: name, asset_type (workstation|server|database|idp|scanner|...),
    #        image, criticality (0..1), crown_jewel (bool), ports (list[int]),
    #        environment (range|twin|canary|production)
    ASSET = "asset"
    # props: name, network_type (bridge|...), trust_zone (dmz|corp|data|external)
    NETWORK = "network"
    # props: name, realm/domain, identity_type (user|service|app_user),
    #        privileged (bool)
    IDENTITY = "identity"
    # props: name, classification (CWE-89 / OWASP ...), severity, confidence (0..1),
    #        remote (bool), port, location, validated (bool), grants (list[dict])
    VULNERABILITY = "vulnerability"
    # props: name, control_type (scanner|waf|segmentation|mfa|...), enabled
    CONTROL = "control"
    # props: name, technique (ATT&CK id), tactic, command, outcome
    ATTACK_STEP = "attack_step"


class EdgeKind(StrEnum):
    MEMBER_OF = "member_of"            # asset -> network
    CAN_REACH = "can_reach"            # asset -> asset (props: ports)
    HAS_VULNERABILITY = "has_vulnerability"  # asset -> vulnerability
    GRANTS = "grants"                  # vulnerability -> asset|identity (props: level)
    ADMIN_OF = "admin_of"              # identity -> asset (props: level)
    CAN_LOGIN = "can_login"            # identity -> asset
    SESSION_ON = "session_on"          # identity -> asset (credential exposure on that host)
    TRUSTS = "trusts"                  # identity/realm federation (FR-6)
    PROTECTS = "protects"              # control -> asset
    DETECTED_BY = "detected_by"        # vulnerability -> control (scanner)
    EXECUTED_ON = "executed_on"        # attack_step -> asset


class Level(StrEnum):
    """Privilege an attacker holds over an asset in the attack graph."""

    FOOTHOLD = "foothold"    # code execution / shell / network position on the asset
    APP_ADMIN = "app_admin"  # administrative access to the asset's application / data
    DATA_READ = "data_read"  # read access to the asset's data


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def node_id(kind: str, key: str) -> str:
    return f"{kind}:{key}"


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return str(self.props.get("name", self.id.split(":", 1)[-1]))

    def fingerprint(self) -> str:
        return _fingerprint(self.kind, self.props)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.src}|{self.kind}|{self.dst}"

    def fingerprint(self) -> str:
        return _fingerprint(self.kind, self.props)


@dataclass
class Observation:
    """One collector run. ``scope`` names what the collector is authoritative for:
    anything previously recorded under the same scope but absent now is closed
    (``valid_to`` set) when the observation is ingested."""

    collector: str
    scope: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: Node) -> Node:
        self.nodes.append(node)
        return node

    def add_edge(self, src: str, dst: str, kind: EdgeKind, **props: Any) -> Edge:
        edge = Edge(src, dst, kind, props)
        self.edges.append(edge)
        return edge


def _fingerprint(kind: str, props: dict[str, Any]) -> str:
    blob = json.dumps({"k": str(kind), "p": props}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
