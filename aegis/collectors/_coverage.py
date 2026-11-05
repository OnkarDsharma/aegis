"""Shared helpers for the Phase 6 broader-coverage collectors
(cloud, kubernetes, OT/endpoints - PRD FR-4).

These collectors all read a declarative export (the kind a cloud inventory API,
a Kubernetes cluster dump, or an OT asset register would produce) and normalize
it into the same vendor-neutral model (FR-2) the rest of AEGIS uses, so the
attack-graph compiler, red/blue agents and proof engine work on them unchanged.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..model import EdgeKind, Level, Node, NodeKind, Observation, node_id

LEVELS = {"foothold": Level.FOOTHOLD, "app_admin": Level.APP_ADMIN, "data_read": Level.DATA_READ}


def load_json(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = Path(path).read_text(encoding="utf-8")
    return json.loads(raw), {"source": str(path), "sha256": hashlib.sha256(raw.encode()).hexdigest()}


def level_of(value: Any, default: Level = Level.APP_ADMIN) -> Level:
    return LEVELS.get(str(value or "").lower(), default)


def asset_node(obs: Observation, name: str, asset_type: str, *, criticality: float = 0.5,
               crown_jewel: bool = False, entry_point: bool = False, ports: list[int] | None = None,
               environment: str = "production", **extra: Any) -> str:
    aid = node_id(NodeKind.ASSET, name)
    obs.add_node(Node(aid, NodeKind.ASSET, {
        "name": name, "asset_type": asset_type, "criticality": float(criticality),
        "crown_jewel": bool(crown_jewel), "entry_point": bool(entry_point),
        "ports": ports or [], "environment": environment, **extra,
    }))
    return aid


def network_node(obs: Observation, name: str, trust_zone: str) -> str:
    nid = node_id(NodeKind.NETWORK, name)
    obs.add_node(Node(nid, NodeKind.NETWORK, {"name": name, "trust_zone": trust_zone}))
    return nid


def add_misconfig(obs: Observation, host_id: str, host_name: str, misconfig: dict[str, Any],
                  source_tool: str, default_technique: str, default_signature: str,
                  default_level: Level = Level.APP_ADMIN, port: int | None = None) -> str:
    """Add a VULNERABILITY node for a misconfiguration, wired to its host with a
    GRANTS edge, a probe technique for the red agent and a remediation hint for
    the blue agent. Returns the vulnerability node id."""
    cls = str(misconfig.get("class", "CWE-0"))
    cwe = cls.split("/")[0].strip().replace("CWE-", "")
    slug = str(misconfig.get("name", cls)).lower().replace(" ", "-")[:40]
    vid = node_id(NodeKind.VULNERABILITY, f"{host_name}/{source_tool}/{slug}")
    fix = str(misconfig.get("fix", "harden-config"))
    obs.add_node(Node(vid, NodeKind.VULNERABILITY, {
        "name": str(misconfig.get("name", cls)),
        "classification": cls,
        "cwe": f"CWE-{cwe}" if cwe else cls,
        "severity": str(misconfig.get("severity", "high")),
        "confidence": float(misconfig.get("confidence", 0.75)),
        "remote": True,
        "port": port,
        "validated": False,
        "location": host_name,
        "source_tool": source_tool,
        "description": str(misconfig.get("description", misconfig.get("name", ""))),
        "probe_technique": str(misconfig.get("probe_technique", default_technique)),
        "probe_signature": str(misconfig.get("probe_signature", default_signature)),
        # remediation hint the blue agent compiles into a concrete fix (Phase 7)
        "remediation": {
            "fix_type": fix,
            "strategy": str(misconfig.get("strategy", "neutralize")),
            "tier": str(misconfig.get("tier", "low-risk")),
            "blast": float(misconfig.get("blast", 0.3)),
            "control": str(misconfig.get("control", fix)),
        },
    }))
    obs.add_edge(host_id, vid, EdgeKind.HAS_VULNERABILITY)
    obs.add_edge(vid, host_id, EdgeKind.GRANTS, level=level_of(misconfig.get("grants"), default_level))
    return vid
