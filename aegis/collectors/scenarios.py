"""Scenario collector: manually validated exploits recorded as YAML.

A scenario whose ``status`` starts with ``exploited`` becomes a *validated*
vulnerability (confidence 0.95) - the strongest evidence the graph has until
the safe red agent (Phase 2) produces automated validations. Scenarios still
pending a scan are kept as metadata only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from ..model import EdgeKind, Level, Node, NodeKind, Observation, node_id


def load_scenarios(scenarios_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    out = []
    for path in sorted(scenarios_dir.glob("SC-*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(doc, dict):
            out.append((path, doc))
    return out


def scenario_observation(scenarios_dir: Path) -> Observation:
    obs = Observation(collector="scenarios", scope="scenarios", evidence={"sources": []})
    for path, sc in load_scenarios(scenarios_dir):
        obs.evidence["sources"].append(
            {"source": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "status": sc.get("status")}
        )
        status = str(sc.get("status", ""))
        vuln = sc.get("vulnerability") or {}
        if not status.startswith("exploited") or not vuln:
            continue
        scenario_id = str(sc.get("scenario_id", path.stem))
        target = str((sc.get("objective") or {}).get("target", "webapp"))
        aid = node_id(NodeKind.ASSET, target)
        vid = node_id(NodeKind.VULNERABILITY, f"{target}/scenario/{scenario_id}")
        classification = " / ".join(str(vuln[k]) for k in ("cwe", "owasp_category") if vuln.get(k))
        obs.add_node(Node(aid, NodeKind.ASSET, {"name": target}))
        obs.add_node(
            Node(
                vid,
                NodeKind.VULNERABILITY,
                {
                    "name": str(vuln.get("class", sc.get("name", scenario_id))),
                    "classification": classification or "manual",
                    "cwe": vuln.get("cwe"),
                    "severity": str(vuln.get("severity", "high")).lower(),
                    "confidence": 0.95,
                    "remote": True,
                    "port": vuln.get("port"),
                    "location": vuln.get("location"),
                    "validated": True,
                    "scenario": scenario_id,
                    "source_tool": "manual",
                    "description": str(sc.get("name", "")),
                    "observed_result": sc.get("observed_result"),
                    "attack_steps": sc.get("attack_steps"),
                },
            )
        )
        obs.add_edge(aid, vid, EdgeKind.HAS_VULNERABILITY)
        for grant in vuln.get("grants") or [{"asset": target, "level": Level.APP_ADMIN}]:
            if grant.get("asset"):
                obs.add_edge(vid, node_id(NodeKind.ASSET, grant["asset"]), EdgeKind.GRANTS, level=grant.get("level", Level.APP_ADMIN))
            if grant.get("identity"):
                obs.add_edge(vid, node_id(NodeKind.IDENTITY, grant["identity"]), EdgeKind.GRANTS, level="identity")
    return obs
