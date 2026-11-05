"""Vulnerability-scanner and adversary-emulation collectors (PRD FR-1, FR-33).

* ZAP JSON reports  -> vulnerability nodes on the scanned asset.
* Caldera op reports -> attack-step nodes executed on the agent's host.

The latest ZAP report is authoritative (scope ``zap``): a finding that stops
appearing after a rescan is closed in the temporal graph, which is exactly the
signal the remediation proof engine needs later.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from ..model import EdgeKind, Level, Node, NodeKind, Observation, node_id

ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
ZAP_CONFIDENCE = {"0": 0.1, "1": 0.4, "2": 0.6, "3": 0.8, "4": 0.95, "low": 0.4, "medium": 0.6, "high": 0.8, "confirmed": 0.95}

# What an attacker gains by exploiting a weakness class. Weaknesses not listed
# here are recorded but do not extend attack paths (e.g. missing headers).
CWE_GRANTS: dict[str, list[str]] = {
    "89": [Level.APP_ADMIN],     # SQL injection
    "943": [Level.APP_ADMIN],    # NoSQL / query injection
    "78": [Level.FOOTHOLD],      # OS command injection
    "94": [Level.FOOTHOLD],      # code injection
    "502": [Level.FOOTHOLD],     # unsafe deserialization
    "22": [Level.DATA_READ],     # path traversal
    "200": [Level.DATA_READ],    # information exposure
    "538": [Level.DATA_READ],    # file / directory information exposure
    "287": [Level.APP_ADMIN],    # improper authentication
    "798": [Level.APP_ADMIN],    # hard-coded credentials
}

# Alias names used by HOST-local service names vs scanner URLs.
LOCAL_HOSTS = {"localhost", "127.0.0.1"}


def latest_report(results_dir: Path, marker: str) -> Path | None:
    candidates = [p for p in results_dir.glob("*.json") if marker in p.name.lower()]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def zap_observation(report_path: Path, default_asset: str = "webapp") -> Observation:
    raw = report_path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    obs = Observation(
        collector="zap",
        scope="zap",
        evidence={"source": str(report_path), "sha256": hashlib.sha256(raw.encode()).hexdigest()},
    )
    scanner = node_id(NodeKind.CONTROL, "zap")
    obs.add_node(Node(scanner, NodeKind.CONTROL, {"name": "zap", "control_type": "scanner", "enabled": True}))

    for site in _as_list(payload.get("site") if isinstance(payload, dict) else None):
        url = str(site.get("@name") or site.get("name") or "")
        parsed = urlparse(url)
        asset = parsed.hostname or default_asset
        if asset in LOCAL_HOSTS:
            asset = default_asset
        port = _int(site.get("@port")) or parsed.port or (443 if parsed.scheme == "https" else 80)
        aid = node_id(NodeKind.ASSET, asset)
        obs.add_node(Node(aid, NodeKind.ASSET, {"name": asset}))
        for alert in _as_list(site.get("alerts")):
            cwe = str(alert.get("cweid", "")).strip()
            plugin = str(alert.get("pluginid") or alert.get("pluginId") or "").strip()
            name = str(alert.get("alert") or alert.get("name") or "Unnamed ZAP alert")
            vid = node_id(NodeKind.VULNERABILITY, f"{asset}/zap/{plugin or name}")
            instances = _as_list(alert.get("instances"))
            confidence = ZAP_CONFIDENCE.get(str(alert.get("confidence", "2")).lower(), 0.6)
            grants = CWE_GRANTS.get(cwe, [])
            obs.add_node(
                Node(
                    vid,
                    NodeKind.VULNERABILITY,
                    {
                        "name": name,
                        "classification": _classification(cwe, alert.get("wascid"), plugin),
                        "cwe": f"CWE-{cwe}" if cwe and cwe not in {"0", "-1"} else None,
                        "severity": normalize_severity(alert.get("riskcode") or alert.get("riskdesc")),
                        "confidence": confidence,
                        "remote": True,
                        "port": port,
                        "location": _first_uri(instances) or url,
                        "instances": len(instances),
                        "validated": False,
                        "source_tool": "zap",
                        "description": strip_markup(str(alert.get("desc") or "")),
                        "solution": strip_markup(str(alert.get("solution") or "")),
                    },
                )
            )
            obs.add_edge(aid, vid, EdgeKind.HAS_VULNERABILITY)
            obs.add_edge(vid, scanner, EdgeKind.DETECTED_BY)
            for level in grants:
                obs.add_edge(vid, aid, EdgeKind.GRANTS, level=level)
    return obs


def caldera_observation(report_paths: Iterable[Path], default_asset: str = "employee") -> Observation:
    obs = Observation(collector="caldera", scope="caldera", evidence={"sources": []})
    for path in report_paths:
        raw = path.read_text(encoding="utf-8")
        obs.evidence["sources"].append({"source": str(path), "sha256": hashlib.sha256(raw.encode()).hexdigest()})
        payload = json.loads(raw)
        for step in _caldera_steps(payload):
            asset = _host_for(step["paw"], payload) or default_asset
            aid = node_id(NodeKind.ASSET, asset)
            sid = node_id(NodeKind.ATTACK_STEP, f"caldera/{step['technique'] or step['name']}/{asset}")
            obs.add_node(Node(aid, NodeKind.ASSET, {"name": asset}))
            obs.add_node(
                Node(
                    sid,
                    NodeKind.ATTACK_STEP,
                    {
                        "name": step["name"],
                        "technique": step["technique"],
                        "tactic": step["tactic"],
                        "command": step["command"],
                        "outcome": step["status"],
                        "source_tool": "caldera",
                        "report": str(path),
                    },
                )
            )
            obs.add_edge(sid, aid, EdgeKind.EXECUTED_ON)
    return obs


def _caldera_steps(payload: Any) -> list[dict[str, Any]]:
    """Extract ability executions from a Caldera operation report.

    Handles the ``steps: {paw: {steps: [...]}}`` layout of the operation report
    export and falls back to any dict carrying ATT&CK metadata.
    """
    steps: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for paw, node in _walk_with_paw(payload, None):
        ability = node.get("ability") if isinstance(node.get("ability"), dict) else node
        technique = ability.get("technique_id") or ability.get("attack_id") or (ability.get("attack") or {}).get("technique_id")
        tactic = ability.get("tactic") or (ability.get("attack") or {}).get("tactic")
        name = ability.get("name") or ability.get("ability_name") or (ability.get("attack") or {}).get("technique_name")
        if not technique and not (tactic and name):
            continue
        key = (paw, technique, name)
        if key in seen:
            continue
        seen.add(key)
        steps.append(
            {
                "paw": paw,
                "technique": str(technique or ""),
                "tactic": str(tactic or ""),
                "name": str(name or technique),
                "command": str(node.get("command") or ability.get("command") or ""),
                "status": _caldera_status(node.get("status")),
            }
        )
    return steps


def _walk_with_paw(value: Any, paw: str | None):
    if isinstance(value, dict):
        current = str(value.get("paw")) if value.get("paw") else paw
        yield current, value
        for key, child in value.items():
            # the operation report keys steps by agent paw
            child_paw = key if isinstance(child, dict) and "steps" in child and key != "steps" else current
            yield from _walk_with_paw(child, child_paw)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_with_paw(child, paw)


def _host_for(paw: str | None, payload: Any) -> str | None:
    if paw and isinstance(payload, dict):
        for agent in _as_list(payload.get("host_group")):
            if isinstance(agent, dict) and agent.get("paw") == paw:
                return agent.get("host") or agent.get("hostname")
    return None


def _caldera_status(value: Any) -> str:
    return {0: "success", -2: "discarded", 1: "failed", 124: "timeout", -3: "collected"}.get(value, "unknown") if isinstance(value, int) else str(value or "unknown")


def normalize_severity(value: Any) -> str:
    text = str(value or "info").lower()
    if text in ZAP_RISK:
        return ZAP_RISK[text]
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity in text:
            return severity
    return "info"


def strip_markup(value: str) -> str:
    return value.replace("<p>", "").replace("</p>", "\n").replace("<br>", "\n").strip()


def _classification(cwe: str, wasc: Any, plugin: str) -> str:
    parts = []
    if cwe and cwe not in {"0", "-1"}:
        parts.append(f"CWE-{cwe}")
    if wasc and str(wasc) not in {"0", "-1"}:
        parts.append(f"WASC-{wasc}")
    if plugin:
        parts.append(f"ZAP-{plugin}")
    return " / ".join(parts) or "ZAP"


def _first_uri(instances: list[Any]) -> str | None:
    for inst in instances:
        if isinstance(inst, dict) and inst.get("uri"):
            method = inst.get("method", "")
            return f"{method} {inst['uri']}".strip()
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
