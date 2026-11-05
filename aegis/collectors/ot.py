"""OT / ICS and remote-endpoint collector (PRD FR-1, FR-4).

Reads an OT asset register (Purdue-style zones, PLCs / HMIs / historians) plus
remote endpoints (laptops, VPN clients) and normalizes it into the model. Zones
become NETWORK nodes, devices and endpoints become ASSETs (a safety-critical PLC
is a crown jewel; a remote endpoint is an assumed-breach entry point), and an
unauthenticated field protocol becomes a VULNERABILITY with GRANTS. Cross-zone
conduits are modelled as (segmentable) reachability, so a flat path from a remote
laptop down to the PLC shows up as an attack path.

Offline by design: the register is ``ot-*.json`` under the coverage dir.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..model import EdgeKind, NodeKind, Observation, node_id
from . import _coverage as cov

PROBE = "ot-protocol-probe"
SIGNATURE = "ot:protocol:no-auth"


def from_file(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return cov.load_json(path)


def ot_observation(register: dict[str, Any], evidence: dict[str, Any]) -> Observation:
    obs = Observation(collector="ot", scope="ot", evidence=evidence)

    for zone in register.get("zones", []):
        cov.network_node(obs, f"ot/{zone['name']}", f"ot-l{zone.get('level', 0)}")

    def place(name: str, zone: str) -> None:
        if zone:
            obs.add_edge(node_id(NodeKind.ASSET, name), node_id(NodeKind.NETWORK, f"ot/{zone}"), EdgeKind.MEMBER_OF)

    # remote endpoints are assumed-breach entry points
    for ep in register.get("endpoints", []):
        name = str(ep["name"])
        cov.asset_node(obs, name, "endpoint", criticality=float(ep.get("criticality", 0.3)),
                       entry_point=bool(ep.get("entry_point", True)))
        place(name, str(ep.get("zone", "")))
        _reaches(obs, name, ep.get("reaches", []))

    for dev in register.get("devices", []):
        name = str(dev["name"])
        aid = cov.asset_node(obs, name, f"ot-{dev.get('type', 'device')}",
                             criticality=float(dev.get("criticality", 0.7)),
                             crown_jewel=bool(dev.get("crown_jewel", False)),
                             ports=[int(p) for p in dev.get("ports", [])])
        place(name, str(dev.get("zone", "")))
        _reaches(obs, name, dev.get("reaches", []))
        misconfig = dev.get("misconfig")
        if misconfig:
            port = (dev.get("ports") or [None])[0]
            cov.add_misconfig(obs, aid, name, misconfig, "ot", PROBE, SIGNATURE, port=port)
    return obs


def _reaches(obs: Observation, src_name: str, reaches: list[dict[str, Any]]) -> None:
    src = node_id(NodeKind.ASSET, src_name)
    for r in reaches:
        obs.add_edge(src, node_id(NodeKind.ASSET, r["to"]), EdgeKind.CAN_REACH,
                     ports=[int(p) for p in r.get("ports", [])],
                     segmentable=bool(r.get("segmentable", False)), via="ot-conduit")
