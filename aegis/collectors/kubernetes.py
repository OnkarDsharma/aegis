"""Kubernetes cluster collector (PRD FR-1, FR-4).

Reads a cluster export - namespaces, workloads, services, RBAC and network
policies - and normalizes it into the model. Namespaces become NETWORK zones,
workloads become ASSETs, a missing NetworkPolicy shows up as flat (segmentable)
reachability, and over-broad RBAC / privileged pods become VULNERABILITY nodes
with GRANTS, so a cluster-admin ServiceAccount or a hostPath breakout appears as
a real attack path to the crown-jewel workload.

Offline by design: the export is ``k8s-*.json`` under the coverage dir; a live
adapter would call the Kubernetes API for the same shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..model import EdgeKind, Node, NodeKind, Observation, node_id
from . import _coverage as cov

PROBE = "k8s-rbac-probe"
SIGNATURE = "k8s:rbac:excessive"


def from_file(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return cov.load_json(path)


def kubernetes_observation(cluster: dict[str, Any], evidence: dict[str, Any]) -> Observation:
    name = str(cluster.get("cluster", "cluster"))
    obs = Observation(collector="kubernetes", scope=f"kubernetes:{name}", evidence=evidence)
    entry = set(cluster.get("entry", []))

    for ns in cluster.get("namespaces", []):
        cov.network_node(obs, f"ns/{ns}", f"k8s:{ns}")

    workloads = {w["name"]: w for w in cluster.get("workloads", [])}
    for wl in cluster.get("workloads", []):
        wname = str(wl["name"])
        aid = cov.asset_node(
            obs, wname, "pod",
            criticality=float(wl.get("criticality", 0.5)),
            crown_jewel=bool(wl.get("crown_jewel", False)),
            entry_point=wname in entry,
            ports=[int(p) for p in wl.get("ports", [])],
            namespace=str(wl.get("namespace", "default")),
        )
        obs.add_edge(aid, node_id(NodeKind.NETWORK, f"ns/{wl.get('namespace', 'default')}"), EdgeKind.MEMBER_OF)
        misconfig = wl.get("misconfig")
        if misconfig:
            port = (wl.get("ports") or [None])[0]
            cov.add_misconfig(obs, aid, wname, misconfig, "kubernetes", PROBE, SIGNATURE, port=port)

    # RBAC: a cluster-admin ServiceAccount is a privilege-escalation weakness. Model
    # it as a vulnerability on its target workload (it can read that workload's data).
    for sa in cluster.get("serviceaccounts", []):
        misconfig = sa.get("misconfig")
        if not misconfig:
            continue
        target = str(misconfig.get("target") or sa.get("namespace", ""))
        host_id = node_id(NodeKind.ASSET, target)
        if any(n.id == host_id for n in obs.nodes):
            cov.add_misconfig(obs, host_id, target, misconfig, "kubernetes", PROBE, SIGNATURE)

    for reach in cluster.get("reachability", []):
        src, dst = node_id(NodeKind.ASSET, reach["from"]), node_id(NodeKind.ASSET, reach["to"])
        if any(n.id == src for n in obs.nodes) and any(n.id == dst for n in obs.nodes):
            obs.add_edge(src, dst, EdgeKind.CAN_REACH,
                         ports=[int(p) for p in reach.get("ports", [])],
                         segmentable=bool(reach.get("segmentable", False)), via="k8s-service")
    return obs
