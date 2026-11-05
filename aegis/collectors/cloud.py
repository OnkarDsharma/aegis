"""Multi-cloud inventory collector (PRD FR-1, FR-4, FR-6, FR-33).

Reads a cloud-provider inventory export (AWS / GCP / Azure, several accounts) and
normalizes compute, managed data stores, object storage, IAM identities, network
reachability and identity federation into the vendor-neutral model. Misconfigs
(public buckets, wide-open security groups, token-reachable metadata) become
VULNERABILITY nodes with a GRANTS edge, so they show up as real attack paths.

Offline by design: the export is a JSON file (``cloud-*.json`` under the coverage
dir). A live adapter would call each provider's inventory/IAM API and produce the
same shape. Secret VALUES are never read or stored - only resource metadata.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..model import EdgeKind, Node, NodeKind, Observation, node_id
from . import _coverage as cov

INTERNET = node_id(NodeKind.ASSET, "internet")
PROBE = "cloud-misconfig-probe"
SIGNATURE = "cloud:misconfig:public-access"


def from_file(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return cov.load_json(path)


def cloud_observation(estate: dict[str, Any], evidence: dict[str, Any]) -> Observation:
    obs = Observation(collector="cloud", scope="cloud", evidence=evidence)
    obs.add_node(Node(INTERNET, NodeKind.ASSET,
                      {"name": "internet", "asset_type": "external", "entry_point": True, "criticality": 0.0}))

    for account in estate.get("accounts", []):
        provider = str(account.get("provider", "cloud"))
        acct = str(account.get("account_id", ""))
        for res in account.get("resources", []):
            name = str(res["name"])
            aid = cov.asset_node(
                obs, name, f"{provider}-{res.get('type', 'resource')}",
                criticality=float(res.get("criticality", 0.5)),
                crown_jewel=bool(res.get("crown_jewel", False)),
                ports=[int(p) for p in res.get("ports", [])],
                provider=provider, account_id=acct,
            )
            for net in res.get("networks", []):
                obs.add_edge(aid, cov.network_node(obs, net, f"{provider}:{_zone(net)}"), EdgeKind.MEMBER_OF)
            if res.get("public") or res.get("public_access"):
                ports = [int(p) for p in res.get("ports", [])] or [443]
                obs.add_edge(INTERNET, aid, EdgeKind.CAN_REACH, ports=ports, via="public-exposure")
            misconfig = res.get("misconfig")
            if misconfig:
                port = (res.get("ports") or [None])[0]
                cov.add_misconfig(obs, aid, name, misconfig, "cloud", PROBE, SIGNATURE, port=port)

        for ident in account.get("identities", []):
            iid = node_id(NodeKind.IDENTITY, f"{provider}/{ident['name']}")
            obs.add_node(Node(iid, NodeKind.IDENTITY, {
                "name": ident["name"], "realm": provider, "identity_type": ident.get("identity_type", "service"),
                "privileged": bool(ident.get("privileged", False)),
            }))
            for target in ident.get("admin_of", []):
                obs.add_edge(iid, node_id(NodeKind.ASSET, target), EdgeKind.ADMIN_OF)

    # explicit cross-service reachability (e.g. a web tier reaching a managed DB)
    for reach in estate.get("reachability", []):
        src, dst = node_id(NodeKind.ASSET, reach["from"]), node_id(NodeKind.ASSET, reach["to"])
        obs.add_edge(src, dst, EdgeKind.CAN_REACH,
                     ports=[int(p) for p in reach.get("ports", [])],
                     segmentable=bool(reach.get("segmentable", False)), via="cloud-route")

    # identity federation across providers / on-prem IdP (FR-6 trust boundaries)
    for fed in estate.get("federation", []):
        for prov in [a.get("provider") for a in estate.get("accounts", [])]:
            iid = node_id(NodeKind.IDENTITY, f"{prov}/{fed['identity']}")
            if any(n.id == iid for n in obs.nodes):
                obs.add_edge(iid, node_id(NodeKind.ASSET, fed["trusts_idp"]), EdgeKind.TRUSTS)
    return obs


def _zone(network: str) -> str:
    net = network.lower()
    if "public" in net or "dmz" in net:
        return "dmz"
    if "data" in net or "db" in net:
        return "data"
    return "corp"
