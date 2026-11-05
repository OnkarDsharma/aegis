"""Asset / network / reachability discovery (PRD FR-1, FR-6).

Two sources produce the same normalized ``ServiceRecord`` list:

* ``from_compose``  - the declared range (docker-compose.yml). Works offline.
* ``from_runtime``  - the running containers (``docker``/``podman inspect``).
  This stands in for a cloud provider's inventory API in the MVP.

Both are ingested under the single scope ``inventory`` so whichever ran last
is authoritative: a container that disappears is closed in the temporal graph.

Services opt into modelling with ``aegis.*`` labels (see cyber_range/docker-compose.yml):

    aegis.asset_type   workstation|server|database|idp|...
    aegis.criticality  0..1 business impact if compromised
    aegis.crown_jewel  "true" if compromising it is an objective
    aegis.entry_point  "true" for assumed-breach starting points
    aegis.ports        comma-separated container ports the service listens on
    aegis.kind         "control" to model the service as a control, not an asset
    aegis.control_type scanner|waf|siem|...
    aegis.ignore       "true" for platform components (the AEGIS dashboard itself)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..model import EdgeKind, Level, Node, NodeKind, Observation, node_id

INTERNET = node_id(NodeKind.ASSET, "internet")
WEAK_SECRETS = {"admin", "password", "changeme", "root", "secret", "test", "123456", "letmein", "welcome"}
SECRET_KEY = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN)$", re.IGNORECASE)


@dataclass
class ServiceRecord:
    name: str
    image: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)          # container ports listened on
    published: dict[int, int] = field(default_factory=dict)  # host port -> container port
    secret_findings: list[dict[str, Any]] = field(default_factory=list)  # never the secret value itself
    running: bool | None = None
    environment: str = "range"


# --------------------------------------------------------------------- sources
def from_compose(path: str | Path) -> tuple[list[ServiceRecord], dict[str, Any]]:
    path = Path(path)
    raw = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw) or {}
    services: list[ServiceRecord] = []
    active_profiles: set[str] = set()
    for name, spec in (doc.get("services") or {}).items():
        spec = spec or {}
        if spec.get("profiles") and not active_profiles.intersection(spec["profiles"]):
            continue
        labels = _labels(spec.get("labels"))
        published: dict[int, int] = {}
        for entry in spec.get("ports") or []:
            host, container = _parse_port(entry)
            if container:
                published[host or container] = container
        ports = _int_list(labels.get("aegis.ports")) or sorted(set(published.values())) or _int_list(spec.get("expose"))
        services.append(
            ServiceRecord(
                name=str(spec.get("container_name") or name),
                image=str(spec.get("image") or "built:" + str((spec.get("build") or {}).get("dockerfile", "Dockerfile"))),
                labels=labels,
                networks=list(spec.get("networks") or ["default"]),
                ports=ports,
                published=published,
                secret_findings=_secret_findings(_env(spec.get("environment"))),
            )
        )
    evidence = {"source": str(path), "sha256": _sha256(raw), "services": [s.name for s in services]}
    return services, evidence


def from_runtime(inspect_json: list[dict[str, Any]] | None = None, cli: str | None = None) -> tuple[list[ServiceRecord], dict[str, Any]]:
    """Build records from ``docker inspect`` output (live, or a captured fixture)."""
    if inspect_json is None:
        inspect_json = _inspect_all(cli)
    services: list[ServiceRecord] = []
    for c in inspect_json:
        config = c.get("Config") or {}
        labels = config.get("Labels") or {}
        if not any(key.startswith("aegis.") for key in labels):
            continue  # only containers that belong to the modelled range
        project = labels.get("com.docker.compose.project") or labels.get("io.podman.compose.project") or ""
        nets = list(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        nets = [n[len(project) + 1:] if project and n.startswith(project + "_") else n for n in nets]
        exposed = [int(p.split("/")[0]) for p in (config.get("ExposedPorts") or {})]
        published: dict[int, int] = {}
        for cport, bindings in ((c.get("HostConfig") or {}).get("PortBindings") or {}).items():
            for binding in bindings or []:
                if binding.get("HostPort"):
                    published[int(binding["HostPort"])] = int(cport.split("/")[0])
        env = dict(item.split("=", 1) for item in (config.get("Env") or []) if "=" in item)
        services.append(
            ServiceRecord(
                name=str(c.get("Name", "")).lstrip("/"),
                image=str(config.get("Image", "")),
                labels=labels,
                networks=nets,
                ports=_int_list(labels.get("aegis.ports")) or sorted(set(exposed)),
                published=published,
                secret_findings=_secret_findings(env),
                running=bool((c.get("State") or {}).get("Running")),
            )
        )
    return services, {"source": "runtime-inspect", "containers": [s.name for s in services]}


def runtime_available(cli: str | None = None) -> bool:
    cli = cli or _cli()
    if not cli:
        return False
    try:
        out = subprocess.run([cli, "ps", "-q"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.returncode == 0 and bool(out.stdout.strip())


# ------------------------------------------------------------------- modelling
def build_observation(services: list[ServiceRecord], collector: str, evidence: dict[str, Any]) -> Observation:
    obs = Observation(collector=collector, scope="inventory", evidence=evidence)
    obs.add_node(
        Node(INTERNET, NodeKind.ASSET, {"name": "internet", "asset_type": "external", "entry_point": True, "criticality": 0.0})
    )

    modelled = [s for s in services if s.labels.get("aegis.ignore", "").lower() != "true"]
    assets = [s for s in modelled if s.labels.get("aegis.kind", "asset") != "control"]
    controls = [s for s in modelled if s.labels.get("aegis.kind") == "control"]

    for svc in assets:
        aid = node_id(NodeKind.ASSET, svc.name)
        obs.add_node(
            Node(
                aid,
                NodeKind.ASSET,
                {
                    "name": svc.name,
                    "asset_type": svc.labels.get("aegis.asset_type", "server"),
                    "image": svc.image,
                    "criticality": float(svc.labels.get("aegis.criticality", 0.5)),
                    "crown_jewel": svc.labels.get("aegis.crown_jewel", "").lower() == "true",
                    "entry_point": svc.labels.get("aegis.entry_point", "").lower() == "true",
                    "ports": svc.ports,
                    "environment": svc.labels.get("aegis.environment", svc.environment),
                    **({"running": svc.running} if svc.running is not None else {}),
                },
            )
        )
        for net in svc.networks:
            nid = node_id(NodeKind.NETWORK, net)
            obs.add_node(Node(nid, NodeKind.NETWORK, {"name": net, "trust_zone": _zone(net)}))
            obs.add_edge(aid, nid, EdgeKind.MEMBER_OF)
        if svc.published:
            obs.add_edge(INTERNET, aid, EdgeKind.CAN_REACH, ports=sorted(set(svc.published.values())), via="published")
        for finding in svc.secret_findings:
            port = svc.ports[0] if svc.ports else None
            vid = node_id(NodeKind.VULNERABILITY, f"{svc.name}/weak-credential/{finding['variable'].lower()}")
            obs.add_node(
                Node(
                    vid,
                    NodeKind.VULNERABILITY,
                    {
                        "name": f"Weak credential in deployment config ({finding['variable']})",
                        "classification": "CWE-521 / CWE-798",
                        "cwe": "CWE-521",
                        "severity": "high",
                        "confidence": 0.6,
                        "remote": port is not None,
                        "port": port,
                        "location": f"{svc.name} environment",
                        "validated": False,
                        "reason": finding["reason"],
                        "source_tool": "inventory",
                        "description": "A guessable secret is configured for this service; anyone who can reach "
                        "its port can likely authenticate with administrative rights.",
                    },
                )
            )
            obs.add_edge(aid, vid, EdgeKind.HAS_VULNERABILITY)
            obs.add_edge(vid, aid, EdgeKind.GRANTS, level=Level.APP_ADMIN)

    # Reachability: services sharing a network can reach each other's listening ports.
    for a in assets:
        for b in assets:
            if a is b or not b.ports:
                continue
            shared = sorted(set(a.networks) & set(b.networks))
            if shared:
                obs.add_edge(
                    node_id(NodeKind.ASSET, a.name),
                    node_id(NodeKind.ASSET, b.name),
                    EdgeKind.CAN_REACH,
                    ports=b.ports,
                    via=shared,
                )

    for svc in controls:
        cid = node_id(NodeKind.CONTROL, svc.name)
        obs.add_node(
            Node(cid, NodeKind.CONTROL, {"name": svc.name, "control_type": svc.labels.get("aegis.control_type", "other"), "enabled": True})
        )
        for target in _split(svc.labels.get("aegis.protects")):
            obs.add_edge(cid, node_id(NodeKind.ASSET, target), EdgeKind.PROTECTS)
    return obs


# --------------------------------------------------------------------- helpers
def _cli() -> str | None:
    return shutil.which("docker") or shutil.which("podman")


def _inspect_all(cli: str | None) -> list[dict[str, Any]]:
    cli = cli or _cli()
    if not cli:
        return []
    ids = subprocess.run([cli, "ps", "-aq"], capture_output=True, text=True, timeout=30).stdout.split()
    if not ids:
        return []
    out = subprocess.run([cli, "inspect", *ids], capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout or "[]")


def _labels(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, list):
        return dict(str(item).split("=", 1) for item in value if "=" in str(item))
    return {}


def _env(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    if isinstance(value, list):
        return dict(str(item).split("=", 1) for item in value if "=" in str(item))
    return {}


def _secret_findings(env: dict[str, str]) -> list[dict[str, Any]]:
    findings = []
    for key, value in env.items():
        if not SECRET_KEY.search(key) or not value or value.startswith("${"):
            continue
        reasons = []
        if len(value) < 12:
            reasons.append("shorter than 12 characters")
        if any(word in value.lower() for word in WEAK_SECRETS):
            reasons.append("contains a common password word")
        if reasons:
            findings.append({"variable": key, "reason": "; ".join(reasons)})
    return findings


def _parse_port(entry: Any) -> tuple[int | None, int | None]:
    if isinstance(entry, dict):
        return _to_int(entry.get("published")), _to_int(entry.get("target"))
    parts = str(entry).split("/")[0].split(":")
    if len(parts) == 1:
        return None, _to_int(parts[0])
    return _to_int(parts[-2]), _to_int(parts[-1])


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_list(value: Any) -> list[int]:
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return sorted({n for n in (_to_int(str(i).strip()) for i in items) if n is not None})


def _split(value: Any) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _zone(network: str) -> str:
    for zone in ("dmz", "corp", "data", "mgmt"):
        if zone in network:
            return zone
    return "internal"


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()
