"""Live red-team probes (aegis/probes.py) against local fake services."""

from __future__ import annotations

import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from aegis.collectors import collect
from aegis.config import ROOT, Settings
from aegis.graph import AttackGraph
from aegis.ledger import EvidenceLedger
from aegis.loop import LoopConfig, RedBlueLoop
from aegis.probes import (
    Endpoint, EndpointResolver, LiveProbes, keycloak_login, mysql_login, mysql_scramble, sqli_login, tcp_reach,
)
from aegis.redteam import RedAgent
from aegis.safety import KillSwitch, Policy, SafetyAgent
from aegis.store import GraphStore

COMPOSE = ROOT / "cyber_range" / "docker-compose.yml"
MYSQL_PW = "rootpass123"  # lab-only value from cyber_range/docker-compose.yml


# --------------------------------------------------------------------------- fakes
class FakeMySQL:
    """Speaks just enough of the MySQL 5.7 handshake to check a native-password login."""

    SALT = bytes(range(1, 21))

    def __init__(self, password: str, user: str = "root") -> None:
        self.password, self.user = password, user
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.logins: list[bool] = []
        self.quits = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _send(self, conn, seq, payload):
        conn.sendall(struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload)

    def _read(self, conn):
        head = conn.recv(4)
        if len(head) < 4:
            return None, b""
        n = head[0] | head[1] << 8 | head[2] << 16
        data = b""
        while len(data) < n:
            data += conn.recv(n - len(data))
        return head[3], data

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                hs = (b"\x0a" + b"5.7.31\x00" + struct.pack("<I", 7) + self.SALT[:8] + b"\x00"
                      + struct.pack("<H", 0xF7FF) + b"\x21" + struct.pack("<H", 2) + struct.pack("<H", 0x81FF)
                      + bytes([21]) + b"\x00" * 10 + self.SALT[8:] + b"\x00" + b"mysql_native_password\x00")
                self._send(conn, 0, hs)
                seq, resp = self._read(conn)
                pos = 4 + 4 + 1 + 23
                end = resp.index(b"\x00", pos)
                user = resp[pos:end].decode()
                alen = resp[end + 1]
                auth = resp[end + 2:end + 2 + alen]
                ok = user == self.user and auth == mysql_scramble(self.password, self.SALT)
                self.logins.append(ok)
                if ok:
                    self._send(conn, seq + 1, b"\x00\x00\x00\x02\x00\x00\x00")
                    _, quit_ = self._read(conn)
                    self.quits += quit_ == b"\x01"
                else:
                    self._send(conn, seq + 1, b"\xff" + struct.pack("<H", 1045) + b"#28000Access denied")

    def close(self):
        self.sock.close()


class FakeHTTP:
    """Juice Shop login (vulnerable or patched) + Keycloak token/logout endpoints."""

    def __init__(self, vulnerable: bool = True, kc_password: str = "admin") -> None:
        outer = self
        self.vulnerable, self.kc_password = vulnerable, kc_password
        self.logouts = 0

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path == "/rest/user/login":
                    body = json.loads(raw)
                    if outer.vulnerable and "OR 1=1" in body["email"]:
                        return self._reply(200, {"authentication": {"token": "jwt-secret", "umail": "admin@juice-sh.op"}})
                    return self._reply(401, {"error": "Invalid email or password."})
                form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                if self.path.endswith("/token"):
                    if form.get("username") == "admin" and form.get("password") == outer.kc_password:
                        return self._reply(200, {"access_token": "at", "refresh_token": "rt"})
                    return self._reply(401, {"error": "invalid_grant"})
                if self.path.endswith("/logout"):
                    outer.logouts += 1
                    self.send_response(204)
                    self.end_headers()
                    return None
                return self._reply(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def mysql():
    srv = FakeMySQL(MYSQL_PW)
    yield srv
    srv.close()


@pytest.fixture
def web():
    srv = FakeHTTP()
    yield srv
    srv.close()


@pytest.fixture
def graph(tmp_path: Path) -> AttackGraph:
    settings = Settings(
        db_path=tmp_path / "aegis.db", results_dir=tmp_path, scenarios_dir=ROOT / "experiments" / "scenarios",
        compose_file=COMPOSE, realm_file=ROOT / "cyber_range" / "keycloak" / "aegis-realm.json",
        coverage_dir=tmp_path / "nocov", inventory_mode="compose", keycloak_url="",
    )
    store = GraphStore(settings.db_path)
    collect(store, settings)
    return AttackGraph(*store.snapshot())


# --------------------------------------------------------------------------- protocol probes
def test_sqli_probe_proves_and_discards_token(web):
    out = sqli_login(Endpoint("127.0.0.1", web.port), 3)
    assert out.succeeded and out.outcome == "access-proven"
    assert out.detail["authenticated_as"] == "admin@juice-sh.op"
    assert "jwt-secret" not in json.dumps(out.detail)


def test_sqli_probe_blocked_when_patched():
    srv = FakeHTTP(vulnerable=False)
    try:
        out = sqli_login(Endpoint("127.0.0.1", srv.port), 3)
    finally:
        srv.close()
    assert not out.succeeded and out.outcome == "blocked" and out.detail["http_status"] == 401


def test_mysql_native_login_and_quit(mysql):
    ep = Endpoint("127.0.0.1", mysql.port)
    assert mysql_login(ep, "root", MYSQL_PW, 3).succeeded
    bad = mysql_login(ep, "root", "nope", 3)
    assert not bad.succeeded and bad.detail["mysql_error"] == 1045
    assert mysql.logins == [True, False] and mysql.quits == 1


def test_keycloak_login_logs_out(web):
    out = keycloak_login(Endpoint("127.0.0.1", web.port), "admin", "admin", 3)
    assert out.succeeded and web.logouts == 1 and "residual" not in out.detail


def test_unreachable_is_not_success():
    out = tcp_reach(Endpoint("127.0.0.1", _closed_port()), 1)
    assert not out.succeeded and out.outcome == "unreachable"


def test_resolver_uses_compose_published_ports_and_overrides():
    r = EndpointResolver("database=10.0.0.5:3306", COMPOSE)
    assert str(r.resolve("webapp", 3000)) == "127.0.0.1:8080"
    assert str(r.resolve("keycloak", 8080)) == "127.0.0.1:8180"
    assert str(r.resolve("database", 3306)) == "10.0.0.5:3306"
    assert r.resolve("employee", 22) is None
    assert r.secret("database", "MYSQL_ROOT_PASSWORD") == ("root", MYSQL_PW)


# --------------------------------------------------------------------------- loop integration
def _live_agent(web, mysql, kill_switch=None, environments=("range", "canary")) -> RedAgent:
    resolver = EndpointResolver(f"webapp=127.0.0.1:{web.port},database=127.0.0.1:{mysql.port},"
                                f"keycloak=127.0.0.1:{web.port}", COMPOSE)
    return RedAgent(live_adapters=LiveProbes(resolver, environments=environments, timeout=3,
                                             kill_switch=kill_switch).adapters())


def test_engagement_runs_live_and_keeps_secrets_out_of_ledger(graph, web, mysql, tmp_path):
    ledger_path = tmp_path / "ledger.jsonl"
    safety = SafetyAgent(Policy.load(ROOT / "policy.yaml"), KillSwitch(tmp_path / "KILL"))
    loop = RedBlueLoop(safety, EvidenceLedger(ledger_path), red=_live_agent(web, mysql))
    report = loop.run(graph, LoopConfig(top_paths=10, max_actions=12))

    assert report.execution_modes.get("live", 0) >= 2
    rows = {r["action"]["technique"] + "@" + r["action"]["target"]: r for r in report.actions if "result" in r}
    sqli = rows["sqli-login-probe@webapp"]["result"]
    assert sqli["succeeded"] and sqli["evidence"]["mode"] == "live"
    db = rows["weak-credential-check@database"]["result"]
    assert db["succeeded"] and db["evidence"]["probe"]["credential_source"] == "deployment-config"
    assert mysql.quits >= 1
    # proof re-runs happen in the twin (graph model), never against the live target
    for row in report.actions:
        for f in row.get("fixes", []):
            assert f["proof"]["verdict"] == "proven"
    text = ledger_path.read_text()
    assert MYSQL_PW not in text and "jwt-secret" not in text
    assert EvidenceLedger(ledger_path).verify()[0]


def test_patched_target_is_not_validated(graph, mysql, tmp_path):
    patched = FakeHTTP(vulnerable=False)
    try:
        safety = SafetyAgent(Policy.load(ROOT / "policy.yaml"), KillSwitch(tmp_path / "KILL"))
        loop = RedBlueLoop(safety, EvidenceLedger(None), red=_live_agent(patched, mysql))
        report = loop.run(graph, LoopConfig(top_paths=10, max_actions=12))
    finally:
        patched.close()
    sqli = [r for r in report.actions if r["action"]["technique"] == "sqli-login-probe"]
    assert sqli and all(r["status"] == "blocked" and not r["result"]["succeeded"] for r in sqli)


def test_twin_and_kill_switch_fall_back_to_simulation(graph, web, mysql, tmp_path):
    action = next(a for a in RedAgent().plan(graph, top_paths=10) if a.technique == "sqli-login-probe")
    twin = _live_agent(web, mysql).execute(action, graph, "twin")
    assert twin.evidence["mode"] == "simulated" and "not live-enabled" in twin.evidence["live_skipped"]

    ks = KillSwitch(tmp_path / "KILL")
    ks.trip("test")
    stopped = _live_agent(web, mysql, kill_switch=ks).execute(action, graph, "range")
    assert stopped.evidence["mode"] == "simulated" and "kill switch" in stopped.evidence["live_skipped"]
