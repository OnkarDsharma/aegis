"""Runtime settings, all overridable with AEGIS_* environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _path(env: str, default: Path) -> Path:
    return Path(os.environ.get(env, default))


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: _path("AEGIS_DB", ROOT / "var" / "aegis.db"))
    results_dir: Path = field(default_factory=lambda: _path("AEGIS_RESULTS_DIR", ROOT / "experiments" / "results"))
    scenarios_dir: Path = field(default_factory=lambda: _path("AEGIS_SCENARIOS_DIR", ROOT / "experiments" / "scenarios"))
    frontend_dir: Path = field(default_factory=lambda: _path("AEGIS_FRONTEND_DIR", ROOT / "frontend"))
    compose_file: Path = field(default_factory=lambda: _path("AEGIS_COMPOSE_FILE", ROOT / "cyber_range" / "docker-compose.yml"))
    # Phase 6 (FR-4): broader-coverage source exports (cloud / kubernetes / OT).
    # Any cloud-*.json, k8s-*.json, ot-*.json here is ingested. Point elsewhere
    # (or at a missing dir) to disable the extra coverage.
    coverage_dir: Path = field(default_factory=lambda: _path("AEGIS_COVERAGE_DIR", ROOT / "cyber_range" / "coverage"))
    policy_file: Path = field(default_factory=lambda: _path("AEGIS_POLICY_FILE", ROOT / "policy.yaml"))
    ledger_path: Path = field(default_factory=lambda: _path("AEGIS_LEDGER", ROOT / "var" / "ledger.jsonl"))
    kill_switch_file: Path = field(default_factory=lambda: _path("AEGIS_KILL_SWITCH", ROOT / "var" / "KILL_SWITCH"))
    realm_file: Path = field(default_factory=lambda: _path("AEGIS_REALM_FILE", ROOT / "cyber_range" / "keycloak" / "aegis-realm.json"))
    # auto: live containers if any are running, else the compose file
    inventory_mode: str = field(default_factory=lambda: os.environ.get("AEGIS_INVENTORY", "auto"))
    keycloak_url: str = field(default_factory=lambda: os.environ.get("AEGIS_KEYCLOAK_URL", ""))
    keycloak_realm: str = field(default_factory=lambda: os.environ.get("AEGIS_KEYCLOAK_REALM", "aegis"))
    keycloak_admin: str = field(default_factory=lambda: os.environ.get("AEGIS_KEYCLOAK_ADMIN", ""))
    keycloak_password: str = field(default_factory=lambda: os.environ.get("AEGIS_KEYCLOAK_PASSWORD", ""))
    # Live red-team probes (aegis/probes.py). Off by default: the loop simulates.
    live_probes: bool = field(default_factory=lambda: os.environ.get("AEGIS_LIVE_PROBES", "").lower() in {"1", "true", "yes", "on"})
    # asset=host:port or asset:containerport=host:port, comma separated; compose published ports are used otherwise
    live_targets: str = field(default_factory=lambda: os.environ.get("AEGIS_LIVE_TARGETS", ""))
    live_environments: str = field(default_factory=lambda: os.environ.get("AEGIS_LIVE_ENVIRONMENTS", "range,canary"))
    live_vantage: str = field(default_factory=lambda: os.environ.get("AEGIS_LIVE_VANTAGE", "host"))  # host | exec
    probe_timeout: float = field(default_factory=lambda: float(os.environ.get("AEGIS_PROBE_TIMEOUT", "5")))
    host: str = field(default_factory=lambda: os.environ.get("AEGIS_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("AEGIS_PORT", "8000")))
