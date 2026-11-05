"""Collectors turn tool output into normalized observations and ingest them."""

from __future__ import annotations

import logging
from typing import Any

from ..config import Settings
from ..model import Observation
from ..store import GraphStore, normalize_time
from . import cloud, identity, inventory, kubernetes, ot, scanners, scenarios

log = logging.getLogger("aegis.collectors")


def gather(settings: Settings) -> tuple[list[Observation], list[dict[str, Any]]]:
    """Run every configured collector. Returns observations plus per-collector status."""
    observations: list[Observation] = []
    status: list[dict[str, Any]] = []

    def attempt(name: str, fn) -> None:
        try:
            obs = fn()
        except Exception as exc:  # one broken source must not stop the others
            log.warning("collector %s failed: %s", name, exc)
            status.append({"collector": name, "ok": False, "error": str(exc)})
            return
        if obs is None:
            status.append({"collector": name, "ok": True, "skipped": True})
            return
        observations.append(obs)
        status.append({"collector": name, "ok": True, "nodes": len(obs.nodes), "edges": len(obs.edges)})

    def run_inventory():
        mode = settings.inventory_mode
        if mode == "runtime" or (mode == "auto" and inventory.runtime_available()):
            services, evidence = inventory.from_runtime()
            if services or mode == "runtime":
                return inventory.build_observation(services, "runtime", evidence)
        services, evidence = inventory.from_compose(settings.compose_file)
        return inventory.build_observation(services, "compose", evidence)

    def run_identity():
        if settings.keycloak_url and settings.keycloak_admin:
            realm, evidence = identity.realm_from_api(
                settings.keycloak_url, settings.keycloak_realm, settings.keycloak_admin, settings.keycloak_password
            )
        elif settings.realm_file.exists():
            realm, evidence = identity.realm_from_file(settings.realm_file)
        else:
            return None
        return identity.identity_observation(realm, evidence)

    def run_zap():
        report = scanners.latest_report(settings.results_dir, "zap") if settings.results_dir.exists() else None
        return scanners.zap_observation(report) if report else None

    def run_caldera():
        if not settings.results_dir.exists():
            return None
        reports = sorted(p for p in settings.results_dir.glob("*.json") if "caldera" in p.name.lower())
        return scanners.caldera_observation(reports) if reports else None

    def coverage(prefix: str, module) -> Any:
        # Phase 6 (FR-4): ingest a cloud / kubernetes / OT export if one is present.
        directory = settings.coverage_dir
        if not directory.exists():
            return None
        files = sorted(directory.glob(f"{prefix}-*.json"))
        if not files:
            return None
        data, evidence = module.from_file(files[0])
        builder = getattr(module, f"{module.__name__.rsplit('.', 1)[-1]}_observation")
        return builder(data, evidence)

    attempt("inventory", run_inventory)
    attempt("identity", run_identity)
    attempt("zap", run_zap)
    attempt("caldera", run_caldera)
    attempt("scenarios", lambda: scenarios.scenario_observation(settings.scenarios_dir))
    attempt("cloud", lambda: coverage("cloud", cloud))
    attempt("kubernetes", lambda: coverage("k8s", kubernetes))
    attempt("ot", lambda: coverage("ot", ot))
    return observations, status


def collect(store: GraphStore, settings: Settings, at: str | None = None) -> list[dict[str, Any]]:
    observations, status = gather(settings)
    at = normalize_time(at)  # one timestamp per collection run = one point on the timeline
    by_name = {s["collector"]: s for s in status}
    for obs in observations:
        stats = store.ingest(obs, at=at)
        key = "inventory" if obs.scope == "inventory" else ("identity" if obs.scope.startswith("identity") else obs.collector)
        by_name.get(key, {}).update(stats, source=obs.collector)
    return status
