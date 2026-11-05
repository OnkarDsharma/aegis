"""Execution-environment selection (PRD FR-23, FR-24, FR-22).

Every red validation and every blue change is routed to an environment based on
its operational risk:

    risk < 0.3        -> range      (the shared lab is fine for low-risk checks)
    0.3 <= risk < 0.6 -> canary     (an isolated throwaway asset)
    risk >= 0.6       -> twin       (a full clone of the estate)

A twin is modelled here as a second compose project (``docker compose -p
aegis-twin``). The router also carries a *fidelity* score for the twin: when it
is below the configured threshold, changes may not be promoted to production
(FR-24). Availability checks run before and after an action so we can show the
action did not take a business service down (FR-22).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

log = logging.getLogger("aegis.environments")


class Environment(StrEnum):
    TWIN = "twin"
    CANARY = "canary"
    RANGE = "range"
    PRODUCTION = "production"


@dataclass
class AvailabilityCheck:
    name: str
    target: str
    ok: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class RouteDecision:
    environment: str
    reason: str
    fidelity: float
    promotable_to_production: bool

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class EnvironmentRouter:
    def __init__(
        self,
        twin_fidelity: float = 0.85,
        fidelity_threshold: float = 0.8,
        twin_project: str = "aegis-twin",
        availability_probe: Callable[[str], AvailabilityCheck] | None = None,
    ) -> None:
        self.twin_fidelity = twin_fidelity
        self.fidelity_threshold = fidelity_threshold
        self.twin_project = twin_project
        self._probe = availability_probe or _simulated_probe

    def route(self, operational_risk: float, prefer: str | None = None) -> RouteDecision:
        if prefer:
            env = prefer
            reason = f"caller requested {prefer}"
        elif operational_risk >= 0.6:
            env, reason = Environment.TWIN, "high operational risk routed to the digital twin"
        elif operational_risk >= 0.3:
            env, reason = Environment.CANARY, "medium operational risk routed to a canary asset"
        else:
            env, reason = Environment.RANGE, "low operational risk validated in the range"
        promotable = self.twin_fidelity >= self.fidelity_threshold
        return RouteDecision(str(env), reason, round(self.twin_fidelity, 3), promotable)

    def guard_production_change(self) -> tuple[bool, str]:
        """FR-24: block production changes when twin fidelity is too low."""
        if self.twin_fidelity < self.fidelity_threshold:
            return False, (
                f"twin fidelity {self.twin_fidelity:.2f} is below threshold "
                f"{self.fidelity_threshold:.2f}; production change blocked"
            )
        return True, "twin fidelity sufficient to guide production change"

    def availability(self, targets: list[str], phase: str) -> list[AvailabilityCheck]:
        checks = [self._probe(t) for t in targets]
        for c in checks:
            log.debug("availability[%s] %s: %s", phase, c.target, c.ok)
        return checks


def twin_up(project: str = "aegis-twin", compose_file: str = "cyber_range/docker-compose.yml") -> list[str]:
    """Command to stand up an isolated clone of the range (not run automatically)."""
    return ["docker", "compose", "-p", project, "-f", compose_file, "up", "-d"]


def twin_down(project: str = "aegis-twin") -> list[str]:
    return ["docker", "compose", "-p", project, "down", "-v"]


def runtime_available(cli: str | None = None) -> bool:
    cli = cli or shutil.which("docker") or shutil.which("podman")
    if not cli:
        return False
    try:
        return subprocess.run([cli, "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _simulated_probe(target: str) -> AvailabilityCheck:
    # Offline default: services are modelled as healthy. A live probe (HTTP/TCP)
    # can be injected via EnvironmentRouter(availability_probe=...).
    return AvailabilityCheck(name="health", target=target, ok=True, detail="simulated healthy")
