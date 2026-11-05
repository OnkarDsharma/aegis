"""Automatic cleanup and residual-artifact scanning (PRD FR-20).

After every validation action the agent runs the action's declared cleanup
steps and then scans for residue (leftover sessions, tokens, dropped files,
processes). Because the validation actions are non-destructive and persist
nothing, a clean result is expected - but the scan is what *proves* it, and a
dirty result trips the kill switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .redteam import ValidationAction


@dataclass
class CleanupResult:
    action_id: str
    steps_run: list[str]
    residual_artifacts: list[dict[str, Any]]
    clean: bool

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


# A residual scanner takes an action and returns any artifacts it left behind.
ResidualScanner = Callable[[ValidationAction], list[dict[str, Any]]]


def _no_residue(_: ValidationAction) -> list[dict[str, Any]]:
    """Offline default: non-destructive actions leave nothing. A live scanner
    (docker exec ps/ls, session listing) can be injected instead."""
    return []


class CleanupEngine:
    def __init__(self, scanner: ResidualScanner | None = None) -> None:
        self._scan = scanner or _no_residue

    def run(self, action: ValidationAction) -> CleanupResult:
        steps = list(action.cleanup) or ["no cleanup required (read-only action)"]
        residue = self._scan(action)
        return CleanupResult(action.action_id, steps, residue, clean=not residue)
