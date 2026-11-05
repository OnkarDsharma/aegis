"""Ticketing / CMDB integration for remediation workflows (PRD FR-34).

Turns a proven, compiled remediation into the change artifacts an operations team
actually works from: a change ticket (Jira / ServiceNow shape) and a CMDB change
record against the affected configuration item. Each carries the compiled per-tool
control changes, a rollback, and a reference to the evidence that justifies it
(the proof re-run + the hash-chained ledger), so the change is auditable (FR-28).

This is a **dry-run adapter**: it builds the payload that *would* be sent and
returns it. Nothing is pushed to an external system here - sending to a real
ticketing system is an outbound action a human authorizes, kept out of the
offline loop on purpose.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .compiler import CompiledRemediation

# approval tier -> change priority
PRIORITY = {"auto": "P4-routine", "low-risk": "P3-normal", "high-risk": "P1-high"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ChangeTicket:
    ticket_id: str
    system: str
    title: str
    priority: str
    asset: str
    change_type: str
    summary: str
    steps: list[str]
    rollback: list[str]
    tools: list[str]
    evidence_ref: dict[str, Any]
    status: str = "staged"           # staged -> (human) approved -> applied
    created_at: str = field(default_factory=_now)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def as_markdown(self) -> str:
        lines = [
            f"# [{self.ticket_id}] {self.title}",
            f"**System:** {self.system}  **Priority:** {self.priority}  **Status:** {self.status}",
            f"**Configuration item:** {self.asset}  **Change type:** {self.change_type}",
            f"**Tools:** {', '.join(self.tools)}",
            "",
            f"## Summary\n{self.summary}",
            "",
            "## Implementation steps",
            *[f"{i}. {s}" for i, s in enumerate(self.steps, 1)],
            "",
            "## Rollback",
            *[f"- {r}" for r in self.rollback],
            "",
            "## Evidence",
            f"- Proof: attack re-run closed = {self.evidence_ref.get('closed')}, "
            f"regression ok = {self.evidence_ref.get('regression_ok')}",
            f"- Ledger head: {self.evidence_ref.get('ledger_head', 'n/a')}",
        ]
        return "\n".join(lines)


@dataclass
class CMDBRecord:
    change_id: str
    ci_name: str
    ci_type: str
    change: str
    risk: str
    reversible: bool
    linked_ticket: str

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class TicketingAdapter:
    """Builds change tickets + CMDB records from compiled remediations (dry-run)."""

    def __init__(self, system: str = "jira") -> None:
        self.system = system

    def create_change_ticket(self, compiled: CompiledRemediation,
                             evidence: dict[str, Any] | None = None) -> ChangeTicket:
        evidence = evidence or {}
        ticket_id = self._id("CHG", compiled.fix_id)
        steps = [f"[{c.tool}] {c.summary}" for c in compiled.changes]
        rollback = [f"[{c.tool}] {c.rollback}" for c in compiled.changes]
        return ChangeTicket(
            ticket_id=ticket_id,
            system=self.system,
            title=f"Remediate: {compiled.title}",
            priority=PRIORITY.get(compiled.approval_tier, "P3-normal"),
            asset=compiled.target,
            change_type="standard" if compiled.approval_tier == "auto" else "normal",
            summary=f"Apply {compiled.fix_type} on {compiled.target} across "
                    f"{len(compiled.tools)} tool(s): {', '.join(compiled.tools)}. "
                    "Proven by AEGIS to close the attack path with no workflow regression.",
            steps=steps,
            rollback=rollback,
            tools=compiled.tools,
            evidence_ref={
                "fix_id": compiled.fix_id,
                "closed": evidence.get("closed"),
                "regression_ok": evidence.get("regression_ok"),
                "ledger_head": evidence.get("ledger_head"),
            },
        )

    def create_cmdb_record(self, compiled: CompiledRemediation, ticket: ChangeTicket) -> CMDBRecord:
        risk = {"auto": "low", "low-risk": "low", "high-risk": "high"}.get(compiled.approval_tier, "medium")
        return CMDBRecord(
            change_id=self._id("CMDB", compiled.fix_id),
            ci_name=compiled.target,
            ci_type="configuration-item",
            change=f"{compiled.fix_type} via {', '.join(compiled.tools)}",
            risk=risk,
            reversible=True,
            linked_ticket=ticket.ticket_id,
        )

    def _id(self, prefix: str, seed: str) -> str:
        return f"{prefix}-" + hashlib.sha1(f"{self.system}|{seed}".encode()).hexdigest()[:8].upper()
