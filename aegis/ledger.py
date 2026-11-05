"""Evidence ledger (PRD FR-28, FR-29, FR-30).

Append-only, hash-chained JSONL. Every agent action - a red validation, a
safety decision, a blue fix, a proof re-run - is written as one record whose
``prev`` is the hash of the record before it, so any tampering breaks the chain
and is detectable (FR-30).

FR-29 ("no unsupported findings") is enforced by :meth:`EvidenceLedger.record`,
which refuses to log a result that claims success/closure without attached
evidence. This is the guard against hallucinated findings.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64

# Record kinds that assert something happened and therefore MUST carry evidence.
EVIDENCE_REQUIRED = {"validation", "proof", "detection", "remediation"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _hash(payload: dict[str, Any], prev: str) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str) + prev
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class LedgerRecord:
    seq: int
    kind: str
    at: str
    payload: dict[str, Any]
    prev: str
    hash: str

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "kind": self.kind, "at": self.at, "payload": self.payload, "prev": self.prev, "hash": self.hash}


class MissingEvidenceError(ValueError):
    """Raised when a success/closure claim is logged without evidence (FR-29)."""


class EvidenceLedger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.RLock()
        self._records: list[LedgerRecord] = []
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            self._records.append(LedgerRecord(d["seq"], d["kind"], d["at"], d["payload"], d["prev"], d["hash"]))

    @property
    def head(self) -> str:
        return self._records[-1].hash if self._records else GENESIS

    def record(
        self,
        kind: str,
        payload: dict[str, Any],
        evidence: dict[str, Any] | None = None,
        asserts_success: bool = False,
    ) -> LedgerRecord:
        """Append one record. If ``asserts_success`` (or the kind always needs
        support) and there is no evidence, refuse - this is FR-29."""
        needs_evidence = asserts_success or kind in EVIDENCE_REQUIRED
        if needs_evidence and not evidence:
            raise MissingEvidenceError(
                f"refusing to record a {kind} result with no attached evidence (FR-29)"
            )
        with self._lock:
            body = {"kind": kind, "payload": payload}
            if evidence:
                body["evidence"] = evidence
            seq = len(self._records)
            at = _now()
            h = _hash({"seq": seq, "at": at, **body}, self.head)
            record = LedgerRecord(seq, kind, at, {**payload, **({"evidence": evidence} if evidence else {})}, self.head, h)
            self._records.append(record)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record.as_dict(), default=str) + "\n")
        return record

    def verify(self) -> tuple[bool, str | None]:
        """Recompute the chain; return (ok, first-broken-hash-or-None)."""
        prev = GENESIS
        for rec in self._records:
            body = {"seq": rec.seq, "at": rec.at, "kind": rec.kind, "payload": {k: v for k, v in rec.payload.items() if k != "evidence"}}
            if "evidence" in rec.payload:
                body["evidence"] = rec.payload["evidence"]
            if rec.prev != prev or _hash(body, prev) != rec.hash:
                return False, rec.hash
            prev = rec.hash
        return True, None

    def __iter__(self) -> Iterator[LedgerRecord]:
        return iter(list(self._records))

    def __len__(self) -> int:
        return len(self._records)

    def entries(self, kind: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        rows = [r.as_dict() for r in self._records if kind is None or r.kind == kind]
        return rows[-limit:] if limit else rows
