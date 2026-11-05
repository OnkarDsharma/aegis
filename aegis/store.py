"""Temporal graph store (PRD FR-5).

Every node and edge is stored as a sequence of *versions*, each valid over the
half-open interval ``[valid_from, valid_to)``. Ingesting an observation:

* inserts a new version for anything new or whose properties changed,
* closes the previous version of anything that changed,
* closes anything the collector previously reported under the same ``scope``
  that is absent from this observation (the asset disappeared, the
  vulnerability was fixed, the permission was revoked ...).

That makes it possible to rebuild the exact graph - and therefore the exact
attack paths - as of any past instant, and to diff two instants.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .model import Edge, EdgeKind, Node, NodeKind, Observation

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector TEXT NOT NULL,
    scope TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    changes INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    props TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    scope TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    run_id INTEGER NOT NULL REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS ix_node_open ON node_versions(scope, node_id, valid_to);
CREATE INDEX IF NOT EXISTS ix_node_time ON node_versions(valid_from, valid_to);
CREATE TABLE IF NOT EXISTS edge_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_key TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    kind TEXT NOT NULL,
    props TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    scope TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    run_id INTEGER NOT NULL REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS ix_edge_open ON edge_versions(scope, edge_key, valid_to);
CREATE INDEX IF NOT EXISTS ix_edge_time ON edge_versions(valid_from, valid_to);
"""

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def normalize_time(value: str | datetime | None) -> str:
    """Accept ISO-8601 in any common shape and return the store's canonical form."""
    if value is None:
        return utcnow()
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


class GraphStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._tx() as cur:
            cur.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ------------------------------------------------------------------ ingest
    def ingest(self, obs: Observation, at: str | datetime | None = None) -> dict[str, int]:
        ts = normalize_time(at)
        evidence_blob = json.dumps(obs.evidence, sort_keys=True, default=str)
        stats = {"added": 0, "changed": 0, "closed": 0, "unchanged": 0}
        with self._tx() as cur:
            last = cur.execute("SELECT MAX(observed_at) FROM runs").fetchone()[0]
            if last and ts < last:
                raise ValueError(f"observation time {ts} is earlier than the latest run {last}")
            cur.execute(
                "INSERT INTO runs (collector, scope, observed_at, node_count, edge_count, changes, evidence, evidence_sha256)"
                " VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
                (
                    obs.collector,
                    obs.scope,
                    ts,
                    len(obs.nodes),
                    len(obs.edges),
                    evidence_blob,
                    hashlib.sha256(evidence_blob.encode()).hexdigest(),
                ),
            )
            run_id = cur.lastrowid

            nodes = {n.id: n for n in obs.nodes}  # last write wins inside one observation
            for node in nodes.values():
                self._upsert(cur, "node", node.id, node, obs.scope, ts, run_id, stats)
            self._close_missing(cur, "node", set(nodes), obs.scope, ts, stats)

            edges = {e.key: e for e in obs.edges}
            for edge in edges.values():
                self._upsert(cur, "edge", edge.key, edge, obs.scope, ts, run_id, stats)
            self._close_missing(cur, "edge", set(edges), obs.scope, ts, stats)

            changes = stats["added"] + stats["changed"] + stats["closed"]
            cur.execute("UPDATE runs SET changes = ? WHERE id = ?", (changes, run_id))
        stats["run_id"] = run_id
        return stats

    def _upsert(self, cur, table, key, item, scope, ts, run_id, stats) -> None:
        key_col = "node_id" if table == "node" else "edge_key"
        fp = item.fingerprint()
        row = cur.execute(
            f"SELECT id, fingerprint FROM {table}_versions WHERE scope = ? AND {key_col} = ? AND valid_to IS NULL",
            (scope, key),
        ).fetchone()
        if row and row["fingerprint"] == fp:
            stats["unchanged"] += 1
            return
        if row:
            cur.execute(f"UPDATE {table}_versions SET valid_to = ? WHERE id = ?", (ts, row["id"]))
            stats["changed"] += 1
        else:
            stats["added"] += 1
        props = json.dumps(item.props, sort_keys=True, default=str)
        if table == "node":
            cur.execute(
                "INSERT INTO node_versions (node_id, kind, props, fingerprint, scope, valid_from, run_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (item.id, str(item.kind), props, fp, scope, ts, run_id),
            )
        else:
            cur.execute(
                "INSERT INTO edge_versions (edge_key, src, dst, kind, props, fingerprint, scope, valid_from, run_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item.key, item.src, item.dst, str(item.kind), props, fp, scope, ts, run_id),
            )

    def _close_missing(self, cur, table, present: set[str], scope, ts, stats) -> None:
        key_col = "node_id" if table == "node" else "edge_key"
        rows = cur.execute(
            f"SELECT id, {key_col} AS k FROM {table}_versions WHERE scope = ? AND valid_to IS NULL", (scope,)
        ).fetchall()
        for row in rows:
            if row["k"] not in present:
                cur.execute(f"UPDATE {table}_versions SET valid_to = ? WHERE id = ?", (ts, row["id"]))
                stats["closed"] += 1

    # ------------------------------------------------------------------- query
    def snapshot(self, at: str | datetime | None = None) -> tuple[dict[str, Node], list[Edge]]:
        """Return the merged graph valid at ``at`` (default: now).

        When several collectors describe the same node, their props are merged;
        later observations win on conflicting keys.
        """
        ts = normalize_time(at)
        with self._lock:
            node_rows = self._conn.execute(
                "SELECT node_id, kind, props FROM node_versions"
                " WHERE valid_from <= ? AND (valid_to IS NULL OR valid_to > ?) ORDER BY valid_from, id",
                (ts, ts),
            ).fetchall()
            edge_rows = self._conn.execute(
                "SELECT edge_key, src, dst, kind, props FROM edge_versions"
                " WHERE valid_from <= ? AND (valid_to IS NULL OR valid_to > ?) ORDER BY valid_from, id",
                (ts, ts),
            ).fetchall()

        merged: dict[str, dict[str, Any]] = defaultdict(dict)
        kinds: dict[str, str] = {}
        for row in node_rows:
            props = json.loads(row["props"])
            merged[row["node_id"]].update(props)
            kinds[row["node_id"]] = row["kind"]
        nodes = {nid: Node(nid, NodeKind(kinds[nid]), props) for nid, props in merged.items()}

        edge_props: dict[str, dict[str, Any]] = {}
        edge_meta: dict[str, tuple[str, str, str]] = {}
        for row in edge_rows:
            edge_props.setdefault(row["edge_key"], {}).update(json.loads(row["props"]))
            edge_meta[row["edge_key"]] = (row["src"], row["dst"], row["kind"])
        edges = [
            Edge(src, dst, EdgeKind(kind), edge_props[key])
            for key, (src, dst, kind) in edge_meta.items()
            if src in nodes and dst in nodes
        ]
        return nodes, edges

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, collector, scope, observed_at, node_count, edge_count, changes, evidence_sha256"
                " FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def run_evidence(self, run_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT evidence FROM runs WHERE id = ?", (run_id,)).fetchone()
        return json.loads(row["evidence"]) if row else None

    def history(self, node_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT scope, props, valid_from, valid_to, run_id FROM node_versions WHERE node_id = ? ORDER BY id",
                (node_id,),
            ).fetchall()
        return [{**dict(row), "props": json.loads(row["props"])} for row in rows]

    def change_times(self) -> list[str]:
        """Instants at which the graph changed - the useful points on a timeline."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT observed_at FROM runs WHERE changes > 0 ORDER BY observed_at"
            ).fetchall()
        return [row[0] for row in rows]

    def close(self) -> None:
        self._conn.close()
