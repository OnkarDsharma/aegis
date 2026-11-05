"""FastAPI service: collection, temporal graph, attack paths, findings, dashboard."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .blue import recommend_blue_ai
from .collectors import collect
from .config import Settings
from .graph import AttackGraph, diff_paths
from .ledger import EvidenceLedger
from .loop import LoopConfig, RedBlueLoop
from .model import SEVERITY_ORDER, EdgeKind, NodeKind
from .safety import KillSwitch, Policy, SafetyAgent
from .store import GraphStore, normalize_time


def create_app(settings: Settings | None = None, store: GraphStore | None = None, auto_collect: bool = True) -> FastAPI:
    settings = settings or Settings()
    store = store or GraphStore(settings.db_path)
    app = FastAPI(title="AEGIS", version=__version__)
    app.state.settings = settings
    app.state.store = store
    policy = Policy.load(settings.policy_file)
    kill_switch = KillSwitch(settings.kill_switch_file)
    ledger = EvidenceLedger(settings.ledger_path)
    app.state.policy = policy
    app.state.kill_switch = kill_switch
    app.state.ledger = ledger

    if auto_collect and not store.runs(limit=1):
        collect(store, settings)

    def graph_at(at: str | None) -> AttackGraph:
        try:
            nodes, edges = store.snapshot(at)
        except ValueError as exc:
            raise HTTPException(400, f"invalid timestamp: {exc}") from exc
        return AttackGraph(nodes, edges)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "runs": len(store.runs(limit=1))}

    @app.post("/api/collect")
    def run_collect() -> dict[str, Any]:
        return {"collectors": collect(store, settings)}

    @app.get("/api/runs")
    def runs(limit: int = 50) -> dict[str, Any]:
        return {"runs": store.runs(limit)}

    @app.get("/api/runs/{run_id}/evidence")
    def run_evidence(run_id: int) -> dict[str, Any]:
        evidence = store.run_evidence(run_id)
        if evidence is None:
            raise HTTPException(404, "run not found")
        return evidence

    @app.get("/api/timeline")
    def timeline() -> dict[str, Any]:
        return {"changes": store.change_times()}

    @app.get("/api/graph")
    def graph(at: str | None = None) -> dict[str, Any]:
        g = graph_at(at)
        return {"at": normalize_time(at), **g.knowledge_graph()}

    @app.get("/api/nodes/{node_id:path}/history")
    def node_history(node_id: str) -> dict[str, Any]:
        return {"node_id": node_id, "versions": store.history(node_id)}

    @app.get("/api/paths")
    def paths(at: str | None = None, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
        g = graph_at(at)
        found = g.attack_paths(limit=limit)
        return {
            "at": normalize_time(at),
            "summary": {
                "paths": len(found),
                "validated": sum(p.status == "validated" for p in found),
                "exploitable": sum(p.status == "exploitable" for p in found),
                "theoretical": sum(p.status == "theoretical" for p in found),
                "exposure": round(sum(max(p.security_value, 0) for p in found), 3),
                "entry_points": g.entry_points(),
                "objectives": g.objectives(),
                "unreachable_vulnerabilities": g.unreachable_vulnerabilities(),
            },
            "paths": [p.as_dict() for p in found],
        }

    @app.get("/api/paths/diff")
    def paths_diff(before: str, after: str | None = None) -> dict[str, Any]:
        return {
            "before": normalize_time(before),
            "after": normalize_time(after),
            **diff_paths(graph_at(before).attack_paths(500), graph_at(after).attack_paths(500)),
        }

    @app.get("/api/findings")
    def findings(at: str | None = None) -> dict[str, Any]:
        g = graph_at(at)
        return {"findings": build_findings(g)}

    @app.post("/api/engage")
    def engage(at: str | None = None, top_paths: int = 5, max_actions: int = 8) -> dict[str, Any]:
        """Run one safety-gated red-blue loop over the current graph (Phases 2-3)."""
        safety = SafetyAgent(policy, kill_switch)
        loop = RedBlueLoop(safety, ledger)
        report = loop.run(graph_at(at), LoopConfig(top_paths=top_paths, max_actions=max_actions))
        return report.as_dict()

    @app.get("/api/policy")
    def get_policy() -> dict[str, Any]:
        return {"policy": policy.data, "kill_switch_engaged": kill_switch.engaged()}

    @app.post("/api/kill-switch")
    def set_kill_switch(engage: bool, reason: str = "manual via API") -> dict[str, Any]:
        if engage:
            kill_switch.trip(reason)
        else:
            kill_switch.reset()
        return {"kill_switch_engaged": kill_switch.engaged()}

    @app.get("/api/ledger")
    def get_ledger(kind: str | None = None, limit: int = 200) -> dict[str, Any]:
        ok, broken = ledger.verify()
        return {"integrity_ok": ok, "broken_at": broken, "count": len(ledger), "entries": ledger.entries(kind, limit)}

    @app.get("/api/ledger/verify")
    def verify_ledger() -> dict[str, Any]:
        ok, broken = ledger.verify()
        return {"integrity_ok": ok, "broken_at": broken, "count": len(ledger)}

    if settings.frontend_dir.exists():
        app.mount("/static", StaticFiles(directory=settings.frontend_dir), name="static")

        @app.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            candidate = (settings.frontend_dir / path).resolve()
            if path and candidate.is_file() and settings.frontend_dir.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(settings.frontend_dir / "index.html")

    return app


def build_findings(g: AttackGraph) -> list[dict[str, Any]]:
    """Vulnerabilities and executed attack steps, enriched with graph context."""
    paths = g.attack_paths(limit=500)
    on_paths: dict[str, int] = {}
    for p in paths:
        for vid in p.vulnerabilities:
            on_paths[vid] = on_paths.get(vid, 0) + 1
    unreachable = set(g.unreachable_vulnerabilities())

    out: list[dict[str, Any]] = []
    for nid, node in g.nodes.items():
        props = node.props
        if node.kind == NodeKind.VULNERABILITY:
            host = next((src for src, _ in g._in(nid, EdgeKind.HAS_VULNERABILITY)), "")
            asset = g.nodes[host].name if host in g.nodes else "unknown"
            severity = str(props.get("severity", "info"))
            classification = str(props.get("classification", ""))
            reachability = "unreachable" if nid in unreachable else ("on_attack_path" if nid in on_paths else "reachable")
        elif node.kind == NodeKind.ATTACK_STEP:
            target = next((dst for dst, _ in g._out(nid, EdgeKind.EXECUTED_ON)), "")
            asset = g.nodes[target].name if target in g.nodes else "unknown"
            severity = "info"
            classification = str(props.get("technique") or props.get("tactic") or "ATT&CK")
            reachability = "executed"
        else:
            continue
        description = str(props.get("description") or props.get("command") or "")
        out.append(
            {
                "finding_id": nid,
                "name": node.name,
                "severity": severity,
                "asset": asset,
                "source_tool": str(props.get("source_tool", "unknown")),
                "classification": classification,
                "description": description,
                "confidence": props.get("confidence"),
                "validated": bool(props.get("validated")),
                "reachability": reachability,
                "attack_paths": on_paths.get(nid, 0),
                "blue_ai": asdict(recommend_blue_ai(node.name, severity, asset, classification, description)),
            }
        )
    order = {"on_attack_path": 0, "reachable": 1, "executed": 2, "unreachable": 3}
    return sorted(out, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), order.get(f["reachability"], 9), f["name"]))
