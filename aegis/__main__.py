"""Command line: ``python -m aegis {collect,paths,serve}``."""

from __future__ import annotations

import argparse
import json
import logging

from .collectors import collect
from .config import Settings
from .graph import AttackGraph
from .store import GraphStore


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("collect", help="run all collectors and ingest into the temporal graph")
    paths = sub.add_parser("paths", help="print ranked attack paths")
    paths.add_argument("--at", help="ISO timestamp; default now")
    paths.add_argument("--limit", type=int, default=10)
    engage = sub.add_parser("engage", help="run one safety-gated red-blue loop and print the report")
    engage.add_argument("--at", help="ISO timestamp; default now")
    engage.add_argument("--top-paths", type=int, default=5)
    pilot = sub.add_parser("pilot", help="measure pilot Success Metrics and print an executive report")
    pilot.add_argument("--at", help="ISO timestamp; default now")
    pilot.add_argument("--top-paths", type=int, default=5)
    pilot.add_argument("--repeat", type=int, default=3, help="runs used to measure repeatability")
    pilot.add_argument("--json", action="store_true", help="print the full metrics JSON instead of the report")
    campaign = sub.add_parser("campaign", help="run a multi-round adaptive red-blue campaign")
    campaign.add_argument("--at", help="ISO timestamp; default now")
    campaign.add_argument("--rounds", type=int, default=4)
    campaign.add_argument("--paths-per-round", type=int, default=3)
    compile_p = sub.add_parser("compile", help="compile proven fixes into cross-tool control changes + tickets")
    compile_p.add_argument("--at", help="ISO timestamp; default now")
    compile_p.add_argument("--top-paths", type=int, default=8)
    compile_p.add_argument("--ticket", help="print the change ticket for this fix_id as Markdown")
    sub.add_parser("serve", help="run the API and dashboard")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    settings = Settings()

    if args.cmd == "collect":
        store = GraphStore(settings.db_path)
        print(json.dumps(collect(store, settings), indent=2))
    elif args.cmd == "paths":
        store = GraphStore(settings.db_path)
        g = AttackGraph(*store.snapshot(args.at))
        for p in g.attack_paths(limit=args.limit):
            print(f"[{p.status:11}] value={p.security_value:+.3f} conf={p.confidence:.2f} risk={p.operational_risk:.2f}")
            print("    " + g.describe(p.entry))
            for step in p.steps:
                print(f"    -> {step['label']}  ({step['detail']}, c={step['confidence']})")
    elif args.cmd == "engage":
        from .ledger import EvidenceLedger
        from .loop import LoopConfig, RedBlueLoop
        from .safety import KillSwitch, Policy, SafetyAgent

        store = GraphStore(settings.db_path)
        g = AttackGraph(*store.snapshot(args.at))
        safety = SafetyAgent(Policy.load(settings.policy_file), KillSwitch(settings.kill_switch_file))
        loop = RedBlueLoop(safety, EvidenceLedger(settings.ledger_path))
        report = loop.run(g, LoopConfig(top_paths=args.top_paths))
        summary = {k: v for k, v in report.as_dict().items() if k != "actions"}
        print(json.dumps(summary, indent=2))
        for row in report.actions:
            if row["status"] == "access-proven":
                fixes = ", ".join(f"{f['fix']['fix_type']}:{f['proof']['verdict']}" for f in row["fixes"])
                print(f"  {row['action']['target']:9} {row['action']['technique']:22} "
                      f"detect={row['detection']['quality']:13} fixes=[{fixes}]")
    elif args.cmd == "pilot":
        from .metrics import MetricsEngine, PilotReport
        from .safety import KillSwitch, Policy
        from .loop import LoopConfig

        store = GraphStore(settings.db_path)
        g = AttackGraph(*store.snapshot(args.at))
        engine = MetricsEngine(Policy.load(settings.policy_file), KillSwitch(settings.kill_switch_file))
        measurement = engine.measure(g, LoopConfig(top_paths=args.top_paths), repeat=args.repeat)
        report = PilotReport(measurement)
        if args.json:
            print(json.dumps(report.as_dict(), indent=2))
        else:
            print(report.executive_report())
    elif args.cmd == "campaign":
        from .adaptive import AdaptiveCampaign, CampaignConfig
        from .ledger import EvidenceLedger
        from .safety import KillSwitch, Policy, SafetyAgent

        store = GraphStore(settings.db_path)
        g = AttackGraph(*store.snapshot(args.at))
        safety = SafetyAgent(Policy.load(settings.policy_file), KillSwitch(settings.kill_switch_file))
        report = AdaptiveCampaign(safety, EvidenceLedger(settings.ledger_path)).run(
            g, CampaignConfig(rounds=args.rounds, paths_per_round=args.paths_per_round)
        )
        summary = {k: v for k, v in report.as_dict().items() if k != "rounds"}
        print(json.dumps(summary, indent=2))
        for r in report.rounds:
            if "note" in r:
                print(f"  round {r['round']}: {r['note']}")
                continue
            print(f"  round {r['round']}: exposure {r['exposure_before']} -> {r['exposure_after']}  "
                  f"validated={r['validated']} proven={r['fixes_proven']} "
                  f"applied={r['fixes_applied']} staged={r['fixes_staged']} closed={r['paths_closed']}"
                  + (f"  REOPENED={r['reopened']}" if r['reopened'] else ""))
    elif args.cmd == "compile":
        from .blueteam import BlueAgent, ProofEngine
        from .compiler import ControlCompiler
        from .integrations import TicketingAdapter
        from .redteam import RedAgent

        store = GraphStore(settings.db_path)
        g = AttackGraph(*store.snapshot(args.at))
        red, blue, proof = RedAgent(), BlueAgent(), ProofEngine()
        compiler, tickets = ControlCompiler(), TicketingAdapter()
        seen: set[str] = set()
        compiled_all = []
        for action in red.plan(g, top_paths=args.top_paths, max_actions=12):
            result = red.execute(action, g, "twin")
            if not result.succeeded:
                continue
            for fix in blue.propose(g, result):
                pr = proof.prove(g, fix, action, "twin")
                if pr.verdict != "proven" or fix.fix_id in seen:
                    continue
                seen.add(fix.fix_id)
                compiled = compiler.compile(fix, g)
                ticket = tickets.create_change_ticket(
                    compiled, {"closed": pr.closed, "regression_ok": pr.regression_ok})
                compiled_all.append((compiled, ticket))
        if args.ticket:
            match = next((t for c, t in compiled_all
                          if args.ticket in (t.ticket_id, c.fix_id)), None)
            print(match.as_markdown() if match else f"no proven fix / ticket matching {args.ticket}")
        else:
            tools = sorted({t for c, _ in compiled_all for t in c.tools})
            print(json.dumps({"proven_fixes": len(compiled_all), "tools": tools}, indent=2))
            for compiled, ticket in compiled_all:
                print(f"  {ticket.ticket_id}  {compiled.fix_type:18} on {compiled.target:16} "
                      f"[{ticket.priority}] -> {', '.join(compiled.tools)}")
    elif args.cmd == "serve":
        import uvicorn

        from .api import create_app

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
