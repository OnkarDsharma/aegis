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
    elif args.cmd == "serve":
        import uvicorn

        from .api import create_app

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
