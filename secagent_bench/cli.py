"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import providers as prov
from . import tasks as task_registry
from .config import load_suite
from .env import load_dotenv
from .report import render
from .runner import run_suite


def _cmd_run(args: argparse.Namespace) -> int:
    # Names only — never values. Keys stay in the file and out of the terminal.
    loaded = load_dotenv(args.env)
    if loaded:
        print(f"loaded from {args.env}: {', '.join(loaded)}", file=sys.stderr)

    config = load_suite(args.config)
    if args.tasks:
        config.tasks = args.tasks
    if args.repeats:
        config.repeats = args.repeats
    if args.workers:
        config.workers = args.workers
    if args.fixtures:
        config.fixtures = Path(args.fixtures)

    results = run_suite(config, on_event=lambda m: print(m, file=sys.stderr))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out}", file=sys.stderr)

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render(results))
        print(f"wrote {report_path}", file=sys.stderr)

    print(render(results))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    results = json.loads(Path(args.results).read_text())
    text = render(results)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def _cmd_providers(_args: argparse.Namespace) -> int:
    print("providers:")
    for name in prov.KNOWN:
        print(f"  {name}")
    print("\ntasks:")
    for name in sorted(task_registry.REGISTRY):
        print(f"  {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secagent-bench",
        description=(
            "Benchmark LLM providers — hosted APIs and your own local models — "
            "on security-analysis tasks and prompt-injection robustness."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a suite")
    run.add_argument("-c", "--config", default="configs/suite.default.yaml")
    run.add_argument("-o", "--out", default="results/results.json")
    run.add_argument("--report", help="also write a Markdown report here")
    run.add_argument("--tasks", nargs="*", help="override the task list")
    run.add_argument("--repeats", type=int, help="runs per case (variance)")
    run.add_argument("--workers", type=int, help="concurrent requests")
    run.add_argument("--fixtures", help="path to the fixtures directory")
    run.add_argument(
        "--env",
        default=".env",
        help="env file holding provider API keys (default: .env). Real "
        "environment variables take precedence over it.",
    )
    run.set_defaults(func=_cmd_run)

    report = sub.add_parser("report", help="render a saved results file")
    report.add_argument("results")
    report.add_argument("-o", "--out")
    report.set_defaults(func=_cmd_report)

    listing = sub.add_parser("providers", help="list known providers and tasks")
    listing.set_defaults(func=_cmd_providers)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
