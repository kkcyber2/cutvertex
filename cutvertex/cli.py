"""Command-line interface.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cutvertex import __version__
from cutvertex.analysis import assess, what_if
from cutvertex.deadline import AnalysisTimeout
from cutvertex.ingest.loader import IngestError, load_document
from cutvertex.report_html import render_html

#: Default wall-clock budget for a single analysis, in seconds. Generous enough
#: for a large estate, small enough that a pathological graph fails fast.
DEFAULT_TIMEOUT = 60.0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cutvertex",
        description="Precondition-aware attack path analysis and chokepoint ranking.",
    )
    p.add_argument("--version", action="version", version=f"cutvertex {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assess", help="analyse an environment document")
    a.add_argument("environment", help="path to the environment JSON document")
    a.add_argument("--max-hops", type=int, default=8, help="longest chain to consider")
    a.add_argument("--max-paths", type=int, default=500, help="cap on enumerated paths")
    a.add_argument("--top", type=int, default=10, help="number of chokepoints to report")
    a.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"wall-clock budget in seconds (default {DEFAULT_TIMEOUT:g}; 0 disables)",
    )
    a.add_argument("--out", help="write JSON report to this path")
    a.add_argument("--html", help="write a self-contained HTML report to this path")
    a.add_argument("--quiet", action="store_true", help="suppress the console summary")

    w = sub.add_parser("what-if", help="re-run analysis with one edge removed")
    w.add_argument("environment", help="path to the environment JSON document")
    w.add_argument("--remove", required=True, metavar="SRC->DST", help="edge to remove")
    w.add_argument("--max-hops", type=int, default=8)
    w.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"wall-clock budget in seconds (default {DEFAULT_TIMEOUT:g}; 0 disables)",
    )

    v = sub.add_parser("validate", help="validate a document without analysing it")
    v.add_argument("environment")
    return p


def _timeout_arg(value: float) -> float | None:
    """Translate the CLI flag into a Deadline budget (0 or negative disables)."""
    return value if value and value > 0 else None


def _parse_edge(spec: str) -> tuple[str, str]:
    if "->" not in spec:
        raise SystemExit(f"error: --remove expects SRC->DST, got {spec!r}")
    src, dst = spec.split("->", 1)
    if not src.strip() or not dst.strip():
        raise SystemExit(f"error: --remove expects SRC->DST, got {spec!r}")
    return src.strip(), dst.strip()


def _write(path: Path, text: str) -> None:
    """Write a report file, creating parent directories as needed."""
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        doc = load_document(args.environment)
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        try:
            assessment = assess(document=doc, max_paths=1)
        except IngestError as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return 1
        issues = assessment.warnings
        if issues:
            print("valid with warnings:")
            for i in issues:
                print(f"  - {i}")
        else:
            print("valid: no structural issues found")
        return 0

    if args.command == "what-if":
        try:
            from cutvertex.ingest.loader import build_environment

            graph, findings = build_environment(doc)
            result = what_if(
                graph,
                findings,
                remove_edge=_parse_edge(args.remove),
                max_hops=args.max_hops,
                timeout=_timeout_arg(args.timeout),
            )
        except IngestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except AnalysisTimeout as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4
        print(json.dumps(result, indent=2))
        return 0

    # assess
    try:
        assessment = assess(
            document=doc,
            max_hops=args.max_hops,
            max_paths=args.max_paths,
            top_chokepoints=args.top,
            timeout=_timeout_arg(args.timeout),
        )
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except AnalysisTimeout as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    payload = assessment.to_dict()

    try:
        if args.out:
            _write(Path(args.out), json.dumps(payload, indent=2))
        if args.html:
            _write(Path(args.html), render_html(payload))
    except OSError as exc:
        print(f"error: cannot write report: {exc}", file=sys.stderr)
        return 3

    if not args.quiet:
        c = payload["summary"]
        print(f"CutVertex {__version__} — {args.environment}")
        print(f"  graph          {c['nodes']} nodes / {c['edges']} edges")
        print(f"  entry points   {c['entry_points']}   crown jewels {c['crown_jewels']}")
        print(f"  paths          {c['paths']} ({c['realizable_paths']} realizable)")
        print(f"  exposure index {payload['exposure_index']}/100")
        print(f"  findings       {c['findings']}  "
              f"[act {c['priority_act']}, attend {c['priority_attend']}]")
        if payload["chokepoints"]:
            print("\n  top chokepoints")
            for i, cp in enumerate(payload["chokepoints"][:5], 1):
                e = cp["edge"]
                print(
                    f"   {i}. {e['src']} -> {e['dst']}: breaks {cp['paths_broken']}/"
                    f"{cp['paths_total']} paths, {cp['risk_share']*100:.0f}% of risk "
                    f"({cp['cost_hint']})"
                )
        if assessment.warnings:
            print("\n  warnings")
            for w in assessment.warnings:
                print(f"   - {w}")
        if args.out or args.html:
            print()
            if args.out:
                print(f"  json written: {args.out}")
            if args.html:
                print(f"  html written: {args.html}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
