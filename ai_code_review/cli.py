from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .review import findings_as_dicts, review_source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline heuristic static review of Python source (never executes input)."
    )
    parser.add_argument("file", help="Python source file to inspect")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        source = Path(args.file).read_text(encoding="utf-8")
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    findings = review_source(source, args.file)
    if args.format == "json":
        print(json.dumps(findings_as_dicts(findings), indent=2))
    elif findings:
        for item in findings:
            print(f"{args.file}:{item.line}: {item.severity} {item.rule}: {item.message}")
    else:
        print(f"{args.file}: no heuristic findings")
    return 1 if any(f.severity in {"high", "error"} for f in findings) else 0
