import argparse
import json
from pathlib import Path
import sys
from .hardware import capabilities

from .core import analyze, compare


def load(path: Path):
    if path.stat().st_size > 2_000_000:
        raise ValueError("trace exceeds 2 MB")
    return analyze(json.loads(path.read_text()))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["hardware"]:
        print(json.dumps(capabilities(), indent=2))
        return 0
    parser = argparse.ArgumentParser(prog="pairinglens")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = load(args.trace)
        if args.compare:
            report["comparison"] = compare(report, load(args.compare))
        result = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(result)
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"pairinglens: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
