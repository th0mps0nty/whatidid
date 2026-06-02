"""whatidid CLI entry point."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="whatidid",
        description="Cross-agent AI work digest — value report for everything you built.",
    )
    parser.add_argument("--days", type=int, default=7, help="Look-back window in days")
    parser.add_argument("--max-sessions", type=int, default=100)
    parser.add_argument("--hourly-rate", type=float, default=125.0)
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / "whatidid-reports",
    )
    args = parser.parse_args()

    try:
        from whatidid.core import run
        run(
            days=args.days,
            max_sessions=args.max_sessions,
            hourly_rate=args.hourly_rate,
            html=not args.no_html,
            output_dir=args.output_dir,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
