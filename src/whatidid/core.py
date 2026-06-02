"""whatidid core — drop-in run() adapter over the full digest engine."""
from __future__ import annotations
import os
import sys
from pathlib import Path


def run(
    days: int = 7,
    max_sessions: int = 100,
    hourly_rate: float = 125.0,
    html: bool = True,
    output_dir: Path | None = None,
) -> None:
    """Run the cross-agent AI work digest and write reports to output_dir."""
    if output_dir is None:
        output_dir = Path.home() / "whatidid-reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Pass output dir to engine via env var (avoids fragile dynamic import patching)
    os.environ["WHATIDID_REPORT_DIR"] = str(output_dir)

    argv_save = sys.argv[:]
    sys.argv = [
        "whatidid",
        "--days", str(days),
        "--max-sessions", str(max_sessions),
        "--hourly-rate", str(hourly_rate),
    ]
    if not html:
        sys.argv.append("--no-html")
    try:
        from whatidid import _engine
        _engine.main()
    finally:
        sys.argv = argv_save
        os.environ.pop("WHATIDID_REPORT_DIR", None)
