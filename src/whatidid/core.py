"""whatidid core — drop-in run() adapter over the full digest engine."""
from __future__ import annotations
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
    import importlib.util, types, os

    if output_dir is None:
        output_dir = Path.home() / "whatidid-reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Locate the bundled engine
    engine_path = Path(__file__).parent / "_engine.py"
    if not engine_path.exists():
        raise FileNotFoundError(
            f"Engine not found at {engine_path}. "
            "Re-install with: pip install --upgrade whatidid"
        )

    spec = importlib.util.spec_from_file_location("_engine", engine_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    # Patch constants before exec
    mod.__dict__["_OVERRIDE_REPORT_DIR"] = output_dir  # type: ignore[attr-defined]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    # Build argv and invoke
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
        mod.main()  # type: ignore[attr-defined]
    finally:
        sys.argv = argv_save
