"""Production command-line interface for RogueAPHunter."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .database import RogueHunterDB
from .detector import Detector
from .scanner import scan

DEFAULT_IFACE: str | None = None  # auto-detect first wireless interface


def _check_root() -> None:
    """Warn the user if not running as root (iw scan needs root)."""
    if os.geteuid() != 0:
        print(
            "WARNING: RogueAPHunter is not running as root. "
            "iw scanning requires root privileges. "
            "The tool will attempt to use sudo automatically.\n",
            file=sys.stderr,
        )


def _auto_detect_iface() -> str | None:
    """Return the first wireless interface from ``iw dev`` output, or None."""
    import re
    import shutil
    import subprocess

    iw_path = shutil.which("iw")
    if iw_path is None:
        return None
    try:
        proc = subprocess.run(
            [iw_path, "dev"],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    ifaces = re.findall(r"Interface\s+(\S+)", proc.stdout)
    return ifaces[0] if ifaces else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raphunter",
        description="RogueAPHunter — detect rogue Wi-Fi access points.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"raphunter {__version__}",
    )
    parser.add_argument(
        "--iface", default=DEFAULT_IFACE,
        help="Wireless interface to scan (default: auto-detect first wireless interface).",
    )
    parser.add_argument(
        "--db", default=None,
        help="Path to the SQLite database (default: XDG data dir).",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single scan/detection pass and exit (no TUI).",
    )
    parser.add_argument(
        "--report", choices=["json", "csv"], default=None,
        help="With --once: export alerts to JSON or CSV and print to stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _check_root()

    if args.report and not args.once:
        print("--report requires --once", file=sys.stderr)
        return 2

    iface = args.iface
    if iface is None:
        iface = _auto_detect_iface()
        if iface is None:
            print(
                "No wireless interface found. Use --iface to specify one.",
                file=sys.stderr,
            )
            return 2

    if args.once:
        return _run_once(args)

    # Default: launch the Textual TUI.
    from .tui.app import RogueHunterApp

    app = RogueHunterApp(iface=iface, db_path=args.db)
    app.run()
    return 0


def _run_once(args: argparse.Namespace) -> int:
    with RogueHunterDB(db_path=args.db) as db:
        detector = Detector(db)

        status = scan(args.iface)
        if not status.ok:
            print(f"Scan failed: {status.message}", file=sys.stderr)
            return 1

        results = status.results
        alerts = detector.detect(results)

        if args.report == "json":
            import json
            print(json.dumps(db.export_alerts_json(), indent=2))
        elif args.report == "csv":
            print(db.export_alerts_csv())
        else:
            print(f"raphunter single-pass scan (interface {args.iface})")
            print(f"  access points seen: {len(results)}")
            print(f"  alerts raised:      {len(alerts)}")
            for alert in alerts:
                print(
                    f"  - [{alert.severity}] {alert.rule}: {alert.explanation}"
                )

    return 0
