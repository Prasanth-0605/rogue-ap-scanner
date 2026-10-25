"""RogueHunter Textual TUI — production application.

Modern terminal UI with clickable buttons, severity-colored access-point
table, keyboard navigation, live monitoring, and screen-based navigation
to Trusted APs, Alerts and Reports.
"""

from __future__ import annotations

import logging
import os
import sys
import json
import threading
import time

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Label,
    Static,
    Input,
    Select,
)
from textual.reactive import reactive
from textual import work

from ..config import (
    SEVERITY_TRUSTED,
    SEVERITY_UNKNOWN,
    SEVERITY_LOW_CONCERN,
    SEVERITY_SUSPICIOUS,
    SEVERITY_HIGH_RISK,
    LOG_DIR,
    LOG_PATH,
)
from ..database import RogueHunterDB
from ..detector import Detector
from ..scanner import scan
from .widgets import APTable

# ---------------------------------------------------------------------------
# Logging setup (production: file-based, no stdout noise)
# ---------------------------------------------------------------------------

logger = logging.getLogger("rogue_ap_hunter")


def setup_logging() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("RogueHunter started")


# ---------------------------------------------------------------------------
# Dashboard screen
# ---------------------------------------------------------------------------


class DashboardScreen(Screen):
    """Main dashboard: live AP table + scan / monitor controls."""

    def __init__(self, app: "RogueHunterApp") -> None:
        super().__init__()
        self._app = app

    def compose(self) -> ComposeResult:
        yield Label("RogueAPHunter — Dashboard", id="dashboard-title", classes="page-title")

        # Status bar.
        yield Horizontal(
            Static("Mode: live", id="mode-pill", classes="pill"),
            Static(f"Iface: {self._app.iface}", id="iface-pill", classes="pill"),
            Static("Status: idle", id="status-pill", classes="pill"),
            id="status-bar",
        )

        # Action buttons.
        yield Horizontal(
            Button("Scan", id="btn-scan", variant="primary"),
            Button("Monitor: Off", id="btn-monitor"),
            Button("Manage Trusted APs", id="btn-trusted"),
            Button("View Alerts", id="btn-alerts"),
            Button("Export Reports", id="btn-reports"),
            id="action-bar",
        )

        # AP table.
        yield APTable(id="ap-table")

        # Alert ticker (most recent alerts).
        yield Label("Recent Alerts", classes="section-title")
        yield VerticalScroll(Static("No alerts yet.", id="alert-ticker"), id="alerts-box")

        yield Footer()

    # -- lifecycle -------------------------------------------------------- #
    def on_mount(self) -> None:
        app = self._app
        logger.info("Dashboard mounted")
        # Initial live scan.
        app.scan_once()

    # -- actions ---------------------------------------------------------- #
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        app = self._app
        if btn == "btn-scan":
            app.scan_once()
        elif btn == "btn-monitor":
            app.toggle_monitor()
        elif btn == "btn-trusted":
            app.show_trusted()
        elif btn == "btn-alerts":
            app.show_alerts()
        elif btn == "btn-reports":
            app.show_reports()
        event.stop()

    # -- public helpers used by the app ----------------------------------- #
    def set_status(self, message: str) -> None:
        self.query_one("#status-pill", Static).update(f"Status: {message}")

    def set_aps(self, aps_with_sev: list) -> None:
        self.query_one(APTable).set_aps(aps_with_sev)

    def _refresh_alerts(self) -> None:
        app = self._app
        alerts = app.db.get_alerts(limit=10)
        box = self.query_one("#alert-ticker", Static)
        if not alerts:
            box.update("No alerts yet.")
            return
        lines = []
        for a in alerts:
            ts = time.strftime("%H:%M:%S", time.localtime(a["timestamp"]))
            lines.append(
                f"[{ts}] {a['severity'].upper():10} {a['rule']}: {a['ssid']} ({a['bssid']})"
            )
        box.update("\n".join(lines))


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


class RogueHunterApp(App[None]):
    """RogueHunter production application."""

    CSS_PATH = __import__("pathlib").Path(__file__).resolve().parent / "styles.tcss"
    TITLE = "RogueAPHunter"
    iface: str = "wlp0s20f3"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan", "Scan"),
        ("m", "toggle_monitor", "Monitor"),
        ("t", "show_trusted", "Trusted APs"),
        ("a", "show_alerts", "Alerts"),
        ("r", "show_reports", "Reports"),
        ("up", "cursor_up", "Up"),
        ("down", "cursor_down", "Down"),
        ("enter", "select", "Select"),
    ]

    def __init__(
        self,
        iface: str = "wlp0s20f3",
        db_path: str | None = None,
    ) -> None:
        super().__init__()
        self.iface = iface
        self.db_path = db_path
        self.db: RogueHunterDB | None = None
        self.detector: Detector | None = None
        self.monitor_interval = None
        self.monitoring = False
        self._closing = False
        self._scan_idle = threading.Event()
        self._scan_idle.set()  # initially no scan in progress
        self._pending_export: str | None = None
        self._export_format: str = "json"

    # -- setup ----------------------------------------------------------- #
    def on_mount(self) -> None:
        setup_logging()
        self.db = RogueHunterDB(db_path=self.db_path)
        self.detector = Detector(self.db)
        self._dashboard_screen = DashboardScreen(self)
        self.install_screen(self._dashboard_screen, name="dashboard")
        self.push_screen(self._dashboard_screen)
        logger.info("TUI started on interface %s", self.iface)

    def on_unmount(self) -> None:
        self._closing = True
        self.stop_monitor()
        # Wait for any in-flight scan worker to finish before closing the DB,
        # otherwise it can write to a closed connection and raise ProgrammingError.
        self._scan_idle.wait(timeout=10.0)
        if self.db is not None:
            self.db.close()
        logger.info("TUI stopped")

    # -- scanning / monitoring ------------------------------------------ #
    def scan_once(self) -> None:
        """Trigger a single scan/detection pass (runs in a worker thread)."""
        self._do_scan()

    @work(thread=True, exclusive=True)
    def _do_scan(self) -> None:
        """Run a single scan/detection pass in a worker thread."""
        if self._closing:
            return
        self._scan_idle.clear()
        try:
            dashboard = self._dashboard()
            dashboard.set_status("scanning…")

            status = scan(self.iface)
            if not status.ok:
                self.call_from_thread(dashboard.set_status, status.message)
                self.call_from_thread(self.notify, status.message, severity="error")
                logger.error("Scan failed: %s", status.message)
                return

            results = status.results
            alerts = self.detector.detect(results)  # type: ignore[union-attr]

            # Build (ap, severity) pairs for the table.
            trusted_bssids = {r["bssid"] for r in self.db.list_trusted_aps()}
            aps_with_sev = []
            for ap in results:
                is_trusted = ap.bssid in trusted_bssids
                sev = (
                    SEVERITY_TRUSTED.name
                    if is_trusted
                    else next(
                        (a.severity for a in alerts if a.bssid == ap.bssid),
                        SEVERITY_UNKNOWN.name,
                    )
                )
                aps_with_sev.append((ap, sev))

            if self._closing:
                return
            self.call_from_thread(dashboard.set_aps, aps_with_sev)
            self.call_from_thread(dashboard._refresh_alerts)
            self.call_from_thread(
                dashboard.set_status,
                f"{len(results)} AP(s) seen, {len(alerts)} alert(s)",
            )
            logger.info("Scan complete: %d AP(s), %d alert(s)", len(results), len(alerts))
        finally:
            self._scan_idle.set()

    def toggle_monitor(self) -> None:
        if self.monitoring:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self) -> None:
        self.monitoring = True
        dash = self._dashboard()
        try:
            btn = dash.query_one("#btn-monitor", Button)
            btn.label = "Monitor: On"
            btn.variant = "success"
        except Exception:
            pass
        self.monitor_interval = self.set_interval(5.0, self.scan_once)
        dash.set_status("monitoring (5s interval)")
        logger.info("Monitoring started (5s interval)")

    def stop_monitor(self) -> None:
        self.monitoring = False
        if self.monitor_interval is not None:
            self.monitor_interval.stop()
            self.monitor_interval = None
        dash = self._dashboard()
        try:
            btn = dash.query_one("#btn-monitor", Button)
            btn.label = "Monitor: Off"
            btn.variant = "default"
            dash.set_status("monitoring stopped")
        except Exception:
            pass
        logger.info("Monitoring stopped")

    def action_scan(self) -> None:
        self.scan_once()

    def action_toggle_monitor(self) -> None:
        self.toggle_monitor()

    def action_cursor_up(self) -> None:
        self._focused_table().key_up() if self._focused_table() else None

    def action_cursor_down(self) -> None:
        self._focused_table().key_down() if self._focused_table() else None

    def action_select(self) -> None:
        table = self._focused_table()
        if table is not None:
            table.action_enter()

    # -- screen navigation ----------------------------------------------- #
    def _dashboard(self) -> DashboardScreen:
        if self._dashboard_screen is None:
            raise RuntimeError("DashboardScreen not yet mounted")
        return self._dashboard_screen

    def _focused_table(self) -> APTable | None:
        try:
            return self._dashboard().query_one(APTable)
        except Exception:
            return None

    def show_trusted(self) -> None:
        from .screens import TrustedScreen
        self._install_if_needed("trusted", TrustedScreen)

    def show_alerts(self) -> None:
        from .screens import AlertsScreen
        self._install_if_needed("alerts", AlertsScreen)

    def show_reports(self) -> None:
        from .screens import ReportsScreen
        self._install_if_needed("reports", ReportsScreen)

    def action_show_trusted(self) -> None:
        self.show_trusted()

    def action_show_alerts(self) -> None:
        self.show_alerts()

    def action_show_reports(self) -> None:
        self.show_reports()

    def _install_if_needed(self, name: str, screen_factory) -> None:
        if name not in self._installed_screens:
            self.install_screen(screen_factory(self), name=name)
        self.switch_screen(name)

    def action_quit(self) -> None:
        self.stop_monitor()
        self.exit()

    def _do_pending_export(self) -> None:
        """Perform the export after the file-save dialog picks a path."""
        path = self._pending_export
        fmt = self._export_format
        self._pending_export = None
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump(self.db.export_alerts_json(), f, indent=2)
            elif fmt == "all-json":
                with open(path, "w") as f:
                    json.dump(self.db.export_detections_json(), f, indent=2)
            elif fmt == "csv":
                with open(path, "w") as f:
                    f.write(self.db.export_alerts_csv())
            elif fmt == "all-csv":
                with open(path, "w") as f:
                    f.write(self.db.export_detections_csv())
            self.notify(f"Report saved: {path}")
            logger.info("Export saved to %s", path)
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            logger.error("Export failed: %s", exc)
