"""Screens for Trusted APs, Alerts and Reports."""

from __future__ import annotations

import time
import json
import os
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import RogueHunterApp


class TrustedScreen(Screen):
    """Manage trusted access points."""

    def __init__(self, app: RogueHunterApp) -> None:
        super().__init__()
        self._app = app
        self._selected_bssid: str | None = None
        self._trusted_buttons: dict[Button, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Manage Trusted APs", classes="page-title")
        yield Static("Trusted access points are never flagged as malicious.", classes="hint")

        yield Label("Trusted APs", classes="section-title")
        yield VerticalScroll(id="trusted-list")

        yield Horizontal(
            Label("BSSID", classes="form-label"),
            Input(placeholder="AA:BB:CC:DD:EE:FF", id="inp-bssid"),
            Label("SSID", classes="form-label"),
            Input(placeholder="MyWiFi", id="inp-ssid"),
            id="form-row-1",
        )
        yield Horizontal(
            Label("Security", classes="form-label"),
            Select(
                [("Open", "Open"), ("WEP", "WEP"), ("WPA", "WPA"), ("WPA2", "WPA2")],
                value="Open",
                id="inp-security",
            ),
            Label("Vendor", classes="form-label"),
            Input(placeholder="Cisco", id="inp-vendor"),
            Label("Notes", classes="form-label"),
            Input(placeholder="optional", id="inp-notes"),
            id="form-row-2",
        )
        yield Horizontal(
            Button("Add Trusted AP", id="btn-add", variant="primary"),
            Button("Remove Selected", id="btn-remove"),
            Button("Refresh", id="btn-refresh"),
            Button("Back to Dashboard", id="btn-back"),
            id="trusted-actions",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        db = self._app.db
        assert db is not None
        rows = db.list_trusted_aps()
        list_w = self.query_one("#trusted-list", VerticalScroll)
        list_w.remove_children()
        self._trusted_buttons.clear()
        for r in rows:
            bssid = r["bssid"]
            ts = time.strftime("%Y-%m-%d", time.localtime(r["first_seen"]))
            text = (
                f"{bssid}  |  {r['ssid']}  |  ch={r['channel']}  "
                f"|  {r['security']}  |  {r['vendor']}  |  added {ts}"
            )
            btn = Button(text, variant="default")
            self._trusted_buttons[btn] = bssid
            list_w.mount(btn)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_widget = event.button
        btn_id = btn_widget.id
        db = self._app.db
        assert db is not None
        if btn_id == "btn-add":
            bssid = self.query_one("#inp-bssid", Input).value.strip()
            ssid = self.query_one("#inp-ssid", Input).value.strip()
            security = self.query_one("#inp-security", Select).value
            vendor = self.query_one("#inp-vendor", Input).value.strip() or "Unknown"
            notes = self.query_one("#inp-notes", Input).value.strip()
            if not bssid or not ssid:
                self.notify("BSSID and SSID are required", severity="error")
            else:
                db.add_trusted_ap(bssid, ssid, None, security, vendor, notes)
                self.notify(f"Trusted {ssid} ({bssid})")
                for inp_id in ("#inp-bssid", "#inp-ssid", "#inp-vendor", "#inp-notes"):
                    self.query_one(inp_id, Input).value = ""
                self._refresh()
        elif btn_widget in self._trusted_buttons:
            self._selected_bssid = self._trusted_buttons[btn_widget]
            self.notify(f"Selected {self._selected_bssid}")
        elif btn_id == "btn-remove":
            if self._selected_bssid:
                if db.remove_trusted_ap(self._selected_bssid):
                    self.notify(f"Removed {self._selected_bssid}")
                    self._selected_bssid = None
                    self._refresh()
                else:
                    self.notify(
                        f"Failed to remove {self._selected_bssid}", severity="error"
                    )
            else:
                self.notify(
                    "Select a trusted AP row to remove", severity="information"
                )
        elif btn_id == "btn-refresh":
            self._refresh()
        elif btn_id == "btn-back":
            self.app.switch_screen("dashboard")
        event.stop()


class AlertsScreen(Screen):
    """View and manage detection alerts — neat, well-organized, severity-colored."""

    def __init__(self, app: RogueHunterApp) -> None:
        super().__init__()
        self._app = app

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Detection Alerts", id="alerts-page-title", classes="page-title")
        yield Label(
            "Each alert explains *why* it was raised and its risk score (0–100). "
            "Severity color: green = trusted/OK, gray = low concern, yellow = suspicious, red = high risk.",
            classes="hint",
        )
        # Alert summary + bulk actions (organized, spaced)
        yield Horizontal(
            Static("Total: 0 alerts", id="alerts-summary", classes="section-title"),
            Button("Acknowledge All", id="btn-ack-all", variant="warning"),
            Button("Clear All", id="btn-clear-all", variant="error"),
            id="alerts-bulk-actions",
            classes="action-bar",
        )
        yield Button("Back to Dashboard", id="btn-back", classes="back-btn")
        yield VerticalScroll(id="alerts-list")
        yield Footer()

    # -- lifecycle -------------------------------------------------------- #
    def on_mount(self) -> None:
        self._refresh()

    # -- helpers ---------------------------------------------------------- #
    def _severity_color(self, severity: str) -> str:
        if severity == "high_risk":
            return "#b22222"   # red
        if severity == "suspicious":
            return "#b8860b"   # orange/dark-yellow
        if severity == "low_concern":
            return "#1e5f9e"   # blue
        if severity == "unknown":
            return "#8b949e"   # gray
        return "#228b22"       # green (trusted)

    def _refresh(self) -> None:
        db = self._app.db
        assert db is not None
        rows = db.get_alerts(limit=100)
        list_w = self.query_one("#alerts-list", VerticalScroll)
        list_w.remove_children()

        # Update summary
        summary = self.query_one("#alerts-summary", Static)
        summary.update(f"Total: {len(rows)} alert(s)")

        if not rows:
            list_w.mount(Static("No alerts yet. Scan some networks to see detections here.", classes="empty-msg"))
            return

        for r in rows:
            ts = time.strftime("%H:%M:%S", time.localtime(r["timestamp"]))
            sev_color = self._severity_color(r["severity"])
            ack_tag = " [ACKED]" if r["acknowledged"] else ""

            # Alert card container
            card = Vertical(classes="alert-card")
            # Top row: time | severity badge | score
            sev_badge = Static(f"[{r['severity'].upper():10}]", classes="sev-badge")
            sev_badge.styles.color = sev_color
            sev_badge.styles.text_style = "bold"
            top = Horizontal(
                Static(ts, classes="alert-time"),
                sev_badge,
                Static(f"score={r['risk_score']}", classes="alert-score"),
                id=f"alert-top-{r['id']}",
            )
            # Middle: rule + SSID + BSSID
            mid = Horizontal(
                Static(r["rule"], classes="alert-rule"),
                Static(f"{r['ssid']} ({r['bssid']}){ack_tag}", classes="alert-ident"),
                id=f"alert-mid-{r['id']}",
            )
            # Explanation
            expl = Static(r["explanation"], classes="alert-expl")
            # Bottom: acknowledge button
            ack_btn = Button("Acknowledge", id=f"btn-ack-{r['id']}", variant="default")

            # Mount complete card into list first, then mount children into card
            list_w.mount(card)
            card.mount(top)
            card.mount(mid)
            card.mount(expl)
            card.mount(ack_btn)

    # -- button handlers -------------------------------------------------- #
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        db = self._app.db
        assert db is not None
        if btn == "btn-ack-all":
            for r in db.get_alerts():
                db.acknowledge_alert(r["id"])
            self.notify("All alerts acknowledged")
        elif btn == "btn-clear-all":
            db.clear_alerts(acknowledged_only=False)
            self.notify("All alerts cleared")
        elif btn == "btn-back":
            self.app.switch_screen("dashboard")
        elif btn and btn.startswith("btn-ack-"):
            alert_id = int(btn.split("-")[-1])
            db.acknowledge_alert(alert_id)
            self.notify(f"Alert #{alert_id} acknowledged")
        event.stop()
        self._refresh()


class ExportPathScreen(Screen):
    """Simple dialog: type an export file path and save."""

    def __init__(self, app: RogueHunterApp, default_path: str) -> None:
        super().__init__()
        self._app = app
        self._default_path = default_path
        self._selected_path: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Save Report", classes="page-title")
        yield Label(
            "Enter the full file path where the report will be saved:",
            classes="hint",
        )
        yield Horizontal(
            Label("Path:", classes="form-label"),
            Input(value=self._default_path, id="inp-path"),
            id="path-row",
        )
        yield Horizontal(
            Button("Save", id="btn-save", variant="primary"),
            Button("Cancel", id="btn-cancel"),
            id="save-actions",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "btn-save":
            path = self.query_one("#inp-path", Input).value.strip() or self._default_path
            self._selected_path = path
            self.app.pop_screen()
            if self._selected_path:
                self.app._pending_export = self._selected_path
                self.app._export_format = getattr(self, "_export_format", "json")
                self.app._do_pending_export()
        elif btn_id == "btn-cancel":
            self.app.pop_screen()
        event.stop()

    def set_export_format(self, fmt: str) -> None:
        self._export_format = fmt


class ReportsScreen(Screen):
    """Export detection data to JSON or CSV with a file-save dialog."""

    def __init__(self, app: RogueHunterApp) -> None:
        super().__init__()
        self._app = app

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Export Reports", classes="page-title")
        yield Horizontal(
            Button("Export Alerts JSON", id="btn-json", variant="primary"),
            Button("Export Alerts CSV", id="btn-csv"),
            Button("Export All APs JSON", id="btn-all-json", variant="success"),
            Button("Export All APs CSV", id="btn-all-csv", variant="success"),
            Button("Back to Dashboard", id="btn-back"),
            id="reports-actions",
        )
        yield Static("", id="report-status")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        db = self._app.db
        assert db is not None
        status = self.query_one("#report-status", Static)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if btn == "btn-json":
            self._export_format = "json"
            default_path = os.path.join(
                os.path.expanduser("~"),
                f"rogue_ap_hunter-alerts-{stamp}.json",
            )
            dlg = ExportPathScreen(self._app, default_path)
            dlg.set_export_format("json")
            self.app.push_screen(dlg)
        elif btn == "btn-csv":
            self._export_format = "csv"
            default_path = os.path.join(
                os.path.expanduser("~"),
                f"rogue_ap_hunter-alerts-{stamp}.csv",
            )
            dlg = ExportPathScreen(self._app, default_path)
            dlg.set_export_format("csv")
            self.app.push_screen(dlg)
        elif btn == "btn-all-json":
            self._export_format = "all-json"
            default_path = os.path.join(
                os.path.expanduser("~"),
                f"rogue_ap_hunter-all-aps-{stamp}.json",
            )
            dlg = ExportPathScreen(self._app, default_path)
            dlg.set_export_format("all-json")
            self.app.push_screen(dlg)
        elif btn == "btn-all-csv":
            self._export_format = "all-csv"
            default_path = os.path.join(
                os.path.expanduser("~"),
                f"rogue_ap_hunter-all-aps-{stamp}.csv",
            )
            dlg = ExportPathScreen(self._app, default_path)
            dlg.set_export_format("all-csv")
            self.app.push_screen(dlg)
        elif btn == "btn-back":
            self.app.switch_screen("dashboard")
        event.stop()
