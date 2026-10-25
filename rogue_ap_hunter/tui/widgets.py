"""Custom widgets for the RogueHunter TUI.

Provides a clean access-point table using Textual's DataTable (robust
tabular widget). Only the STATUS column shows a severity label (OK / SUSP /
HIGH); rows stay uniform dark so the table stays clean and readable.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.widgets import DataTable, Label
from textual.reactive import reactive

from ..config import ScanResult

COLUMNS = [
    ("STATUS", "status"),
    ("SSID", "ssid"),
    ("BSSID", "bssid"),
    ("CH", "channel"),
    ("SIGNAL (dBm)", "signal"),
    ("SECURITY", "security"),
    ("VENDOR", "vendor"),
]


def severity_label(severity_name: str) -> str:
    if severity_name == "high_risk":
        return "HIGH"
    if severity_name == "suspicious":
        return "SUSP"
    if severity_name == "low_concern":
        return "LOW"
    return "OK"


class APTable(Widget):
    """Scrollable access-point table backed by DataTable."""

    selected_bssid = reactive("")

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._aps: dict[str, ScanResult] = {}
        self._bssids: list[str] = []
        self._severity_by_bssid: dict[str, str] = {}

    def compose(self):
        yield Label("Access Points", id="ap-table-title", classes="section-title")
        table = DataTable(id="ap-table", zebra_stripes=True, show_header=True)
        table.cursor_type = "row"
        yield table

    def on_mount(self) -> None:
        table = self.query_one("#ap-table", DataTable)
        for label, _key in COLUMNS:
            table.add_column(label, key=label.lower())

    @property
    def _data_table(self) -> DataTable:
        return self.query_one("#ap-table", DataTable)

    @property
    def row_count(self) -> int:
        return self._data_table.row_count

    @property
    def index(self) -> int | None:
        if self.selected_bssid in self._bssids:
            return self._bssids.index(self.selected_bssid)
        return None

    @index.setter
    def index(self, value: int) -> None:
        if 0 <= value < len(self._bssids):
            self.selected_bssid = self._bssids[value]

    def set_aps(self, aps_with_sev: list[tuple[ScanResult, str]]) -> None:
        """Replace the table contents with ``(ap, severity_name)`` pairs."""
        table = self._data_table
        table.clear()

        self._aps = {}
        self._bssids = []
        self._severity_by_bssid = {}

        for ap, sev in aps_with_sev:
            bssid = ap.bssid
            label = severity_label(sev)
            table.add_row(
                label,
                ap.ssid or "<hidden>",
                bssid,
                str(ap.channel) if ap.channel is not None else "-",
                (
                    f"{ap.signal_dbm:.1f}"
                    if ap.signal_dbm is not None
                    else "-"
                ),
                ap.security,
                ap.vendor,
            )
            self._aps[bssid] = ap
            self._severity_by_bssid[bssid] = sev
            self._bssids.append(bssid)

        if self._bssids:
            self.selected_bssid = self._bssids[0]

    def select_bssid(self, bssid: str) -> None:
        if bssid in self._aps:
            self.selected_bssid = bssid

    def selected_ap(self) -> ScanResult | None:
        if not self._bssids:
            return None
        return self._aps.get(self.selected_bssid)

    def get_status(self, bssid: str) -> str:
        sev = self._severity_by_bssid.get(bssid)
        if sev is None:
            return ""
        return severity_label(sev)

    def key_up(self) -> None:
        if not self._bssids:
            return
        current = self._bssids.index(self.selected_bssid) if self.selected_bssid in self._bssids else 0
        if current > 0:
            self.selected_bssid = self._bssids[current - 1]

    def key_down(self) -> None:
        if not self._bssids:
            return
        current = self._bssids.index(self.selected_bssid) if self.selected_bssid in self._bssids else 0
        if current < len(self._bssids) - 1:
            self.selected_bssid = self._bssids[current + 1]

    def action_enter(self) -> None:
        pass

    def key_enter(self) -> None:
        self.action_enter()
