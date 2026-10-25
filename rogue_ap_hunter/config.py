"""Configuration for RogueHunter (production).

Central place for paths, risk-score weights, severity thresholds, logging,
and the 2.4 / 5 / 6 GHz frequency -> channel mapping.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Filesystem paths (XDG compliant)
# ---------------------------------------------------------------------------
DATA_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
    "rogue_ap_hunter",
)
DB_PATH = os.path.join(DATA_DIR, "rogue_ap_hunter.db")
LOG_DIR = os.path.join(
    os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
    "rogue_ap_hunter",
)
LOG_PATH = os.path.join(LOG_DIR, "rogue_ap_hunter.log")

# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
RISK_WEIGHTS: dict[str, int] = {
    "duplicate_ssid": 35,       # trusted SSID seen on a different BSSID (evil twin)
    "security_mismatch": 25,    # trusted AP now advertising different security
    "fingerprint_anomaly": 15,  # channel/signal/vendor drift vs. trusted record
    "insecure_duplicate": 25,   # trusted SSID duplicated on an Open/WEP AP
}

# unknown_bssid is intentionally NOT a risk weight: an unknown AP by itself
# is not suspicious — it only contributes to risk when combined with other rules.

RISK_LOW_CONCERN = 1    # >= 1   -> low concern (not suspicious by itself)
RISK_SUSPICIOUS = 40    # >= 40  -> suspicious (yellow)
RISK_HIGH_RISK = 70     # >= 70  -> high risk / suspected rogue (red)

# ---------------------------------------------------------------------------
# Alert deduplication
# ---------------------------------------------------------------------------

ALERT_DEDUPE_WINDOW_SECONDS = 600  # 10 minutes: don't re-log same (rule, bssid) alert

# ---------------------------------------------------------------------------
# Detection efficiency
# ---------------------------------------------------------------------------

# Only re-run detection on an AP if its fingerprint (security/channel/vendor)
# has changed since the last scan.  Unknown APs with no evidence are never
# re-evaluated unless something changes.
ENABLE_DELTA_DETECTION = True

# Maximum number of alerts to keep in memory for dedupe lookups.
DEDUPE_ALERT_CACHE_LIMIT = 2000

# Kismet-style rate limiting: max alerts per window to prevent alert storms.
ALERT_RATE_LIMIT_WINDOW = 60      # seconds
ALERT_RATE_LIMIT_MAX = 50         # max alerts per window

# ---------------------------------------------------------------------------
# Frequency -> channel helpers
# ---------------------------------------------------------------------------


def freq_to_channel(freq_mhz: int | float | None) -> int | None:
    """Convert a center frequency in MHz to a Wi-Fi channel number."""
    if freq_mhz is None:
        return None
    try:
        f = int(freq_mhz)
    except (TypeError, ValueError):
        return None

    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if f == 2484:
        return 14
    if 5170 <= f <= 5895:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5955) // 5 + 1
    return None


@dataclass(frozen=True)
class ScanResult:
    """A single access point observed during a scan."""

    bssid: str
    ssid: str
    channel: int | None
    freq: int | None
    signal_dbm: float | None
    security: str  # "Open", "WEP", "WPA", "WPA2", "WPA3", "Unknown"
    vendor: str


@dataclass(frozen=True)
class Alert:
    """A detection alert produced by the detector."""

    rule: str
    bssid: str
    ssid: str
    channel: int | None
    signal_dbm: float | None
    security: str
    vendor: str
    risk_score: int
    severity: str  # "trusted", "suspicious", "high_risk"
    explanation: str
    timestamp: float


@dataclass(frozen=True)
class Severity:
    name: str
    label: str
    color: str


SEVERITY_TRUSTED = Severity("trusted", "Trusted", "green")
SEVERITY_UNKNOWN = Severity("unknown", "Unknown", "gray")
SEVERITY_LOW_CONCERN = Severity("low_concern", "Low Concern", "blue")
SEVERITY_SUSPICIOUS = Severity("suspicious", "Suspicious", "yellow")
SEVERITY_HIGH_RISK = Severity("high_risk", "High Risk", "red")

SEVERITY_BY_SCORE = {
    "trusted": SEVERITY_TRUSTED,
    "unknown": SEVERITY_UNKNOWN,
    "low_concern": SEVERITY_LOW_CONCERN,
    "suspicious": SEVERITY_SUSPICIOUS,
    "high_risk": SEVERITY_HIGH_RISK,
}


def classify_severity(risk_score: int, is_trusted: bool) -> Severity:
    """Classify an AP into trusted / unknown / low concern / suspicious / high risk.

    A trusted AP is never marked malicious regardless of score.
    An unknown AP with no evidence (score 0) is "unknown" — not suspicious —
    until evidence accumulates.
    """
    if is_trusted:
        return SEVERITY_TRUSTED
    if risk_score >= RISK_HIGH_RISK:
        return SEVERITY_HIGH_RISK
    if risk_score >= RISK_SUSPICIOUS:
        return SEVERITY_SUSPICIOUS
    if risk_score >= RISK_LOW_CONCERN:
        return SEVERITY_LOW_CONCERN
    return SEVERITY_UNKNOWN


def risk_score_for(triggered_rules: list[str]) -> int:
    """Sum weights for a list of rule names, clamped at 100."""
    return min(100, sum(RISK_WEIGHTS.get(r, 0) for r in triggered_rules))
