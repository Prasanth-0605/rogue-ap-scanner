"""Rogue AP detection engine.

Takes a list of scan results and the trusted-AP database, applies a set of
detection rules, computes a configurable 0-100 risk score for every access
point, and emits explained :class:`Alert` objects.

Guiding principle: an unknown AP is *never* assumed malicious.  It is
classified as "suspicious" or "high risk" only when the accumulated evidence
crosses configurable thresholds, and every alert carries a plain-language
explanation.  An AP that is simply not in the trusted database is "unknown"
— not suspicious — until evidence accumulates.

Efficiency:
- Delta detection: only re-evaluate APs whose fingerprint (security/channel/
  vendor) has changed since the last scan.
- Alert rate limiting (Kismet-style throttle/burst): prevents alert storms.
- Batch detection-history inserts.
"""

from __future__ import annotations

import time
from typing import Any

from .config import (
    ALERT_DEDUPE_WINDOW_SECONDS,
    ALERT_RATE_LIMIT_MAX,
    ALERT_RATE_LIMIT_WINDOW,
    DEDUPE_ALERT_CACHE_LIMIT,
    ENABLE_DELTA_DETECTION,
    RISK_HIGH_RISK,
    RISK_LOW_CONCERN,
    RISK_SUSPICIOUS,
    RISK_WEIGHTS,
    SEVERITY_TRUSTED,
    SEVERITY_UNKNOWN,
    Alert,
    ScanResult,
    classify_severity,
    risk_score_for,
)
from .database import RogueHunterDB


class Detector:
    """Apply detection rules to scanned access points."""

    def __init__(self, db: RogueHunterDB) -> None:
        self.db = db
        # Last-seen fingerprint per BSSID for delta detection:
        # bssid -> (security, channel, vendor)
        self._last_fingerprint: dict[str, tuple[str, int | None, str]] = {}
        # Alert rate limiting: list of timestamps within the current window.
        self._alert_timestamps: list[float] = []

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #
    def detect(self, results: list[ScanResult]) -> list[Alert]:
        """Run every detection rule over ``results`` and return alerts.

        Uses delta detection: APs whose fingerprint hasn't changed since the
        last scan are skipped (they were already evaluated).  Unknown APs
        with no evidence are never alerted — they are only recorded in
        detection history.
        """
        trusted_by_bssid = {
            r["bssid"]: r for r in self.db.list_trusted_aps()
        }
        trusted_by_ssid: dict[str, list[dict[str, Any]]] = {}
        for row in self.db.list_trusted_aps():
            trusted_by_ssid.setdefault(row["ssid"], []).append(row)

        alerts: list[Alert] = []
        detection_rows: list[tuple] = []

        now = time.time()

        for ap in results:
            # --- Delta detection: skip unchanged APs ------------------- #
            fingerprint = (ap.security, ap.channel, ap.vendor)
            if ENABLE_DELTA_DETECTION:
                last = self._last_fingerprint.get(ap.bssid)
                if last == fingerprint:
                    # Fingerprint unchanged — no new evidence, skip detection.
                    # Still record in history for completeness.
                    trusted = trusted_by_bssid.get(ap.bssid) is not None
                    detection_rows.append((
                        now, ap.bssid, ap.ssid, ap.channel, ap.signal_dbm,
                        ap.security, ap.vendor, 0,
                        SEVERITY_TRUSTED.name if trusted else SEVERITY_UNKNOWN.name,
                    ))
                    continue
            self._last_fingerprint[ap.bssid] = fingerprint

            alert = self._evaluate(ap, trusted_by_bssid, trusted_by_ssid)

            if alert is not None:
                # Alert rate limiting (Kismet-style throttle/burst).
                self._prune_alert_timestamps(now)
                if len(self._alert_timestamps) >= ALERT_RATE_LIMIT_MAX:
                    # Drop this alert to prevent alert storms.
                    continue
                # Alert deduplication: skip logging if an unacknowledged alert
                # for the same (rule, bssid) already exists within the window.
                if not self._is_duplicate_alert(alert.rule, alert.bssid):
                    alerts.append(alert)
                    self._alert_timestamps.append(now)
                    detection_rows.append((
                        now, alert.bssid, alert.ssid, alert.channel,
                        alert.signal_dbm, alert.security, alert.vendor,
                        alert.risk_score, alert.severity,
                    ))
                    self.db.log_alert(
                        rule=alert.rule,
                        bssid=alert.bssid,
                        ssid=alert.ssid,
                        channel=alert.channel,
                        signal_dbm=alert.signal_dbm,
                        security=alert.security,
                        vendor=alert.vendor,
                        risk_score=alert.risk_score,
                        severity=alert.severity,
                        explanation=alert.explanation,
                    )
            else:
                # No alert — record detection in history only.
                trusted = trusted_by_bssid.get(ap.bssid) is not None
                detection_rows.append((
                    now, ap.bssid, ap.ssid, ap.channel, ap.signal_dbm,
                    ap.security, ap.vendor, 0,
                    SEVERITY_TRUSTED.name if trusted else SEVERITY_UNKNOWN.name,
                ))

        # Batch insert detection history.
        if detection_rows:
            self.db.log_detections_batch(detection_rows)

        return alerts

    def _prune_alert_timestamps(self, now: float) -> None:
        """Remove alert timestamps outside the rate-limit window."""
        cutoff = now - ALERT_RATE_LIMIT_WINDOW
        self._alert_timestamps = [
            t for t in self._alert_timestamps if t >= cutoff
        ]

    def _is_duplicate_alert(self, rule: str, bssid: str) -> bool:
        """Return True if an unacknowledged alert for (rule, bssid) exists
        within the dedupe window, to avoid logging the same alert repeatedly."""
        cutoff = time.time() - ALERT_DEDUPE_WINDOW_SECONDS
        recent = self.db.get_alerts(limit=DEDUPE_ALERT_CACHE_LIMIT)
        for r in recent:
            if (
                r["rule"] == rule
                and r["bssid"] == bssid
                and r["acknowledged"] == 0
                and r["timestamp"] >= cutoff
            ):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Per-AP evaluation
    # ------------------------------------------------------------------ #
    def _evaluate(
        self,
        ap: ScanResult,
        trusted_by_bssid: dict[str, dict[str, Any]],
        trusted_by_ssid: dict[str, list[dict[str, Any]]],
    ) -> Alert | None:
        trusted_row = trusted_by_bssid.get(ap.bssid)
        is_trusted = trusted_row is not None

        triggered: list[tuple[str, int, str]] = []  # (rule, weight, detail)

        # Rule 1: unknown BSSID is intentionally NOT a standalone rule.
        # An AP not in the trusted DB is "unknown", not suspicious, until
        # evidence accumulates.  See config.py RISK_WEIGHTS comment.

        # Rule 2: duplicate trusted SSID (same SSID, different BSSID) ->
        # possible evil twin.
        # Skip for trusted APs (legitimate mesh/roaming) and hidden SSIDs
        # (empty SSIDs collide in the trusted_by_ssid grouping).
        if not is_trusted and ap.ssid != "":
            same_ssid_trusted = trusted_by_ssid.get(ap.ssid, [])
            if any(row["bssid"] != ap.bssid for row in same_ssid_trusted):
                others = ", ".join(
                    row["bssid"] for row in same_ssid_trusted
                    if row["bssid"] != ap.bssid
                )
                triggered.append(
                    ("duplicate_ssid", RISK_WEIGHTS["duplicate_ssid"],
                     f"SSID '{ap.ssid}' is trusted on BSSID(s) {others} but "
                     f"this frame comes from {ap.bssid}")
                )
                # An unencrypted twin of a trusted network is a strong rogue
                # indicator (classic evil twin: no encryption to crack).
                if ap.security in ("Open", "WEP"):
                    triggered.append(
                        ("insecure_duplicate",
                         RISK_WEIGHTS["insecure_duplicate"],
                         f"Unencrypted ({ap.security}) AP impersonating trusted "
                         f"SSID '{ap.ssid}'")
                    )

        # Rules that only apply to already-trusted APs.
        if is_trusted:
            trusted_ssid = trusted_row["ssid"]
            trusted_channel = trusted_row["channel"]
            trusted_security = trusted_row["security"]
            trusted_vendor = trusted_row["vendor"]

            # Rule 3: security mismatch vs. trusted record.
            if ap.security != trusted_security:
                triggered.append(
                    ("security_mismatch", RISK_WEIGHTS["security_mismatch"],
                     f"Trusted AP {ap.bssid} now advertises security "
                     f"'{ap.security}' (was '{trusted_security}')")
                )

            # Rule 3b: trusted AP downgraded to Open/WEP (insecure duplicate).
            if ap.security in ("Open", "WEP") and trusted_security not in ("Open", "WEP"):
                triggered.append(
                    ("insecure_duplicate", RISK_WEIGHTS["insecure_duplicate"],
                     f"Trusted AP {ap.bssid} downgraded to insecure security "
                     f"'{ap.security}' (was '{trusted_security}')")
                )

            # Rule 4: fingerprint anomaly (channel/vendor drift).
            anomaly_parts: list[str] = []
            if trusted_channel is not None and ap.channel is not None \
                    and ap.channel != trusted_channel:
                anomaly_parts.append(
                    f"channel {ap.channel} (trusted: {trusted_channel})"
                )
            if trusted_vendor and ap.vendor and ap.vendor != trusted_vendor:
                anomaly_parts.append(
                    f"vendor {ap.vendor} (trusted: {trusted_vendor})"
                )
            if anomaly_parts:
                triggered.append(
                    ("fingerprint_anomaly", RISK_WEIGHTS["fingerprint_anomaly"],
                     "Trusted AP fingerprint changed: " + "; ".join(anomaly_parts))
                )

        if not triggered:
            return None

        risk_score = min(100, sum(w for _, w, _ in triggered))
        explanation = self._build_explanation(triggered, ap, trusted_row)
        severity = classify_severity(risk_score, is_trusted)

        return Alert(
            rule=triggered[0][0],
            bssid=ap.bssid,
            ssid=ap.ssid,
            channel=ap.channel,
            signal_dbm=ap.signal_dbm,
            security=ap.security,
            vendor=ap.vendor,
            risk_score=risk_score,
            severity=severity.name,
            explanation=explanation,
            timestamp=time.time(),
        )

    # ------------------------------------------------------------------ #
    # Explanation builder
    # ------------------------------------------------------------------ #
    def _build_explanation(
        self,
        triggered: list[tuple[str, int, str]],
        ap: ScanResult,
        trusted_row: dict[str, Any] | None,
    ) -> str:
        parts = [detail for _, _, detail in triggered]
        score = min(100, sum(w for _, w, _ in triggered))
        trusted_status = (
            "This AP is in the trusted database." if trusted_row
            else "This AP is not in the trusted database."
        )
        return (
            f"Risk score {score}/100. {trusted_status} "
            + " ".join(parts) + "."
        )
