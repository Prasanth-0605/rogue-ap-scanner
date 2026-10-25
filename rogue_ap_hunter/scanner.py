"""Production Wi-Fi scanning via ``iw`` with automatic sudo escalation.

Runs ``iw dev <iface> scan`` and parses the output into :class:`ScanResult`
objects.  If not running as root, automatically attempts to escalate via
``sudo`` so the tool works without manual privilege management.
Every failure mode (missing ``iw``, missing wireless interface,
insufficient permissions, scan returning nothing) is reported clearly —
there is no demo fallback in production.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .config import ScanResult, freq_to_channel
from .vendor import vendor_from_mac

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_BSS_HEADER = re.compile(r"^BSS\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.MULTILINE)
_FREQ = re.compile(r"^\tfreq:\s+(\d+)", re.MULTILINE)
_SIGNAL = re.compile(r"^\tsignal:\s+(-?\d+(?:\.\d+)?) dBm", re.MULTILINE)
_SSID = re.compile(r"^\tSSID:\s*(.*)$", re.MULTILINE)
_CAPABILITY = re.compile(r"^\tcapability:\s*(.*)$", re.MULTILINE)


def _parse_security(capability: str, ies: str) -> str:
    """Determine security from capability flags and information elements."""
    upper_ies = ies.upper()
    if "RSN:" in upper_ies:
        # WPA3 networks advertise RSN with SAE (Simultaneous Authentication of
        # Equals) instead of PSK. Detect WPA3 before falling back to WPA2.
        if "SAE" in upper_ies:
            return "WPA3"
        return "WPA2"
    if "WPA:" in upper_ies:
        return "WPA"
    if "Privacy" in capability:
        return "WEP"
    return "Open"


def parse_iw_scan(output: str, iface: str) -> list[ScanResult]:
    """Parse raw ``iw dev <iface> scan`` text into a list of ScanResults."""
    results: list[ScanResult] = []

    blocks: list[str] = []
    current: list[str] = []
    for line in output.splitlines():
        if _BSS_HEADER.match(line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))

    for block in blocks:
        m = _BSS_HEADER.match(block.splitlines()[0])
        if not m:
            continue
        bssid = m.group(1).upper()

        freq_m = _FREQ.search(block)
        freq = int(freq_m.group(1)) if freq_m else None
        channel = freq_to_channel(freq) if freq else None

        sig_m = _SIGNAL.search(block)
        signal = float(sig_m.group(1)) if sig_m else None

        ssid_m = _SSID.search(block)
        ssid = ssid_m.group(1).strip() if ssid_m else ""

        cap_m = _CAPABILITY.search(block)
        capability = cap_m.group(1) if cap_m else ""

        security = _parse_security(capability, block)
        vendor = vendor_from_mac(bssid)

        results.append(
            ScanResult(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                freq=freq,
                signal_dbm=signal,
                security=security,
                vendor=vendor,
            )
        )

    return results


def _is_root() -> bool:
    """Return True if the current process is running as root (UID 0)."""
    return os.geteuid() == 0


def _sudo_available() -> bool:
    """Return True if the ``sudo`` command is available on PATH."""
    return shutil.which("sudo") is not None


def _build_iw_cmd(iface: str, subcmd: list[str]) -> list[str]:
    """Build the ``iw`` command, prepending ``sudo`` when not root."""
    iw_path = shutil.which("iw")
    if iw_path is None:
        return []
    cmd = [iw_path] + subcmd
    if not _is_root():
        if _sudo_available():
            cmd = ["sudo", "-n"] + cmd  # -n = non-interactive, no password prompt
        else:
            cmd = ["sudo"] + cmd
    return cmd


@dataclass
class ScanStatus:
    ok: bool
    message: str
    results: list[ScanResult]


def scan(iface: str, timeout: float = 30.0) -> ScanStatus:
    """Run ``iw dev <iface> scan`` and return parsed results plus a status.

    If not running as root, automatically attempts to escalate via ``sudo``.
    """
    iw_path = shutil.which("iw")
    if iw_path is None:
        return ScanStatus(
            ok=False,
            message="`iw` is not installed. Install it (dnf/apt install iw).",
            results=[],
        )

    # --- list interfaces ------------------------------------------------- #
    dev_cmd = ["iw", "dev"]
    if not _is_root() and _sudo_available():
        dev_cmd = ["sudo", "-n"] + dev_cmd
    elif not _is_root():
        dev_cmd = ["sudo"] + dev_cmd

    try:
        dev_out = subprocess.run(
            dev_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return ScanStatus(
            ok=False,
            message=f"Failed to list wireless interfaces: {exc}",
            results=[],
        )

    if dev_out.returncode != 0:
        stderr = dev_out.stderr.strip()
        if "password" in stderr.lower() or "permission" in stderr.lower():
            return ScanStatus(
                ok=False,
                message=(
                    "Insufficient privileges to run `iw`. "
                    "Run as root or configure passwordless sudo for `iw`."
                ),
                results=[],
            )
        return ScanStatus(
            ok=False,
            message=f"Failed to list wireless interfaces: {stderr or dev_out.returncode}",
            results=[],
        )

    ifaces = re.findall(r"Interface\s+(\S+)", dev_out.stdout)
    if iface not in ifaces:
        available = ", ".join(ifaces) if ifaces else "none found"
        return ScanStatus(
            ok=False,
            message=f"Wireless interface '{iface}' not found. Available: {available}",
            results=[],
        )

    # --- run the scan ---------------------------------------------------- #
    scan_cmd = _build_iw_cmd(iface, ["dev", iface, "scan"])

    try:
        proc = subprocess.run(
            scan_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return ScanStatus(
            ok=False,
            message=f"Scan failed: {exc}",
            results=[],
        )

    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        message = stderr or f"iw scan exited with code {proc.returncode}"
        if "Permission denied" in message or "No such device" in message:
            message = (
                f"Cannot scan on '{iface}' ({message}). "
                "Run as root or configure passwordless sudo for `iw`."
            )
        elif "password" in message.lower():
            message = (
                "sudo requires a password. Configure passwordless sudo for `iw` "
                "or run RogueHunter as root."
            )
        return ScanStatus(
            ok=False,
            message=message,
            results=[],
        )

    results = parse_iw_scan(proc.stdout, iface)
    if not results:
        return ScanStatus(
            ok=True,
            message=f"Scan completed on '{iface}' but no access points were found.",
            results=[],
        )

    return ScanStatus(
        ok=True,
        message=f"Scanned '{iface}': {len(results)} access point(s) found.",
        results=results,
    )
