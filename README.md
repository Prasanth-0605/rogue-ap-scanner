# RogueAPHunter

RogueAPHunter is a Linux CLI tool for detecting rogue Wi-Fi access points. It scans Wi-Fi with `iw`, classifies each access point as trusted / unknown / suspicious / high risk, and shows results in a terminal UI.

## Install

```bash
git clone <repo-url>
cd rouge-access-point
sudo pip3 install .
```

## Use

```bash
# Interactive terminal UI
sudo raphunter

# Single scan and exit
sudo raphunter --once

# Scan and export alerts to JSON
sudo raphunter --once --report json

# Scan and export alerts to CSV
sudo raphunter --once --report csv

# Use a specific interface
sudo raphunter --iface wlan0

# Help
raphunter --help
```

## How it works

- Scans Wi-Fi with `iw dev <iface> scan` (needs root)
- Unknown APs are shown as **OK** (green) — not suspicious by themselves
- Only APs with real evidence (duplicate trusted SSID, security mismatch, etc.) show as **SUSP** (yellow) or **HIGH** (red)
- Alerts are deduplicated so the same AP doesn't alert repeatedly
- Export reports to JSON or CSV from the "Export Reports" screen

## Keys (in the TUI)

| Key | Action |
|-----|--------|
| `s` | Scan |
| `m` | Toggle monitor |
| `t` | Manage Trusted APs |
| `a` | View Alerts |
| `r` | Export Reports |
| `q` | Quit |
