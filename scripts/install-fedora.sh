#!/usr/bin/env bash
# Install RogueAPHunter on Fedora (production).
set -euo pipefail

echo "[RogueAPHunter] Checking for root privileges..."
if [ "$EUID" -ne 0 ]; then
  echo "[RogueAPHunter] Requesting sudo for system package installation..."
  exec sudo "$0" "$@"
fi

echo "[RogueAPHunter] Installing system dependency: iw via dnf..."
if ! command -v iw >/dev/null 2>&1; then
  dnf install -y iw
else
  echo "[RogueAPHunter] iw already installed."
fi

echo "[RogueAPHunter] Installing RogueHunter from source..."
pip3 install .

echo
echo "[RogueAPHunter] Installation complete."
echo "Run with:    raphunter          (live TUI, requires root for iw scan)"
echo "Single-pass: raphunter --once   (one scan, then exit)"
echo "Help:        raphunter --help"
