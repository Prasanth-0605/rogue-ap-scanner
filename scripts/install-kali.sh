#!/usr/bin/env bash
# Install RogueAPHunter on Kali Linux (production).
set -euo pipefail

echo "[RogueAPHunter] Checking for root privileges..."
if [ "$EUID" -ne 0 ]; then
  echo "[RogueAPHunter] Requesting sudo for system package installation..."
  exec sudo "$0" "$@"
fi

echo "[RogueAPHunter] Installing system dependency: iw via apt..."
if ! command -v iw >/dev/null 2>&1; then
  apt-get update
  apt-get install -y iw
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
