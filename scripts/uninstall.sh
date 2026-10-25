#!/usr/bin/env bash
# Uninstall RogueAPHunter.
set -euo pipefail

echo "[RogueAPHunter] Uninstalling..."
pip3 uninstall -y rogue-ap-hunter 2>/dev/null || true

echo "[RogueAPHunter] Removing data directory..."
rm -rf ~/.local/share/rogue_ap_hunter ~/.local/state/rogue_ap_hunter 2>/dev/null || true

echo "[RogueAPHunter] Uninstall complete."
