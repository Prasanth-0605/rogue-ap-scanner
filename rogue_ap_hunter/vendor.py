"""MAC OUI -> vendor lookup.

A small, bundled table of commonly-seen wireless OUIs keeps the tool usable
offline (no network lookup).  Any OUI not in the table resolves to "Unknown".
"""

from __future__ import annotations

# Mini OUI registry: first 3 octets (uppercase, separators removed) -> vendor.
OUI_TABLE: dict[str, str] = {
    # Apple
    "ACBC32": "Apple",
    "A483E7": "Apple",
    "D8CB8A": "Apple",
    "F01898": "Apple",
    "3C22FB": "Apple",
    "70CD60": "Apple",
    "B4B362": "Apple",
    "D0D242": "Apple",
    "F4B5E3": "Apple",
    # Google / Nest
    "A4087D": "Google",
    "B4DD3F": "Google",
    "FCF136": "Google",
    "54E43A": "Google",
    # Amazon / Echo / Ring
    "A002DC": "Amazon",
    "18B430": "Amazon",
    "F0D22F": "Amazon",
    "84D6D8": "Ring",
    # Microsoft / Xbox
    "809CEA": "Microsoft",
    "90FBA6": "Microsoft",
    "001310": "Microsoft",
    # Samsung
    "A4904D": "Samsung",
    "B4B52F": "Samsung",
    "C82A14": "Samsung",
    "ECB1D7": "Samsung",
    # Intel
    "A434D9": "Intel",
    "001302": "Intel",
    "00166F": "Intel",
    "001B77": "Intel",
    # TP-Link
    "50C7BF": "TP-Link",
    "90F652": "TP-Link",
    "B0487A": "TP-Link",
    "D85D4C": "TP-Link",
    "14CC20": "TP-Link",
    # Asus
    "40167F": "ASUS",
    "B06EBF": "ASUS",
    "F81A17": "ASUS",
    "F07959": "ASUS",
    # Netgear
    "2CF05D": "Netgear",
    "F8D111": "Netgear",
    "D4619D": "Netgear",
    "C891F2": "Netgear",
    # Linksys / Cisco
    "C02506": "Linksys",
    "A42B8C": "Linksys",
    "0014BF": "Linksys",
    "000C41": "Cisco",
    "00127F": "Cisco",
    # Ubiquiti
    "B4FB3E": "Ubiquiti",
    "E4D332": "Ubiquiti",
    "24A47C": "Ubiquiti",
    "002722": "Ubiquiti",
    # D-Link
    "0015E9": "D-Link",
    "C8D719": "D-Link",
    "B80305": "D-Link",
    # HP
    "001A4B": "HP",
    "001B25": "HP",
    "34E2FD": "HP",
    # LG
    "F87A94": "LG",
    "00E091": "LG",
    "D0577B": "LG",
    # Sony
    "0004ED": "Sony",
    "D05139": "Sony",
    "A41FB6": "Sony",
}


def normalize_mac(mac: str) -> str:
    """Return the uppercase hex digits of a MAC, e.g. 'aa:bb:cc' -> 'AABBCC'."""
    return "".join(ch for ch in mac.upper() if ch in "0123456789ABCDEF")


def vendor_from_mac(mac: str | None) -> str:
    """Resolve a MAC address to a vendor name using the bundled OUI table.

    Returns "Unknown" for empty/invalid input or an OUI not in the table.
    """
    if not mac:
        return "Unknown"
    digits = normalize_mac(mac)
    if len(digits) < 6:
        return "Unknown"
    oui = digits[:6]
    return OUI_TABLE.get(oui, "Unknown")
