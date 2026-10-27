"""CSV formula-injection guard shared by every CSV export.

A cell that starts with = + - @ TAB or CR is executed as a formula by Excel /
LibreOffice / Sheets. Prefixing an apostrophe makes it plain text without
changing what the user reads (documented in Help → "CSV exports look wrong").
"""
from __future__ import annotations

FORMULA_CHARS = frozenset("=+-@\t\r")


def safe_csv_cell(val):
    if isinstance(val, str) and val and val[0] in FORMULA_CHARS:
        return "'" + val
    return val
