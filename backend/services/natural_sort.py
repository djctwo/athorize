"""Natural ordering for control identifiers (E2E-25).

Lexicographic ORDER BY gives AC-1, AC-10, AC-11 … AC-2. Every list of controls
a person reads (catalog, binder, assessment report) should read AC-1, AC-2 …
AC-10, AC-2(1) after AC-2, and 1.1, 1.2 … 1.10 for dotted schemes."""
import re

# ASCII digits ONLY. `\d` and str.isdigit() also accept Unicode digits such as
# "²" or Arabic-Indic numerals, and int() raises on some of those — a custom
# control id containing one would 500 the whole controls list.
_TOKEN = re.compile(r"([0-9]+)")
_DIGITS = re.compile(r"[0-9]+")


def control_sort_key(control_id: str | None) -> tuple:
    """Sort key: ASCII digit runs compare as numbers, everything else
    case-insensitively. Each token is tagged so ints and strings never compare
    against each other."""
    parts = _TOKEN.split(control_id or "")
    return tuple((0, int(p), "") if _DIGITS.fullmatch(p) else (1, 0, p.lower()) for p in parts if p != "")
