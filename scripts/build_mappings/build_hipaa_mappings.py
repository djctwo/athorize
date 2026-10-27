"""Generate frameworks/hipaa-security/mappings.json from the official OLIR crosswalk.

Source: NIST OLIR informative reference #110, "HIPAA Security Rule to
SP 800-53 Rev 5.1.1" — the focal=800-53 / reference=HIPAA workbook:
    https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/SP800-53_SecurityRule_Crosswalk_2024.xlsx

The workbook is directed 800-53 -> HIPAA (focal column = 800-53 control,
reference column = 45 CFR 164.x citation). The crosswalk hub is 800-53, so we
INVERT each row to point HIPAA -> 800-53. Like the CSF concept crosswalk, NIST
does not assert control equivalency here, so every edge ships as `intersects`
(enriches views + evidence suggestions; does NOT feed status propagation).

The bundled 800-53 catalog is base-controls-only, so each focal enhancement
(AU-02(01)) collapses to its base control (AU-2). HIPAA reference citations are
mapped up to the granularity present in the bundled HIPAA catalog.

Usage:
    python scripts/build_mappings/build_hipaa_mappings.py /path/to/SP800-53_SecurityRule_Crosswalk_2024.xlsx

Requires: openpyxl (dev-only).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "hipaa-security" / "mappings.json"

# Focal 800-53 ids look like "AC-01" or "AU-02(01)"; collapse to base "AC-1".
FOCAL = re.compile(r"^([A-Z]{2})-0*(\d+)")
# HIPAA reference ids look like "164.308(a)(3)(ii)(A)".
HIPAA = re.compile(r"^\d{3}\.\d+(\([a-zA-Z0-9]+\))*$")


def base_53(focal: str) -> str | None:
    m = FOCAL.match(focal.strip())
    return f"{m.group(1)}-{m.group(2)}" if m else None


def truncate_to_catalog(cite: str, catalog_ids: set[str]) -> str | None:
    """Trim trailing (..) groups until the citation matches a bundled HIPAA id."""
    candidate = cite
    while candidate:
        if candidate in catalog_ids:
            return candidate
        if "(" not in candidate:
            return None
        candidate = candidate.rsplit("(", 1)[0]
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    import openpyxl

    hipaa_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "hipaa-security" / "catalog.json").read_text())["controls"]
    }
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }

    wb = openpyxl.load_workbook(sys.argv[1], read_only=True)
    mappings = []
    seen: set[tuple[str, str]] = set()
    skipped_53: set[str] = set()
    skipped_hipaa: set[str] = set()

    for ws in wb.worksheets:
        for row in ws.iter_rows(min_row=2, values_only=True):
            focal = str(row[0] or "").strip()
            ref = str(row[3] or "").strip()
            if not focal or not ref or ref.lower().startswith("withdrawn"):
                continue
            target = base_53(focal)
            if not target or target not in n53_ids:
                if target:
                    skipped_53.add(focal)
                continue
            if not HIPAA.match(ref):
                continue
            cite = truncate_to_catalog(ref, hipaa_ids)
            if not cite:
                skipped_hipaa.add(ref)
                continue
            key = (cite, target)
            if key in seen:
                continue
            seen.add(key)
            mappings.append({
                "control_id": cite,
                "target_framework": "nist-800-53-r5",
                "target_control": target,
                "relationship": "intersects",
                "confidence": "official",
                "rationale": f"HIPAA Security Rule ↔ SP 800-53 r5 OLIR crosswalk (#110): {cite} → {target}",
            })

    mappings.sort(key=lambda m: (m["control_id"], m["target_control"]))
    OUT.write_text(json.dumps({
        "framework_id": "hipaa-security",
        "version": "1.0",
        "source": "NIST OLIR #110 — HIPAA Security Rule to SP 800-53 Rev 5.1.1 crosswalk (2024), inverted to point at the 800-53 hub",
        "mappings": mappings,
    }, indent=2) + "\n")
    covered = len({m["control_id"] for m in mappings})
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} edges covering {covered}/{len(hipaa_ids)} HIPAA controls")
    if skipped_hipaa:
        print(f"note — HIPAA citations not resolvable to a bundled id: {sorted(skipped_hipaa)[:8]}…")
    if skipped_53:
        print(f"note — 800-53 focal not in bundled catalog (collapsed/absent): {sorted(skipped_53)[:8]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
