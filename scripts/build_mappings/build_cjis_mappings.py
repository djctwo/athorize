"""Generate frameworks/cjis/mappings.json from the official FBI CJIS→800-53 mapping.

Source: FBI CJIS ISO Program Office, "Security Control Mapping of CJIS Security
Policy Requirements to NIST SP 800-53 Revision 5" (06/01/2021):
    https://www.fbi.gov/file-repository/cjis/csp-v5_5-to-nist-controls-mapping-1.pdf

The PDF lists, per CSP section, the "best fit" 800-53 r5 controls. It is already
directed CJIS -> 800-53 (toward the hub). The FBI presents these as best-fit
associations, not equivalency, so every edge ships as `intersects` / `official`
(enriches views + evidence suggestions; does not feed status propagation).

CSP sections run deeper than the bundled CJIS catalog (5.1.1.1 vs 5.1.1), so
each section is mapped up to the granularity present in the catalog. The bundled
800-53 catalog is base-controls-only, so enhancements (SA-4(01)) collapse to
their base control (SA-4).

Usage:
    python scripts/build_mappings/build_cjis_mappings.py /path/to/csp-v5_5-to-nist-controls-mapping-1.pdf

Requires: pdfplumber (dev-only).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "cjis" / "mappings.json"

SECTION = re.compile(r"^\d+(\.\d+)+$")          # 5.1.1.1
CTRL = re.compile(r"\b([A-Z]{2})-(\d+)")        # AC-21, SA-4(01) → AC-21 / SA-4


def truncate_to_catalog(section: str, catalog_ids: set[str]) -> str | None:
    candidate = section
    while candidate:
        if candidate in catalog_ids:
            return candidate
        if "." not in candidate:
            return None
        candidate = candidate.rsplit(".", 1)[0]
    return None


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    import pdfplumber

    cjis_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "cjis" / "catalog.json").read_text())["controls"]
    }
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }

    mappings = []
    seen: set[tuple[str, str]] = set()
    unresolved_sections: set[str] = set()

    with pdfplumber.open(sys.argv[1]) as pdf:
        for page in pdf.pages:
            for table in page.extract_tables():
                for row in table:
                    cells = [str(c).strip() if c else "" for c in row]
                    section = next((c for c in cells if SECTION.match(c)), None)
                    if not section:
                        continue
                    ctrl_cell = next((c for c in cells if CTRL.search(c) and c != section), "")
                    if not ctrl_cell or ctrl_cell.upper().startswith("N/A"):
                        continue
                    target_section = truncate_to_catalog(section, cjis_ids)
                    if not target_section:
                        unresolved_sections.add(section)
                        continue
                    for m in CTRL.finditer(ctrl_cell):
                        base = f"{m.group(1)}-{m.group(2)}"
                        if base not in n53_ids:
                            continue
                        key = (target_section, base)
                        if key in seen:
                            continue
                        seen.add(key)
                        mappings.append({
                            "control_id": target_section,
                            "target_framework": "nist-800-53-r5",
                            "target_control": base,
                            "relationship": "intersects",
                            "confidence": "official",
                            "rationale": f"FBI CJIS Security Policy → SP 800-53 r5 best-fit mapping: CSP {target_section} → {base}",
                        })

    mappings.sort(key=lambda m: (m["control_id"], m["target_control"]))
    OUT.write_text(json.dumps({
        "framework_id": "cjis",
        "version": "1.0",
        "source": "FBI CJIS ISO — Security Control Mapping of CJIS Security Policy to NIST SP 800-53 Rev 5 (2021)",
        "mappings": mappings,
    }, indent=2) + "\n")
    covered = len({m["control_id"] for m in mappings})
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} edges covering {covered}/{len(cjis_ids)} CJIS sections")
    if unresolved_sections:
        print(f"note — CSP sections not resolvable to a bundled id: {sorted(unresolved_sections)[:8]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
