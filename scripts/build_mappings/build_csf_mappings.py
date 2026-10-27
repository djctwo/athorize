"""Generate frameworks/nist-csf-2.0/mappings.json from the official OLIR crosswalk.

Source: NIST OLIR informative reference #186, "Cybersecurity-Framework-v2.0-to-
SP-800-53-Rev-5-2-0" (Final, 2025-11-17) — concept crosswalk workbook:
    https://csrc.nist.gov/csrc/media/projects/olir/documents/submissions/Cybersecurity_Framework_v2-0_Concept_Crosswalk_800-53_5_2_0_draft.xlsx

NIST is explicit that concept crosswalks do not imply control equivalency, so
every edge ships as `intersects` — it enriches crosswalk views, finding
impact, and evidence suggestions, but deliberately does NOT qualify for
implementation-status propagation.

Usage:
    python scripts/build_mappings/build_csf_mappings.py /path/to/crosswalk.xlsx

Requires: openpyxl (dev-only).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "nist-csf-2.0" / "mappings.json"

SUBCATEGORY = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")  # GV.OC-01
CTRL = re.compile(r"^([A-Z]{2})-0*(\d+)$")  # PM-09 → PM-9


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    import openpyxl

    csf_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-csf-2.0" / "catalog.json").read_text())["controls"]
    }
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }

    wb = openpyxl.load_workbook(sys.argv[1])
    ws = wb["Relationships"]
    mappings = []
    seen = set()
    skipped_targets = set()
    for row in ws.iter_rows(min_row=2, values_only=True):
        focal = str(row[0] or "").strip()
        ref = str(row[2] or "").strip()
        if not SUBCATEGORY.match(focal) or focal not in csf_ids or not ref:
            continue
        for token in re.split(r"[,\s]+", ref):
            m = CTRL.match(token.strip())
            if not m:
                continue
            target = f"{m.group(1)}-{m.group(2)}"
            if target not in n53_ids:
                skipped_targets.add(token.strip())
                continue
            key = (focal, target)
            if key in seen:
                continue
            seen.add(key)
            mappings.append({
                "control_id": focal,
                "target_framework": "nist-800-53-r5",
                "target_control": target,
                "relationship": "intersects",
                "confidence": "official",
                "rationale": f"NIST CSF 2.0 ↔ SP 800-53 concept crosswalk (OLIR #186): {focal} → {target}",
            })

    OUT.write_text(json.dumps({
        "framework_id": "nist-csf-2.0",
        "version": "1.0",
        "source": "NIST OLIR #186 — Cybersecurity Framework v2.0 to SP 800-53 Rev 5 concept crosswalk (Final 2025-11-17)",
        "mappings": mappings,
    }, indent=2) + "\n")
    covered = len({m["control_id"] for m in mappings})
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} mappings covering {covered} CSF subcategories")
    if skipped_targets:
        print(f"note — targets not in bundled r5 catalog (enhancements/withdrawn): {sorted(skipped_targets)[:10]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
