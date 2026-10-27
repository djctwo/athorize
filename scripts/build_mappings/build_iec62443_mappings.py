#!/usr/bin/env python3
"""Build frameworks/iec-62443/mappings.json — IEC 62443 → NIST 800-53r5 crosswalk.

All crosswalk edges point at the hub framework (nist-800-53-r5); the crosswalk
engine fans out transitively to every other framework that maps to the same hub
controls, so mapping IEC 62443's System Requirements to 800-53 wires it into the
whole "prove once, comply many" graph.

Editorial rendering informed by the published NIST SP 800-82r3 / ISA-IEC 62443-3-3
correspondence. Relationship discipline:
  - "equivalent"  → the SR and the 800-53 control state substantially the same
                    requirement. ONLY equivalent/superset + confidence != vendor
                    auto-propagate a satisfied status (routers/crosswalk.py), so
                    this set is kept to genuinely equivalent pairs.
  - "intersects"  → partial / broader overlap. Shows in the crosswalk and shares
                    evidence hints, but never auto-satisfies.

Component (4-2) requirements inherit their SR twin's meaning, so the 51 System
Requirements carry the crosswalk for the whole framework.

Run:  python3 scripts/build_mappings/build_iec62443_mappings.py
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HUB = "nist-800-53-r5"
SRC = "iec-62443"

# (SR id, 800-53 control, relationship)
MAPPINGS = [
    # FR 1 — Identification and Authentication Control
    ("SR-1.1", "IA-2", "equivalent"),
    ("SR-1.2", "IA-3", "intersects"),
    ("SR-1.3", "AC-2", "equivalent"),
    ("SR-1.4", "IA-4", "equivalent"),
    ("SR-1.5", "IA-5", "equivalent"),
    ("SR-1.6", "AC-18", "intersects"),
    ("SR-1.7", "IA-5", "intersects"),
    ("SR-1.8", "IA-5", "intersects"),
    ("SR-1.9", "IA-5", "intersects"),
    ("SR-1.10", "IA-6", "equivalent"),
    ("SR-1.11", "AC-7", "equivalent"),
    ("SR-1.12", "AC-8", "equivalent"),
    ("SR-1.13", "AC-17", "intersects"),
    ("SR-1.13", "SC-7", "intersects"),
    # FR 2 — Use Control
    ("SR-2.1", "AC-3", "equivalent"),
    ("SR-2.1", "AC-6", "intersects"),
    ("SR-2.2", "AC-18", "intersects"),
    ("SR-2.3", "AC-19", "equivalent"),
    ("SR-2.4", "SC-18", "equivalent"),
    ("SR-2.5", "AC-11", "equivalent"),
    ("SR-2.6", "AC-12", "equivalent"),
    ("SR-2.7", "AC-10", "equivalent"),
    ("SR-2.8", "AU-2", "equivalent"),
    ("SR-2.8", "AU-3", "intersects"),
    ("SR-2.9", "AU-4", "equivalent"),
    ("SR-2.10", "AU-5", "equivalent"),
    ("SR-2.11", "AU-8", "equivalent"),
    ("SR-2.12", "AU-10", "equivalent"),
    # FR 3 — System Integrity
    ("SR-3.1", "SC-8", "equivalent"),
    ("SR-3.2", "SI-3", "equivalent"),
    ("SR-3.3", "SI-6", "equivalent"),
    ("SR-3.4", "SI-7", "equivalent"),
    ("SR-3.5", "SI-10", "equivalent"),
    ("SR-3.6", "SC-5", "intersects"),
    ("SR-3.7", "SI-11", "equivalent"),
    ("SR-3.8", "SC-23", "equivalent"),
    ("SR-3.9", "AU-9", "equivalent"),
    # FR 4 — Data Confidentiality
    ("SR-4.1", "SC-28", "intersects"),
    ("SR-4.1", "SC-8", "intersects"),
    ("SR-4.2", "SC-4", "intersects"),
    ("SR-4.2", "MP-6", "intersects"),
    ("SR-4.3", "SC-13", "equivalent"),
    # FR 5 — Restricted Data Flow
    ("SR-5.1", "SC-7", "intersects"),
    ("SR-5.1", "AC-4", "intersects"),
    ("SR-5.2", "SC-7", "equivalent"),
    ("SR-5.3", "AC-4", "intersects"),
    ("SR-5.4", "SC-2", "equivalent"),
    # FR 6 — Timely Response to Events
    ("SR-6.1", "AU-6", "intersects"),
    ("SR-6.1", "AU-7", "intersects"),
    ("SR-6.2", "SI-4", "equivalent"),
    ("SR-6.2", "CA-7", "intersects"),
    # FR 7 — Resource Availability
    ("SR-7.1", "SC-5", "equivalent"),
    ("SR-7.2", "SC-5", "intersects"),
    ("SR-7.3", "CP-9", "equivalent"),
    ("SR-7.4", "CP-10", "equivalent"),
    ("SR-7.5", "PE-11", "intersects"),
    ("SR-7.6", "CM-6", "equivalent"),
    ("SR-7.7", "CM-7", "equivalent"),
    ("SR-7.8", "CM-8", "equivalent"),
]


def main() -> int:
    hub_ids = {c["id"] for c in json.loads((REPO / "frameworks" / HUB / "catalog.json").read_text())["controls"]}
    src_ids = {c["id"] for c in json.loads((REPO / "frameworks" / SRC / "catalog.json").read_text())["controls"]}

    errors = []
    seen = set()
    out = []
    for sid, tgt, rel in MAPPINGS:
        if sid not in src_ids:
            errors.append(f"source control not in iec-62443 catalog: {sid}")
        if tgt not in hub_ids:
            errors.append(f"target control not in {HUB} catalog: {tgt}")
        key = (sid, tgt)
        if key in seen:
            errors.append(f"duplicate edge: {sid} -> {tgt}")
        seen.add(key)
        verb = "is equivalent to" if rel == "equivalent" else "intersects"
        out.append({
            "control_id": sid,
            "target_framework": HUB,
            "target_control": tgt,
            "relationship": rel,
            "confidence": "official",
            "rationale": f"IEC 62443 {sid} {verb} SP 800-53r5 {tgt} (NIST SP 800-82r3 / ISA-IEC 62443-3-3 correspondence)",
        })

    if errors:
        print("VALIDATION FAILED:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        return 1

    doc = {
        "framework_id": SRC,
        "version": "1.0",
        "source": "IEC 62443-3-3 System Requirements mapped to NIST SP 800-53r5, informed by the published NIST SP 800-82r3 / ISA-IEC 62443-3-3 correspondence (Athorize editorial rendering). 'equivalent' edges auto-propagate a satisfied status via the hub; 'intersects' edges provide crosswalk navigation and shared-evidence hints only.",
        "mappings": out,
    }
    dest = REPO / "frameworks" / SRC / "mappings.json"
    dest.write_text(json.dumps(doc, indent=2) + "\n")
    eq = sum(1 for m in out if m["relationship"] == "equivalent")
    print(f"Wrote {dest.relative_to(REPO)}: {len(out)} edges ({eq} equivalent / {len(out)-eq} intersects) → {HUB}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
