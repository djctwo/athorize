"""Generate vendor *advisory* crosswalk mappings for the regulation frameworks
that have NO authoritative public 800-53 crosswalk:

    nerc-cip, gdpr, ccpa-cpra, sox, glba, dora

These are regulations, not 800-53-derived control catalogs, so no standards body
publishes a control-level crosswalk to SP 800-53. The edges below are
Athorize editorial judgment — every edge ships as:

    relationship = "related"     → "see also" navigation + evidence hints ONLY
    confidence   = "vendor"      → NEVER feeds implementation-status propagation
                                   (crosswalk engine §5: propagation requires a
                                    non-vendor confidence and equivalent/superset)

So these widen the crosswalk view and evidence-suggestion surface without ever
asserting that implementing an 800-53 control satisfies a regulatory article.
Maintained here in ONE reviewable file precisely because the judgment is ours.

All targets are validated against the bundled (base-controls-only) 800-53
catalog; any target not present is dropped with a warning.

Usage:
    python scripts/build_mappings/build_vendor_mappings.py
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# framework_id -> { control_id: [800-53 r5 base control ids] }
MAP: dict[str, dict[str, list[str]]] = {
    "nerc-cip": {
        "CIP-002-5.1a": ["RA-2", "CM-8", "PM-5"],
        "CIP-003-8": ["PM-1", "PL-1", "AC-1"],
        "CIP-004-6": ["PS-1", "AT-1"],
        "CIP-004-6-R1": ["AT-2"],
        "CIP-004-6-R2": ["AT-3"],
        "CIP-004-6-R3": ["PS-3"],
        "CIP-004-6-R4": ["AC-2", "AC-6"],
        "CIP-004-6-R5": ["PS-4", "AC-2"],
        "CIP-005-5": ["SC-7"],
        "CIP-005-5-R1": ["SC-7"],
        "CIP-005-5-R2": ["AC-17"],
        "CIP-006-6": ["PE-3"],
        "CIP-006-6-R1": ["PE-3", "PE-2"],
        "CIP-006-6-R2": ["PE-8", "PE-3"],
        "CIP-006-6-R3": ["PE-3", "MA-2"],
        "CIP-007-6": ["CM-6", "SI-2"],
        "CIP-007-6-R1": ["CM-7"],
        "CIP-007-6-R2": ["SI-2"],
        "CIP-007-6-R3": ["SI-3"],
        "CIP-007-6-R4": ["AU-6", "SI-4"],
        "CIP-007-6-R5": ["AC-2", "IA-2", "AC-7"],
        "CIP-008-5": ["IR-1", "IR-8"],
        "CIP-008-5-R1": ["IR-8"],
        "CIP-008-5-R2": ["IR-3", "IR-4"],
        "CIP-008-5-R3": ["IR-8"],
        "CIP-009-6": ["CP-1", "CP-2"],
        "CIP-009-6-R1": ["CP-2"],
        "CIP-009-6-R2": ["CP-4", "CP-10"],
        "CIP-009-6-R3": ["CP-2"],
        "CIP-010-2": ["CM-3", "RA-5"],
        "CIP-010-2-R1": ["CM-3", "CM-2"],
        "CIP-010-2-R2": ["CM-6", "SI-4"],
        "CIP-010-2-R3": ["RA-5", "CA-8"],
        "CIP-011-2": ["MP-1", "SC-28"],
        "CIP-011-2-R1": ["MP-1"],
        "CIP-011-2-R2": ["MP-6"],
        "CIP-013-1": ["SR-1", "SR-3", "SR-5"],
        "CIP-014-2": ["PE-3", "RA-3"],
    },
    "gdpr": {
        "Art.5": ["PT-1", "PM-1"],
        "Art.6": ["PT-2"],
        "Art.7": ["PT-4"],
        "Art.12": ["PT-5"],
        "Art.13": ["PT-5"],
        "Art.14": ["PT-5"],
        "Art.15": ["AC-3", "PT-6"],
        "Art.16": ["PT-3", "SI-12"],
        "Art.17": ["SI-12", "MP-6"],
        "Art.20": ["PT-3"],
        "Art.24": ["PM-1", "PT-1"],
        "Art.25": ["SA-8", "SA-3"],
        "Art.28": ["SR-3", "SA-9"],
        "Art.30": ["CM-8", "PT-3"],
        "Art.32": ["SC-28", "SC-13", "SI-4"],
        "Art.33": ["IR-6"],
        "Art.34": ["IR-6"],
        "Art.35": ["RA-3", "RA-7"],
        "Art.37": ["PM-1"],
        "Art.44": ["SA-9"],
        "Art.46": ["SA-9", "SC-8"],
    },
    "ccpa-cpra": {
        "1798.100": ["PT-5", "PT-3"],
        "1798.105": ["SI-12", "MP-6"],
        "1798.106": ["PT-3", "SI-12"],
        "1798.110": ["PT-5"],
        "1798.115": ["PT-5"],
        "1798.120": ["PT-4"],
        "1798.121": ["PT-4", "AC-3"],
        "1798.125": ["PT-1"],
        "1798.130": ["PT-5"],
        "1798.135": ["PT-5", "PT-4"],
        "1798.140": ["PT-1"],
        "1798.145": ["PT-1"],
        "1798.150": ["IR-6", "SC-28"],
        "1798.155": ["PM-1"],
        "1798.185": ["PM-1"],
        "1798.199.40": ["CA-2", "AU-6"],
    },
    "sox": {
        "ITGC-1": ["AC-1"],
        "ITGC-2": ["AC-2"],
        "ITGC-3": ["AC-2", "AC-6"],
        "ITGC-4": ["IA-2", "IA-5"],
        "ITGC-5": ["AC-5"],
        "ITGC-6": ["AC-6"],
        "ITGC-7": ["CM-1", "CM-3"],
        "ITGC-8": ["CM-3", "CM-4"],
        "ITGC-9": ["CM-4", "AC-5"],
        "ITGC-10": ["CM-3"],
        "ITGC-11": ["CP-9", "CP-10"],
        "ITGC-12": ["CM-6", "SI-4"],
        "ITGC-13": ["IR-1", "IR-4"],
        "ITGC-14": ["PE-3", "PE-13"],
        "ITGC-15": ["SA-3", "SA-8"],
        "ITGC-16": ["SI-7", "CM-3"],
        "ITGC-17": ["AU-2", "AU-3", "AU-6"],
    },
    "glba": {
        "GLB-1": ["RA-3"],
        "GLB-2": ["PM-2"],
        "GLB-3": ["AC-2", "AC-3"],
        "GLB-4": ["CM-8", "RA-2"],
        "GLB-5": ["SC-13", "SC-28"],
        "GLB-6": ["SA-3", "SA-8"],
        "GLB-7": ["IA-2"],
        "GLB-8": ["MP-6"],
        "GLB-9": ["CM-3"],
        "GLB-10": ["AU-6", "SI-4"],
        "GLB-11": ["AT-2"],
        "GLB-12": ["SR-3", "SA-9"],
        "GLB-13": ["IR-1", "IR-8"],
        "GLB-14": ["CA-2", "CA-7"],
        "GLB-15": ["PM-1"],
    },
    "dora": {
        "DORA-5": ["PM-1", "PL-1"],
        "DORA-6": ["RA-1", "PM-9"],
        "DORA-7": ["CM-2", "SA-4"],
        "DORA-8": ["CM-8", "RA-2"],
        "DORA-9": ["SC-7", "SI-3", "AC-3"],
        "DORA-10": ["SI-4", "AU-6"],
        "DORA-11": ["IR-4", "CP-2"],
        "DORA-12": ["CP-9", "CP-10"],
        "DORA-13": ["IR-4", "CA-7"],
        "DORA-14": ["IR-6"],
        "DORA-17": ["IR-1", "IR-4"],
        "DORA-18": ["IR-4", "RA-3"],
        "DORA-19": ["IR-6"],
        "DORA-20": ["IR-6"],
        "DORA-23": ["IR-6", "SI-5"],
        "DORA-24": ["CA-2", "CA-8"],
        "DORA-25": ["CA-8", "RA-5"],
        "DORA-26": ["CA-8"],
        "DORA-28": ["SR-1", "SA-9"],
        "DORA-29": ["SR-3", "RA-3"],
        "DORA-30": ["SA-4", "SR-3"],
        "DORA-31": ["SR-6"],
        "DORA-32": ["SR-6"],
        "DORA-33": ["SR-6"],
        "DORA-45": ["SI-5", "IR-6"],
    },
}

SOURCE = ("Advisory mapping (Athorize editorial judgment) — no published "
          "800-53 crosswalk exists for this regulation. relationship='related' / confidence='vendor': "
          "navigation + evidence hints only, never propagates compliance status.")


def main() -> int:
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }
    grand_total = 0
    for fw, control_map in MAP.items():
        cat_ids = {
            c["id"]
            for c in json.loads((REPO / "frameworks" / fw / "catalog.json").read_text())["controls"]
        }
        mappings = []
        dropped_targets: set[str] = set()
        unknown_sources: set[str] = set()
        for control_id, targets in control_map.items():
            if control_id not in cat_ids:
                unknown_sources.add(control_id)
                continue
            for t in targets:
                if t not in n53_ids:
                    dropped_targets.add(t)
                    continue
                mappings.append({
                    "control_id": control_id,
                    "target_framework": "nist-800-53-r5",
                    "target_control": t,
                    "relationship": "related",
                    "confidence": "vendor",
                    "rationale": f"Advisory: {fw} {control_id} relates to SP 800-53r5 {t} (vendor judgment, see-also only)",
                })
        mappings.sort(key=lambda m: (m["control_id"], m["target_control"]))
        out = REPO / "frameworks" / fw / "mappings.json"
        out.write_text(json.dumps({
            "framework_id": fw,
            "version": "1.0",
            "source": SOURCE,
            "mappings": mappings,
        }, indent=2) + "\n")
        covered = len({m["control_id"] for m in mappings})
        grand_total += len(mappings)
        print(f"wrote {out.relative_to(REPO)}: {len(mappings)} edges covering {covered}/{len(cat_ids)} controls")
        if dropped_targets:
            print(f"  WARNING — {fw} targets not in bundled 800-53 catalog (dropped): {sorted(dropped_targets)}")
        if unknown_sources:
            print(f"  WARNING — {fw} source ids not in its catalog: {sorted(unknown_sources)}")
    print(f"TOTAL vendor advisory edges: {grand_total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
