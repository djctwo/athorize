"""Generate frameworks/cmmc-2.0/mappings.json from NIST SP 800-171r2 Appendix D.

CMMC 2.0 practices are 1:1 with SP 800-171r2 requirements (already recorded in
the CMMC catalog's external_references). Appendix D of SP 800-171r2 is NIST's
official mapping of each requirement to its relevant SP 800-53 controls — so
CMMC practice → 800-53 control falls out by composition.

Source PDF (public domain):
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf

Usage:
    python scripts/build_mappings/build_cmmc_mappings.py /path/to/NIST.SP.800-171r2.pdf

Requires: pypdf (dev-only; not a runtime dependency).

Parsing notes:
- Appendix D tables group consecutive requirements that share one "relevant
  controls" cell (e.g., 3.1.1 and 3.1.2 both map to AC-2/AC-3/AC-17). In the
  linearized text the controls appear after the LAST requirement of the group,
  so requirements with no controls of their own inherit from the next
  requirement that has them (backfill).
- The ISO/IEC 27001 column is ignored: its identifiers are A.x.y.z (2013
  edition), which do not match our iso-27001-2022 plugin's control ids.
- Relationship is recorded as "intersects" — Appendix D is explicit that the
  mapped controls are "relevant", not equal in scope. Confidence is "official".
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "frameworks" / "cmmc-2.0" / "mappings.json"

REQ_ID = re.compile(r"\b(3\.\d{1,2}\.\d{1,2})\b")
CTRL_ID = re.compile(r"\b([A-Z]{2}-\d{1,2})(\(\d{1,2}\))?\b")
# Families used by 800-53 r5 — guards against false positives in prose
VALID_FAMILIES = {
    "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP",
    "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR",
}


def extract_appendix_d(pdf_path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(pdf_path))
    start = end = None
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        if start is None and "TABLE D-" in text:
            start = i
        if start is not None and "APPENDIX E" in text:
            end = i
            break
    if start is None:
        raise SystemExit("Could not locate Appendix D in the PDF")
    return "\n".join((reader.pages[i].extract_text() or "") for i in range(start, end or len(reader.pages)))


def parse(text: str) -> dict[str, list[str]]:
    # Split the appendix into per-requirement segments; controls found inside a
    # segment belong to that requirement.
    matches = list(REQ_ID.finditer(text))
    raw: dict[str, list[str]] = {}
    order: list[str] = []
    for idx, m in enumerate(matches):
        req = m.group(1)
        seg_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        segment = text[m.end():seg_end]
        controls: list[str] = []
        for cm in CTRL_ID.finditer(segment):
            family = cm.group(1).split("-")[0]
            if family not in VALID_FAMILIES:
                continue
            ctrl = cm.group(1) + (cm.group(2) or "")
            if ctrl not in controls:
                controls.append(ctrl)
        if req not in raw:
            raw[req] = controls
            order.append(req)
        elif controls and not raw[req]:
            raw[req] = controls

    # Backfill: a requirement with no controls shares the cell of the next
    # requirement in document order that has controls (grouped-row layout).
    backfilled: dict[str, list[str]] = {}
    for i, req in enumerate(order):
        controls = raw[req]
        if not controls:
            for later in order[i + 1:]:
                if raw[later]:
                    controls = raw[later]
                    break
        backfilled[req] = controls
    return backfilled


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    pdf = Path(sys.argv[1])
    text = extract_appendix_d(pdf)
    req_to_53 = parse(text)

    # Validate targets against the bundled r5 catalog — Appendix D predates the
    # final r5 withdrawals (e.g., SC-19), and enhancement-level ids collapse to
    # base controls at our catalog granularity.
    n53_ids = {
        c["id"]
        for c in json.loads((REPO / "frameworks" / "nist-800-53-r5" / "catalog.json").read_text())["controls"]
    }

    # CMMC practice ↔ 800-171 requirement from the catalog's external_references
    catalog = json.loads((REPO / "frameworks" / "cmmc-2.0" / "catalog.json").read_text())
    ref_re = re.compile(r"NIST SP 800-171 (3\.\d{1,2}\.\d{1,2})")
    mappings = []
    missing = []
    for c in catalog["controls"]:
        reqs = [m.group(1) for r in c.get("external_references", []) if (m := ref_re.search(r))]
        targets: list[str] = []
        dropped: list[str] = []
        for req in reqs:
            for ctrl in req_to_53.get(req, []):
                base = ctrl.split("(")[0]
                if base not in n53_ids:
                    dropped.append(ctrl)
                    continue
                if base not in targets:
                    targets.append(base)
        if dropped:
            print(f"note: {c['id']}: dropped targets not in r5 catalog: {sorted(set(dropped))}")
        if not targets:
            missing.append(c["id"])
            continue
        for ctrl in targets:
            mappings.append({
                "control_id": c["id"],
                "target_framework": "nist-800-53-r5",
                "target_control": ctrl,
                "relationship": "intersects",
                "confidence": "official",
                "rationale": f"SP 800-171r2 {', '.join(reqs)} → {ctrl} (Appendix D)",
            })

    out = {
        "framework_id": "cmmc-2.0",
        "version": "1.0",
        "source": "NIST SP 800-171r2 Appendix D (official requirement → SP 800-53r5 control mapping), composed with CMMC↔800-171 references from catalog.json",
        "mappings": mappings,
    }
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(mappings)} mappings for {len(catalog['controls']) - len(missing)} practices")
    if missing:
        print(f"WARNING — no mapping derived for: {missing}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
