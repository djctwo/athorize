"""Crosswalk resolution — direct and hub-transitive control mappings.

Mappings are stored as directed edges (plugin → hub, nist-800-53-r5). This
service resolves, for one (framework, control):

1. Direct edges, both directions (outbound rows + inbound rows reversed).
2. Transitive edges through the hub: A —r1→ hub —r2(reversed)→ B, composed
   with relationship degradation and confidence downgraded to "derived" —
   or kept at "vendor" when either leg is vendor-confidence, so a weak leg is
   never laundered into a propagating suggestion.

Results are filtered to the org's ACTIVE frameworks — a mapping into a
framework the customer hasn't licensed/activated is noise.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from models.control_mapping import ControlMapping

HUB_FRAMEWORK = "nist-800-53-r5"

# Reversing a directed edge flips subset/superset; the rest are symmetric.
_REVERSE = {
    "equivalent": "equivalent",
    "subset": "superset",
    "superset": "subset",
    "intersects": "intersects",
    "related": "related",
}

# Composing two relationships across the hub. Conservative: anything that
# isn't equivalent∘equivalent degrades toward intersects/related.
def _compose(r1: str, r2: str) -> str:
    if r1 == "equivalent" and r2 == "equivalent":
        return "equivalent"
    if "related" in (r1, r2):
        return "related"
    if (r1, r2) in {("equivalent", "subset"), ("subset", "equivalent"), ("subset", "subset")}:
        return "subset"
    if (r1, r2) in {("equivalent", "superset"), ("superset", "equivalent"), ("superset", "superset")}:
        return "superset"
    return "intersects"


# Confidence strength, weakest first. A composed (hub-transitive) edge is never
# stronger than "derived" and never stronger than its weakest leg.
_CONFIDENCE_RANK = {"vendor": 0, "derived": 1, "official": 2}


def _compose_confidence(c1: str, c2: str) -> str:
    return min((c1, c2, "derived"), key=lambda c: _CONFIDENCE_RANK.get(c, 0))


@dataclass
class CrosswalkEntry:
    framework_id: str
    control_id: str
    relationship: str
    confidence: str
    path: str  # "direct" or "via nist-800-53-r5"
    rationale: str


def resolve(
    db: Session,
    framework_id: str,
    control_id: str,
    active_framework_ids: set[str],
) -> list[CrosswalkEntry]:
    entries: dict[tuple[str, str], CrosswalkEntry] = {}

    def consider(e: CrosswalkEntry) -> None:
        key = (e.framework_id, e.control_id)
        existing = entries.get(key)
        # Direct beats transitive; otherwise first wins (stable, deterministic)
        if existing is None or (existing.path != "direct" and e.path == "direct"):
            entries[key] = e

    outbound = db.query(ControlMapping).filter(
        ControlMapping.source_framework_id == framework_id,
        ControlMapping.source_control_id == control_id,
    ).all()
    inbound = db.query(ControlMapping).filter(
        ControlMapping.target_framework_id == framework_id,
        ControlMapping.target_control_id == control_id,
    ).all()

    for m in outbound:
        if m.target_framework_id in active_framework_ids:
            consider(CrosswalkEntry(
                framework_id=m.target_framework_id,
                control_id=m.target_control_id,
                relationship=m.relationship,
                confidence=m.confidence,
                path="direct",
                rationale=m.rationale or "",
            ))
    for m in inbound:
        if m.source_framework_id in active_framework_ids:
            consider(CrosswalkEntry(
                framework_id=m.source_framework_id,
                control_id=m.source_control_id,
                relationship=_REVERSE[m.relationship],
                confidence=m.confidence,
                path="direct",
                rationale=m.rationale or "",
            ))

    # Transitive through the hub: collect the hub controls this control touches
    # (either it IS hub-side, or it maps to hub controls), then fan out to
    # every other framework that maps to those same hub controls.
    if framework_id == HUB_FRAMEWORK:
        hub_touch = {control_id: ("equivalent", "official")}
    else:
        hub_touch = {
            m.target_control_id: (m.relationship, m.confidence)
            for m in outbound
            if m.target_framework_id == HUB_FRAMEWORK
        }

    if hub_touch:
        siblings = db.query(ControlMapping).filter(
            ControlMapping.target_framework_id == HUB_FRAMEWORK,
            ControlMapping.target_control_id.in_(list(hub_touch.keys())),
        ).all()
        for m in siblings:
            if m.source_framework_id == framework_id:
                continue
            if m.source_framework_id not in active_framework_ids:
                continue
            r1, c1 = hub_touch[m.target_control_id]
            composed = _compose(r1, _REVERSE[m.relationship])
            consider(CrosswalkEntry(
                framework_id=m.source_framework_id,
                control_id=m.source_control_id,
                relationship=composed,
                confidence=_compose_confidence(c1, m.confidence),
                path=f"via {HUB_FRAMEWORK}",
                rationale=f"both map to {HUB_FRAMEWORK} {m.target_control_id}",
            ))

    result = list(entries.values())
    result.sort(key=lambda e: (e.path != "direct", e.framework_id, e.control_id))
    return result
