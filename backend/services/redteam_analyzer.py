"""Compliance Red Team Analyzer — Athorize.

Framework-agnostic adversarial analysis of compliance data: control
implementations, evidence, findings, assessments, and calendar events.
Produces findings mapped to framework controls with remediation guidance
and pre-filled finding language.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy.orm import Session

from models import (
    System,
    Finding,
    EvidenceArtifact,
    ControlImplementation,
    Control,
    Assessment,
    CalendarEvent,
    FrameworkActivation,
)
from models.assessment import ASSESSMENT_COMPLETE
from models.organization import Organization
from services.metrics import open_finding_clause
from services.risk_quantification import chain_exposure, compute_report_totals, quantify_findings


_TODAY = None


def _today() -> date:
    return _TODAY or date.today()


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

_COMPLETION_DAYS = {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 90, "LOW": 180}


class _FindingBuilder:
    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._counter = 0

    def add(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        category: str,
        control_ids: list[str],
        affected_entities: list[dict[str, Any]] | None = None,
        remediation: str,
        finding_title: str | None = None,
        finding_description: str | None = None,
        finding_remediation: str | None = None,
    ) -> str:
        self._counter += 1
        fid = f"RT-{self._counter:03d}"
        self._findings.append({
            "id": fid,
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "control_ids": control_ids,
            "affected_entities": affected_entities or [],
            "remediation": remediation,
            "finding_language": {
                "title": finding_title or title,
                "description": finding_description or description,
                "remediation_plan": finding_remediation or remediation,
                "severity": severity,
                "scheduled_completion_days": _COMPLETION_DAYS.get(severity, 90),
            },
        })
        return fid

    @property
    def findings(self) -> list[dict[str, Any]]:
        return self._findings


# ---------------------------------------------------------------------------
# Analysis checks
# ---------------------------------------------------------------------------

def _check_evidence_coverage(
    db: Session, system: System, framework_id: str,
    impls: list[ControlImplementation], evidence: list[EvidenceArtifact],
    fb: _FindingBuilder,
) -> None:
    evidence_control_map: set[str] = set()
    for e in evidence:
        if framework_id in (e.framework_ids or []):
            for cid in (e.control_ids or []):
                evidence_control_map.add(cid)

    no_evidence = []
    for impl in impls:
        if impl.implementation_status in ("NOT_APPLICABLE",):
            continue
        if impl.control_id not in evidence_control_map:
            no_evidence.append(impl.control_id)

    if no_evidence:
        sample = no_evidence[:10]
        more = f" (and {len(no_evidence) - 10} more)" if len(no_evidence) > 10 else ""
        fb.add(
            title=f"{len(no_evidence)} controls have no linked evidence",
            description=(
                f"Controls with zero evidence artifacts: {', '.join(sample)}{more}. "
                f"An assessor would flag these as unsupported claims."
            ),
            severity="HIGH" if len(no_evidence) > 20 else "MEDIUM",
            category="Evidence Gap",
            control_ids=no_evidence[:20],
            remediation=(
                "Upload supporting evidence (scan results, policy documents, screenshots, "
                "configuration exports) and link to the appropriate control IDs."
            ),
        )


def _check_evidence_freshness(
    db: Session, system: System, framework_id: str,
    evidence: list[EvidenceArtifact], fb: _FindingBuilder,
) -> None:
    today = _today()
    relevant = [e for e in evidence if framework_id in (e.framework_ids or [])]
    expired = [e for e in relevant if e.expiration_date and e.expiration_date < today]
    expiring = [e for e in relevant
                if e.expiration_date and today <= e.expiration_date <= today + timedelta(days=30)]

    if expired:
        names = [f"{e.filename} (expired {e.expiration_date})" for e in expired[:5]]
        fb.add(
            title=f"{len(expired)} evidence artifact(s) expired",
            description=f"Expired evidence cannot substantiate compliance: {'; '.join(names)}.",
            severity="HIGH",
            category="Evidence Freshness",
            control_ids=list({cid for e in expired for cid in (e.control_ids or [])}),
            affected_entities=[{"type": "evidence", "id": e.id, "name": e.filename} for e in expired],
            remediation="Recollect and upload fresh evidence. Update expiration dates.",
        )

    if expiring:
        names = [f"{e.filename} (expires {e.expiration_date})" for e in expiring[:5]]
        fb.add(
            title=f"{len(expiring)} evidence artifact(s) expiring within 30 days",
            description=f"Upcoming expirations: {'; '.join(names)}.",
            severity="LOW",
            category="Evidence Freshness",
            control_ids=list({cid for e in expiring for cid in (e.control_ids or [])}),
            affected_entities=[{"type": "evidence", "id": e.id, "name": e.filename} for e in expiring],
            remediation="Schedule recollection before expiration.",
        )


def _check_control_narratives(
    db: Session, system: System, impls: list[ControlImplementation], fb: _FindingBuilder,
) -> None:
    weak = []
    for impl in impls:
        if impl.implementation_status in ("NOT_APPLICABLE", "NOT_ASSESSED"):
            continue
        narrative = (impl.narrative or "").strip()
        if len(narrative) < 50:
            weak.append(impl.control_id)

    if weak:
        sample = weak[:10]
        more = f" (and {len(weak) - 10} more)" if len(weak) > 10 else ""
        fb.add(
            title=f"{len(weak)} controls have weak or missing narratives",
            description=(
                f"Controls with narratives under 50 characters: {', '.join(sample)}{more}. "
                f"Assessors require detailed narratives describing implementation."
            ),
            severity="MEDIUM",
            category="Documentation Gap",
            control_ids=weak[:20],
            remediation=(
                "Write detailed implementation narratives including: technology/process, "
                "responsible party, monitoring approach, and evidence location."
            ),
        )


def _check_implementation_gaps(
    db: Session, system: System, framework_id: str,
    impls: list[ControlImplementation], total_controls: int, fb: _FindingBuilder,
) -> None:
    implemented_ids = {i.control_id for i in impls}
    all_controls = db.query(Control.control_id).filter(
        Control.framework_id == framework_id
    ).all()
    all_ids = {c[0] for c in all_controls}

    missing = all_ids - implemented_ids
    if missing and len(missing) > 5:
        sample = sorted(missing)[:10]
        fb.add(
            title=f"{len(missing)} controls have no implementation record",
            description=(
                f"Controls with no implementation status set: {', '.join(sample)} "
                f"(and {len(missing) - 10} more). " if len(missing) > 10 else
                f"Controls with no implementation status: {', '.join(sorted(missing))}. "
            ) + "These appear as gaps during assessment.",
            severity="HIGH" if len(missing) > total_controls * 0.3 else "MEDIUM",
            category="Implementation Gap",
            control_ids=sorted(missing)[:20],
            remediation="Review each control and set an implementation status (implemented, partially, inherited, N/A).",
        )

    failed = [i for i in impls if i.assessment_result == "FAIL"]
    if failed:
        fb.add(
            title=f"{len(failed)} control(s) failed assessment",
            description=(
                f"Controls with FAIL assessment result: "
                f"{', '.join(i.control_id for i in failed[:10])}."
            ),
            severity="HIGH" if len(failed) > 5 else "MEDIUM",
            category="Assessment Finding",
            control_ids=[i.control_id for i in failed[:20]],
            remediation="Review failed controls, update implementation, and reassess.",
        )

    partial = [i for i in impls if i.implementation_status == "PARTIALLY"]
    if partial:
        fb.add(
            title=f"{len(partial)} control(s) only partially implemented",
            description=(
                f"Partial implementations: {', '.join(i.control_id for i in partial[:10])}. "
                f"These indicate known gaps in the control environment."
            ),
            severity="MEDIUM",
            category="Implementation Gap",
            control_ids=[i.control_id for i in partial[:20]],
            remediation="Complete implementation or document compensating controls and acceptance rationale.",
        )


def _check_findings_management(
    db: Session, system: System, framework_id: str, fb: _FindingBuilder,
) -> None:
    today = _today()
    open_findings = (
        db.query(Finding)
        .filter(
            Finding.system_id == system.id,
            Finding.framework_id == framework_id,
            open_finding_clause(),
        )
        .all()
    )

    overdue = [f for f in open_findings if f.due_date and f.due_date < today]
    no_plan = [f for f in open_findings if not f.remediation_plan]
    critical_open = [f for f in open_findings if f.severity == "CRITICAL"]

    if overdue:
        for f in overdue:
            days_late = (today - f.due_date).days
            fb.add(
                title=f"Finding overdue: {f.title}",
                description=(
                    f"Finding #{f.id} ({f.severity}) due {f.due_date} — {days_late} days overdue. "
                    f"Overdue findings indicate unmanaged risk."
                ),
                severity="HIGH" if f.severity in ("CRITICAL", "HIGH") else "MEDIUM",
                category="Finding Management",
                control_ids=[f.control_id] if f.control_id else [],
                affected_entities=[{"type": "finding", "id": f.id, "name": f.title}],
                remediation=f"Update remediation status. If blocked, document rationale and request extension.",
            )

    if no_plan:
        fb.add(
            title=f"{len(no_plan)} open finding(s) have no remediation plan",
            description=(
                f"Findings without documented remediation: "
                f"{', '.join(f.title for f in no_plan[:5])}."
            ),
            severity="MEDIUM",
            category="Finding Management",
            control_ids=[f.control_id for f in no_plan if f.control_id],
            affected_entities=[{"type": "finding", "id": f.id, "name": f.title} for f in no_plan],
            remediation="Document remediation plans with specific actions, owners, and timelines.",
        )

    if critical_open:
        fb.add(
            title=f"{len(critical_open)} CRITICAL finding(s) remain open",
            description=(
                f"Critical findings: {', '.join(f.title for f in critical_open[:5])}. "
                f"These represent the highest organizational risk."
            ),
            severity="CRITICAL",
            category="Finding Management",
            control_ids=[f.control_id for f in critical_open if f.control_id],
            affected_entities=[{"type": "finding", "id": f.id, "name": f.title} for f in critical_open],
            remediation="Prioritize immediate remediation of CRITICAL findings. Escalate to leadership.",
        )


def _check_assessment_coverage(
    db: Session, system: System, framework_id: str, fb: _FindingBuilder,
) -> None:
    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.system_id == system.id,
            Assessment.framework_id == framework_id,
        )
        .all()
    )

    if not assessments:
        fb.add(
            title="No assessments conducted for this framework",
            description="No assessment records exist. The compliance posture has never been formally evaluated.",
            severity="HIGH",
            category="Assessment Gap",
            control_ids=[],
            remediation="Schedule and conduct a formal assessment against the framework controls.",
        )
        return

    completed = [a for a in assessments if a.status == ASSESSMENT_COMPLETE]
    if not completed:
        fb.add(
            title="No completed assessments",
            description=f"{len(assessments)} assessment(s) exist but none are completed.",
            severity="MEDIUM",
            category="Assessment Gap",
            control_ids=[],
            remediation="Complete in-progress assessments. Document findings and results.",
        )


def _check_calendar_overdue(
    db: Session, system: System, framework_id: str, org_id: int, fb: _FindingBuilder,
) -> None:
    today = _today()
    overdue_events = (
        db.query(CalendarEvent)
        .filter(
            CalendarEvent.organization_id == org_id,
            CalendarEvent.framework_id == framework_id,
            CalendarEvent.event_date < today,
        )
        .all()
    )

    deadlines = [e for e in overdue_events if (e.event_type or "").upper() == "DEADLINE"]
    reviews = [e for e in overdue_events if (e.event_type or "").upper() == "REVIEW"]

    if deadlines:
        fb.add(
            title=f"{len(deadlines)} deadline(s) past due",
            description=(
                f"Overdue deadlines: {', '.join(f'{e.title} (due {e.event_date})' for e in deadlines[:5])}."
            ),
            severity="HIGH" if len(deadlines) > 2 else "MEDIUM",
            category="Deadline Management",
            control_ids=[],
            affected_entities=[{"type": "calendar", "id": e.id, "name": e.title} for e in deadlines],
            remediation="Address overdue deadlines immediately. Update timelines or close completed items.",
        )

    if reviews:
        fb.add(
            title=f"{len(reviews)} scheduled review(s) overdue",
            description=(
                f"Overdue reviews: {', '.join(f'{e.title} (due {e.event_date})' for e in reviews[:5])}."
            ),
            severity="LOW",
            category="Deadline Management",
            control_ids=[],
            affected_entities=[{"type": "calendar", "id": e.id, "name": e.title} for e in reviews],
            remediation="Schedule and complete overdue reviews.",
        )


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

def _build_attack_chains(
    findings: list[dict[str, Any]], org_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)

    evidence_findings = by_cat.get("Evidence Gap", []) + by_cat.get("Evidence Freshness", [])
    doc_findings = by_cat.get("Documentation Gap", [])
    if evidence_findings and doc_findings:
        ids = [f["id"] for f in evidence_findings[:3]] + [f["id"] for f in doc_findings[:3]]
        chains.append({
            "id": "AC-001",
            "title": "Audit Failure Risk",
            "severity": "HIGH",
            "description": (
                "Missing or expired evidence combined with weak control narratives will result in "
                "assessment findings. Assessors cannot verify controls are implemented."
            ),
            "finding_ids": ids,
            "impact": "Non-compliance determination. Assessment failure even if controls are technically in place.",
        })

    impl_findings = by_cat.get("Implementation Gap", []) + by_cat.get("Assessment Finding", [])
    finding_mgmt = by_cat.get("Finding Management", [])
    if impl_findings and finding_mgmt:
        ids = [f["id"] for f in impl_findings[:3]] + [f["id"] for f in finding_mgmt[:3]]
        chains.append({
            "id": "AC-002",
            "title": "Unmanaged Compliance Debt",
            "severity": "HIGH",
            "description": (
                "Control implementation gaps combined with overdue or unplanned findings create "
                "accumulating compliance debt. Known weaknesses persist without remediation."
            ),
            "finding_ids": ids,
            "impact": "Growing risk exposure. Regulatory penalties or certification loss.",
        })

    assessment_findings = by_cat.get("Assessment Gap", [])
    deadline_findings = by_cat.get("Deadline Management", [])
    if assessment_findings and deadline_findings:
        ids = [f["id"] for f in assessment_findings] + [f["id"] for f in deadline_findings[:3]]
        chains.append({
            "id": "AC-003",
            "title": "Assessment Program Failure",
            "severity": "CRITICAL",
            "description": (
                "No completed assessments combined with overdue deadlines indicates a broken "
                "compliance program. The organization cannot demonstrate due diligence."
            ),
            "finding_ids": ids,
            "impact": "Certification denial. Regulatory action. Loss of customer trust.",
        })

    # Combined estimate per chain: same probable-loss model + revenue cap as
    # the report total (never a straight sum, never above the report).
    for chain in chains:
        chain.update(chain_exposure(chain["finding_ids"], findings, org_context))
    return chains


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_system(
    db: Session, system_id: int, framework_id: str,
    organization_id: int, run_by: str,
) -> dict[str, Any]:
    system = db.query(System).filter(
        System.id == system_id,
        System.organization_id == organization_id,
    ).first()
    if not system:
        raise ValueError(f"System {system_id} not found")

    org = db.query(Organization).filter(Organization.id == organization_id).first()
    org_context = (org.settings or {}).get("risk_context", {}) if org else {}

    total_controls = db.query(Control).filter(Control.framework_id == framework_id).count()

    impls = db.query(ControlImplementation).filter(
        ControlImplementation.system_id == system_id,
        ControlImplementation.framework_id == framework_id,
    ).all()

    evidence = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.system_id == system_id,
    ).all()

    fb = _FindingBuilder()

    _check_evidence_coverage(db, system, framework_id, impls, evidence, fb)
    _check_evidence_freshness(db, system, framework_id, evidence, fb)
    _check_control_narratives(db, system, impls, fb)
    _check_implementation_gaps(db, system, framework_id, impls, total_controls, fb)
    _check_findings_management(db, system, framework_id, fb)
    _check_assessment_coverage(db, system, framework_id, fb)
    _check_calendar_overdue(db, system, framework_id, organization_id, fb)

    findings = fb.findings
    findings.sort(key=lambda f: _SEV_RANK.get(f["severity"], 0), reverse=True)

    enriched = quantify_findings(findings, framework_id, org_context)

    attack_chains = _build_attack_chains(enriched, org_context)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in enriched:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    totals = compute_report_totals(enriched, org_context)

    parts = [f"{v} {k}" for k, v in counts.items() if v]
    exposure_str = ""
    if totals["total_exposure_high"] > 0:
        exposure_str = f" Estimated total exposure: ${totals['total_exposure_low']:,}–${totals['total_exposure_high']:,}."
    summary = (
        f"Compliance red team analysis of {system.name} ({system.acronym or system_id}) "
        f"against {framework_id} identified {len(enriched)} finding(s) "
        f"({', '.join(parts)}) and {len(attack_chains)} attack chain(s).{exposure_str}"
    )

    return {
        "system_id": system_id,
        "framework_id": framework_id,
        "organization_id": organization_id,
        "run_by": run_by,
        "summary": summary,
        "total_findings": len(enriched),
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "findings": enriched,
        "attack_chains": attack_chains,
        "total_exposure_low": totals["total_exposure_low"],
        "total_exposure_high": totals["total_exposure_high"],
        "top5_reduction_low": totals["top5_reduction_low"],
        "top5_reduction_high": totals["top5_reduction_high"],
        "quick_win_count": totals["quick_win_count"],
        "has_org_context": totals["has_org_context"],
    }
