from dataclasses import dataclass
from datetime import date
from sqlalchemy.orm import Session
from models.control import Control
from models.control_implementation import ControlImplementation
from models.finding import Finding
from services.metrics import NOT_APPLICABLE, SATISFIED_STATUSES, finding_counts


@dataclass
class ComplianceScore:
    framework_id: str
    total_controls: int
    implemented: int
    partially_implemented: int
    not_implemented: int
    not_applicable: int
    score_percentage: float
    open_findings: int
    critical_findings: int
    overdue_findings: int = 0
    # Catalog controls with any status other than Not Assessed: 0 means nobody
    # has started this system x framework pair (the Dashboard chart hides it).
    assessed: int = 0


def score_system(system_id: int, framework_id: str, db: Session, today: date | None = None) -> ComplianceScore:
    """The compliance score for one system x framework (definition in
    services/metrics.py). Only implementation rows whose control exists in the
    framework catalog are counted, so orphaned rows (a control dropped or
    renamed by a catalog update, a custom-framework edit, or a PUT for an
    unknown id) can never push the score above 100%."""
    total = db.query(Control).filter(Control.framework_id == framework_id).count()
    if total == 0:
        return ComplianceScore(
            framework_id=framework_id, total_controls=0,
            implemented=0, partially_implemented=0, not_implemented=0,
            not_applicable=0, score_percentage=0.0,
            open_findings=0, critical_findings=0, overdue_findings=0,
        )

    impls = (
        db.query(ControlImplementation.implementation_status)
        .join(Control, (Control.framework_id == ControlImplementation.framework_id)
              & (Control.control_id == ControlImplementation.control_id))
        .filter(
            ControlImplementation.system_id == system_id,
            ControlImplementation.framework_id == framework_id,
        )
        .all()
    )
    statuses = [s for (s,) in impls]

    partial = statuses.count("PARTIALLY")
    na = statuses.count(NOT_APPLICABLE)
    satisfied = sum(1 for st in statuses if st in SATISFIED_STATUSES)

    assessable = total - na
    score = (satisfied / assessable * 100) if assessable > 0 else 0.0

    counts = finding_counts(db.query(Finding).filter(
        Finding.system_id == system_id,
        Finding.framework_id == framework_id,
    ), today)

    return ComplianceScore(
        framework_id=framework_id,
        total_controls=total,
        implemented=satisfied,
        partially_implemented=partial,
        not_implemented=max(0, assessable - satisfied - partial),
        not_applicable=na,
        score_percentage=round(score, 1),
        open_findings=counts["open"],
        critical_findings=counts["critical"],
        overdue_findings=counts["overdue"],
        assessed=sum(1 for st in statuses if st != "NOT_ASSESSED"),
    )
