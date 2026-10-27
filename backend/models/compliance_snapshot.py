from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Date, ForeignKey, UniqueConstraint
from database import Base, UTCDateTime


class ComplianceSnapshot(Base):
    """Daily point-in-time compliance state per (org, system, framework).

    Powers the dashboard trend chart, the findings burndown, and the Audit
    Binder's progress section — proof of improvement over time, not just a
    snapshot of today. One row per day per combination (idempotent upsert).
    """
    __tablename__ = "compliance_snapshots"
    __table_args__ = (
        UniqueConstraint("organization_id", "system_id", "framework_id", "snapshot_date",
                         name="uq_snapshot_day"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String, nullable=False)
    snapshot_date = Column(Date, nullable=False, index=True)
    score_percentage = Column(Float, nullable=False, default=0.0)
    total_controls = Column(Integer, nullable=False, default=0)
    implemented = Column(Integer, nullable=False, default=0)
    open_findings = Column(Integer, nullable=False, default=0)
    critical_findings = Column(Integer, nullable=False, default=0)
    overdue_findings = Column(Integer, nullable=False, default=0)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
