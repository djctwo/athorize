from datetime import datetime, date, timezone
from sqlalchemy import Column, Integer, String, Text, Date, JSON, ForeignKey
from database import Base, UTCDateTime


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String, nullable=False, index=True)
    control_id = Column(String)
    title = Column(String, nullable=False)
    description = Column(Text)
    weakness_description = Column(Text)
    severity = Column(String, nullable=False, default="MEDIUM")
    status = Column(String, nullable=False, default="OPEN")
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    owner_name = Column(String)
    owner_email = Column(String)
    due_date = Column(Date)
    scheduled_completion = Column(Date)
    actual_completion = Column(Date)
    closed_date = Column(Date)
    remediation_plan = Column(Text)
    risk_rationale = Column(Text)
    reopen_reason = Column(String)
    milestones = Column(JSON, default=list)
    extra_data = Column(JSON, default=dict)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
