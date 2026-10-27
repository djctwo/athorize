from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Date, Boolean, ForeignKey
from database import Base, UTCDateTime


class ConMonEntry(Base):
    __tablename__ = "conmon_entries"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    framework_id = Column(String, index=True)
    entry_date = Column(Date, nullable=False, index=True)
    activity_type = Column(String, nullable=False, index=True)
    description = Column(Text)
    performed_by = Column(String)
    findings = Column(Text)
    actions_taken = Column(Text)
    follow_up_required = Column(Boolean, default=False)
    follow_up_date = Column(Date)
    evidence_artifact_id = Column(Integer, ForeignKey("evidence_artifacts.id", ondelete="SET NULL"))
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
