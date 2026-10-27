from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, JSON, ForeignKey
from database import Base, UTCDateTime

# Canonical assessment statuses: the values the Assessments API and UI write.
# Compare against these constants, never a hand-typed string ("COMPLETED" once
# made Red Team ignore every completed assessment).
ASSESSMENT_PLANNED = "PLANNED"
ASSESSMENT_IN_PROGRESS = "IN_PROGRESS"
ASSESSMENT_COMPLETE = "COMPLETE"
ASSESSMENT_STATUSES = (ASSESSMENT_PLANNED, ASSESSMENT_IN_PROGRESS, ASSESSMENT_COMPLETE)


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String, nullable=False)
    assessment_type = Column(String, nullable=False)
    assessor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    status = Column(String, default=ASSESSMENT_PLANNED)
    started_at = Column(UTCDateTime)
    completed_at = Column(UTCDateTime)
    item_states = Column(JSON, default=dict)
    notes = Column(Text)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
