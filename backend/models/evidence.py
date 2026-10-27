from datetime import datetime, date, timezone
from sqlalchemy import Column, Integer, String, Text, Date, JSON, ForeignKey
from database import Base, UTCDateTime


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)
    description = Column(Text)
    artifact_type = Column(String, default="OTHER")
    control_ids = Column(JSON, default=list)
    framework_ids = Column(JSON, default=list)
    date_collected = Column(Date)
    expiration_date = Column(Date)
    expiration_days = Column(Integer)
    uploaded_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    # Who is responsible for keeping this artifact fresh (refresh workflow /
    # "My Work" / expiry reminders). Distinct from uploaded_by (historical fact).
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    file_path = Column(String)
    file_hash = Column(String)
    notes = Column(Text)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
