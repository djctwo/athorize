from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, JSON, Boolean, ForeignKey
from database import Base, UTCDateTime


class System(Base):
    __tablename__ = "systems"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    acronym = Column(String)
    description = Column(Text)
    system_type = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    environment = Column(String, default="production")
    criticality = Column(String, default="moderate")
    impact_level = Column(String, default="MODERATE")
    authorization_status = Column(String, default="NOT_AUTHORIZED")
    is_ot_enabled = Column(Boolean, default=False)
    extra_data = Column(JSON, default=dict)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
