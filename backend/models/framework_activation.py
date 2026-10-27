from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, UniqueConstraint
from database import Base, UTCDateTime


class FrameworkActivation(Base):
    __tablename__ = "framework_activations"
    __table_args__ = (UniqueConstraint("organization_id", "framework_id"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String, nullable=False)
    license_key = Column(String)
    activated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(UTCDateTime)
    catalog_version = Column(String)
    is_active = Column(Boolean, default=True)
    activated_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
