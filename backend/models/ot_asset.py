from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Date, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base, UTCDateTime


class OTAsset(Base):
    __tablename__ = "ot_assets"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_name = Column(String, nullable=False)
    asset_type = Column(String)
    vendor = Column(String)
    model = Column(String)
    firmware_version = Column(String)
    ip_address = Column(String)
    mac_address = Column(String)
    purdue_level = Column(String)
    protocols = Column(JSON, default=list)
    network_zone = Column(String)
    patch_status = Column(String)
    patch_notes = Column(Text)
    last_firmware_review = Column(Date)
    stig_applicable = Column(Boolean, default=False)
    stig_id = Column(String)
    stig_compliance_status = Column(String)
    connected_to = Column(JSON, default=list)
    notes = Column(Text)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    system = relationship("System")
