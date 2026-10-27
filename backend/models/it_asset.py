from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Date, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base, UTCDateTime


class ITAsset(Base):
    __tablename__ = "it_assets"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_name = Column(String, nullable=False)
    asset_role = Column(String)
    vendor = Column(String)
    model = Column(String)
    os_family = Column(String)
    os_version = Column(String)
    hostname = Column(String)
    ip_address = Column(String)
    mac_address = Column(String)
    environment = Column(String)
    criticality = Column(String)
    data_classification = Column(String)
    location = Column(String)
    owner_name = Column(String)
    cloud_provider = Column(String)
    patch_status = Column(String)
    patch_notes = Column(Text)
    last_patch_date = Column(Date)
    stig_applicable = Column(Boolean, default=False)
    stig_id = Column(String)
    stig_compliance_status = Column(String)
    connected_to = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    notes = Column(Text)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    system = relationship("System")
