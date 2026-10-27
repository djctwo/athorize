from datetime import UTC, datetime
from sqlalchemy import (
    Column, Integer, String, Text, Date, JSON,
    ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from database import Base, UTCDateTime


class IcsAdvisory(Base):
    __tablename__ = "ics_advisories"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    advisory_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    summary = Column(Text)
    severity = Column(String, index=True)
    cvss_score = Column(String)
    cve_ids = Column(JSON, default=list)
    affected_vendor = Column(String, index=True)
    affected_product = Column(String, index=True)
    affected_firmware_range = Column(String)
    recommended_mitigations = Column(Text)
    published_date = Column(Date)
    source = Column(String, default="MOCK")
    source_url = Column(String)
    # Inferred SP 800-53 control obligations (hub framework — the crosswalk
    # fans these out to every active framework)
    related_controls = Column(JSON, default=list)
    status = Column(String, default="NEW", index=True)
    triaged_by = Column(String)
    triaged_at = Column(UTCDateTime)
    notes = Column(Text)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        UTCDateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "advisory_id", name="uq_org_advisory"),
    )

    matches = relationship(
        "IcsAdvisoryMatch",
        back_populates="advisory",
        cascade="all, delete-orphan",
    )


class IcsAdvisoryMatch(Base):
    __tablename__ = "ics_advisory_matches"
    __table_args__ = (
        UniqueConstraint("advisory_id", "ot_asset_id", name="uq_advisory_asset"),
        UniqueConstraint("advisory_id", "it_asset_id", name="uq_advisory_it_asset"),
    )

    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(
        Integer, ForeignKey("ics_advisories.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # Exactly one of ot_asset_id / it_asset_id is set per match row
    ot_asset_id = Column(
        Integer, ForeignKey("ot_assets.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    it_asset_id = Column(
        Integer, ForeignKey("it_assets.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )
    system_id = Column(
        Integer, ForeignKey("systems.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    confidence = Column(String, nullable=False)
    dismissed = Column(Integer, default=0)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(UTC), nullable=False)

    advisory = relationship("IcsAdvisory", back_populates="matches")
    ot_asset = relationship("OTAsset")
    it_asset = relationship("ITAsset")
