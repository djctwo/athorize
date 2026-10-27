from datetime import UTC, datetime
from sqlalchemy import Column, Integer, String, Text, Date, ForeignKey
from sqlalchemy.orm import relationship
from database import Base, UTCDateTime


class RiskRegisterEntry(Base):
    __tablename__ = "risk_register_entries"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    category = Column(String)
    control_id = Column(String, index=True)
    likelihood = Column(String)
    impact = Column(String)
    status = Column(String)
    treatment = Column(String)
    mitigation = Column(Text)
    residual_risk = Column(String)
    owner_name = Column(String)
    owner_email = Column(String)
    review_date = Column(Date)
    template_key = Column(String)
    linked_finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), index=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False)

    system = relationship("System")
