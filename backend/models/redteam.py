from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base, UTCDateTime


class RedTeamReport(Base):
    __tablename__ = "redteam_reports"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    framework_id = Column(String, nullable=False)
    run_by = Column(String, nullable=False)
    summary = Column(Text)
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    total_exposure_low = Column(Integer, nullable=False, default=0)
    total_exposure_high = Column(Integer, nullable=False, default=0)
    top5_reduction_low = Column(Integer, nullable=False, default=0)
    top5_reduction_high = Column(Integer, nullable=False, default=0)
    quick_win_count = Column(Integer, nullable=False, default=0)
    has_org_context = Column(Integer, nullable=False, default=0)
    findings = Column(JSON, nullable=False, default=list)
    attack_chains = Column(JSON, nullable=False, default=list)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    system = relationship("System")
