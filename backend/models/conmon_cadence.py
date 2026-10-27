from sqlalchemy import Column, Integer, String, Boolean, UniqueConstraint
from database import Base


class ConMonCadence(Base):
    """Org-level override of a continuous-monitoring cadence requirement.

    framework_id = "" means an org-wide cadence (applies regardless of
    framework). A row here overrides the code/metadata default for that
    (framework, activity_type) pair. `interval_days` is the required cadence;
    `enabled=False` suppresses the requirement entirely.
    """
    __tablename__ = "conmon_cadences"
    __table_args__ = (
        UniqueConstraint("organization_id", "framework_id", "activity_type",
                         name="ux_cadence_org_fw_activity"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, nullable=False, index=True)
    framework_id = Column(String, nullable=False, default="")
    activity_type = Column(String, nullable=False)
    interval_days = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
