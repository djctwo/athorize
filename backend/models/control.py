from sqlalchemy import Column, String, Text, JSON
from database import Base


class Control(Base):
    __tablename__ = "controls"

    framework_id = Column(String, primary_key=True)
    control_id = Column(String, primary_key=True)
    family = Column(String, index=True)
    family_name = Column(String)
    title = Column(String)
    description = Column(Text)
    supplemental_guidance = Column(Text)
    baselines = Column(JSON, default=list)
    parent_id = Column(String)
    related_controls = Column(JSON, default=list)
    typical_evidence = Column(JSON, default=list)
    assessment_objectives = Column(JSON, default=list)
    external_references = Column(JSON, default=list)
