from sqlalchemy import Column, Integer, String, Index, UniqueConstraint
from database import Base


class ControlMapping(Base):
    """One directed crosswalk edge between two framework controls.

    Loaded from each plugin's mappings.json on framework activation and
    removed on deactivation (same lifecycle as the controls table). Edges are
    stored once in the direction the plugin ships them (toward the hub,
    nist-800-53-r5); the reverse direction is derived at query time.
    """

    __tablename__ = "control_mappings"
    __table_args__ = (
        UniqueConstraint(
            "source_framework_id", "source_control_id",
            "target_framework_id", "target_control_id",
            name="ux_control_mapping_edge",
        ),
        Index("ix_control_mappings_source", "source_framework_id", "source_control_id"),
        Index("ix_control_mappings_target", "target_framework_id", "target_control_id"),
    )

    id = Column(Integer, primary_key=True)
    source_framework_id = Column(String, nullable=False)
    source_control_id = Column(String, nullable=False)
    target_framework_id = Column(String, nullable=False)
    target_control_id = Column(String, nullable=False)
    relationship = Column(String, nullable=False)  # equivalent|subset|superset|intersects|related
    confidence = Column(String, nullable=False, default="official")  # official|derived|vendor
    rationale = Column(String, default="")
