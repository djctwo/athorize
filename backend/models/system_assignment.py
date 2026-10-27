from sqlalchemy import Column, Integer, ForeignKey, UniqueConstraint
from database import Base


class SystemAssignment(Base):
    __tablename__ = "system_assignments"
    __table_args__ = (
        UniqueConstraint("user_id", "system_id", name="uq_user_system"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
