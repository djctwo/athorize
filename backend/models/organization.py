from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, JSON
from database import Base, UTCDateTime


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, nullable=False, index=True)
    settings = Column(JSON, default=dict)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
