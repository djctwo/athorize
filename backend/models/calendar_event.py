from datetime import datetime, date, timezone
from sqlalchemy import Column, Integer, String, Text, Date, ForeignKey
from database import Base, UTCDateTime


class CalendarEvent(Base):
    __tablename__ = "calendar_events"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="SET NULL"))
    framework_id = Column(String)
    event_type = Column(String, default="CUSTOM")
    title = Column(String, nullable=False)
    description = Column(Text)
    event_date = Column(Date, nullable=False)
    recurring = Column(String)
    related_entity_type = Column(String)
    related_entity_id = Column(Integer)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
