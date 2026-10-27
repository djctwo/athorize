from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, JSON, ForeignKey
from database import Base, UTCDateTime


class SavedView(Base):
    """A user's named filter set for a list page (findings, evidence, risks…).

    Server-side because the app forbids localStorage; views follow the user
    across browsers and survive reinstalls with the database.
    """
    __tablename__ = "saved_views"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    page = Column(String, nullable=False)   # e.g. "findings"
    name = Column(String, nullable=False)
    params = Column(JSON, default=dict)     # the page's filter state, verbatim
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
