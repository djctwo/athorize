from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, ForeignKey
from database import Base, UTCDateTime


class UserSession(Base):
    __tablename__ = "user_sessions"

    # SHA-256 of the cookie token (services/sessions.py) — never the raw value.
    id = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(UTCDateTime, nullable=False)
    last_activity = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = Column(String)
    csrf_token = Column(String)
    # Operator org-switch: the company an operator is currently viewing. NULL =
    # the user's home organization. Only honored for is_operator users
    # (dependencies.get_current_user). SET NULL so deleting an org reverts any
    # session pointing at it to its home org.
    active_organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
