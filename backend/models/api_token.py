from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, ForeignKey
from database import Base, UTCDateTime


class ApiToken(Base):
    """A long-lived bearer token for programmatic API access.

    The raw token is shown exactly once at creation; only its SHA-256 hash is
    stored. A request authenticates by sending `Authorization: Bearer <token>`.
    The token acts as its creating user (inherits that user's role/scoping) and
    is exempt from CSRF (there is no cookie/session to forge against).
    """
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    token_prefix = Column(String, nullable=False, index=True)  # e.g. "athu_a1b2c3d4" for display
    token_hash = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(UTCDateTime)
    expires_at = Column(UTCDateTime)   # nullable → never expires
    revoked_at = Column(UTCDateTime)   # nullable → active
