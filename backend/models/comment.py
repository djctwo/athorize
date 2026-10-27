from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, JSON, ForeignKey, Index
from database import Base, UTCDateTime


class Comment(Base):
    """A discussion note on a finding or control implementation.

    Comments form a flat thread per entity (ordered by created_at). @mentions
    are parsed from the body at create time and stored as user ids so mentioned
    teammates can be emailed (when SMTP is configured) without re-parsing.
    """
    __tablename__ = "comments"
    __table_args__ = (
        Index("ix_comments_entity", "entity_type", "entity_id"),
    )

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String, nullable=False)  # 'finding' | 'control_implementation'
    entity_id = Column(Integer, nullable=False)
    # SET NULL (not CASCADE): a departed author's comments stay in the thread.
    author_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    body = Column(Text, nullable=False)
    mentions = Column(JSON, default=list)  # user ids @mentioned in the body
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    extra_data = Column(JSON, default=dict)
