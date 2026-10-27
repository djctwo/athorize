from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base, UTCDateTime


class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id = Column(Integer, primary_key=True)
    timestamp = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), index=True)
    # Deliberately no FK: audit entries must survive org deletion
    organization_id = Column(Integer, nullable=False, index=True)
    actor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    actor_username = Column(String)
    action = Column(String, nullable=False)
    entity_type = Column(String)
    entity_id = Column(Integer)
    system_id = Column(Integer)
    summary = Column(String)
    integrity_hash = Column(String)
    # Hash scheme: NULL/1 = legacy (prev|ts|actor|action|entity only),
    # 2 = every content field (services/audit.compute_hash).
    hash_version = Column(Integer)


class AuditChainHead(Base):
    """Per-organization anchor of the audit chain: entry count + newest hash,
    HMAC'd with the audit key. Detects deletion of the newest entries
    (truncation), which a hash chain alone cannot. Updated in the same
    transaction as every append (services/audit.record)."""
    __tablename__ = "audit_chain_heads"

    organization_id = Column(Integer, primary_key=True)
    entry_count = Column(Integer, nullable=False, default=0)
    last_entry_id = Column(Integer)
    last_hash = Column(String)
    head_mac = Column(String)
    # Highest id of the legacy (v1) prefix that existed when the chain was
    # anchored at upgrade. v1 entries are accepted only up to here; NULL = none.
    legacy_boundary_id = Column(Integer)
    # Set (and covered by head_mac) when an append found the anchor missing or
    # not matching the log: the id of the first entry chained after that. The
    # anchor is re-signed so new entries stay protected, but verify() keeps
    # reporting the chain as broken at this point forever — a later write can
    # never launder truncation or a rewrite (R2SEC-11). NULL = never rebuilt.
    rebuilt_at_id = Column(Integer)
