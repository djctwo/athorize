"""Tamper-evident audit log: every entry is HMAC-chained to its predecessor.

The key is settings.audit_hmac_key (env ATHORIZE_AUDIT_HMAC_KEY; see config.py).

Hash schemes (AuditEntry.hash_version):
  1 / NULL  legacy: prev | timestamp | actor_username | action | entity_type | entity_id.
            Verified with the active key, or the old public default key that
            installs without a configured key used before 2026-10.
  2         every content field: prev, timestamp, organization_id, actor_username,
            action, entity_type, entity_id, system_id, summary (canonical JSON).
            actor_id is deliberately excluded: it is an FK with ON DELETE SET
            NULL, so covering it would make a legitimate user deletion look like
            tampering; actor_username (covered) names the actor.
Once an org's chain has a v2 entry, a later v1 entry is a downgrade = broken.

AuditChainHead anchors each org's chain (count + newest hash, HMAC'd), so
deleting the newest entries is detected. Appends are serialized: record()
takes the database write lock (SQLite) / an advisory lock (PostgreSQL) BEFORE
reading the chain tail, so concurrent writers can never fork the chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from config import settings
from services import safe_compare
from models.audit import AuditChainHead, AuditEntry

_logger = logging.getLogger(__name__)

CURRENT_VERSION = 2
GENESIS = "0" * 64
# Pre-2026-10 installs that never configured a key signed with this public
# value; it is only ever used to VERIFY legacy (v1) entries.
LEGACY_DEFAULT_KEY = b"audit-chain-default-key"


def _key() -> bytes:
    return settings.audit_hmac_key.encode()


def key_fingerprint(key: bytes | None = None) -> str:
    """Non-secret identifier of the audit key (e.g. for backup manifests)."""
    return hmac.new(key or _key(), b"athorize-audit-key-fingerprint", hashlib.sha256).hexdigest()[:16]


def _ts(entry: AuditEntry) -> str:
    # Canonical naive-UTC timestamp: SQLite stores DateTime without tzinfo, so an
    # aware datetime at record time would hash differently than the naive value
    # read back at verify time. Stripping tzinfo makes both sides identical.
    return entry.timestamp.replace(tzinfo=None).isoformat(sep=" ") if entry.timestamp else ""


def compute_hash(prev_hash: str, entry: AuditEntry, key: bytes | None = None) -> str:
    if (entry.hash_version or 1) >= 2:
        chain_input = json.dumps(
            [2, prev_hash, _ts(entry), entry.organization_id, entry.actor_username, entry.action,
             entry.entity_type, entry.entity_id, entry.system_id, entry.summary or ""],
            separators=(",", ":"), ensure_ascii=False,
        )
    else:
        chain_input = f"{prev_hash}|{_ts(entry)}|{entry.actor_username}|{entry.action}|{entry.entity_type}|{entry.entity_id}"
    return hmac.new(key or _key(), chain_input.encode(), hashlib.sha256).hexdigest()


def _head_mac(org_id: int, count: int, last_id: int | None, last_hash: str | None,
              legacy_boundary_id: int | None, rebuilt_at_id: int | None = None) -> str:
    fields = ["head", org_id, count, last_id, last_hash, legacy_boundary_id]
    if rebuilt_at_id is not None:  # absent from older anchors, which keep verifying
        fields.append(["rebuilt_at", rebuilt_at_id])
    msg = json.dumps(fields, separators=(",", ":"))
    return hmac.new(_key(), msg.encode(), hashlib.sha256).hexdigest()


def _head_mac_of(head: AuditChainHead) -> str:
    return _head_mac(head.organization_id, head.entry_count, head.last_entry_id, head.last_hash,
                     head.legacy_boundary_id, head.rebuilt_at_id)


def _set_head(head: AuditChainHead, count: int, last_id: int | None, last_hash: str | None) -> None:
    head.entry_count = count
    head.last_entry_id = last_id
    head.last_hash = last_hash
    head.head_mac = _head_mac_of(head)


def _anchor_problem(head: AuditChainHead | None, last: AuditEntry | None) -> str | None:
    """Why the stored anchor does not vouch for the tail an append is about
    to extend (None = it does). Cheap: no full-chain walk."""
    if head is None:
        return "missing" if last is not None else None
    if not safe_compare.equal(head.head_mac or "", _head_mac_of(head)):
        return "altered or signed with a different key"
    if last is None:
        return "pointing at entries that no longer exist" if head.entry_count else None
    if head.last_entry_id != last.id or head.last_hash != last.integrity_hash:
        return "not matching the newest entry"
    return None


def _lock_chain(db: Session, organization_id: int) -> None:
    """Serialize appends to one org's chain for the rest of this transaction."""
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        # Any write statement takes SQLite's single write lock (waiting up to
        # busy_timeout) and holds it until commit; the tail is read after this,
        # so it is the committed tail. Matches 0 rows for a brand-new org — the
        # lock is taken either way.
        db.execute(text("UPDATE audit_chain_heads SET entry_count = entry_count "
                        "WHERE organization_id = :o"), {"o": organization_id})
    elif dialect == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": 0x41554400000000 + int(organization_id)})
    else:
        db.query(AuditChainHead).filter(AuditChainHead.organization_id == organization_id).with_for_update().first()


def record(
    db: Session,
    *,
    organization_id: int,
    actor_id: int | None,
    actor_username: str,
    action: str,
    entity_type: str,
    entity_id: int | None = None,
    system_id: int | None = None,
    summary: str = "",
) -> AuditEntry:
    _lock_chain(db, organization_id)
    last = db.query(AuditEntry).filter(
        AuditEntry.organization_id == organization_id,
    ).order_by(AuditEntry.id.desc()).first()
    prev_hash = last.integrity_hash if last else GENESIS
    head = db.get(AuditChainHead, organization_id)
    problem = _anchor_problem(head, last)

    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc),
        organization_id=organization_id,
        actor_id=actor_id,
        actor_username=actor_username,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        system_id=system_id,
        summary=summary,
        hash_version=CURRENT_VERSION,
    )
    entry.integrity_hash = compute_hash(prev_hash, entry)
    db.add(entry)
    db.flush()

    if problem is None and head is not None:
        count = (head.entry_count or 0) + 1
    else:
        # A brand-new chain — or an anchor that does not vouch for the log
        # (deleted, forged, or the newest entries removed). Re-anchor over what
        # is there so NEW entries stay protected, but never bless the past:
        # rebuilt_at_id (MAC'd) keeps verify() reporting the break forever, and
        # the legacy boundary is never carried over from an untrusted anchor.
        count = db.query(AuditEntry.id).filter(AuditEntry.organization_id == organization_id).count()
        if head is None:
            head = AuditChainHead(organization_id=organization_id)
            db.add(head)
        if problem is not None:
            _logger.warning("audit chain anchor for organization %s was %s; re-anchored at entry %s and "
                            "flagged as broken. Investigate (possible tampering or an incomplete restore).",
                            organization_id, problem, entry.id)
            head.legacy_boundary_id = None
            head.rebuilt_at_id = head.rebuilt_at_id or entry.id
    _set_head(head, count, entry.id, entry.integrity_hash)
    db.flush()
    return entry


def upgrade_legacy_schema(engine) -> int | None:
    """SQLite upgrade step: if audit_entries predates hash_version, add the
    column and anchor every existing chain at its current tail. Returns the
    number of chains anchored, or None when the DB was already upgraded.
    Idempotent — safe at every startup and after a restore swaps the DB."""
    from sqlalchemy import inspect as _inspect
    AuditChainHead.__table__.create(bind=engine, checkfirst=True)
    if "rebuilt_at_id" not in {c["name"] for c in _inspect(engine).get_columns("audit_chain_heads")}:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_chain_heads ADD COLUMN rebuilt_at_id INTEGER"))
    if "hash_version" in {c["name"] for c in _inspect(engine).get_columns("audit_entries")}:
        return None
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_entries ADD COLUMN hash_version INTEGER"))
    with Session(bind=engine) as db:
        n = anchor_legacy_chains(db)
        db.commit()
    return n


def anchor_legacy_chains(db: Session) -> int:
    """Upgrade step (run once, when the hash_version column is first added):
    anchor every org's existing chain at its current tail. Returns orgs anchored."""
    n = 0
    org_ids = [o for (o,) in db.query(AuditEntry.organization_id).distinct()]
    for org_id in org_ids:
        if db.get(AuditChainHead, org_id) is not None:
            continue
        q = db.query(AuditEntry).filter(AuditEntry.organization_id == org_id)
        last = q.order_by(AuditEntry.id.desc()).first()
        head = AuditChainHead(organization_id=org_id, legacy_boundary_id=last.id)
        _set_head(head, q.count(), last.id, last.integrity_hash)
        db.add(head)
        n += 1
    db.flush()
    return n


def verify(db: Session, organization_id: int) -> dict:
    """Recompute the org's chain and check it against its anchor.

    `valid` = the chain is intact and anchored. Legacy (v1) entries are only
    accepted inside the anchored legacy prefix (id <= legacy_boundary_id), and
    the ones that verify only under the old PUBLIC default key are counted in
    `unauthenticated_legacy_entries`: they are linked into the chain (so they
    cannot be altered without breaking everything after them) but were not
    signed with a secret key.
    """
    entries = (
        db.query(AuditEntry)
        .filter(AuditEntry.organization_id == organization_id)
        .order_by(AuditEntry.id)
        .all()
    )
    head = db.get(AuditChainHead, organization_id)
    out = {"valid": True, "entries_checked": len(entries), "broken_at_id": None, "reason": None,
           "legacy_entries": 0, "unauthenticated_legacy_entries": 0}

    def broken(entry_id, reason):
        return {**out, "valid": False, "broken_at_id": entry_id, "reason": reason}

    if head is not None and not safe_compare.equal(head.head_mac or "", _head_mac_of(head)):
        return broken(None, "chain anchor was altered or signed with a different key")
    if not entries:
        if head is not None and head.entry_count:
            return broken(None, f"all {head.entry_count} entries are missing (log truncated)")
        return out
    if head is None:
        return broken(None, "chain anchor is missing")

    boundary = head.legacy_boundary_id
    prev_hash = GENESIS
    seen_v2 = False
    for entry in entries:
        if (entry.hash_version or 1) >= 2:
            seen_v2 = True
            if entry.integrity_hash != compute_hash(prev_hash, entry):
                return broken(entry.id, "entry content or link does not match its hash")
        else:
            if seen_v2:
                return broken(entry.id, "legacy-format entry after current-format entries (downgrade)")
            if boundary is None or entry.id > boundary:
                return broken(entry.id, "legacy-format entry outside the anchored legacy prefix")
            if entry.integrity_hash == compute_hash(prev_hash, entry):
                out["legacy_entries"] += 1
            elif entry.integrity_hash == compute_hash(prev_hash, entry, LEGACY_DEFAULT_KEY):
                out["legacy_entries"] += 1
                out["unauthenticated_legacy_entries"] += 1
            else:
                return broken(entry.id, "entry content or link does not match its hash")
        prev_hash = entry.integrity_hash

    last = entries[-1]
    if head.entry_count != len(entries) or head.last_entry_id != last.id or head.last_hash != last.integrity_hash:
        return broken(None, f"anchor expects {head.entry_count} entries ending at id {head.last_entry_id}; "
                            f"found {len(entries)} ending at id {last.id} (entries deleted or log truncated)")
    if head.rebuilt_at_id is not None:
        return broken(head.rebuilt_at_id,
                      "the chain anchor was missing or did not match the log when entry "
                      f"{head.rebuilt_at_id} was written (entries deleted or the anchor forged before it); "
                      "entries from there on are chained and anchored")
    if out["unauthenticated_legacy_entries"]:
        out["reason"] = (f"{out['unauthenticated_legacy_entries']} legacy entries were signed with the public "
                         "default key (before an audit key was configured); they are chained and anchored "
                         "but unauthenticated")
    return out


# Name used by the backup/restore service (one implementation).
verify_chain = verify
