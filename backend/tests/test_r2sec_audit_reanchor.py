"""R2SEC: deleting the newest entries AND the anchor row is healed (hidden) by the next write."""
from sqlalchemy import text
from tests.test_audit_chain import _rec, _verify


def test_truncation_plus_anchor_delete_stays_detected_after_next_write(auth_client, db):
    client, seeded, _ = auth_client
    org = seeded["org"].id
    entries = _rec(db, org, 6)
    assert _verify(client)["valid"] is True
    # DB-level tamper: drop the 3 newest entries and the anchor row (no key needed)
    db.execute(text("DELETE FROM audit_entries WHERE id >= :i"), {"i": entries[3].id})
    db.execute(text("DELETE FROM audit_chain_heads"))
    db.commit()
    assert _verify(client)["valid"] is False          # detected now...
    _rec(db, org, 1)                                  # ...until any ordinary app write
    r = _verify(client)
    assert r["valid"] is False, r


def test_forged_anchor_is_not_laundered_by_next_write(auth_client, db):
    client, seeded, _ = auth_client
    org = seeded["org"].id
    entries = _rec(db, org, 6)
    keep = entries[2]
    db.execute(text("DELETE FROM audit_entries WHERE id > :i"), {"i": keep.id})
    n = db.execute(text("SELECT count(*) FROM audit_entries WHERE organization_id=:o"), {"o": org}).scalar()
    db.execute(text("UPDATE audit_chain_heads SET entry_count=:n, last_entry_id=:i, last_hash=:h"),
               {"n": n, "i": keep.id, "h": keep.integrity_hash})   # head_mac now wrong
    db.commit()
    assert _verify(client)["valid"] is False
    _rec(db, org, 1)
    r = _verify(client)
    assert r["valid"] is False, r


def test_full_history_rewrite_with_public_key_is_not_laundered(auth_client, db):
    """Rewrite every entry as a v1 entry signed with the PUBLIC legacy key, widen
    the (MAC'd) legacy boundary; the next app write re-signs the anchor."""
    import hashlib, hmac
    client, seeded, _ = auth_client
    org = seeded["org"].id
    _rec(db, org, 4)
    rows = db.execute(text("SELECT id, timestamp FROM audit_entries WHERE organization_id=:o ORDER BY id"),
                      {"o": org}).fetchall()
    prev = "0" * 64
    for rid, ts in rows:
        ts = str(ts)
        h = hmac.new(b"audit-chain-default-key", f"{prev}|{ts}|someone-else|VIEW|finding|1".encode(),
                     hashlib.sha256).hexdigest()
        db.execute(text("UPDATE audit_entries SET hash_version=NULL, actor_username='someone-else', action='VIEW',"
                        " entity_type='finding', entity_id=1, summary='rewritten', integrity_hash=:h WHERE id=:i"),
                   {"h": h, "i": rid})
        prev = h
    db.execute(text("UPDATE audit_chain_heads SET legacy_boundary_id=:b, last_hash=:h"), {"b": rows[-1][0], "h": prev})
    db.commit()
    assert _verify(client)["valid"] is False
    _rec(db, org, 1)
    r = _verify(client)
    assert r["valid"] is False, r


def test_break_stays_reported_after_many_writes_and_new_entries_are_still_protected(auth_client, db):
    client, seeded, _ = auth_client
    org = seeded["org"].id
    entries = _rec(db, org, 5)
    db.execute(text("DELETE FROM audit_entries WHERE id >= :i"), {"i": entries[3].id})
    db.execute(text("DELETE FROM audit_chain_heads"))
    db.commit()
    new = _rec(db, org, 3)
    r = _verify(client)
    assert r["valid"] is False and r["broken_at_id"] == new[0].id, r
    # the re-signed anchor still protects what was written after the rebuild
    db.execute(text("DELETE FROM audit_entries WHERE id = :i"), {"i": new[-1].id})
    db.commit()
    assert "entries deleted" in _verify(client)["reason"]
    # and the rebuild marker itself can't be stripped without the key
    db.execute(text("UPDATE audit_chain_heads SET rebuilt_at_id = NULL"))
    db.commit()
    assert "altered" in _verify(client)["reason"]


def test_upgrade_adds_the_rebuild_marker_column(tmp_path):
    import sqlalchemy as sa
    from database import Base
    from services.audit import upgrade_legacy_schema
    eng = sa.create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(eng)
    with eng.begin() as c:
        c.execute(sa.text("ALTER TABLE audit_chain_heads DROP COLUMN rebuilt_at_id"))
    upgrade_legacy_schema(eng)
    assert "rebuilt_at_id" in {c["name"] for c in sa.inspect(eng).get_columns("audit_chain_heads")}
    eng.dispose()
