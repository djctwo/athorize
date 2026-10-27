"""Audit chain v2: every field covered, truncation detected, legacy entries only
inside the anchored legacy prefix, appends serialized (SECCODE-16,
INTEGRITY-9/10, review item "legacy key accepted for ANY entry")."""
from __future__ import annotations

import hashlib
import hmac
import threading

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from models import AuditEntry
from services import audit as audit_svc


def _rec(db, org_id, n=1, **kw):
    out = []
    for i in range(n):
        out.append(audit_svc.record(db, organization_id=org_id, actor_id=None, actor_username="admin",
                                    action="UPDATE", entity_type="finding", entity_id=i,
                                    summary=kw.get("summary", f"change {i}"), system_id=kw.get("system_id")))
    db.commit()
    return out


def _verify(client):
    return client.get("/api/audit/verify").json()


def _legacy_insert(db, org_id, n, key=b"audit-chain-default-key", start_prev=None):
    """Write v1 rows exactly as the pre-2026-10 code did (hash_version NULL)."""
    prev = start_prev or db.execute(text(
        "SELECT integrity_hash FROM audit_entries WHERE organization_id=:o ORDER BY id DESC LIMIT 1"),
        {"o": org_id}).scalar() or "0" * 64
    for i in range(n):
        ts = f"2026-06-0{i + 1} 10:00:00"
        h = hmac.new(key, f"{prev}|{ts}|old|LEGACY|finding|{i}".encode(), hashlib.sha256).hexdigest()
        db.execute(text("INSERT INTO audit_entries (organization_id, actor_username, action, entity_type,"
                        " entity_id, summary, timestamp, integrity_hash) VALUES"
                        " (:o, 'old', 'LEGACY', 'finding', :e, 's', :ts, :h)"),
                   {"o": org_id, "e": i, "ts": ts, "h": h})
        prev = h
    db.commit()


class TestCoverage:
    @pytest.mark.parametrize("column,value", [("summary", "'viewed'"), ("system_id", "999"),
                                              ("organization_id", "organization_id"), ("actor_username", "'x'")])
    def test_edit_of_any_content_field_breaks_verify(self, auth_client, db, column, value):
        client, seeded, _ = auth_client
        e = _rec(db, seeded["org"].id, 3, system_id=1)[1]
        assert _verify(client)["valid"] is True
        if column == "organization_id":
            # moving an entry into another org's chain removes it from this one
            db.execute(text("UPDATE audit_entries SET organization_id = organization_id + 100 WHERE id=:i"), {"i": e.id})
        else:
            db.execute(text(f"UPDATE audit_entries SET {column} = {value} WHERE id=:i"), {"i": e.id})
        db.commit()
        assert _verify(client)["valid"] is False

    def test_truncating_newest_entries_is_detected(self, auth_client, db):
        client, seeded, _ = auth_client
        entries = _rec(db, seeded["org"].id, 4)
        assert _verify(client)["valid"] is True
        db.execute(text("DELETE FROM audit_entries WHERE id >= :i"), {"i": entries[-2].id})
        db.commit()
        r = _verify(client)
        assert r["valid"] is False and "truncated" in r["reason"]

    def test_deleting_the_anchor_is_detected(self, auth_client, db):
        client, seeded, _ = auth_client
        _rec(db, seeded["org"].id, 2)
        db.execute(text("DELETE FROM audit_chain_heads"))
        db.commit()
        r = _verify(client)
        assert r["valid"] is False and "anchor" in r["reason"]

    def test_forged_anchor_is_detected(self, auth_client, db):
        client, seeded, _ = auth_client
        entries = _rec(db, seeded["org"].id, 3)
        db.execute(text("DELETE FROM audit_entries WHERE id=:i"), {"i": entries[-1].id})
        db.execute(text("UPDATE audit_chain_heads SET entry_count=entry_count-1, last_entry_id=:i, last_hash=:h"),
                   {"i": entries[-2].id, "h": entries[-2].integrity_hash})
        db.commit()
        assert _verify(client)["valid"] is False

    def test_downgrade_to_v1_is_detected(self, auth_client, db):
        client, seeded, _ = auth_client
        e = _rec(db, seeded["org"].id, 2)[0]
        db.execute(text("UPDATE audit_entries SET hash_version=NULL WHERE id=:i"), {"i": e.id})
        db.commit()
        assert _verify(client)["valid"] is False


class TestLegacyPrefix:
    def test_upgraded_legacy_chain_verifies_and_is_flagged_unauthenticated(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"].id
        db.execute(text("DELETE FROM audit_entries"))   # login entry from the fixture
        db.execute(text("DELETE FROM audit_chain_heads"))
        db.commit()
        _legacy_insert(db, org, 3)
        assert audit_svc.anchor_legacy_chains(db) == 1   # the upgrade step
        db.commit()
        _rec(db, org, 2)                                 # new entries after upgrade are v2
        r = _verify(client)
        assert r["valid"] is True
        assert r["legacy_entries"] == 3 and r["unauthenticated_legacy_entries"] == 3
        assert "public default key" in r["reason"]

    def test_legacy_signed_entry_after_the_boundary_fails(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"].id
        db.execute(text("DELETE FROM audit_entries"))
        db.execute(text("DELETE FROM audit_chain_heads"))
        db.commit()
        _legacy_insert(db, org, 2)
        audit_svc.anchor_legacy_chains(db)
        db.commit()
        # Attacker forges a v1 entry with the PUBLIC key and fixes up the
        # (unforgeable) anchor fields as best they can.
        _legacy_insert(db, org, 1)
        r = _verify(client)
        assert r["valid"] is False

    def test_new_chain_never_accepts_legacy_key_entries(self, auth_client, db):
        client, seeded, _ = auth_client
        db.execute(text("DELETE FROM audit_entries"))
        db.execute(text("DELETE FROM audit_chain_heads"))
        db.commit()
        _legacy_insert(db, seeded["org"].id, 1)
        _rec(db, seeded["org"].id, 1)   # re-anchors (warning) with NO legacy boundary
        r = _verify(client)
        assert r["valid"] is False and r["broken_at_id"] is not None


def _engine(path):
    from database import Base
    eng = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _pragmas(conn, _rec):
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()

    Base.metadata.create_all(eng)
    return eng


def test_many_concurrent_writers_never_fork_the_chain(tmp_path):
    """INTEGRITY-9 under load: 8 threads x 25 appends, each its own session and
    each doing a read first (like a request handler) before recording."""
    eng = _engine(tmp_path / "race.db")
    Session = sessionmaker(bind=eng, autoflush=False, autocommit=False)
    errors = []
    barrier = threading.Barrier(8)

    def worker(n):
        barrier.wait()
        for i in range(25):
            s = Session()
            try:
                s.query(AuditEntry).count()
                audit_svc.record(s, organization_id=1, actor_id=None, actor_username=f"w{n}",
                                 action="UPDATE", entity_type="finding", entity_id=i)
                s.commit()
            except Exception as e:  # pragma: no cover - diagnostic
                errors.append(repr(e))
                s.rollback()
            finally:
                s.close()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    s = Session()
    try:
        # Recompute links directly (works on the pre-fix code too = the red run).
        prev, forks = "0" * 64, []
        rows = s.query(AuditEntry).filter(AuditEntry.organization_id == 1).order_by(AuditEntry.id).all()
        for e in rows:
            if e.integrity_hash != audit_svc.compute_hash(prev, e):
                forks.append(e.id)
            prev = e.integrity_hash
        verified = audit_svc.verify(s, 1) if hasattr(audit_svc, "verify") else None
    finally:
        s.close()
        eng.dispose()
    assert not errors, errors[:3]
    assert len(rows) == 200
    assert not forks, f"{len(forks)} of 200 entries do not chain to their predecessor: {forks[:10]}"
    assert verified["valid"] is True, verified


def test_upgrade_step_on_a_pre_v2_database(tmp_path):
    """The step main.py runs at startup (and a restore of an old backup must
    run): adds the column, anchors legacy chains once, then is a no-op."""
    import gzip
    from pathlib import Path
    from sqlalchemy.orm import Session
    src = Path(__file__).resolve().parent / "hunts" / "fixtures" / "athorize-2026-06-13-schema.db.gz"
    db_path = tmp_path / "old.db"
    db_path.write_bytes(gzip.decompress(src.read_bytes()))
    eng = create_engine(f"sqlite:///{db_path}")
    try:
        n = audit_svc.upgrade_legacy_schema(eng)
        assert n and n >= 1
        assert audit_svc.upgrade_legacy_schema(eng) is None
        with Session(bind=eng) as s:
            org = s.query(AuditEntry.organization_id).first()[0]
            r = audit_svc.verify(s, org)
        assert r["valid"] is True and r["legacy_entries"] > 0, r
    finally:
        eng.dispose()
