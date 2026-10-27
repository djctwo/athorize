"""Every datetime the API returns must be timezone-aware UTC.

SQLite stores DateTime without tzinfo, so values used to come back naive and
were serialised as e.g. "2026-10-21T08:00:00" — which browsers parse as LOCAL
time, skewing every "2h ago" by the viewer's UTC offset. The UTCDateTime
column type (database.py) re-attaches UTC on load; these tests pin that across
the different serialisation paths (ORM rows, hand-built dicts, explicit
.isoformat() strings, Pydantic response models, non-DB timestamps)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from models import AuditEntry, Comment, Finding, System


def _h(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


def _assert_utc(value, label):
    assert isinstance(value, str) and value, f"{label}: missing ({value!r})"
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, f"{label}: naive timestamp {value!r} (browsers read it as local time)"
    assert parsed.utcoffset() == timedelta(0), f"{label}: not UTC ({value!r})"
    return parsed


def test_comment_created_at_is_tz_aware_utc(auth_client, db):
    client, seeded, csrf = auth_client
    system = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(system)
    db.flush()
    finding = Finding(organization_id=seeded["org"].id, system_id=system.id, framework_id="fw",
                      control_id="AC-1", title="t", severity="LOW", status="OPEN")
    db.add(finding)
    db.commit()

    before = datetime.now(timezone.utc)
    r = client.post("/api/comments", json={"entity_type": "finding", "entity_id": finding.id, "body": "hi"},
                    headers=_h(csrf))
    assert r.status_code == 200
    _assert_utc(r.json()["created_at"], "POST /comments created_at")

    rows = client.get(f"/api/comments?entity_type=finding&entity_id={finding.id}").json()
    ts = _assert_utc(rows[0]["created_at"], "GET /comments created_at")
    # And it is the real instant, not shifted by the server's offset.
    assert abs((ts - before).total_seconds()) < 60


def test_orm_dict_and_pydantic_paths_are_utc(auth_client, db):
    client, seeded, csrf = auth_client
    system = System(organization_id=seeded["org"].id, name="ERP", acronym="ERP")
    db.add(system)
    db.flush()
    db.add(Finding(organization_id=seeded["org"].id, system_id=system.id, framework_id="fw",
                   control_id="AC-1", title="t", severity="LOW", status="OPEN"))
    db.commit()

    me = client.get("/api/auth/me").json()                       # Pydantic UserOut
    _assert_utc(me["created_at"], "/auth/me created_at")
    _assert_utc(me["last_login"], "/auth/me last_login")

    f = client.get("/api/findings").json()[0]                    # column-dict serializer
    _assert_utc(f["created_at"], "/findings created_at")
    _assert_utc(f["updated_at"], "/findings updated_at")

    audit = client.get("/api/audit").json()                      # raw ORM rows
    assert audit, "login should have written an audit row"
    for e in audit:
        _assert_utc(e["timestamp"], "/audit timestamp")

    sysrow = client.get("/api/systems").json()[0]
    _assert_utc(sysrow["created_at"], "/systems created_at")


def test_existing_naive_rows_are_read_as_utc(auth_client, db):
    """Rows written before this fix (naive UTC strings in SQLite) must read
    back as the same instant in UTC — no data migration needed."""
    client, seeded, _csrf = auth_client
    db.execute(text(
        "INSERT INTO audit_entries (organization_id, actor_username, action, entity_type, timestamp) "
        "VALUES (:o, 'legacy', 'LEGACY', 'system', '2026-01-02 03:04:05.000000')"
    ), {"o": seeded["org"].id})
    db.commit()
    rows = client.get("/api/audit?entity_type=system").json()
    legacy = [e for e in rows if e["action"] == "LEGACY"][0]
    assert _assert_utc(legacy["timestamp"], "legacy row") == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_storage_stays_naive_utc(db, seeded):
    """Aware values (any offset) are stored as naive UTC, exactly like before,
    so existing databases and the audit HMAC chain stay compatible."""
    cest = timezone(timedelta(hours=2))
    db.add(AuditEntry(organization_id=seeded["org"].id, actor_username="x", action="T",
                      entity_type="system", timestamp=datetime(2026, 7, 1, 12, 0, tzinfo=cest)))
    db.commit()
    raw = db.execute(text("SELECT timestamp FROM audit_entries WHERE action='T'")).scalar()
    assert raw.startswith("2026-07-01 10:00:00")


def test_backup_info_last_backup_at_is_utc(auth_client):
    """last_backup_at comes from a file mtime, not the DB — it used to be the
    server's naive LOCAL time."""
    client, _seeded, _csrf = auth_client
    from services.backup import _backups_dir
    f = _backups_dir() / "universal-backup-2099-01-01-000000.tar.gz"
    f.write_bytes(b"x")
    try:
        info = client.get("/api/backup/info").json()
        ts = _assert_utc(info["last_backup_at"], "/backup/info last_backup_at")
        assert abs((ts - datetime.now(timezone.utc)).total_seconds()) < 120
    finally:
        f.unlink()
