import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from services.import_common import UploadSizeLimitMiddleware
from sqlalchemy import inspect, text
from database import _IS_SQLITE, engine, Base
from config import settings
from _appbase import bundle_root
from routers import auth, users, systems, findings, evidence, controls, crosswalk, frameworks, assessments, dashboard, calendar, audit, redteam, conmon, it_assets, ot_assets, ics_advisories, risks, siem_import, asset_import, reports, backup, inspection, api_tokens, digest, orgs, saved_views, search, custom_frameworks, migration, comments

# An interrupted backup restore must be rolled back (or finished) before
# anything else opens the database. The server lock first: it marks this
# process as a server on DATA_DIR (the offline restore CLI refuses while one
# runs) and waits while an offline restore is in progress.
from services.backup import acquire_server_lock, recover_interrupted_restore, release_server_lock
acquire_server_lock()
recover_interrupted_restore()

Base.metadata.create_all(bind=engine)

# Inline migrations are SQLite-dialect (sqlite_master, PRAGMA, ALTER ADD
# COLUMN). Non-SQLite engines get their full schema from create_all above.
# A function (not module-level code) so a backup restore can bring an older
# archive's database up to the current schema before it goes live.
def run_schema_migrations(engine) -> None:
  Base.metadata.create_all(bind=engine)
  # Session ids are stored hashed (2026-10); rows from before hold the raw
  # cookie value and are dropped (users sign in again after this upgrade).
  from sqlalchemy.orm import Session as _PurgeSession
  from services.sessions import purge_unhashed_sessions
  with _PurgeSession(bind=engine) as _s:
    if purge_unhashed_sessions(_s):
        print("sessions: signed out pre-upgrade sessions (session ids are now stored hashed)")
    _s.commit()
  if engine.dialect.name != "sqlite":
    return
  with engine.connect() as conn:
    # Redteam columns migration
    existing_rt = {c["name"] for c in inspect(engine).get_columns("redteam_reports")}
    _REDTEAM_COLUMNS = [
        ("total_exposure_low", "INTEGER NOT NULL DEFAULT 0"),
        ("total_exposure_high", "INTEGER NOT NULL DEFAULT 0"),
        ("top5_reduction_low", "INTEGER NOT NULL DEFAULT 0"),
        ("top5_reduction_high", "INTEGER NOT NULL DEFAULT 0"),
        ("quick_win_count", "INTEGER NOT NULL DEFAULT 0"),
        ("has_org_context", "INTEGER NOT NULL DEFAULT 0"),
    ]
    for col_name, col_def in _REDTEAM_COLUMNS:
        if col_name not in existing_rt:
            conn.execute(text(f"ALTER TABLE redteam_reports ADD COLUMN {col_name} {col_def}"))

    # Session csrf_token migration
    existing_sess = {c["name"] for c in inspect(engine).get_columns("user_sessions")}
    if "csrf_token" not in existing_sess:
        conn.execute(text("ALTER TABLE user_sessions ADD COLUMN csrf_token TEXT"))

    # Finding POA&M-compatible columns migration
    existing_find = {c["name"] for c in inspect(engine).get_columns("findings")}
    _FINDING_COLUMNS = [
        ("weakness_description", "TEXT"),
        ("owner_name", "TEXT"),
        ("owner_email", "TEXT"),
        ("scheduled_completion", "DATE"),
        ("actual_completion", "DATE"),
        ("reopen_reason", "TEXT"),
        ("milestones", "TEXT"),
    ]
    for col_name, col_def in _FINDING_COLUMNS:
        if col_name not in existing_find:
            conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}"))

    # System new columns migration
    existing_sys = {c["name"] for c in inspect(engine).get_columns("systems")}
    _SYSTEM_COLUMNS = [
        ("impact_level", "TEXT DEFAULT 'MODERATE'"),
        ("authorization_status", "TEXT DEFAULT 'NOT_AUTHORIZED'"),
        ("is_ot_enabled", "INTEGER DEFAULT 0"),
    ]
    for col_name, col_def in _SYSTEM_COLUMNS:
        if col_name not in existing_sys:
            conn.execute(text(f"ALTER TABLE systems ADD COLUMN {col_name} {col_def}"))

    # Rate limit state table
    tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
    if "rate_limit_state" not in tables:
        conn.execute(text(
            "CREATE TABLE rate_limit_state ("
            "  key TEXT PRIMARY KEY,"
            "  lockout_until REAL NOT NULL"
            ")"
        ))

    # Session idle-timeout column (2026-06-11)
    existing_sess2 = {c["name"] for c in inspect(engine).get_columns("user_sessions")}
    if "last_activity" not in existing_sess2:
        conn.execute(text("ALTER TABLE user_sessions ADD COLUMN last_activity DATETIME"))
        conn.execute(text("UPDATE user_sessions SET last_activity = created_at WHERE last_activity IS NULL"))

    # Multi-company / operator org-switch (2026-07-01)
    existing_users = {c["name"] for c in inspect(engine).get_columns("users")}
    if "is_operator" not in existing_users:
        conn.execute(text("ALTER TABLE users ADD COLUMN is_operator INTEGER NOT NULL DEFAULT 0"))
    existing_sess3 = {c["name"] for c in inspect(engine).get_columns("user_sessions")}
    if "active_organization_id" not in existing_sess3:
        conn.execute(text("ALTER TABLE user_sessions ADD COLUMN active_organization_id INTEGER REFERENCES organizations(id)"))

    # Ownership / My Work (2026-07-03): real user assignment on control
    # implementations and evidence (refresh workflow).
    existing_impl = {c["name"] for c in inspect(engine).get_columns("control_implementations")}
    if "owner_id" not in existing_impl:
        conn.execute(text("ALTER TABLE control_implementations ADD COLUMN owner_id INTEGER REFERENCES users(id)"))
    existing_ev = {c["name"] for c in inspect(engine).get_columns("evidence_artifacts")}
    if "owner_id" not in existing_ev:
        conn.execute(text("ALTER TABLE evidence_artifacts ADD COLUMN owner_id INTEGER REFERENCES users(id)"))

    # Threat feed columns (KEV + control inference, 2026-06-11)
    existing_adv = {c["name"] for c in inspect(engine).get_columns("ics_advisories")}
    if "related_controls" not in existing_adv:
        conn.execute(text("ALTER TABLE ics_advisories ADD COLUMN related_controls TEXT DEFAULT '[]'"))
    match_cols = {c["name"]: c for c in inspect(engine).get_columns("ics_advisory_matches")}
    if "it_asset_id" not in match_cols:
        conn.execute(text("ALTER TABLE ics_advisory_matches ADD COLUMN it_asset_id INTEGER REFERENCES it_assets(id)"))
    # Old DBs created ot_asset_id NOT NULL; IT-asset matches need it nullable.
    notnull_ot = any(
        r[1] == "ot_asset_id" and r[3] == 1
        for r in conn.execute(text("PRAGMA table_info(ics_advisory_matches)")).fetchall()
    )
    if notnull_ot:
        conn.execute(text(
            "CREATE TABLE ics_advisory_matches_new ("
            " id INTEGER PRIMARY KEY,"
            " advisory_id INTEGER NOT NULL REFERENCES ics_advisories(id) ON DELETE CASCADE,"
            " ot_asset_id INTEGER REFERENCES ot_assets(id) ON DELETE CASCADE,"
            " it_asset_id INTEGER REFERENCES it_assets(id) ON DELETE CASCADE,"
            " system_id INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,"
            " confidence VARCHAR NOT NULL,"
            " dismissed INTEGER DEFAULT 0,"
            " created_at DATETIME,"
            " CONSTRAINT uq_advisory_asset UNIQUE (advisory_id, ot_asset_id),"
            " CONSTRAINT uq_advisory_it_asset UNIQUE (advisory_id, it_asset_id)"
            ")"
        ))
        conn.execute(text(
            "INSERT INTO ics_advisory_matches_new (id, advisory_id, ot_asset_id, it_asset_id, system_id, confidence, dismissed, created_at)"
            " SELECT id, advisory_id, ot_asset_id, it_asset_id, system_id, confidence, dismissed, created_at FROM ics_advisory_matches"
        ))
        conn.execute(text("DROP TABLE ics_advisory_matches"))
        conn.execute(text("ALTER TABLE ics_advisory_matches_new RENAME TO ics_advisory_matches"))

    # Trend averages count only pairs with work (services.metrics.pair_has_work):
    # snapshots record how many controls were assessed. Older rows stay NULL.
    existing_snap = {c["name"] for c in inspect(engine).get_columns("compliance_snapshots")}
    if "assessed_controls" not in existing_snap:
        conn.execute(text("ALTER TABLE compliance_snapshots ADD COLUMN assessed_controls INTEGER"))

    # SSO identity binding (R2SEC-3/-9): users carry the IdP (issuer, sub)
    # they were linked to; one IdP identity binds at most one account.
    existing_users2 = {c["name"] for c in inspect(engine).get_columns("users")}
    if "oidc_issuer" not in existing_users2:
        conn.execute(text("ALTER TABLE users ADD COLUMN oidc_issuer TEXT"))
    if "oidc_subject" not in existing_users2:
        conn.execute(text("ALTER TABLE users ADD COLUMN oidc_subject TEXT"))
    conn.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_oidc_identity ON users (oidc_issuer, oidc_subject)"
        " WHERE oidc_subject IS NOT NULL"))

    # Usernames are globally unique (sign-in looks them up across companies).
    # Enforce it in the DB unless an older install already holds duplicates —
    # those keep working (login checks each) and new duplicates are refused
    # by the API.
    dup = conn.execute(text("SELECT username FROM users GROUP BY username HAVING count(*) > 1 LIMIT 1")).first()
    if dup is None:
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users (username)"))
    else:
        print("users: duplicate usernames across companies exist; rename them to enable the unique index")

    # Audit queries always filter on organization_id; index it for existing DBs
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_audit_entries_organization_id"
        " ON audit_entries (organization_id)"
    ))
    # Enforce one implementation row per (system, framework, control); the
    # upsert in routers/controls.py is otherwise racy. Existing DBs may have
    # accumulated duplicates — keep the newest row, then add the index.
    conn.execute(text(
        "DELETE FROM control_implementations WHERE id NOT IN ("
        "  SELECT MAX(id) FROM control_implementations"
        "  GROUP BY system_id, framework_id, control_id"
        ")"
    ))
    conn.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_control_impl_system_framework_control"
        " ON control_implementations (system_id, framework_id, control_id)"
    ))

    # Comments / @mentions (2026-07-29): the comments table itself is a new
    # model, so create_all above materializes it on old and new DBs alike (no
    # ALTERs needed). Backstop the entity-lookup index for any DB where the
    # table pre-exists without it — every list query filters on these columns.
    tables_now = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
    if "comments" in tables_now:
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_comments_entity"
            " ON comments (entity_type, entity_id)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_comments_organization_id"
            " ON comments (organization_id)"
        ))

    conn.commit()

  # Audit chain v2 (2026-10): adds hash_version to pre-v2 databases and anchors
  # their existing chains exactly once (idempotent; restores run it too).
  from services.audit import upgrade_legacy_schema
  _n = upgrade_legacy_schema(engine)
  if _n is not None:
    print(f"audit-chain: anchored {_n} existing chain(s) (v1 entries; new entries use v2)")


run_schema_migrations(engine)

# R2SEC-5: the audit key in use must be the one that signed the existing log —
# checked before anything below can write an audit entry.
from services.audit_key_check import reconcile_audit_key
reconcile_audit_key(engine)

# Crosswalk mapping backfill: mappings.json normally loads on framework
# activation, but installs that activated frameworks before the crosswalk
# feature existed have no mapping rows. Load them once at startup.
def _backfill_crosswalk_mappings() -> None:
    from sqlalchemy.orm import Session as _Session
    from models import ControlMapping, FrameworkActivation
    from services.framework_loader import FrameworkLoader

    loader = FrameworkLoader(settings.frameworks_dir)
    db = _Session(bind=engine)
    try:
        active_ids = {
            row[0]
            for row in db.query(FrameworkActivation.framework_id)
            .filter(FrameworkActivation.is_active == True)  # noqa: E712
            .distinct()
        }
        for fw_id in sorted(active_ids):
            has_rows = db.query(ControlMapping.id).filter(
                ControlMapping.source_framework_id == fw_id
            ).first() is not None
            if not has_rows:
                loaded = loader.load_mappings(fw_id, db)
                if loaded:
                    print(f"crosswalk: backfilled {loaded} mappings for {fw_id}")
        db.commit()
    finally:
        db.close()


_backfill_crosswalk_mappings()


# Catalog refresh: the controls/control_mappings rows are a copy of each active
# framework plugin's catalog.json/mappings.json taken at activation. When an
# upgrade ships different catalog content (rewritten summaries, new controls,
# new crosswalk edges), re-load it so installs never keep stale catalog text.
# Implementations reference controls by id, so nothing user-entered is lost.
def _refresh_stale_catalogs() -> None:
    from sqlalchemy.orm import Session as _Session
    from services.framework_loader import FrameworkLoader

    from services.catalog_maintenance import refresh_catalogs

    db = _Session(bind=engine)
    try:
        refreshed, retired = refresh_catalogs(db, FrameworkLoader(settings.frameworks_dir))
        for notice in retired:  # R2INSTALL-6
            print(f"catalog: NOTICE: {notice}")
        for fw_id in refreshed:
            print(f"catalog: refreshed {fw_id} from the installed release")
    except Exception as exc:  # never block startup on a refresh problem
        db.rollback()
        print(f"catalog: refresh skipped ({exc})")
    finally:
        db.close()


_refresh_stale_catalogs()


def _maybe_seed_demo() -> None:
    """Demo builds only: auto-populate an EMPTY database on first boot so the
    recipient gets a fully-loaded instance to evaluate with no commands to run.
    Gated by the `DEMO_BUILD` marker (written by `package_release.sh --demo`) or
    ATHORIZE_DEMO_SEED=1, and only ever runs against an empty DB. Every other
    build offers the same demo on the Setup screen ("Explore with demo data")."""
    from config import is_demo_mode
    if not is_demo_mode(settings):
        return
    from database import SessionLocal
    from services import demo_seed
    with SessionLocal() as _db:
        if not demo_seed.instance_is_empty(_db):  # never touch a populated DB
            return
        try:
            demo_seed.seed_demo(_db)
            _db.commit()
            print("demo-seed: instance auto-populated with demo data on first boot")
        except Exception as exc:  # a seed failure must never block startup
            _db.rollback()
            demo_seed.discard_demo_files()
            print(f"demo-seed: skipped ({exc})")


_maybe_seed_demo()

# First-run setup token: generated when the DB has no users (closes the
# open-setup window). No-op once provisioned (incl. after a demo seed).
from services.setup_token import ensure_setup_token
ensure_setup_token()


# ---------------------------------------------------------------------------
# Scheduled threat-feed refresh: set THREAT_FEEDS_INTERVAL_HOURS > 0 to pull
# all feeds on an interval for every organization. Off by default —
# air-gapped installs stay quiet, demos refresh on demand.
# ---------------------------------------------------------------------------
def _run_scheduled_feed_refresh() -> None:
    from sqlalchemy.orm import Session as _Session
    from models import Organization
    from services.feed_refresh import refresh_feeds_for_org

    db = _Session(bind=engine)
    try:
        for (org_id,) in db.query(Organization.id).all():
            try:
                result = refresh_feeds_for_org(
                    db, org_id, actor_id=None, actor_username="feed-scheduler",
                )
                print(
                    f"feed-scheduler: org {org_id} refreshed "
                    f"{result['advisories_refreshed']} items, "
                    f"+{result['matches_new']} matches"
                    + (f", errors: {result['feed_errors']}" if result["feed_errors"] else "")
                )
            except Exception as exc:  # one org failing must not stop the rest
                db.rollback()
                print(f"feed-scheduler: org {org_id} refresh failed: {exc}")
    finally:
        db.close()


async def _feed_scheduler_loop(interval_hours: float) -> None:
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            await asyncio.to_thread(_run_scheduled_feed_refresh)
        except Exception as exc:  # never let one failed tick kill the loop
            print(f"feed-scheduler: tick failed, will retry next interval: {exc}")


# Scheduled email digests: set DIGEST_INTERVAL_HOURS > 0 (e.g. 24) to email the
# compliance digest to each org's admins/compliance-managers. Requires SMTP
# configured; off by default so air-gapped installs stay silent.
def _run_scheduled_digests() -> None:
    from sqlalchemy.orm import Session as _Session
    from models import Organization
    from services import digest as digest_svc, email as email_svc

    if not email_svc.is_configured():
        print("digest-scheduler: SMTP not configured, skipping")
        return
    db = _Session(bind=engine)
    try:
        from services import assignee_reminders

        for (org_id,) in db.query(Organization.id).all():
            try:
                d = digest_svc.build_digest(db, org_id)
                to = digest_svc.recipients(db, org_id)
                if digest_svc.has_content(d) and to:
                    email_svc.send_email(to, digest_svc.subject(d), digest_svc.render_html(d), digest_svc.render_text(d))
                    print(f"digest-scheduler: org {org_id} sent to {len(to)} recipient(s)")
                # Per-assignee nudges (findings due soon/overdue + evidence to
                # refresh) ride the same schedule.
                sent = assignee_reminders.send_reminders(db, org_id)
                if sent:
                    print(f"digest-scheduler: org {org_id} sent {sent} assignee reminder(s)")
            except Exception as exc:  # one org failing must not stop the rest
                db.rollback()
                print(f"digest-scheduler: org {org_id} failed: {exc}")
    finally:
        db.close()


async def _digest_scheduler_loop(interval_hours: float) -> None:
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            await asyncio.to_thread(_run_scheduled_digests)
        except Exception as exc:  # never let one failed tick kill the loop
            print(f"digest-scheduler: tick failed, will retry next interval: {exc}")


# Daily compliance snapshots (trend charts / burndown / Audit Binder progress).
# Purely local computation, so ON by default — HISTORY_SNAPSHOT_INTERVAL_HOURS=0
# disables. An immediate catch-up run at startup covers installs that aren't up
# 24h continuously (the service is idempotent per day).
def _run_history_snapshots() -> None:
    from sqlalchemy.orm import Session as _Session
    from services.history import take_snapshots

    db = _Session(bind=engine)
    try:
        written = take_snapshots(db)
        if written:
            print(f"history-snapshots: recorded {written} rows")
    except Exception as exc:
        db.rollback()
        print(f"history-snapshots: failed: {exc}")
    finally:
        db.close()


async def _history_scheduler_loop(interval_hours: float) -> None:
    await asyncio.to_thread(_run_history_snapshots)  # catch-up at startup
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            await asyncio.to_thread(_run_history_snapshots)
        except Exception as exc:  # never let one failed tick kill the loop
            print(f"history-snapshots: tick failed, will retry next interval: {exc}")


# Scheduled connector asset sync: set ASSET_SYNC_INTERVAL_HOURS > 0 to pull the
# env-configured live asset connectors (Tanium / Cisco ISE) on an interval and
# import any new assets — the exact same dedup/insert path as a manual
# connector Pull → Confirm. Off by default so self-hosted installs stay quiet.
# ASSET_SYNC_ORG_SLUG picks the target company on multi-company installs
# (blank = first org, mirroring OIDC_PROVISION_ORG_SLUG).
def _run_scheduled_asset_sync() -> None:
    from sqlalchemy.orm import Session as _Session
    from services.asset_sync import run_asset_sync

    db = _Session(bind=engine)
    try:
        result = run_asset_sync(db)
        if not result.get("ran"):
            print(f"asset-sync: skipped: {result.get('reason', 'unknown')}")
            return
        connectors = result.get("connectors") or {}
        if not connectors:
            print("asset-sync: no live connectors configured")
        for key, r in connectors.items():
            if r.get("ok"):
                print(f"asset-sync: {key} +{r['created']} new, {r['skipped']} duplicate(s) skipped")
            else:  # per-connector failures are isolated inside run_asset_sync
                print(f"asset-sync: {key} failed: {r.get('error')}")
    except Exception as exc:
        db.rollback()
        print(f"asset-sync: run failed: {exc}")
    finally:
        db.close()


async def _asset_sync_scheduler_loop(interval_hours: float) -> None:
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            await asyncio.to_thread(_run_scheduled_asset_sync)
        except Exception as exc:  # never let one failed tick kill the loop
            print(f"asset-sync: tick failed, will retry next interval: {exc}")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    server_lock = acquire_server_lock()  # no-op unless DATA_DIR changed since import (tests)
    tasks = []
    try:
        interval = float(os.getenv("THREAT_FEEDS_INTERVAL_HOURS") or 0)
    except ValueError:
        interval = 0
    if interval > 0:
        tasks.append(asyncio.create_task(_feed_scheduler_loop(interval)))
        print(f"feed-scheduler: enabled, every {interval}h")
    try:
        digest_interval = float(os.getenv("DIGEST_INTERVAL_HOURS") or 0)
    except ValueError:
        digest_interval = 0
    if digest_interval > 0:
        tasks.append(asyncio.create_task(_digest_scheduler_loop(digest_interval)))
        print(f"digest-scheduler: enabled, every {digest_interval}h")
    try:
        history_interval = float(os.getenv("HISTORY_SNAPSHOT_INTERVAL_HOURS") or 24)
    except ValueError:
        history_interval = 24
    if history_interval > 0:
        tasks.append(asyncio.create_task(_history_scheduler_loop(history_interval)))
    # Same env parsing the status endpoint reports (0/unset/invalid = off).
    from services.asset_sync import sync_interval_hours as _asset_sync_hours
    asset_sync_interval = _asset_sync_hours()
    if asset_sync_interval > 0:
        tasks.append(asyncio.create_task(_asset_sync_scheduler_loop(asset_sync_interval)))
        print(f"asset-sync: enabled, every {asset_sync_interval}h")
    from database import SessionLocal
    from services.sso_scope import sso_scope_warning
    try:
        with SessionLocal() as _db:
            _sso_warning = sso_scope_warning(_db)
        if _sso_warning:
            print(_sso_warning)
    except Exception as exc:  # a warning must never stop startup
        print(f"sso: scope check skipped ({exc})")
    yield
    for task in tasks:
        task.cancel()
    if tasks:
        # Await cancellation so shutdown is deterministic and CancelledError is
        # retrieved (no "Task was destroyed but is pending" warnings on reload).
        await asyncio.gather(*tasks, return_exceptions=True)
    release_server_lock(server_lock)


from version import __version__  # noqa: E402

app = FastAPI(title="Athorize", version=__version__, lifespan=_lifespan)

_MIB = 1024 * 1024
# Upload endpoints get their file cap (the middleware adds 1 MiB for multipart
# framing and form fields); every other API request (JSON) gets a generous
# default. Bodies past the limit are refused with 413 while streaming — never
# buffered first.
_UPLOAD_BODY_LIMITS = (
    ("/api/siem/import", 16 * _MIB),
    ("/api/asset-import/import", 16 * _MIB),
    ("/api/migration/", 16 * _MIB),
    ("/api/evidence/upload", 100 * _MIB),
)
_DEFAULT_API_BODY_LIMIT = 32 * _MIB


def _request_body_limit(path: str) -> int | None:
    for prefix, cap in _UPLOAD_BODY_LIMITS:
        if path.startswith(prefix):
            return cap
    if path.startswith("/api/backup/restore"):
        from routers import backup as backup_router
        return getattr(backup_router, "_MAX_RESTORE_BYTES", 512 * _MIB)
    if path.startswith("/api/"):
        return _DEFAULT_API_BODY_LIMIT
    return None


app.add_middleware(UploadSizeLimitMiddleware, limit_for=_request_body_limit)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Host header check (DNS rebinding): a page on attacker.example that rebinds its
# name to 127.0.0.1 would otherwise talk to a local instance as same-origin.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
_host_warning_logged = False


def _host_only(value: str) -> str:
    value = (value or "").strip().lower()
    if value.startswith("["):
        return value[1:value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _host_allowed(host: str) -> bool:
    global _host_warning_logged
    configured = [h.strip().lower() for h in settings.allowed_hosts if h.strip()]
    if "*" in configured:
        return True
    if not configured and settings.trust_xff:
        # Proxy installs from before this check have no ATHORIZE_ALLOWED_HOSTS;
        # don't break them on upgrade — but say what to set.
        if not _host_warning_logged:
            _host_warning_logged = True
            print("WARNING: ATHORIZE_ALLOWED_HOSTS is not set; Host header checking is off for this "
                  "proxy install. Set it to the name users browse to (docs/INSTALL.md §5).")
        return True
    from urllib.parse import urlparse
    allowed = _LOCAL_HOSTS | {_host_only(h) for h in configured}
    allowed |= {(urlparse(o).hostname or "").lower() for o in settings.cors_origins}
    return _host_only(host) in allowed


@app.middleware("http")
async def host_check(request: Request, call_next):
    if request.url.path != "/api/health" and not _host_allowed(request.headers.get("host", "")):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            {"detail": "Host header not allowed. Add this host name to ATHORIZE_ALLOWED_HOSTS."},
            status_code=400)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    from services.csrf import is_secure_request
    # A route may set a STRICTER policy of its own (evidence download serves
    # user files under `default-src 'none'; sandbox`) — keep it (R2SEC-13).
    response.headers.setdefault("Content-Security-Policy", _CSP)
    if is_secure_request(request):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(orgs.router, prefix="/api/orgs", tags=["orgs"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(systems.router, prefix="/api/systems", tags=["systems"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(evidence.router, prefix="/api/evidence", tags=["evidence"])
app.include_router(controls.router, prefix="/api/controls", tags=["controls"])
app.include_router(crosswalk.router, prefix="/api/crosswalk", tags=["crosswalk"])
app.include_router(frameworks.router, prefix="/api/frameworks", tags=["frameworks"])
app.include_router(assessments.router, prefix="/api/assessments", tags=["assessments"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(calendar.router, prefix="/api/calendar", tags=["calendar"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(redteam.router, prefix="/api/redteam", tags=["redteam"])
app.include_router(conmon.router, prefix="/api/conmon", tags=["conmon"])
app.include_router(it_assets.router, prefix="/api/it-assets", tags=["it-assets"])
app.include_router(ot_assets.router, prefix="/api/ot-assets", tags=["ot-assets"])
app.include_router(ics_advisories.router, prefix="/api/advisories", tags=["advisories"])
app.include_router(risks.router, prefix="/api/risks", tags=["risks"])
app.include_router(siem_import.router, prefix="/api/siem", tags=["siem"])
app.include_router(asset_import.router, prefix="/api/asset-import", tags=["asset-import"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(backup.router, prefix="/api/backup", tags=["backup"])
app.include_router(inspection.router, prefix="/api/inspection", tags=["inspection"])
app.include_router(api_tokens.router, prefix="/api/tokens", tags=["api-tokens"])
app.include_router(digest.router, prefix="/api/digest", tags=["digest"])
app.include_router(saved_views.router, prefix="/api/views", tags=["views"])
app.include_router(search.router, prefix="/api/search", tags=["search"])
app.include_router(custom_frameworks.router, prefix="/api/custom-frameworks", tags=["custom-frameworks"])
app.include_router(migration.router, prefix="/api/migration", tags=["migration"])
app.include_router(comments.router, prefix="/api/comments", tags=["comments"])


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


@app.middleware("http")
async def restore_gate(request: Request, call_next):
    """While a backup restore swaps the data (or Settings -> Start fresh wipes
    a demo), other API calls wait it out (a write landing mid-swap would be lost
    or orphaned)."""
    from services.backup import restore_in_progress
    from services.start_fresh import in_progress as start_fresh_in_progress
    path = request.url.path
    if path.startswith("/api/") and path != "/api/health":
        from fastapi.responses import JSONResponse
        if restore_in_progress() and not path.startswith("/api/backup/"):
            return JSONResponse({"detail": "A backup restore is in progress. Try again in a minute."},
                                status_code=503, headers={"Retry-After": "30"})
        if start_fresh_in_progress():
            return JSONResponse({"detail": "This instance is starting fresh (deleting the demo data). "
                                           "Try again in a minute."},
                                status_code=503, headers={"Retry-After": "30"})
    return await call_next(request)


# --- Optional single-process serving (eval / local) ---
# With ATHORIZE_SERVE_FRONTEND=1 this process also serves the pre-built web UI
# from frontend/dist on the SAME origin, so /api works with no reverse proxy —
# the whole app runs from one `uvicorn` command (see scripts/run-eval.sh).
# OFF by default; production serves the UI via nginx (docs/INSTALL.md).
if os.getenv("ATHORIZE_SERVE_FRONTEND") == "1":
    from fastapi import HTTPException as _HTTPException
    from fastapi.responses import FileResponse as _FileResponse
    from fastapi.staticfiles import StaticFiles as _StaticFiles

    _DIST = bundle_root() / "frontend" / "dist"
    if _DIST.is_dir():
        _DIST_ROOT = _DIST.resolve()
        _INDEX = _DIST_ROOT / "index.html"
        _ASSETS = _DIST / "assets"
        if _ASSETS.is_dir():
            app.mount("/assets", _StaticFiles(directory=str(_ASSETS)), name="assets")

        # SPA fallback: serve a real file if it exists, else index.html. Never
        # swallow /api (those routers are registered above and match first; this
        # guard keeps a missing API route returning JSON 404, not the SPA shell).
        # Resolve the candidate and require containment in dist so a crafted path
        # (e.g. ../../etc/passwd) can't escape the directory (path traversal).
        @app.get("/{full_path:path}")
        def _spa(full_path: str):
            if full_path == "api" or full_path.startswith("api/"):
                raise _HTTPException(status_code=404, detail="Not found")
            if full_path:
                candidate = (_DIST_ROOT / full_path).resolve(strict=False)
                if candidate.is_relative_to(_DIST_ROOT) and candidate.is_file():
                    return _FileResponse(str(candidate))
            return _FileResponse(str(_INDEX))

        print(f"serve-frontend: UI mounted from {_DIST} (single-process mode)")
    else:
        print(f"serve-frontend: ATHORIZE_SERVE_FRONTEND=1 but {_DIST} not found — UI not served")
