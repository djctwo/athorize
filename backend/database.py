from datetime import datetime, timezone

from sqlalchemy import create_engine, event, DateTime
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.types import TypeDecorator

from config import settings

from services.data_perms import secure_data_dirs  # noqa: E402

secure_data_dirs(settings.data_dir, settings.evidence_dir, settings.backup_dir)

# SQLite needs check_same_thread=False (FastAPI threads) and per-connection
# PRAGMAs; any other engine (e.g. PostgreSQL via DATABASE_URL) must get
# neither — passing them used to crash non-SQLite startups outright.
_IS_SQLITE = settings.db_url.startswith("sqlite")

engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if _IS_SQLITE else {},
    echo=settings.debug,
)

if _IS_SQLITE:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragmas(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class UTCDateTime(TypeDecorator):
    """DateTime stored as naive UTC (the existing on-disk format) and always
    returned as timezone-aware UTC.

    SQLite has no timezone support, so a plain DateTime column hands back naive
    datetimes; the API then emitted ISO strings without an offset, which
    browsers parse as *local* time ("2h ago" off by the viewer's UTC offset).
    Normalising here fixes every serialisation path at once (ORM rows,
    column-dict serializers, explicit .isoformat(), Pydantic models). Aware
    values with any offset are converted to UTC before storing; naive values
    are assumed to already be UTC, matching how rows have always been written.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if isinstance(value, datetime) and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
