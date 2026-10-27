from datetime import datetime, timezone
from sqlalchemy import Column, String
from database import Base, UTCDateTime


class FrameworkCatalogState(Base):
    """Which version of a framework plugin's files is loaded into the shared
    controls / control_mappings tables (one row per framework, install-wide —
    same scope as those tables). `content_hash` is a SHA-256 over the plugin's
    catalog.json + mappings.json; at startup a mismatch means the installed
    release ships different catalog content, so the catalog is re-loaded."""
    __tablename__ = "framework_catalog_state"

    framework_id = Column(String, primary_key=True)
    content_hash = Column(String, nullable=False)
    loaded_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
