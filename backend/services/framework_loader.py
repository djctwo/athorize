import hashlib
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from sqlalchemy.orm import Session
from models.control import Control
from models.control_mapping import ControlMapping

logger = logging.getLogger(__name__)

VALID_RELATIONSHIPS = {"equivalent", "subset", "superset", "intersects", "related"}
VALID_CONFIDENCES = {"official", "derived", "vendor"}


@dataclass
class FrameworkMeta:
    id: str
    name: str
    short_name: str
    version: str
    catalog_version: str
    description: str
    publisher: str
    category: str
    tags: list[str] = field(default_factory=list)
    status: str = "available"
    terminology: dict = field(default_factory=dict)
    scoring: dict = field(default_factory=dict)
    cross_references: list[dict] = field(default_factory=list)
    icon: str = "shield"
    color: str = "#666666"
    control_count: int = 0
    conmon_cadences: list = field(default_factory=list)
    license: dict = field(default_factory=dict)
    # Customer-authored framework (lives in the data dir, not the bundle).
    # Custom frameworks bypass license entitlement — they are the customer's
    # own content, not vendor-licensed IP.
    is_custom: bool = False
    # Company that authored a custom framework (None for bundled frameworks and
    # for custom frameworks created before ownership was recorded).
    owner_organization_id: int | None = None

    def visible_to(self, organization_id: int, is_operator: bool = False) -> bool:
        """Bundled and legacy (ownerless) frameworks are install-wide; a custom
        framework authored by one company is private to that company."""
        if not self.is_custom or self.owner_organization_id is None or is_operator:
            return True
        return self.owner_organization_id == organization_id

    def manageable_by(self, organization_id: int, is_operator: bool = False) -> bool:
        """Only the owning company (or an instance operator) may edit/delete a
        custom framework. Legacy ownerless ones are operator-only."""
        if not self.is_custom:
            return False
        if is_operator:
            return True
        return self.owner_organization_id is not None and self.owner_organization_id == organization_id


class FrameworkLoader:
    def __init__(self, frameworks_dir: Path, custom_dir: Path | None = None):
        self._dir = frameworks_dir
        if custom_dir is None:
            # Lazy import: config pulls in _appbase; keep the loader importable
            # standalone (tests, scripts) while defaulting to the app's data dir.
            from config import settings
            custom_dir = settings.custom_frameworks_dir
        self._custom_dir = custom_dir
        self._registry: dict[str, FrameworkMeta] = {}
        self._paths: dict[str, Path] = {}
        self.discover()

    def _scan_dir(self, base: Path, is_custom: bool) -> None:
        if not base.exists():
            return
        for subdir in sorted(base.iterdir()):
            if not subdir.is_dir() or subdir.name.startswith("_"):
                continue
            meta_file = subdir / "metadata.json"
            if not meta_file.exists():
                continue
            try:
                data = json.loads(meta_file.read_text())
                catalog_file = subdir / "catalog.json"
                control_count = 0
                if catalog_file.exists():
                    catalog = json.loads(catalog_file.read_text())
                    control_count = len(catalog.get("controls", []))

                meta = FrameworkMeta(
                    id=data["id"],
                    name=data["name"],
                    short_name=data.get("short_name", data["id"]),
                    version=data.get("version", "1.0"),
                    catalog_version=data.get("catalog_version", ""),
                    description=data.get("description", ""),
                    publisher=data.get("publisher", ""),
                    category=data.get("category", "general"),
                    tags=data.get("tags", []),
                    status=data.get("status", "available"),
                    terminology=data.get("terminology", {}),
                    scoring=data.get("scoring", {}),
                    cross_references=data.get("cross_references", []),
                    icon=data.get("icon", "shield"),
                    color=data.get("color", "#666666"),
                    control_count=control_count,
                    conmon_cadences=data.get("conmon_cadences", []),
                    license=data.get("license", {}),
                    is_custom=is_custom,
                    owner_organization_id=(data.get("owner_organization_id") if is_custom else None),
                )
                if meta.id in self._registry:
                    # Bundled frameworks always win: a custom dir cannot shadow
                    # (or tamper with) vendor-shipped content.
                    logger.warning(
                        "Framework id collision: %r in %s ignored (already registered)",
                        meta.id, subdir.name,
                    )
                    continue
                self._registry[meta.id] = meta
                self._paths[meta.id] = subdir
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Skipping framework dir %s: %s", subdir.name, exc)
                continue

    def discover(self) -> list[FrameworkMeta]:
        self._registry.clear()
        self._paths.clear()
        self._scan_dir(self._dir, is_custom=False)
        self._scan_dir(self._custom_dir, is_custom=True)
        return list(self._registry.values())

    def list_all(self) -> list[FrameworkMeta]:
        return list(self._registry.values())

    def get_metadata(self, framework_id: str) -> FrameworkMeta | None:
        return self._registry.get(framework_id)

    def load_catalog(self, framework_id: str, db: Session) -> int:
        meta = self._registry.get(framework_id)
        if not meta:
            raise ValueError(f"Unknown framework: {framework_id}")

        catalog_file = self._paths[framework_id] / "catalog.json"
        if not catalog_file.exists():
            raise ValueError(f"Catalog file missing for framework: {framework_id}")

        catalog = json.loads(catalog_file.read_text())
        controls = catalog.get("controls", [])

        try:
            db.query(Control).filter(Control.framework_id == framework_id).delete()
            for c in controls:
                db.add(Control(
                    framework_id=framework_id,
                    control_id=c["id"],
                    family=c.get("family", ""),
                    family_name=c.get("family_name", ""),
                    title=c.get("title", ""),
                    description=c.get("description", ""),
                    supplemental_guidance=c.get("supplemental_guidance", ""),
                    baselines=c.get("baselines", []),
                    parent_id=c.get("parent_id"),
                    related_controls=c.get("related_controls", []),
                    typical_evidence=c.get("typical_evidence", []),
                    assessment_objectives=c.get("assessment_objectives", []),
                    external_references=c.get("external_references", []),
                ))
            self._record_loaded(framework_id, db)
            db.flush()
        except Exception:
            db.rollback()
            raise
        return len(controls)

    def unload_catalog(self, framework_id: str, db: Session) -> None:
        from models.framework_catalog_state import FrameworkCatalogState
        db.query(Control).filter(Control.framework_id == framework_id).delete()
        db.query(FrameworkCatalogState).filter(FrameworkCatalogState.framework_id == framework_id).delete()
        db.flush()

    def content_hash(self, framework_id: str) -> str | None:
        """SHA-256 over the plugin's catalog.json + mappings.json bytes (None
        when the framework is not installed)."""
        base = self._paths.get(framework_id)
        if base is None:
            return None
        h = hashlib.sha256()
        for name in ("catalog.json", "mappings.json"):
            f = base / name
            h.update(name.encode() + b"\0")
            h.update(f.read_bytes() if f.exists() else b"")
            h.update(b"\0")
        return h.hexdigest()

    def _record_loaded(self, framework_id: str, db: Session) -> None:
        from models.framework_catalog_state import FrameworkCatalogState
        digest = self.content_hash(framework_id)
        if digest is None:
            return
        row = db.get(FrameworkCatalogState, framework_id)
        if row is None:
            db.add(FrameworkCatalogState(framework_id=framework_id, content_hash=digest))
        else:
            row.content_hash = digest
            from datetime import datetime, timezone
            row.loaded_at = datetime.now(timezone.utc)

    def refresh_stale_catalogs(self, db: Session) -> list[str]:
        """Re-load the catalog + crosswalk of every framework that is active in
        at least one company and whose shipped files differ from what is loaded
        (an upgrade shipped new catalog text, or the DB predates this check).
        Only catalog rows are replaced: implementations, findings and evidence
        reference controls by id and are untouched. Returns refreshed ids."""
        from models.framework_activation import FrameworkActivation
        from models.framework_catalog_state import FrameworkCatalogState
        active = sorted({
            fid for (fid,) in db.query(FrameworkActivation.framework_id)
            .filter(FrameworkActivation.is_active == True)  # noqa: E712
            .distinct()
        })
        refreshed = []
        for fid in active:
            digest = self.content_hash(fid)
            if digest is None:
                continue  # plugin no longer installed: keep what is loaded
            row = db.get(FrameworkCatalogState, fid)
            if row is not None and row.content_hash == digest:
                continue
            try:
                self.load_catalog(fid, db)
                self.load_mappings(fid, db)
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                logger.warning("catalog refresh for %s skipped: %s", fid, exc)
                db.rollback()
                continue
            db.commit()
            refreshed.append(fid)
        return refreshed

    def load_mappings(self, framework_id: str, db: Session) -> int:
        """Load the plugin's crosswalk mappings (mappings.json), if it ships any.

        Optional file — frameworks without mapping data load zero edges. Invalid
        entries are skipped with a warning rather than failing activation: the
        crosswalk is an enrichment, not a prerequisite.
        """
        base = self._paths.get(framework_id)
        if base is None:
            return 0
        mappings_file = base / "mappings.json"
        if not mappings_file.exists():
            return 0
        try:
            data = json.loads(mappings_file.read_text())
            entries = data.get("mappings", [])
        except json.JSONDecodeError as exc:
            logger.warning("mappings.json for %s is invalid JSON, skipping: %s", framework_id, exc)
            return 0

        db.query(ControlMapping).filter(
            ControlMapping.source_framework_id == framework_id
        ).delete()

        loaded = 0
        seen: set[tuple[str, str, str]] = set()
        for m in entries:
            try:
                key = (m["control_id"], m["target_framework"], m["target_control"])
            except (KeyError, TypeError):
                logger.warning("mappings.json for %s: malformed entry skipped: %r", framework_id, m)
                continue
            if key in seen:
                continue
            if m.get("relationship") not in VALID_RELATIONSHIPS or m.get("confidence") not in VALID_CONFIDENCES:
                logger.warning("mappings.json for %s: invalid relationship/confidence skipped: %r", framework_id, key)
                continue
            seen.add(key)
            db.add(ControlMapping(
                source_framework_id=framework_id,
                source_control_id=m["control_id"],
                target_framework_id=m["target_framework"],
                target_control_id=m["target_control"],
                relationship=m["relationship"],
                confidence=m["confidence"],
                rationale=m.get("rationale", ""),
            ))
            loaded += 1
        db.flush()
        return loaded

    def unload_mappings(self, framework_id: str, db: Session) -> None:
        db.query(ControlMapping).filter(
            ControlMapping.source_framework_id == framework_id
        ).delete()
        db.flush()

    def get_report_templates(self, framework_id: str) -> list[dict]:
        base = self._paths.get(framework_id)
        if base is None:
            return []
        templates_dir = base / "report_templates"
        if not templates_dir.exists():
            return []
        templates = []
        for f in sorted(templates_dir.glob("*.json")):
            try:
                templates.append(json.loads(f.read_text()))
            except json.JSONDecodeError:
                continue
        return templates

    def get_assessment_templates(self, framework_id: str) -> list[dict]:
        base = self._paths.get(framework_id)
        if base is None:
            return []
        templates_dir = base / "assessment_templates"
        if not templates_dir.exists():
            return []
        templates = []
        for f in sorted(templates_dir.glob("*.json")):
            try:
                templates.append(json.loads(f.read_text()))
            except json.JSONDecodeError:
                continue
        return templates
