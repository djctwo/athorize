"""Bring the loaded framework catalogs in line with the installed release.

Runs at every startup and right after a backup restore (R2INSTALL-5: a restore
of an older archive used to bring back old catalog text and control counts —
and so wrong scores — until the next restart).

1. Retired frameworks (R2INSTALL-6). Frameworks that earlier versions shipped
   and this one does not (no plugin with that id is installed, bundled or
   custom) are deactivated for every company that still had them active, their
   catalog and crosswalk rows are unloaded (so dashboards and search stop
   counting them, and the activation matches what Marketplace can show), and
   each affected company's audit log says so. Implementation records are kept.
2. Stale catalogs: every active framework whose shipped catalog.json /
   mappings.json differ from what is loaded is re-loaded
   (FrameworkLoader.refresh_stale_catalogs).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

_logger = logging.getLogger(__name__)

# id -> name, for frameworks earlier releases shipped and this one removed.
RETIRED_FRAMEWORKS = {
    "cis-controls-v8": "CIS Controls v8",
    "soc-2": "SOC 2",
    "hitrust-csf": "HITRUST CSF",
}


def retire_removed_frameworks(db: Session, loader) -> list[str]:
    """Deactivate retired frameworks still active anywhere. Returns one notice
    per retired framework that was active (empty when there was nothing to do)."""
    from models import ControlMapping
    from models.control import Control
    from models.framework_activation import FrameworkActivation
    from services import audit as audit_svc

    notices: list[str] = []
    for fid, name in RETIRED_FRAMEWORKS.items():
        if loader.get_metadata(fid) is not None:
            continue  # someone installed a plugin with this id: it is not retired here
        active = (db.query(FrameworkActivation)
                  .filter(FrameworkActivation.framework_id == fid,
                          FrameworkActivation.is_active == True)  # noqa: E712
                  .all())
        if active:
            for act in active:
                act.is_active = False
                audit_svc.record(
                    db, organization_id=act.organization_id, actor_id=None, actor_username="system",
                    action="DEACTIVATE", entity_type="framework",
                    summary=(f"Framework '{name}' ({fid}) is no longer included in Athorize and was "
                             "deactivated by the upgrade. Its implementation records are kept."),
                )
            notices.append(f"{name} ({fid}) is no longer included in Athorize and was deactivated for "
                           f"{len(active)} compan{'y' if len(active) == 1 else 'ies'}; implementation "
                           "records are kept.")
        # Rows of a framework nobody can activate any more are dead weight either way.
        db.query(Control).filter(Control.framework_id == fid).delete()
        db.query(ControlMapping).filter(ControlMapping.source_framework_id == fid).delete()
        try:
            from models.framework_catalog_state import FrameworkCatalogState
            db.query(FrameworkCatalogState).filter(FrameworkCatalogState.framework_id == fid).delete()
        except Exception:  # table absent on very old databases until create_all ran
            pass
    db.commit()
    return notices


def refresh_catalogs(db: Session, loader=None) -> tuple[list[str], list[str]]:
    """(refreshed framework ids, retirement notices)."""
    if loader is None:
        from config import settings
        from services.framework_loader import FrameworkLoader
        loader = FrameworkLoader(settings.frameworks_dir)
    notices = retire_removed_frameworks(db, loader)
    refreshed = loader.refresh_stale_catalogs(db)
    return refreshed, notices
