"""Control and framework ids that users type or import, checked against the
loaded catalogs.

A control id that is not in the framework's catalog (a typo, an id from
another framework) is never counted by readiness, the audit binder or the
crosswalk, so it must be refused (or, for imports, reported) instead of being
stored silently (R2USER-7). A finding filed under a framework that is not
active for the company never reaches a score card or the trend (R2DATA-6).

Matching is case-insensitive and whitespace-tolerant; the stored spelling is
always the catalog's ("ac-2 " -> "AC-2").
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import exists
from sqlalchemy.orm import Session

from models.control import Control
from models.framework_activation import FrameworkActivation

_SHOWN = 10


def _key(control_id: str) -> str:
    return " ".join((control_id or "").split()).casefold()


def _listed(ids: list[str]) -> str:
    return ", ".join(ids[:_SHOWN]) + (f" (+{len(ids) - _SHOWN} more)" if len(ids) > _SHOWN else "")


def has_catalog(db: Session, framework_id: str) -> bool:
    return db.query(exists().where(Control.framework_id == framework_id)).scalar()


def active_framework_ids(db: Session, organization_id: int) -> list[str]:
    """Frameworks active for the company whose catalog is loaded."""
    return [fid for (fid,) in db.query(FrameworkActivation.framework_id).filter(
        FrameworkActivation.organization_id == organization_id,
        FrameworkActivation.is_active == True,  # noqa: E712
        exists().where(Control.framework_id == FrameworkActivation.framework_id),
    ).all()]


def require_active_framework(db: Session, organization_id: int, framework_id: str) -> None:
    """422 unless the framework is active for the company and its catalog is
    loaded — findings anywhere else would never be counted."""
    if framework_id not in active_framework_ids(db, organization_id):
        raise HTTPException(422, f"Framework '{framework_id}' is not active for this company. "
                                 "Activate it in the Marketplace first, or choose an active framework.")


class CatalogIndex:
    """Lookup of catalog control ids for a set of frameworks."""

    def __init__(self, db: Session, framework_ids: list[str] | set[str]):
        self.framework_ids = sorted(set(framework_ids))
        self._by_fw: dict[str, dict[str, str]] = {fid: {} for fid in self.framework_ids}
        if self.framework_ids:
            for fid, cid in db.query(Control.framework_id, Control.control_id).filter(
                Control.framework_id.in_(self.framework_ids)
            ):
                self._by_fw[fid].setdefault(_key(cid), cid)

    def missing_catalogs(self) -> list[str]:
        return [fid for fid, ids in self._by_fw.items() if not ids]

    def canonical(self, control_id: str, framework_id: str | None = None) -> str | None:
        """The catalog spelling of ``control_id`` (in ``framework_id``, or in
        any indexed framework), or None when it is unknown."""
        k = _key(control_id)
        fws = [framework_id] if framework_id else self.framework_ids
        for fid in fws:
            hit = self._by_fw.get(fid, {}).get(k)
            if hit:
                return hit
        return None

    def split(self, control_ids: list[str], framework_id: str | None = None) -> tuple[list[str], list[str]]:
        """(known ids in catalog spelling, unknown ids as given)."""
        known, unknown = [], []
        for cid in control_ids:
            c = self.canonical(cid, framework_id)
            if c is None:
                unknown.append(cid.strip())
            elif c not in known:
                known.append(c)
        return known, unknown


def require_known_controls(db: Session, organization_id: int, control_ids: list[str],
                           framework_ids: list[str]) -> list[str]:
    """Evidence linkage: every control id must exist in the catalog of one of
    ``framework_ids`` (or, when none are given, of an active framework).
    Returns the ids in catalog spelling; 422 listing the unknown ones."""
    if framework_ids:
        index = CatalogIndex(db, framework_ids)
        missing = index.missing_catalogs()
        if missing:
            raise HTTPException(422, f"Unknown framework(s): {_listed(missing)}. "
                                     "Use the id of a framework that is loaded on this install.")
    else:
        if not control_ids:
            return []
        index = CatalogIndex(db, active_framework_ids(db, organization_id))
        if not index.framework_ids:
            raise HTTPException(422, "No framework is active, so linked control ids can't be checked. "
                                     "Activate a framework first.")
    known, unknown = index.split(control_ids)
    if unknown:
        where = ", ".join(index.framework_ids)
        raise HTTPException(422, f"Control id(s) not in the {where} catalog: {_listed(unknown)}. "
                                 "Check the spelling (e.g. AC-2 or AC.L2-3.1.1).")
    return known


def require_known_control(db: Session, control_id: str | None, framework_id: str) -> str:
    """A finding's single control id: '' stays '' (no control), anything else
    must be in the finding framework's catalog. Returns the catalog spelling."""
    if not (control_id or "").strip():
        return ""
    hit = CatalogIndex(db, [framework_id]).canonical(control_id, framework_id)
    if hit is None:
        raise HTTPException(422, f"Control id '{control_id.strip()}' is not in the {framework_id} catalog. "
                                 "Check the spelling, or leave Control ID empty.")
    return hit
