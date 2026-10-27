"""Migration endpoints — import existing POA&M / SSP data.

Stateless preview→commit: the same upload is sent twice, once with
commit=false (parse + validate, no writes) and once with commit=true.
Non-clobber guarantees: POA&M rows that duplicate an existing finding title on
the target system+framework are skipped; SSP rows never overwrite an
implementation a human already assessed (only missing / NOT_ASSESSED rows).
"""
from fastapi.concurrency import run_in_threadpool
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from database import get_db
from dependencies import require_can
from models.control import Control
from models.control_implementation import ControlImplementation
from models.finding import Finding
from models.system import System
from models.user import User
from services import audit as audit_svc
from services.import_common import ImportFileError, read_upload_capped
from services.migration_import import parse_poam, parse_ssp, poam_identity
from services.payload import safe_commit
from services.control_catalog import CatalogIndex, require_active_framework
from services.permissions import can
from services.aging import TERMINAL_STATUSES
from services.system_scope import system_scope_filter

router = APIRouter()

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MiB — POA&Ms are small


def _require_system(db: Session, user: User, system_id: int) -> System:
    system = db.query(System).filter(
        System.id == system_id, System.organization_id == user.organization_id,
        *system_scope_filter(System.id, db, user),
    ).first()
    if not system:
        raise HTTPException(404, "System not found")
    return system


async def _read(file: UploadFile) -> bytes:
    raw = await read_upload_capped(file, MAX_FILE_SIZE)
    if not raw.strip():
        raise HTTPException(422, "Empty file")
    return raw


def _parse_sync(parser, raw: bytes) -> dict:
    try:
        return parser(raw)
    except ImportFileError as exc:
        raise HTTPException(422, str(exc))


async def _parse(parser, raw: bytes) -> dict:
    # CPU-bound parse off the event loop (R2SEC-4).
    return await run_in_threadpool(_parse_sync, parser, raw)


@router.post("/poam")
async def import_poam(
    system_id: int = Form(...),
    framework_id: str = Form(...),
    commit: bool = Form(False),
    file: UploadFile = File(...),
    user: User = Depends(require_can("edit:finding")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    require_active_framework(db, user.organization_id, framework_id)
    result = await _parse(parse_poam, await _read(file))
    rows, issues = result["rows"], result["issues"]
    # Control ids: stored in the catalog's spelling; ids the catalog doesn't
    # have are kept as given (the POA&M is the record) but reported (R2USER-7).
    catalog = CatalogIndex(db, [framework_id])
    unknown_ctrl: list[str] = []
    for r in rows:
        if r["control_id"]:
            hit = catalog.canonical(r["control_id"], framework_id)
            if hit is None:
                unknown_ctrl.append(r["control_id"])
            else:
                r["control_id"] = hit
    if unknown_ctrl:
        shown = list(dict.fromkeys(unknown_ctrl))
        issues.append(f"{len(unknown_ctrl)} item(s) name a control that is not in the {framework_id} catalog "
                      f"({', '.join(shown[:8])}{'…' if len(shown) > 8 else ''}) — imported, but they won't "
                      "count toward that control until the Control ID is corrected")
    terminal = sum(1 for r in rows if r["status"] in TERMINAL_STATUSES)
    if terminal and not can(user.role, "approve:finding_close"):
        # Same rule as PATCH / bulk: a closed or accepted finding is an approval decision.
        raise HTTPException(403, f"This POA&M has {terminal} closed / risk-accepted / false-positive item(s); "
                                 "importing them needs the approve:finding_close permission.")

    # Re-import identity = poam_identity(): the POA&M ID when the row has one,
    # else the title. Findings with no stored ID (imported before IDs were
    # kept, or entered by hand) are ADOPTED once: the first ID-bearing row with
    # the same title writes its ID onto that finding instead of creating a new
    # one; later rows with other IDs are distinct items and are created.
    # Re-importing stays idempotent because the adopted finding now has the ID.
    existing_ids: set[tuple[str, str]] = set()
    existing_titles: set[str] = set()
    legacy_by_title: dict[str, list[Finding]] = {}
    for f in db.query(Finding).filter(
        Finding.organization_id == user.organization_id,
        Finding.system_id == system_id,
        Finding.framework_id == framework_id,
    ).order_by(Finding.id).all():
        tkey = poam_identity("", f.title)[1]
        existing_titles.add(tkey)
        stored = f.extra_data.get("poam_id") if isinstance(f.extra_data, dict) else None
        if stored:
            existing_ids.add(poam_identity(str(stored), f.title))
        else:
            legacy_by_title.setdefault(tkey, []).append(f)

    new_rows: list[dict] = []
    adoptions: list[tuple[Finding, str]] = []
    for r in rows:
        key = poam_identity(r["poam_id"], r["title"])
        if key[0] == "title":
            if key[1] not in existing_titles:
                new_rows.append(r)
            continue
        if key in existing_ids:
            continue
        legacy = legacy_by_title.get(poam_identity("", r["title"])[1])
        if legacy:
            adoptions.append((legacy.pop(0), r["poam_id"]))
        else:
            new_rows.append(r)
    dupes = len(rows) - len(new_rows) - len(adoptions)

    if not commit:
        return {
            "kind": "poam", "total": len(rows), "new": len(new_rows),
            "duplicates": dupes, "adopted": len(adoptions), "merged_in_file": result["merged"], "issues": issues,
            "mapped_columns": result["mapped_columns"],
            "preview": new_rows[:20],
        }

    from datetime import date as _date
    for finding, poam_id in adoptions:
        finding.extra_data = {**(finding.extra_data or {}), "poam_id": poam_id}  # reassign: JSON change tracking
    for r in new_rows:
        db.add(Finding(
            organization_id=user.organization_id, system_id=system_id,
            framework_id=framework_id, control_id=r["control_id"],
            title=r["title"], description=r["description"],
            severity=r["severity"], status=r["status"],
            due_date=_date.fromisoformat(r["due_date"]) if r["due_date"] else None,
            owner_name=r["owner_name"], owner_email=r["owner_email"],
            remediation_plan=r["remediation_plan"], milestones=r["milestones"],
            actual_completion=_date.fromisoformat(r["actual_completion"]) if r["actual_completion"] else None,
            risk_rationale=r["risk_rationale"] or None,
            extra_data={"poam_id": r["poam_id"]} if r["poam_id"] else {},
        ))
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="MIGRATION_IMPORT", entity_type="finding",
        system_id=system_id,
        summary=f"POA&M import: {len(new_rows)} finding(s) created for {framework_id} ({dupes} duplicate(s) skipped"
                + (f", {len(adoptions)} existing finding(s) linked to their POA&M ID" if adoptions else "")
                + (f", {result['merged']} repeated row(s) merged" if result["merged"] else "") + ")",
    )
    safe_commit(db)
    return {"kind": "poam", "created": len(new_rows), "duplicates": dupes, "adopted": len(adoptions),
            "merged_in_file": result["merged"], "issues": issues}


@router.post("/ssp")
async def import_ssp(
    system_id: int = Form(...),
    framework_id: str = Form(...),
    commit: bool = Form(False),
    file: UploadFile = File(...),
    user: User = Depends(require_can("assess:control")),
    db: Session = Depends(get_db),
):
    _require_system(db, user, system_id)
    from routers.frameworks import require_framework_visible
    require_framework_visible(framework_id, user)
    result = await _parse(parse_ssp, await _read(file))
    rows, issues = result["rows"], result["issues"]

    catalog_ids = {
        cid for (cid,) in db.query(Control.control_id).filter(
            Control.framework_id == framework_id).all()
    }
    if not catalog_ids:
        raise HTTPException(404, "Framework has no controls loaded (activate it first)")

    matched = [r for r in rows if r["control_id"] in catalog_ids]
    unknown = [r["control_id"] for r in rows if r["control_id"] not in catalog_ids]
    if unknown:
        issues.append(f"{len(unknown)} control id(s) not in the {framework_id} catalog "
                      f"(skipped): {', '.join(unknown[:8])}{'…' if len(unknown) > 8 else ''}")

    existing = {
        i.control_id: i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == system_id,
            ControlImplementation.framework_id == framework_id,
            ControlImplementation.control_id.in_([r["control_id"] for r in matched]),
        ).all()
    } if matched else {}
    would_skip = sum(
        1 for r in matched
        if (i := existing.get(r["control_id"])) is not None
        and i.implementation_status != "NOT_ASSESSED"
    )

    if not commit:
        return {
            "kind": "ssp", "total": len(rows), "matched": len(matched),
            "unknown_controls": len(unknown), "already_assessed": would_skip,
            "issues": issues, "mapped_columns": result["mapped_columns"],
            "preview": matched[:20],
        }

    written = 0
    skipped = 0
    for r in matched:
        impl = existing.get(r["control_id"])
        if impl is None:
            db.add(ControlImplementation(
                system_id=system_id, framework_id=framework_id,
                control_id=r["control_id"], implementation_status=r["status"],
                narrative=r["narrative"], responsible_party=r["responsible_party"],
            ))
            written += 1
        elif impl.implementation_status == "NOT_ASSESSED":
            impl.implementation_status = r["status"]
            impl.narrative = impl.narrative or r["narrative"]
            impl.responsible_party = impl.responsible_party or r["responsible_party"]
            written += 1
        else:
            skipped += 1  # human-assessed — never overwrite

    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="MIGRATION_IMPORT", entity_type="control_implementation",
        system_id=system_id,
        summary=f"SSP import: {written} implementation(s) written for {framework_id} "
                f"({skipped} already-assessed skipped, {len(unknown)} unknown control(s))",
    )
    safe_commit(db)
    return {"kind": "ssp", "written": written, "already_assessed": skipped,
            "unknown_controls": len(unknown), "issues": issues}
