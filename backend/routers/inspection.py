import csv
import re
import io
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user
from models.user import User
from services import inspection_prep
from services.csv_safety import safe_csv_cell
from services.system_scope import require_system_allowed
from routers.frameworks import require_framework_visible

router = APIRouter()


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise HTTPException(422, "inspection_date must be YYYY-MM-DD")


def _build(db: Session, user: User, framework_id: str, system_ids: list[int], inspection_date: str | None) -> dict:
    """Shared by the JSON package and the CSV: a user scoped to particular
    systems gets 404 for any system outside that scope (same convention as
    every other per-system surface), never another system's readiness data."""
    if not system_ids:
        raise HTTPException(422, "At least one system_id is required")
    require_framework_visible(framework_id, user)
    for sid in system_ids:
        require_system_allowed(db, user, sid)
    return inspection_prep.build_prep(
        db, user.organization_id, framework_id, system_ids, _parse_date(inspection_date)
    )


@router.get("/prep")
def inspection_prep_package(
    framework_id: str,
    system_ids: list[int] = Query(default=[]),
    inspection_date: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _build(db, user, framework_id, system_ids, inspection_date)


@router.get("/prep/punch-list.csv")
def punch_list_csv(
    framework_id: str,
    system_ids: list[int] = Query(default=[]),
    inspection_date: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pkg = _build(db, user, framework_id, system_ids, inspection_date)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Priority", "System", "Control", "Title", "Family", "Status", "Issues", "Owner"])
    for p in pkg["punch_list"]:
        w.writerow([safe_csv_cell(v) for v in (
            p["priority"], p["system_acronym"], p["control_id"], p["control_title"],
            p["family"], p["status"], "; ".join(p["issues"]), p["owner"] or "",
        )])
    buf.seek(0)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="punch-list-{re.sub(r"[^A-Za-z0-9._-]", "_", framework_id)}-{date.today()}.csv"'},
    )
