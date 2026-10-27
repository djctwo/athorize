from typing import Any, Callable

from fastapi import HTTPException
from sqlalchemy.orm import Session

MAX_ROWS = 5000
MAX_ERRORS = 500
PREVIEW_LIMIT = 25

ValidateRow = Callable[[int, dict], tuple[dict | None, list[dict]]]


def run_bulk_import(
    db: Session,
    *,
    organization_id: int,
    system_id: int,
    rows: Any,
    commit: bool,
    system_model,
    record_model,
    validate_row: ValidateRow,
) -> dict:
    system = (
        db.query(system_model)
        .filter(system_model.id == system_id, system_model.organization_id == organization_id)
        .first()
    )
    if not system:
        raise HTTPException(404, "System not found")
    if not isinstance(rows, list):
        raise HTTPException(400, "rows must be a list")
    if len(rows) > MAX_ROWS:
        raise HTTPException(400, f"too many rows (max {MAX_ROWS})")

    # Every row is validated; only the error LIST is capped (MAX_ERRORS) so the
    # response stays small. error_count is the true total, and
    # errors_truncated says when the list is incomplete.
    valid: list[dict] = []
    errors: list[dict] = []
    error_total = 0
    invalid_rows = 0
    for idx, raw in enumerate(rows):
        if not isinstance(raw, dict):
            errs = [{"row": idx, "field": "*", "message": "row must be an object"}]
            v = None
        else:
            v, errs = validate_row(idx, raw)
        if v is not None:
            valid.append(v)
        else:
            invalid_rows += 1
        error_total += len(errs)
        if len(errors) < MAX_ERRORS:
            errors.extend(errs[:MAX_ERRORS - len(errors)])
    counts = {
        "error_count": error_total,
        "invalid_rows": invalid_rows,
        "errors_truncated": error_total > len(errors),
    }

    if not commit:
        return {
            "valid_count": len(valid),
            **counts,
            "errors": errors,
            "preview": valid[:PREVIEW_LIMIT],
        }

    for clean in valid:
        db.add(record_model(organization_id=organization_id, system_id=system_id, **clean))
    db.commit()
    return {
        "valid_count": len(valid),
        **counts,
        "errors": errors,
        "committed": len(valid),
    }
