from datetime import date
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_TRUE_VALUES = {"1", "true", "yes", "y", "t"}
_FALSE_VALUES = {"0", "false", "no", "n", "f"}


def safe_commit(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        msg = str(exc.orig) if exc.orig else str(exc)
        if "UNIQUE constraint" in msg:
            raise HTTPException(409, "Duplicate record — this entry already exists") from exc
        if "FOREIGN KEY constraint" in msg or "NOT NULL constraint" in msg:
            raise HTTPException(400, "Invalid reference or missing required field") from exc
        raise HTTPException(400, "Data integrity error — check your input and try again") from exc


def coerce_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE_VALUES:
            return True
        if v in _FALSE_VALUES:
            return False
    return None


def coerce_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        return [p.strip() for p in value.split(",") if p.strip()]
    return []


def coerce_dates(payload: dict, fields: set[str]) -> dict:
    out = dict(payload)
    for k in fields:
        v = out.get(k)
        if isinstance(v, str) and v:
            try:
                out[k] = date.fromisoformat(v)
            except ValueError as exc:
                raise HTTPException(
                    422, f"Invalid ISO date for {k}: {v}"
                ) from exc
        elif v == "":
            out[k] = None
    return out
