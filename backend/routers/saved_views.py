"""Saved filter views — per-user named filter sets for list pages."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user
from models.saved_view import SavedView
from models.user import User

router = APIRouter()

MAX_VIEWS_PER_PAGE = 20


class ViewCreate(BaseModel):
    page: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=60)
    params: dict = {}


def _serialize(v: SavedView) -> dict:
    return {"id": v.id, "page": v.page, "name": v.name, "params": v.params or {}}


@router.get("")
def list_views(page: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(SavedView).filter(
        SavedView.user_id == user.id,
        SavedView.organization_id == user.organization_id,
        SavedView.page == page,
    ).order_by(SavedView.name).all()
    return [_serialize(v) for v in rows]


@router.post("")
def create_view(req: ViewCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(SavedView).filter(
        SavedView.user_id == user.id,
        SavedView.organization_id == user.organization_id,
        SavedView.page == req.page,
    )
    existing = q.filter(SavedView.name == req.name).first()
    if existing:  # same name = update in place (natural "save again" behavior)
        existing.params = req.params
        db.commit()
        return _serialize(existing)
    if q.count() >= MAX_VIEWS_PER_PAGE:
        raise HTTPException(422, f"View limit reached ({MAX_VIEWS_PER_PAGE} per page)")
    v = SavedView(organization_id=user.organization_id, user_id=user.id,
                  page=req.page, name=req.name, params=req.params)
    db.add(v)
    db.commit()
    return _serialize(v)


@router.delete("/{view_id}")
def delete_view(view_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    v = db.query(SavedView).filter(
        SavedView.id == view_id,
        SavedView.user_id == user.id,  # own views only
        SavedView.organization_id == user.organization_id,
    ).first()
    if not v:
        raise HTTPException(404, "View not found")
    db.delete(v)
    db.commit()
    return {"ok": True}
