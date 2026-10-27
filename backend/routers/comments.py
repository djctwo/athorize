"""Comments / @mentions on findings and control implementations.

Any authenticated org member who can SEE the parent entity can read and post
comments on it (visibility runs through the parent: org scope + per-system
SystemAssignment scoping). Posting needs post:comment (every role except the
read-only auditor). Delete is author-or-admin. @mentions are parsed
server-side, resolve only to teammates who can see the parent item, and, when
SMTP is configured, those teammates get an email — there is no in-app
notification center by design.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from dependencies import get_current_user, require_can
from models.comment import Comment
from models.control_implementation import ControlImplementation
from models.finding import Finding
from models.system import System
from models.user import User
from services import audit as audit_svc
from services.mentions import parse_mentions, send_mention_emails
from services.payload import safe_commit
from services.system_scope import system_scope_filter

router = APIRouter()

ENTITY_TYPES = {"finding", "control_implementation"}
MAX_BODY_CHARS = 5000


class CommentCreate(BaseModel):
    entity_type: str
    entity_id: int
    body: str = Field(min_length=1, max_length=MAX_BODY_CHARS)


def _load_parent(db: Session, user: User, entity_type: str, entity_id: int) -> tuple[str, int, str]:
    """Validate the parent entity exists, belongs to the caller's org, and is
    within the caller's system scope. Returns (entity_type, system_id, label).
    404 (not 403) on cross-org / out-of-scope — don't reveal existence."""
    et = (entity_type or "").strip().lower()
    if et not in ENTITY_TYPES:
        raise HTTPException(422, "entity_type must be 'finding' or 'control_implementation'")
    if et == "finding":
        f = db.query(Finding).filter(
            Finding.id == entity_id,
            Finding.organization_id == user.organization_id,
            *system_scope_filter(Finding.system_id, db, user),
        ).first()
        if not f:
            raise HTTPException(404, "Finding not found")
        return et, f.system_id, f.title
    impl = (
        db.query(ControlImplementation)
        .join(System, ControlImplementation.system_id == System.id)
        .filter(
            ControlImplementation.id == entity_id,
            System.organization_id == user.organization_id,
            *system_scope_filter(ControlImplementation.system_id, db, user),
        )
        .first()
    )
    if not impl:
        raise HTTPException(404, "Control implementation not found")
    return et, impl.system_id, f"{impl.framework_id}/{impl.control_id}"


def _serialize(c: Comment, authors: dict[int, User]) -> dict:
    author = authors.get(c.author_id) if c.author_id else None
    return {
        "id": c.id,
        "entity_type": c.entity_type,
        "entity_id": c.entity_id,
        "author_id": c.author_id,
        "author_name": (author.display_name or author.username) if author else "Former user",
        "body": c.body,
        "mentions": c.mentions or [],
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _author_map(db: Session, comments: list[Comment]) -> dict[int, User]:
    ids = {c.author_id for c in comments if c.author_id}
    if not ids:
        return {}
    return {u.id: u for u in db.query(User).filter(User.id.in_(ids)).all()}


@router.get("")
def list_comments(
    entity_type: str,
    entity_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    et, _system_id, _label = _load_parent(db, user, entity_type, entity_id)
    rows = (
        db.query(Comment)
        .filter(
            Comment.organization_id == user.organization_id,
            Comment.entity_type == et,
            Comment.entity_id == entity_id,
        )
        .order_by(Comment.created_at.asc(), Comment.id.asc())
        .all()
    )
    authors = _author_map(db, rows)
    return [_serialize(c, authors) for c in rows]


@router.post("")
def create_comment(
    req: CommentCreate,
    user: User = Depends(require_can("post:comment")),
    db: Session = Depends(get_db),
):
    et, system_id, label = _load_parent(db, user, req.entity_type, req.entity_id)
    body = req.body.strip()
    if not body:
        raise HTTPException(422, "Comment body cannot be empty")

    mention_ids = parse_mentions(db, user.organization_id, body, system_id)
    comment = Comment(
        organization_id=user.organization_id,
        entity_type=et,
        entity_id=req.entity_id,
        author_id=user.id,
        body=body,
        mentions=mention_ids,
    )
    db.add(comment)
    db.flush()
    entity_label = "finding" if et == "finding" else "control implementation"
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="CREATE", entity_type="comment",
        entity_id=comment.id, system_id=system_id,
        summary=f"Commented on {entity_label} '{label}'",
    )
    safe_commit(db)
    db.refresh(comment)

    # Emails go out only after the comment is durably committed; a mail failure
    # must never roll back (or 500) the comment itself.
    try:
        send_mention_emails(
            db, organization_id=user.organization_id, author=user,
            mention_ids=mention_ids, entity_label=entity_label,
            entity_name=label, body=body,
        )
    except Exception as exc:
        print(f"comments: mention emails failed: {exc}")

    return _serialize(comment, _author_map(db, [comment]))


@router.delete("/{comment_id}")
def delete_comment(
    comment_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(
        Comment.id == comment_id,
        Comment.organization_id == user.organization_id,
    ).first()
    if not comment:
        raise HTTPException(404, "Comment not found")
    if comment.author_id != user.id and user.role != "admin":
        raise HTTPException(403, "Only the comment author or an admin can delete a comment")

    entity_label = "finding" if comment.entity_type == "finding" else "control implementation"
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="DELETE", entity_type="comment",
        entity_id=comment.id,
        summary=f"Deleted a comment on {entity_label} #{comment.entity_id}",
    )
    db.delete(comment)
    safe_commit(db)
    return {"ok": True}
