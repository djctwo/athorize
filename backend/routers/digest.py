"""Email digest: preview, configuration status, and on-demand test send."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from dependencies import require_role
from models.user import User
from services import digest as digest_svc
from services import email as email_svc
from services import audit as audit_svc

router = APIRouter()


@router.get("/config")
def digest_config(
    user: User = Depends(require_role("admin", "compliance_manager")),
    db: Session = Depends(get_db),
):
    return {
        "smtp_configured": email_svc.is_configured(),
        "recipients": digest_svc.recipients(db, user.organization_id),
    }


@router.get("/preview")
def digest_preview(
    user: User = Depends(require_role("admin", "compliance_manager")),
    db: Session = Depends(get_db),
):
    d = digest_svc.build_digest(db, user.organization_id)
    return {
        "digest": d,
        "subject": digest_svc.subject(d),
        "html": digest_svc.render_html(d),
        "has_content": digest_svc.has_content(d),
    }


@router.post("/send-test")
def digest_send_test(
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    if not email_svc.is_configured():
        raise HTTPException(400, "SMTP is not configured. Set SMTP_HOST and SMTP_FROM.")
    if not user.email:
        raise HTTPException(400, "Your account has no email address set.")
    d = digest_svc.build_digest(db, user.organization_id)
    try:
        email_svc.send_email([user.email], digest_svc.subject(d), digest_svc.render_html(d), digest_svc.render_text(d))
    except Exception as exc:  # SMTP/connection errors surface to the admin
        raise HTTPException(502, f"Send failed: {exc}")
    audit_svc.record(
        db, organization_id=user.organization_id, actor_id=user.id,
        actor_username=user.username, action="SEND", entity_type="digest",
        summary=f"Sent test digest to {user.email}",
    )
    db.commit()
    return {"ok": True, "sent_to": user.email}
