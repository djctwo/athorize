"""@mention parsing + notification emails for comments.

A mention is an `@username` token in a comment body that matches an active
user in the author's organization who can see the commented item (system
scope: a SCADA-only contractor is never emailed about an ERP finding). Matching is case-insensitive (usernames are
stored as typed; comparing normalized avoids the silent case-mismatch trap).
When SMTP is configured, each mentioned user (except the author) gets one
short email; delivery failures never block the comment itself.
"""
from __future__ import annotations

import html
import re

from sqlalchemy.orm import Session

from models.user import User

MENTION_RE = re.compile(r"@([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_mentions(db: Session, organization_id: int, body: str,
                   system_id: int | None = None) -> list[int]:
    """User ids of active org members @mentioned in the body (sorted, deduped).
    With system_id, only users whose system scope includes that system."""
    tokens: set[str] = set()
    for raw in MENTION_RE.findall(body or ""):
        tokens.add(raw.lower())
        # "@bob." at the end of a sentence captures "bob." — also try the token
        # with trailing punctuation-ish username chars stripped.
        stripped = raw.rstrip("._-").lower()
        if stripped:
            tokens.add(stripped)
    if not tokens:
        return []
    users = db.query(User).filter(
        User.organization_id == organization_id,
        User.is_active == True,  # noqa: E712
    ).all()
    matched = [u for u in users if (u.username or "").lower() in tokens]
    if system_id is not None:
        from services.system_scope import allowed_system_ids
        matched = [u for u in matched
                   if (ids := allowed_system_ids(db, u)) is None or system_id in ids]
    return sorted({u.id for u in matched})


def render_mention_email(author_name: str, entity_label: str, entity_name: str,
                         body: str) -> tuple[str, str, str]:
    """(subject, html, text) for one mention notification."""
    subject = f"Athorize: {author_name} mentioned you in a comment"
    text = (
        f'{author_name} mentioned you in a comment on {entity_label} "{entity_name}":\n\n'
        f"{body}\n\nSign in to reply."
    )
    html_body = (
        f"<p>{html.escape(author_name)} mentioned you in a comment on "
        f"{html.escape(entity_label)} <strong>{html.escape(entity_name)}</strong>:</p>"
        f"<blockquote>{html.escape(body)}</blockquote>"
        "<p>Sign in to reply.</p>"
    )
    return subject, html_body, text


def send_mention_emails(db: Session, *, organization_id: int, author: User,
                        mention_ids: list[int], entity_label: str,
                        entity_name: str, body: str) -> int:
    """Email each mentioned user (except the author). Returns emails sent."""
    from services import email as email_svc

    if not email_svc.is_configured() or not mention_ids:
        return 0
    recipients = db.query(User).filter(
        User.id.in_(mention_ids),
        User.organization_id == organization_id,
        User.is_active == True,  # noqa: E712
    ).all()
    author_name = author.display_name or author.username
    sent = 0
    for u in recipients:
        if u.id == author.id or not u.email:
            continue
        subject, html_body, text = render_mention_email(author_name, entity_label, entity_name, body)
        try:
            email_svc.send_email([u.email], subject, html_body, text)
            sent += 1
        except Exception as exc:  # one bad mailbox must not stop the rest
            print(f"mention-emails: {u.username} failed: {exc}")
    return sent
