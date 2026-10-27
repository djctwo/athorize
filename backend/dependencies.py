from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value
from database import get_db
from models.user import User
from models.session import UserSession
from models.organization import Organization
from config import settings
from services.csrf import validate_csrf, validate_csrf_session_bound
from services.permissions import can, Action

ROLE_HIERARCHY = {
    "admin": 6,
    "compliance_manager": 5,
    "assessor": 4,
    "system_owner": 3,
    "evidence_contributor": 2,
    "auditor": 1,
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/setup", "/api/auth/setup/demo", "/api/auth/logout"}


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    # Programmatic clients authenticate with a bearer API token. Token auth has
    # no cookie/session, so it is exempt from CSRF; the token acts as its
    # creating user (inheriting that user's role and system scoping).
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        from services import api_token as api_token_svc
        user = api_token_svc.resolve(db, auth_header[7:].strip())
        if user is None:
            raise HTTPException(401, "Invalid or expired API token")
        return user

    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(401, "Not authenticated")

    from services import sessions as session_svc
    session = session_svc.lookup(db, session_id)
    if not session:
        raise HTTPException(401, "Invalid session")

    now = datetime.now(timezone.utc)
    expires = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
    if expires < now:
        db.delete(session)
        db.commit()
        raise HTTPException(401, "Session expired")

    # Idle timeout: sessions inactive longer than idle_timeout_minutes are
    # revoked. Absolute expiry above still caps total lifetime.
    idle_minutes = settings.idle_timeout_minutes
    if idle_minutes > 0 and session.last_activity is not None:
        last = session.last_activity.replace(tzinfo=timezone.utc) if session.last_activity.tzinfo is None else session.last_activity
        if (now - last) > timedelta(minutes=idle_minutes):
            db.delete(session)
            db.commit()
            raise HTTPException(401, "Session expired due to inactivity")

    if request.method not in SAFE_METHODS and request.url.path not in CSRF_EXEMPT_PATHS:
        if not validate_csrf(request):
            raise HTTPException(403, "CSRF validation failed")
        if not validate_csrf_session_bound(request, session.csrf_token):
            raise HTTPException(403, "CSRF session binding failed")

    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(401, "User not found or inactive")

    # Throttle the activity write to once a minute to avoid a DB write per request.
    if session.last_activity is None or (now - (
        session.last_activity.replace(tzinfo=timezone.utc) if session.last_activity.tzinfo is None else session.last_activity
    )) > timedelta(minutes=1):
        session.last_activity = now
        db.commit()

    # Operator org-switch: an operator viewing another company sees/writes to the
    # session's active organization. The override is applied with
    # set_committed_value, which changes the in-memory value WITHOUT marking the
    # attribute dirty — so any later flush/commit by an endpoint (most mutation
    # endpoints commit) can never persist the switch onto the operator's home
    # org. A plain assignment here once did exactly that. db.refresh(user) would
    # discard the override and de-scope the request — don't refresh user rows in
    # endpoint code.
    # Guards: honored only for operators (re-read fresh above, so demotion reverts)
    # and only if the target org still exists (deletion reverts to home org).
    active_org = session.active_organization_id
    if user.is_operator and active_org and active_org != user.organization_id:
        if db.query(Organization.id).filter(Organization.id == active_org).first():
            set_committed_value(user, "organization_id", active_org)

    return user


def get_current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    """Return the caller's UserSession row (for endpoints that must mutate it,
    e.g. org switch). Session-cookie auth only — bearer tokens have no session.
    Auth/CSRF are enforced separately by the endpoint's get_current_user dep."""
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(401, "Not authenticated")
    from services import sessions as session_svc
    session = session_svc.lookup(db, session_id)
    if not session:
        raise HTTPException(401, "Invalid session")
    return session


def require_session_user(request: Request, user: User = Depends(get_current_user)) -> User:
    """The caller, only when signed in interactively (session cookie). Token
    management refuses bearer tokens: a token that could mint tokens would
    outlive its own expiry and revocation (R2SEC-1) — the same rule GitHub
    and GitLab apply to personal access tokens."""
    if request.headers.get("authorization", "").lower().startswith("bearer "):
        raise HTTPException(403, "API tokens cannot create or revoke API tokens — sign in to manage tokens.")
    return user


def require_role(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, f"Requires one of: {', '.join(roles)}")
        return user
    return checker


def require_min_role(min_role: str):
    min_level = ROLE_HIERARCHY.get(min_role, 0)

    def checker(user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        if user_level < min_level:
            raise HTTPException(403, f"Requires at least {min_role} role")
        return user
    return checker


def require_can(action: Action):
    def checker(user: User = Depends(get_current_user)) -> User:
        if not can(user.role, action):
            raise HTTPException(403, f"Permission denied: {action}")
        return user
    return checker
