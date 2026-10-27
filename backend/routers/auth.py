import re
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from config import is_demo_mode, settings
from models.user import User
from models.organization import Organization
from models.session import UserSession
from schemas import SetupRequest, DemoSetupRequest, LoginRequest, ChangePasswordRequest, StartFreshRequest, UserOut
from services.auth import DUMMY_HASH, hash_password, verify_password
from services.csrf import generate_csrf_token, set_csrf_cookie, is_secure_request
from services import oidc as oidc_svc
from services import sessions as session_svc
from services import rate_limit
from services.demo_marker import is_demo_instance
from services import audit as audit_svc
from services.password_policy import validate_password
from services.sso_scope import sso_link_company
from services import safe_compare
from services.setup_token import (
    claim_setup_token, clear_setup_token, finish_setup_claim, generate_setup_token, read_setup_token,
    release_setup_claim, setup_claimed, verify_setup_token,
)
from dependencies import get_current_user, get_current_session, ROLE_HIERARCHY
from routers.backup import require_instance_operator

router = APIRouter()

MAX_SESSIONS_PER_USER = 5
OIDC_STATE_COOKIE = "oidc_state"
OIDC_NONCE_COOKIE = "oidc_nonce"
OIDC_PKCE_COOKIE = "oidc_pkce"
# Roles an SSO user may be auto-provisioned into — every known role EXCEPT admin:
# anyone able to authenticate at the IdP would otherwise become an admin on first
# login. Derived from the role catalog so a new role is auto-included (never admin).
OIDC_PROVISIONABLE_ROLES = set(ROLE_HIERARCHY) - {"admin"}


def _safe_oidc_role() -> str:
    role = (settings.oidc_default_role or "").strip()
    return role if role in OIDC_PROVISIONABLE_ROLES else "auditor"


def _establish_session(db: Session, user: User, client_ip: str) -> tuple[str, str]:
    """Create a session for `user`, trimming old sessions past the per-user cap.
    Returns (raw session token for the cookie, csrf_token). Caller commits and
    sets cookies. Only the token's hash is stored (services/sessions.py)."""
    user.last_login = datetime.now(timezone.utc)
    existing = db.query(UserSession).filter(
        UserSession.user_id == user.id
    ).order_by(UserSession.expires_at.desc()).all()
    if len(existing) >= MAX_SESSIONS_PER_USER:
        for old in existing[MAX_SESSIONS_PER_USER - 1:]:
            db.delete(old)
    csrf_token = generate_csrf_token()
    raw, session_id = session_svc.new_token()
    session = UserSession(
        id=session_id,
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        last_activity=datetime.now(timezone.utc),
        ip_address=client_ip,
        csrf_token=csrf_token,
    )
    db.add(session)
    return raw, csrf_token


def _set_session_cookies(response: Response, request: Request, session_id: str, csrf_token: str) -> None:
    secure = is_secure_request(request)
    response.set_cookie("session_id", session_id, httponly=True, samesite="lax", secure=secure, max_age=30 * 86400)
    set_csrf_cookie(response, csrf_token, secure=secure)


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    has_users = db.query(User).first() is not None
    return {
        "setup_complete": has_users,
        # Setup always needs the one-time token (it fails closed).
        "setup_token_required": not has_users,
        "oidc_enabled": oidc_svc.is_enabled(),
        # Deliberately NO demo flag here: this endpoint is anonymous, and
        # "this instance uses the public demo passwords" is an attacker hint.
        # The flag is on /auth/me (authenticated) only — DOCKER-4.
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _require_setup_token(provided: str, request: Request, db: Session) -> None:
    """The one-time setup token gate shared by both Setup-screen choices (set
    up a company / explore with demo data). Wrong tokens from one address are
    rate limited across both."""
    ip = _client_ip(request)
    if not rate_limit.setup_attempt_allowed(ip):
        raise HTTPException(429, "Too many setup attempts. Try again in a minute.")
    # Fail closed: no token file means no setup (SECCODE-9). Generate a fresh
    # one so the operator can recover by reading the log or the data dir —
    # unless another submit holds the token right now or just finished.
    if read_setup_token() is None:
        _refuse_if_setup_busy_or_done(db)
        generate_setup_token()
        raise HTTPException(403, "A setup token is required. A new one was written to the server log "
                                 "and to <DATA_DIR>/setup-token.")
    if not verify_setup_token(provided):
        _refuse_if_setup_busy_or_done(db)
        rate_limit.record_setup_failure(ip)
        raise HTTPException(403, "Invalid or missing setup token.")


@router.post("/setup")
def setup(req: SetupRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if db.query(User).first():
        raise HTTPException(400, "Setup already complete")

    _require_setup_token(req.setup_token, request, db)

    pw_error = validate_password(req.password, username=req.username)
    if pw_error:
        raise HTTPException(422, pw_error)

    # Exactly one submit may run setup: concurrent valid submits (double click,
    # a token-holder racing the real admin) used to create one company and
    # operator admin EACH (R2SEC-7).
    claim = claim_setup_token()
    if claim is None:
        raise HTTPException(400, "Setup already complete or in progress")
    try:
        db.expire_all()
        if db.query(User).first():
            finish_setup_claim(claim)
            raise HTTPException(400, "Setup already complete")
        result = _create_first_admin(req, request, response, db)
    except BaseException:
        if claim.exists():
            release_setup_claim(claim)
        raise
    finish_setup_claim(claim)
    clear_setup_token()
    return result


@router.post("/setup/demo")
def setup_demo(req: DemoSetupRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """First-run alternative to /setup: load the demo data (three sample
    companies, password = username) and sign in as the demo admin. Same token,
    rate limit and one-winner claim as /setup; only an EMPTY instance (no
    companies, no users) is ever seeded, and a failed seed rolls back to an
    empty instance with the token still valid."""
    from services import demo_seed

    if not demo_seed.instance_is_empty(db):
        raise HTTPException(400, "Setup already complete: demo data can only be loaded into an empty instance.")
    _require_setup_token(req.setup_token, request, db)

    claim = claim_setup_token()
    if claim is None:
        raise HTTPException(400, "Setup already complete or in progress")
    seeding = False
    try:
        db.expire_all()
        if not demo_seed.instance_is_empty(db):
            finish_setup_claim(claim)
            raise HTTPException(400, "Setup already complete: demo data can only be loaded into an empty instance.")
        seeding = True
        result, raw, csrf_token = _load_demo(request, db)  # commits
    except BaseException:
        if seeding:
            db.rollback()
            demo_seed.discard_demo_files()
        if claim.exists():
            release_setup_claim(claim)
        raise
    finish_setup_claim(claim)
    clear_setup_token()
    _set_session_cookies(response, request, raw, csrf_token)
    return result


def _load_demo(request: Request, db: Session) -> tuple[dict, str, str]:
    from services import demo_seed

    ip = _client_ip(request)
    demo_seed.seed_demo(db)
    admin = db.query(User).filter(User.username == "admin").one()
    audit_svc.record(db, organization_id=admin.organization_id, actor_id=None, actor_username="setup",
                     action="DEMO_LOAD", entity_type="organization", entity_id=admin.organization_id,
                     summary=f"Demo data loaded from the first-run Setup screen (from {ip}). Every company "
                             "on this instance is sample data; the demo passwords are public.")
    raw, csrf_token = _establish_session(db, admin, ip)
    result = {"user_id": admin.id, "org_id": admin.organization_id, "demo_logins": list(demo_seed.DEMO_LOGINS)}
    db.commit()
    print(f"demo-seed: demo data loaded from the Setup screen (from {ip})")
    return result, raw, csrf_token


def _refuse_if_setup_busy_or_done(db: Session) -> None:
    db.expire_all()
    if setup_claimed():
        raise HTTPException(400, "Setup already complete or in progress")
    if db.query(User).first():
        raise HTTPException(400, "Setup already complete")


def _create_first_admin(req: SetupRequest, request: Request, response: Response, db: Session) -> dict:
    slug = re.sub(r"[^a-z0-9]+", "-", req.org_name.lower()).strip("-")
    org = Organization(name=req.org_name, slug=slug)
    db.add(org)
    db.flush()

    # The bootstrap admin is an operator so a fresh install has someone who can
    # create additional companies and switch between them (multi-company model).
    user = User(
        organization_id=org.id,
        username=req.username,
        password_hash=hash_password(req.password),
        email=req.email,
        display_name=req.display_name or req.username,
        role="admin",
        is_operator=True,
    )
    db.add(user)
    db.flush()

    raw, csrf_token = _establish_session(db, user, request.client.host if request.client else "unknown")
    db.commit()

    _set_session_cookies(response, request, raw, csrf_token)
    return {"user_id": user.id, "org_id": org.id}


@router.post("/login")
def login(req: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    check = rate_limit.login_check(client_ip, req.username)
    if check == rate_limit.DENY:
        raise HTTPException(429, "Too many login attempts. Try again later.")

    # Usernames are globally unique for new accounts; installs from before that
    # rule may still hold the same username in two companies, so check each.
    # Always run exactly one hash when nothing matches, so response time doesn't
    # reveal whether the username exists (SECLIVE-4).
    candidates = db.query(User).filter(User.username == req.username, User.is_active == True).all()  # noqa: E712
    user = None
    for cand in candidates:
        if verify_password(req.password, cand.password_hash):
            user = cand
            break
    if not candidates:
        verify_password(req.password, DUMMY_HASH)
    if user is None:
        rate_limit.record_failure(client_ip, req.username, db)
        if check == rate_limit.CORRECT_ONLY:
            raise HTTPException(429, "Too many login attempts. Try again later.")
        raise HTTPException(401, "Invalid credentials")

    rate_limit.record_success(client_ip, req.username, db)
    session_token, csrf_token = _establish_session(db, user, client_ip)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="LOGIN", entity_type="session",
                     summary=f"Login from {client_ip}")
    db.commit()
    _set_session_cookies(response, request, session_token, csrf_token)
    return {"user_id": user.id, "role": user.role}


@router.get("/oidc/login")
def oidc_login(request: Request):
    """Begin the OIDC Authorization Code flow — redirect to the IdP."""
    if not oidc_svc.is_enabled():
        raise HTTPException(404, "SSO is not enabled")
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = oidc_svc.pkce_pair()
    try:
        url = oidc_svc.build_authorization_url(state, nonce, challenge)
    except oidc_svc.OidcError as exc:
        raise HTTPException(502, str(exc))
    resp = RedirectResponse(url, status_code=302)
    secure = is_secure_request(request)
    # Short-lived httponly state/nonce — CSRF + replay protection across the round-trip.
    resp.set_cookie(OIDC_STATE_COOKIE, state, httponly=True, samesite="lax", secure=secure, max_age=600)
    resp.set_cookie(OIDC_NONCE_COOKIE, nonce, httponly=True, samesite="lax", secure=secure, max_age=600)
    resp.set_cookie(OIDC_PKCE_COOKIE, verifier, httponly=True, samesite="lax", secure=secure, max_age=600,
                    path="/api/auth/oidc")
    return resp


def _claim_str(claims: dict, key: str) -> str:
    v = claims.get(key)
    return str(v).strip() if v is not None else ""


def _email_verified(claims: dict) -> bool:
    ev = claims.get("email_verified")
    return ev is True or (isinstance(ev, str) and ev.strip().lower() == "true")


def _resolve_sso_user(db: Session, claims: dict, email: str) -> tuple[User | None, Organization | None]:
    """(account, company) for an SSO sign-in; account None → JIT into company.

    1. An account bound to the IdP's stable (issuer, sub) pair is the identity,
       whatever email the IdP sends today.
    2. Unbound: the first link is by verified email, and only inside the one
       company SSO links into (services.sso_scope). Every check — deactivated,
       duplicate address, already bound elsewhere — looks at that company's
       accounts only; other tenants' accounts are ignored, so they can neither
       block nor capture the identity (R2SEC-3/-9).
    """
    iss, sub = _claim_str(claims, "iss"), _claim_str(claims, "sub")
    if not iss or not sub:
        raise HTTPException(401, "SSO login failed: id_token has no issuer/subject")
    bound = db.query(User).filter(User.oidc_issuer == iss, User.oidc_subject == sub).first()
    if bound is not None:
        if not bound.is_active:
            raise HTTPException(403, "This account is deactivated — contact an admin.")
        return bound, None

    org = sso_link_company(db)
    if org is None:
        raise HTTPException(403, "This SSO identity is not linked to an account, and SSO cannot link new "
                                 "accounts on this install (the operator must set OIDC_PROVISION_ORG_SLUG).")
    if not _email_verified(claims):
        raise HTTPException(403, "The SSO provider did not verify this email address.")
    # Stored emails may carry any case/whitespace (typed by an admin before
    # emails were normalized) — compare them the way the IdP's address was.
    holders = db.query(User).filter(
        User.organization_id == org.id, func.lower(func.trim(User.email)) == email,
    ).order_by(User.id).all()
    if any(not u.is_active for u in holders):
        raise HTTPException(403, "This account is deactivated — contact an admin.")
    if len(holders) > 1:
        raise HTTPException(409, "Several accounts share this email, so SSO cannot tell which one is yours — "
                                 "an admin must give the address to one account only.")
    if not holders:
        return None, org
    user = holders[0]
    if user.oidc_subject:
        raise HTTPException(409, "This account is already linked to a different SSO identity — an admin can "
                                 "unlink it on the Users page.")
    user.oidc_issuer, user.oidc_subject = iss, sub
    return user, org


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str = "", state: str = "", db: Session = Depends(get_db)):
    """Handle the IdP redirect: validate, find/provision the user, start a session."""
    if not oidc_svc.is_enabled():
        raise HTTPException(404, "SSO is not enabled")
    cookie_state = request.cookies.get(OIDC_STATE_COOKIE)
    nonce = request.cookies.get(OIDC_NONCE_COOKIE) or ""
    verifier = request.cookies.get(OIDC_PKCE_COOKIE) or ""
    if not code or not state or not cookie_state or not safe_compare.equal(state, cookie_state):
        raise HTTPException(400, "Invalid SSO state")
    if not nonce or not verifier:
        raise HTTPException(400, "SSO session expired or cookies blocked — start the sign-in again.")
    try:
        tokens = oidc_svc.exchange_code(code, verifier)
        claims = oidc_svc.verify_id_token(tokens["id_token"], nonce)
    except oidc_svc.OidcError as exc:
        raise HTTPException(401, f"SSO login failed: {exc}")

    email = (claims.get("email") or "").strip().lower()
    allowed = {d.strip().lower().lstrip("@") for d in settings.oidc_allowed_domains if d.strip()}
    if allowed and email.rpartition("@")[2] not in allowed:
        raise HTTPException(403, "This email domain is not allowed to sign in with SSO.")
    user, org = _resolve_sso_user(db, claims, email)
    if user is None:
        if not settings.oidc_auto_provision:
            raise HTTPException(403, "No account for this SSO identity — ask an admin to create one.")
        # JIT joins the company SSO links into (services.sso_scope): the only
        # company on a single-company install, else OIDC_PROVISION_ORG_SLUG.
        base = (email.split("@")[0] or email)[:60]
        username = base
        i = 1
        while db.query(User).filter(User.username == username).first() is not None:
            i += 1
            username = f"{base}{i}"
        user = User(
            organization_id=org.id, username=username, email=email,
            display_name=claims.get("name") or username,
            password_hash=hash_password(secrets.token_urlsafe(32)),  # unusable; SSO only
            role=_safe_oidc_role(), is_active=True,
            oidc_issuer=_claim_str(claims, "iss"), oidc_subject=_claim_str(claims, "sub"),
        )
        db.add(user)
        db.flush()

    client_ip = request.client.host if request.client else "unknown"
    session_token, csrf_token = _establish_session(db, user, client_ip)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="LOGIN", entity_type="session",
                     summary=f"SSO login ({email}) from {client_ip}")
    db.commit()
    resp = RedirectResponse("/", status_code=302)
    _set_session_cookies(resp, request, session_token, csrf_token)
    resp.delete_cookie(OIDC_STATE_COOKIE)
    resp.delete_cookie(OIDC_NONCE_COOKIE)
    resp.delete_cookie(OIDC_PKCE_COOKIE, path="/api/auth/oidc")
    return resp


@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get("session_id")
    if session_id:
        session_obj = session_svc.lookup(db, session_id)
        if session_obj:
            session_user = db.query(User).filter(User.id == session_obj.user_id).first()
            db.delete(session_obj)
            if session_user:
                audit_svc.record(db, organization_id=session_user.organization_id,
                                 actor_id=session_user.id, actor_username=session_user.username,
                                 action="LOGOUT", entity_type="session", summary="Logged out")
        db.commit()
    response.delete_cookie("session_id")
    return {"ok": True}


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    current: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """Self-service password change (R2USER-13): the admin-issued initial
    password no longer has to stay forever. Needs a browser session (not an API
    token) and the current password, follows the same policy as setup and admin
    resets, and signs out every OTHER session and revokes every API token — they
    must not outlive the credential they were created under (as for an admin
    reset, SECCODE-10). Wrong current passwords count toward the login limiter."""
    from services import api_token as api_token_svc
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limit.login_allowed(client_ip, user.username):
        raise HTTPException(429, "Too many attempts. Try again later.")
    if not verify_password(req.current_password, user.password_hash):
        rate_limit.record_failure(client_ip, user.username, db)  # same connection (R2DATA-5)
        raise HTTPException(400, "Current password is incorrect")
    if req.new_password == req.current_password:
        raise HTTPException(422, "The new password must be different from the current one")
    pw_error = validate_password(req.new_password, username=user.username)
    if pw_error:
        raise HTTPException(422, pw_error)

    user.password_hash = hash_password(req.new_password)
    signed_out = db.query(UserSession).filter(
        UserSession.user_id == user.id, UserSession.id != current.id,
    ).delete(synchronize_session=False)
    revoked = api_token_svc.revoke_all_for_user(db, user.id)
    audit_svc.record(db, organization_id=user.organization_id, actor_id=user.id,
                     actor_username=user.username, action="UPDATE", entity_type="user",
                     entity_id=user.id,
                     summary=f"Changed own password ({signed_out} other session(s) signed out"
                             f", {revoked} API token(s) revoked)")
    db.commit()
    return {"ok": True, "other_sessions_signed_out": signed_out, "api_tokens_revoked": revoked}


@router.post("/start-fresh")
def start_fresh(
    req: StartFreshRequest,
    request: Request,
    response: Response,
    # The people who may restore a backup: this replaces every company too.
    user: User = Depends(require_instance_operator),
    db: Session = Depends(get_db),
):
    """Settings -> Start fresh (demo instances only): delete all demo data and
    return to the first-run Setup screen with a new setup token
    (services/start_fresh). Needs an interactive session, the current password
    and the typed confirmation."""
    from services import backup as backup_svc
    from services import start_fresh as start_fresh_svc

    if request.headers.get("authorization", "").lower().startswith("bearer "):
        raise HTTPException(403, "API tokens cannot start fresh — sign in to do this.")
    if not is_demo_instance(db):
        raise HTTPException(409, "Start fresh is only available on a demo instance. This instance holds real "
                                 "data; nothing was deleted.")
    if req.confirm.strip() != start_fresh_svc.CONFIRM_PHRASE:
        raise HTTPException(400, f"Type {start_fresh_svc.CONFIRM_PHRASE} to confirm.")
    client_ip = _client_ip(request)
    if not rate_limit.login_allowed(client_ip, user.username):
        raise HTTPException(429, "Too many attempts. Try again later.")
    if not verify_password(req.password, user.password_hash):
        rate_limit.record_failure(client_ip, user.username, db)  # same connection (R2DATA-5)
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    actor = f"{user.username} (from {client_ip})"
    db.commit()
    try:
        outcome = start_fresh_svc.start_fresh(db, actor)
    except backup_svc.BackupBusy as exc:
        raise HTTPException(409, str(exc))
    response.delete_cookie("session_id")
    return {"ok": True, "next": outcome}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # user.organization_id already reflects the operator's ACTIVE company (the
    # get_current_user override), so /me reports the currently-viewed company.
    org = db.query(Organization).filter(Organization.id == user.organization_id).first()
    branding = ((org.settings or {}).get("branding") or {}) if org else {}
    return UserOut(
        id=user.id, username=user.username, email=user.email,
        display_name=user.display_name, role=user.role, is_active=user.is_active,
        created_at=user.created_at, last_login=user.last_login,
        organization_id=user.organization_id,
        organization_name=org.name if org else None,
        organization_logo=branding.get("logo_data_uri"),
        is_operator=user.is_operator,
        demo_instance=is_demo_instance(db),
        demo_autoseed=is_demo_mode(settings),
    )
