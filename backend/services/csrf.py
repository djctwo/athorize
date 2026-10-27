from __future__ import annotations

import secrets

from fastapi import Request, Response
from services import safe_compare

CSRF_COOKIE = "universal_csrf"
CSRF_HEADER = "X-CSRF-Token"


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response: Response, token: str, *, secure: bool = False) -> None:
    response.set_cookie(
        key=CSRF_COOKIE,
        value=token,
        httponly=False,
        samesite="strict",
        secure=secure,
        path="/",
    )


def is_secure_request(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    from config import settings
    if settings.trust_xff:
        proto = request.headers.get("x-forwarded-proto", "").lower()
        if proto == "https":
            return True
    return False


def validate_csrf(request: Request) -> bool:
    cookie_value = request.cookies.get(CSRF_COOKIE, "")
    header_value = request.headers.get(CSRF_HEADER, "")
    if not cookie_value or not header_value:
        return False
    return safe_compare.equal(cookie_value, header_value)


def validate_csrf_session_bound(request: Request, session_csrf: str | None) -> bool:
    if not session_csrf:
        return False
    header_value = request.headers.get(CSRF_HEADER, "")
    if not header_value:
        return False
    return safe_compare.equal(header_value, session_csrf)
