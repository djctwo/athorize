"""Password complexity policy.

Beyond the 12-char minimum enforced at the schema layer, require a mix of
character classes and reject the most obvious weak choices. Returned message
is safe to show the user verbatim.
"""
from __future__ import annotations

import re

MIN_LENGTH = 12

_COMMON = {
    "password", "passw0rd", "changeme", "letmein", "admin123456",
    "qwertyuiop", "1234567890", "iloveyou123", "welcome12345",
}


def validate_password(password: str, *, username: str = "") -> str | None:
    """Return an error message if the password is unacceptable, else None."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters."
    classes = sum(bool(rx.search(password)) for rx in (
        re.compile(r"[a-z]"),
        re.compile(r"[A-Z]"),
        re.compile(r"[0-9]"),
        re.compile(r"[^A-Za-z0-9]"),
    ))
    if classes < 3:
        return (
            "Password must include at least three of: lowercase, uppercase, "
            "digit, and symbol."
        )
    lowered = password.lower()
    if lowered in _COMMON:
        return "Password is too common — choose something less guessable."
    if username and len(username) >= 3 and username.lower() in lowered:
        return "Password must not contain the username."
    if re.search(r"(.)\1\1\1", password):
        return "Password must not contain a character repeated four or more times in a row."
    return None
