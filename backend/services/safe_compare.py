"""Constant-time string comparison that never raises.

secrets.compare_digest / hmac.compare_digest raise TypeError for a str with
non-ASCII characters, so a crafted token, header or cookie turned a refusal
into a 500 (R2SEC-18). Compare the UTF-8 bytes instead."""
import hmac


def equal(a: str | None, b: str | None) -> bool:
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))
