"""Minimal SMTP sender for email digests.

No email is sent unless SMTP is configured (smtp_host + smtp_from). STARTTLS by
default; auth only when smtp_user is set. Self-hosted/air-gapped installs simply
leave SMTP unset and the digest scheduler stays dormant.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from config import settings


class EmailNotConfigured(RuntimeError):
    pass


def is_configured() -> bool:
    return settings.smtp_configured


def send_email(to: list[str], subject: str, html: str, text: str) -> None:
    """Send one multipart (text + html) message. Raises EmailNotConfigured if
    SMTP isn't set up, or smtplib errors propagate to the caller."""
    if not settings.smtp_configured:
        raise EmailNotConfigured("SMTP is not configured (set SMTP_HOST and SMTP_FROM)")
    recipients = [a for a in to if a]
    if not recipients:
        return

    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    # Refuse to transmit credentials over an unencrypted connection — a
    # misconfiguration (SMTP_USER set with SMTP_USE_TLS=false) would otherwise
    # leak the SMTP username/password in cleartext on the wire.
    if settings.smtp_user and not settings.smtp_use_tls:
        raise EmailNotConfigured(
            "SMTP_USER is set but SMTP_USE_TLS is false — refusing to send credentials "
            "over an unencrypted connection. Enable TLS or use an unauthenticated relay."
        )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as server:
        if settings.smtp_use_tls:
            server.starttls(context=ssl.create_default_context())
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)
