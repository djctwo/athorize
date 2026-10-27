"""Minimal, dependency-light OpenID Connect (Authorization Code) client.

Uses only httpx + cryptography (no authlib/jose). Discovers the provider's
endpoints, builds the authorization redirect, exchanges the code, and verifies
the id_token's RS256 signature against the provider JWKS plus the standard
iss/aud/exp/nonce claims.

Enabled only when OIDC_ENABLED is true and issuer/client are configured.
"""
from __future__ import annotations

import base64
import json
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from config import settings
from services.safe_http import INTERNAL, guarded_client

_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_JWKS_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 3600  # seconds
HTTP_TIMEOUT = 15


class OidcError(RuntimeError):
    pass


def is_enabled() -> bool:
    return bool(
        settings.oidc_enabled
        and settings.oidc_issuer
        and settings.oidc_client_id
        and settings.oidc_redirect_uri
    )


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _require_https(url: str, label: str) -> None:
    """Reject any endpoint that isn't HTTPS (localhost allowed for dev IdPs).

    The login redirect sends the browser to `authorization_endpoint`, so an
    http:// or attacker-substituted endpoint would be an open-redirect / MITM
    vector. Endpoints come from the operator-configured issuer's discovery
    document; pinning them to HTTPS keeps the redirect target trustworthy.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    is_local = host in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_local):
        raise OidcError(f"OIDC {label} must be https: {url!r}")


def _client() -> httpx.Client:
    """IdPs are often on-prem, so private ranges are allowed, but every
    connection is pinned to its validated IP and cloud-metadata / link-local
    addresses are refused — the discovery document (a network response)
    chooses token_endpoint and jwks_uri. Scheme is checked by _require_https."""
    return guarded_client(INTERNAL, https_only=False, timeout=HTTP_TIMEOUT)


def discover() -> dict:
    issuer = settings.oidc_issuer.rstrip("/")
    _require_https(issuer, "issuer")
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and cached[0] > time.time():
        return cached[1]
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with _client() as client:
            resp = client.get(url)
            resp.raise_for_status()
            doc = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError(f"OIDC discovery failed: {exc}")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if key not in doc:
            raise OidcError(f"OIDC discovery document missing {key}")
    # Anchor trust to the operator-configured issuer, not the doc's self-claim:
    # the id_token `iss` is later compared to doc["issuer"], so that value must
    # equal the configured issuer or an attacker-served doc could move the anchor.
    if doc["issuer"].rstrip("/") != issuer:
        raise OidcError("OIDC discovery issuer does not match the configured OIDC_ISSUER")
    # Pin every endpoint the browser or server will be sent to, to HTTPS.
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _require_https(doc[key], key)
    _DISCOVERY_CACHE[issuer] = (time.time() + _CACHE_TTL, doc)
    return doc


def _jwks(jwks_uri: str) -> dict:
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached and cached[0] > time.time():
        return cached[1]
    try:
        with _client() as client:
            resp = client.get(jwks_uri)
            resp.raise_for_status()
            keys = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError(f"JWKS fetch failed: {exc}")
    _JWKS_CACHE[jwks_uri] = (time.time() + _CACHE_TTL, keys)
    return keys


def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge) — RFC 7636."""
    import hashlib
    import secrets
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def build_authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    doc = discover()
    from urllib.parse import urlencode
    params = {
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
    }
    return f"{doc['authorization_endpoint']}?{urlencode(params)}"


def exchange_code(code: str, code_verifier: str) -> dict:
    doc = discover()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": settings.oidc_redirect_uri,
        "client_id": settings.oidc_client_id,
    }
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret
    try:
        with _client() as client:
            resp = client.post(doc["token_endpoint"], data=data)
            resp.raise_for_status()
            tokens = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise OidcError(f"Token exchange failed: {exc}")
    if "id_token" not in tokens:
        raise OidcError("Token response has no id_token")
    return tokens


def _public_key_for(kid: str | None, jwks_uri: str):
    keys = [k for k in _jwks(jwks_uri).get("keys", []) if k.get("kty") == "RSA"]
    # When the token header names a kid, require an EXACT match — never fall back
    # to "first RSA key", which breaks on key rotation and weakens key binding.
    if kid:
        keys = [k for k in keys if k.get("kid") == kid]
    for jwk in keys:
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise OidcError("No matching RSA key in provider JWKS")


def verify_id_token(id_token: str, expected_nonce: str, *, require_nonce: bool = True) -> dict:
    """Verify signature + standard claims; return the claim set.

    The nonce is required (replay protection for the browser flow); only a
    non-interactive grant with no nonce (tests against a live IdP) may pass
    require_nonce=False."""
    if require_nonce and not expected_nonce:
        raise OidcError("Missing nonce")
    try:
        header_b64, payload_b64, sig_b64 = id_token.split(".")
    except ValueError:
        raise OidcError("Malformed id_token")
    header = json.loads(_b64url_decode(header_b64))
    if header.get("alg") != "RS256":
        raise OidcError(f"Unsupported id_token alg: {header.get('alg')}")

    doc = discover()
    pub = _public_key_for(header.get("kid"), doc["jwks_uri"])
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        pub.verify(_b64url_decode(sig_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise OidcError("id_token signature verification failed")

    claims = json.loads(_b64url_decode(payload_b64))
    if claims.get("iss") != doc["issuer"]:
        raise OidcError("id_token issuer mismatch")
    aud = claims.get("aud")
    aud_ok = settings.oidc_client_id == aud or (isinstance(aud, list) and settings.oidc_client_id in aud)
    if not aud_ok:
        raise OidcError("id_token audience mismatch")
    if claims.get("exp", 0) < time.time():
        raise OidcError("id_token expired")
    if (require_nonce or expected_nonce) and claims.get("nonce") != expected_nonce:
        raise OidcError("id_token nonce mismatch")
    if not claims.get("email"):
        raise OidcError("id_token has no email claim")
    # Require an explicitly VERIFIED email. Accounts are matched/provisioned by
    # email, so an unverified address would allow taking over an existing user
    # (e.g. an admin) who happens to share that email. `email_verified` arrives
    # as a bool or a string depending on the IdP (Google has shipped "true"/
    # "false" strings) — accept only explicit truthiness; reject false, "false",
    # 0, and absence alike. Configure your IdP to assert email_verified=true.
    ev = claims.get("email_verified")
    if not (ev is True or (isinstance(ev, str) and ev.strip().lower() == "true")):
        raise OidcError("id_token email is not verified (email_verified must be true)")
    return claims
