"""Application settings — the ONE place configuration is resolved.

Sources, highest priority first:
  1. the process environment;
  2. `backend/.env` (or the file ATHORIZE_ENV_FILE names) — every key in it is
     also exported to the process environment, so modules that read
     operational knobs with os.getenv (THREAT_FEEDS, TANIUM_URL, ...) see the
     same values as this Settings object. A `.env` in the working directory is
     NOT read: a double-clicked desktop app starts wherever it was launched
     (e.g. Downloads), and a stray project file there must not redirect the
     database or switch protections off;
  3. secrets only: `<DATA_DIR>/secrets.env` (written by the Docker entrypoint and
     by this module), then the legacy `eval-secrets.env` / `desktop-secrets.env`.

Each setting has one documented name. Old names still work as deprecated
aliases (a warning is logged) — see DEPRECATED_ALIASES.

Secrets: SECRET_KEY and ATHORIZE_AUDIT_HMAC_KEY are generated on first start
and persisted to `<DATA_DIR>/secrets.env` (mode 600) when not configured, so no
install ever runs on a public default key. An explicitly configured audit key
shorter than MIN_SECRET_LEN is refused outside demo mode.
"""
from __future__ import annotations

import logging
import os
import secrets as _secrets
from collections.abc import MutableMapping
from pathlib import Path
from typing import Annotated

from dotenv import dotenv_values
from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode

from _appbase import bundle_root

_logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parent

# old name -> canonical name. Every Athorize-specific setting is ATHORIZE_*;
# the old names keep working (one warning per process).
DEPRECATED_ALIASES = {
    "UNIVERSAL_AUDIT_HMAC_KEY": "ATHORIZE_AUDIT_HMAC_KEY",
    "AUDIT_HMAC_KEY": "ATHORIZE_AUDIT_HMAC_KEY",
    "UNIVERSAL_TRUST_XFF": "ATHORIZE_TRUST_XFF",
    "UNIVERSAL_DISABLE_RATE_LIMIT": "ATHORIZE_DISABLE_RATE_LIMIT",
    "BACKUP_KEEP": "ATHORIZE_BACKUP_KEEP",
    "BACKUP_KEEP_ROLLBACKS": "ATHORIZE_BACKUP_KEEP_ROLLBACKS",
}

# Values shipped in docs/examples (or the old hard-coded fallback). Treated as
# "not configured", never used as a key.
PLACEHOLDER_SECRETS = {
    "change-me-to-a-random-string",
    "audit-chain-default-key",
    "<output of: openssl rand -hex 32>",
}
MIN_SECRET_LEN = 32
SECRETS_FILE_NAME = "secrets.env"
# Read (never written) so installs made by older run-eval.sh / desktop builds
# keep their keys when started some other way.
LEGACY_SECRETS_FILES = ("desktop-secrets.env", "eval-secrets.env")


class ConfigError(RuntimeError):
    """Startup configuration is unsafe or unusable; the message says how to fix it."""


class Settings(BaseSettings):
    secret_key: str = ""
    # Keys the tamper-evident audit-log hash chain (services/audit.py).
    audit_hmac_key: str = Field("", validation_alias=AliasChoices("ATHORIZE_AUDIT_HMAC_KEY", "audit_hmac_key"))
    # Trust X-Forwarded-Proto from the reverse proxy for the Secure cookie flag.
    trust_xff: bool = Field(False, validation_alias=AliasChoices("ATHORIZE_TRUST_XFF", "trust_xff"))
    # Explicit opt-in outbound HTTP(S) proxy for the SSRF-guarded clients
    # (services/safe_http.py). Blank = connect directly (IP-pinned).
    outbound_proxy: str = Field("", validation_alias=AliasChoices("ATHORIZE_OUTBOUND_PROXY", "outbound_proxy"))
    # Extra Host header values accepted (comma-separated) besides localhost /
    # 127.0.0.1 / [::1] and the CORS origins. "*" disables the Host check.
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias=AliasChoices("ATHORIZE_ALLOWED_HOSTS", "allowed_hosts"))
    demo_seed: bool = Field(False, validation_alias=AliasChoices("ATHORIZE_DEMO_SEED", "demo_seed"))

    data_dir: Path = Path.home() / ".athorize-universal"
    database_url: str = ""
    evidence_dir: Path | None = None   # default: <DATA_DIR>/evidence
    backup_dir: Path | None = None     # default: <DATA_DIR>/backups
    # Retention in BACKUP_DIR (0 = keep all).
    backup_keep: int = Field(10, validation_alias=AliasChoices("ATHORIZE_BACKUP_KEEP", "backup_keep"))
    backup_keep_rollbacks: int = Field(
        3, validation_alias=AliasChoices("ATHORIZE_BACKUP_KEEP_ROLLBACKS", "backup_keep_rollbacks"))
    frameworks_dir: Path = bundle_root() / "frameworks"
    # Comma-separated (or a JSON list).
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]
    debug: bool = False
    idle_timeout_minutes: int = 30  # 0 disables idle timeout (absolute 30-day expiry still applies)
    api_token_default_expiry_days: int = 90  # tokens created without an expiry; 0 = never expire

    # SMTP for email digests — all unset by default (no email until configured).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True  # STARTTLS

    # OIDC single sign-on — disabled by default (password auth always works).
    oidc_enabled: bool = False
    oidc_issuer: str = ""            # base URL; discovery at {issuer}/.well-known/openid-configuration
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""      # e.g. https://host/api/auth/oidc/callback
    oidc_scopes: str = "openid email profile"
    oidc_default_role: str = "auditor"   # role for auto-provisioned SSO users
    oidc_auto_provision: bool = True     # create a user on first SSO login
    oidc_provision_org_slug: str = ""    # multi-company: org slug new SSO users join (blank = first org)
    # Comma-separated email domains allowed to sign in via SSO (blank = any).
    oidc_allowed_domains: Annotated[list[str], NoDecode] = []

    # Environment only — .env files are loaded (and exported) by load_settings().
    model_config = {"env_file": None, "extra": "ignore", "populate_by_name": True}

    @field_validator("cors_origins", "allowed_hosts", "oidc_allowed_domains", mode="before")
    @classmethod
    def _split_list(cls, v):
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                import json
                return json.loads(s)
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @model_validator(mode="after")
    def _derive_paths(self):
        # "~" in .env files is common (and in our own example); expand it.
        self.data_dir = Path(os.path.expanduser(str(self.data_dir)))
        self.frameworks_dir = Path(os.path.expanduser(str(self.frameworks_dir)))
        self.evidence_dir = (Path(os.path.expanduser(str(self.evidence_dir)))
                             if self.evidence_dir else self.data_dir / "evidence")
        self.backup_dir = (Path(os.path.expanduser(str(self.backup_dir)))
                           if self.backup_dir else self.data_dir / "backups")
        return self

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'data.db'}"

    @property
    def custom_frameworks_dir(self) -> Path:
        """Customer-authored framework plugins — under the DATA dir (writable,
        survives app updates, never inside the read-only bundle)."""
        return self.data_dir / "custom_frameworks"


def _env_files(environ: MutableMapping[str, str] | None = None) -> list[Path]:
    environ = os.environ if environ is None else environ
    explicit = (environ.get("ATHORIZE_ENV_FILE") or "").strip()
    return [Path(os.path.expanduser(explicit))] if explicit else [BACKEND_DIR / ".env"]


def _export_env_files(environ: MutableMapping[str, str], files: list[Path]) -> None:
    """Export .env keys into `environ` without overriding real env vars."""
    for path in files:
        if not path.is_file():
            continue
        for key, value in dotenv_values(path).items():
            if value is not None and key not in environ:
                environ[key] = value


def _apply_deprecated_aliases(environ: MutableMapping[str, str]) -> None:
    for old, new in DEPRECATED_ALIASES.items():
        if environ.get(old):
            if not environ.get(new):
                environ[new] = environ[old]
            _logger.warning("%s is deprecated; rename it to %s (the old name still works for now).", old, new)


def is_demo_mode(s: Settings) -> bool:
    return bool(s.demo_seed) or (bundle_root() / "DEMO_BUILD").exists()


# Where the audit key in use came from: "environment" (env / backend/.env),
# "file:<name>" (a secrets file in DATA_DIR) or "generated". Read by
# services/audit_key_check.py.
AUDIT_KEY_SOURCE = ""


def _read_secret_file(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.is_file():
        return vals
    try:
        for k, v in dotenv_values(path).items():
            if v:
                vals[DEPRECATED_ALIASES.get(k, k)] = v
    except OSError as exc:
        _logger.warning("Could not read %s: %s", path, exc)
    return vals


def _read_secret_files(data_dir: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    sources: dict[str, str] = {}
    for name in (*LEGACY_SECRETS_FILES, SECRETS_FILE_NAME):  # canonical file read last = wins
        for k, v in _read_secret_file(data_dir / name).items():
            vals[k] = v
            sources[k] = name
    vals["__sources__"] = sources  # type: ignore[assignment]
    return vals


def persisted_audit_keys(data_dir: Path) -> list[tuple[str, str]]:
    """(file name, audit key) for every secrets file in DATA_DIR that holds one,
    canonical file first. Used to find the key that signed an existing log."""
    out = []
    for name in (SECRETS_FILE_NAME, *reversed(LEGACY_SECRETS_FILES)):
        key = (_read_secret_file(data_dir / name).get("ATHORIZE_AUDIT_HMAC_KEY") or "").strip()
        if key and key not in PLACEHOLDER_SECRETS:
            out.append((name, key))
    return out


def check_dir_layout(s: "Settings") -> None:
    """R2SEC-6: backup archives the whole EVIDENCE_DIR and custom-frameworks
    trees and restore swaps them wholesale, so neither may contain (or be) the
    data dir, the backup dir or the other tree — otherwise a backup carries the
    live database and earlier archives, and a restore moves key material
    (secrets.env) out of DATA_DIR."""
    def norm(p: Path) -> Path:
        return Path(os.path.abspath(os.path.expanduser(str(p))))

    named = {"DATA_DIR": norm(s.data_dir), "BACKUP_DIR": norm(s.backup_dir),
             "EVIDENCE_DIR": norm(s.evidence_dir), "custom frameworks folder": norm(s.custom_frameworks_dir)}
    for tree in ("EVIDENCE_DIR", "custom frameworks folder"):
        root = named[tree]
        for other, path in named.items():
            if other == tree:
                continue
            if path == root or path.is_relative_to(root):
                where = "is" if path == root else "is inside"
                raise ConfigError(
                    f"{other} ({path}) {where} {tree} ({root}). Backups archive the whole {tree} and a restore "
                    f"replaces it, so it must be a folder of its own. Set EVIDENCE_DIR to its own folder "
                    f"(the default is <DATA_DIR>/evidence) and move the existing evidence files there.")


def _persist_secrets(data_dir: Path, new: dict[str, str]) -> Path:
    path = data_dir / SECRETS_FILE_NAME
    existing: dict[str, str] = {}
    if path.is_file():
        existing = {k: v for k, v in dotenv_values(path).items() if v}
    existing.update(new)
    lines = ["# Generated by Athorize on first start. KEEP THIS FILE (and back it up separately",
             "# from data backups). Losing ATHORIZE_AUDIT_HMAC_KEY makes the audit log unverifiable."]
    lines += [f"{k}={v}" for k, v in existing.items()]
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".env.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _resolve_secrets(s: Settings) -> None:
    """Fill SECRET_KEY / audit key from config, then persisted files, then
    generate + persist. Refuse a weak explicitly-configured audit key."""
    global AUDIT_KEY_SOURCE
    demo = is_demo_mode(s)
    files = None
    generated: dict[str, str] = {}
    for attr, env_name in (("secret_key", "SECRET_KEY"), ("audit_hmac_key", "ATHORIZE_AUDIT_HMAC_KEY")):
        value = (getattr(s, attr) or "").strip()
        if value in PLACEHOLDER_SECRETS:
            if value:
                _logger.warning("%s is set to a documented placeholder value; ignoring it.", env_name)
            value = ""
        if value:
            if attr == "audit_hmac_key" and len(value) < MIN_SECRET_LEN:
                msg = (f"{env_name} is too short ({len(value)} chars; at least {MIN_SECRET_LEN} required). "
                       "Generate one with: openssl rand -hex 32")
                if not demo:
                    raise ConfigError(msg)
                _logger.warning("%s (allowed in demo mode only)", msg)
            setattr(s, attr, value)
            if attr == "audit_hmac_key":
                AUDIT_KEY_SOURCE = "environment"
            continue
        if files is None:
            files = _read_secret_files(s.data_dir)
        value = (files.get(env_name) or "").strip()
        if value and value not in PLACEHOLDER_SECRETS:
            setattr(s, attr, value)
            if attr == "audit_hmac_key":
                AUDIT_KEY_SOURCE = "file:" + files["__sources__"].get(env_name, SECRETS_FILE_NAME)
            continue
        value = _secrets.token_hex(32)
        generated[env_name] = value
        setattr(s, attr, value)
        if attr == "audit_hmac_key":
            AUDIT_KEY_SOURCE = "generated"
    if generated:
        try:
            path = _persist_secrets(s.data_dir, generated)
        except OSError as exc:
            raise ConfigError(
                f"No {', '.join(generated)} configured and the generated value could not be saved under "
                f"{s.data_dir} ({exc}). Set them in backend/.env or the environment."
            ) from exc
        _logger.warning("Generated %s and saved it to %s (mode 600). Back this file up separately "
                        "from data backups.", ", ".join(generated), path)


def load_settings(environ: MutableMapping[str, str] | None = None,
                  env_files: list[Path] | None = None) -> Settings:
    environ = os.environ if environ is None else environ
    _export_env_files(environ, _env_files(environ) if env_files is None else env_files)
    _apply_deprecated_aliases(environ)
    if environ is os.environ:
        s = Settings()
    else:  # tests: resolve from an explicit mapping
        old = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(environ)
            s = Settings()
        finally:
            os.environ.clear()
            os.environ.update(old)
    check_dir_layout(s)
    _resolve_secrets(s)
    return s


settings = load_settings()
