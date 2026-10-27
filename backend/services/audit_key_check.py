"""Startup check: is the audit key in use the one that signed this instance's
audit log? (R2SEC-5)

Starting Athorize a second way on the same data folder (run-eval.sh, the
desktop app, Docker, a service with keys in backend/.env) used to bring its own
key; every entry written before then reported "tampered" and every entry
written after it was signed with the wrong key, for good. All start paths now
share <DATA_DIR>/secrets.env, and this check catches what is left:

* The newest current-format entry of every company verifies with the key in
  use -> nothing to do.
* It does not, but a key saved in a secrets file in DATA_DIR does:
  - the key in use came from a secrets file itself -> switch to the one that
    provably signed the log (logged loudly);
  - the key was configured explicitly (environment / backend/.env) -> refuse to
    start, naming the file that holds the right key. Demo mode only warns.
* Nothing verifies it (data restored from elsewhere, or tampering) -> a warning;
  Audit Log -> Verify shows the details.
Only the newest entry per company is checked, so this is cheap at any log size.
"""
from __future__ import annotations

import logging

from sqlalchemy import inspect
from sqlalchemy.orm import Session

_logger = logging.getLogger(__name__)


def _newest_samples(engine) -> list[tuple[str, object]]:
    from models.audit import AuditEntry
    from services.audit import GENESIS
    if "audit_entries" not in inspect(engine).get_table_names():
        return []
    samples = []
    with Session(engine) as db:
        for (org_id,) in db.query(AuditEntry.organization_id).distinct():
            last_two = (db.query(AuditEntry).filter(AuditEntry.organization_id == org_id)
                        .order_by(AuditEntry.id.desc()).limit(2).all())
            last = last_two[0]
            if (last.hash_version or 1) < 2:
                continue  # legacy entries may be signed with the old public key: not evidence either way
            prev = last_two[1].integrity_hash if len(last_two) > 1 else GENESIS
            db.expunge(last)
            samples.append((prev, last))
    return samples


def reconcile_audit_key(engine) -> str:
    """Returns "ok", "switched", "unknown" or "empty"; raises config.ConfigError
    when an explicitly configured key would fork the log."""
    import config
    from config import ConfigError, is_demo_mode, persisted_audit_keys, settings
    from services.audit import compute_hash

    samples = _newest_samples(engine)
    if not samples:
        return "empty"

    def signs_all(key: str) -> bool:
        return all(e.integrity_hash == compute_hash(prev, e, key.encode()) for prev, e in samples)

    current = settings.audit_hmac_key
    if signs_all(current):
        return "ok"
    match = next(((name, key) for name, key in persisted_audit_keys(settings.data_dir)
                  if key != current and signs_all(key)), None)
    if match is None:
        _logger.warning(
            "AUDIT KEY: the newest audit-log entries do not verify with the configured "
            "ATHORIZE_AUDIT_HMAC_KEY, and no key saved in %s does either. The data may come from "
            "another instance, or the log was altered. Audit Log -> Verify shows the details.",
            settings.data_dir)
        return "unknown"
    name, key = match
    path = settings.data_dir / name
    source = config.AUDIT_KEY_SOURCE
    if source == "environment" and not is_demo_mode(settings):
        raise ConfigError(
            f"ATHORIZE_AUDIT_HMAC_KEY (set in the environment or backend/.env) is not the key that signed "
            f"this instance's audit log; that key is saved in {path}. Starting with a different key would "
            f"make the existing log unverifiable and sign new entries with the wrong key. Set "
            f"ATHORIZE_AUDIT_HMAC_KEY to the value in {path} (or remove it so the saved key is used).")
    _logger.warning(
        "AUDIT KEY: the key from %s did not sign this instance's audit log; using the key saved in %s, "
        "which did. Remove or correct %s so every way of starting Athorize uses the same key.",
        source or "configuration", path, source.removeprefix("file:") if source.startswith("file:") else "it")
    settings.audit_hmac_key = key
    return "switched"
