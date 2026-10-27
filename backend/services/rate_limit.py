"""Login throttling that stops guessing without letting outsiders lock users out.

Three counters over a sliding 15-minute window (failures only):

* (address, username) pair — PAIR_MAX failures lock that pair. This is the main
  brute-force stop, and it can't be used against anyone at another address.
* address — IP_MAX failures across any usernames lock the address (password
  spraying), except for usernames that have signed in from it before. A
  locked address still lets a username with NO failures of its own from that
  address sign in with the CORRECT password; any wrong guess gets 429 (like
  an unknown username, so nothing is revealed). Behind Docker port publishing
  every client shares one address, and junk logins must not lock out every
  user who is new to it (R2SEC-17). Usernames the sprayer actually guessed
  are locked for the window.
* username — USER_MAX failures across all addresses put the account under
  attack: sign-in is then refused from addresses it has never signed in from,
  while its *familiar* addresses (successful sign-ins in the last 90 days) are
  subject only to their pair counter. An attacker rotating (or spoofing)
  addresses gets a fixed number of guesses and cannot lock the real user out of
  their usual address ("smart lockout").

Unknown usernames count like real ones, so the limiter reveals nothing.
Locks persist in `rate_limit_state` and familiar addresses in
`login_known_addresses`, across restarts.

The address is request.client.host, which uvicorn derives from
X-Forwarded-For only for proxies listed in FORWARDED_ALLOW_IPS (default
127.0.0.1). Behind Docker port publishing without a proxy every client shares
one address; the pair counter then still keeps one user's typos (or an
attacker) from locking out everybody else — docs/INSTALL.md §14d.
"""
from __future__ import annotations

import logging
import os
import threading
import time

_logger = logging.getLogger(__name__)

WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60
PAIR_MAX = 5
IP_MAX = 30
USER_MAX = 20
FAMILIAR_SECONDS = 90 * 86400

_lock = threading.Lock()
_failures: dict[str, list[float]] = {}   # key -> monotonic timestamps
_lockouts: dict[str, float] = {}         # key -> monotonic expiry
_familiar: dict[str, float] = {}         # "user|ip" -> wall-clock expiry

# Kept for callers of the old per-endpoint helpers.
ENDPOINT_MAX_ATTEMPTS = 20
ENDPOINT_WINDOW_SECONDS = 60
_endpoint_attempts: dict[str, list[float]] = {}


def _engine():
    from database import engine
    return engine


_TABLES = (
    "CREATE TABLE IF NOT EXISTS rate_limit_state (key TEXT PRIMARY KEY, lockout_until REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS login_known_addresses (key TEXT PRIMARY KEY, until REAL NOT NULL)",
)


def _db(sql: str, params: dict | None = None, fetch: bool = False, _retry: bool = True):
    try:
        from sqlalchemy import text
        with _engine().connect() as conn:
            res = conn.execute(text(sql), params or {})
            rows = res.fetchall() if fetch else None
            conn.commit()
            return rows
    except Exception as exc:
        if _retry and "no such table" in str(exc):  # e.g. a DB swapped in by restore
            for ddl in _TABLES:
                _db(ddl, _retry=False)
            return _db(sql, params, fetch, _retry=False)
        _logger.warning("rate_limit_state: %s", exc)
        return [] if fetch else None


def _write(db, sql: str, params: dict) -> None:
    """Persist through the caller's Session when it has one. The login request
    already holds a pooled connection; checking out a SECOND one per sign-in
    deadlocked the pool under ~15 simultaneous logins (R2DATA-5)."""
    if db is None:
        _db(sql, params)
        return
    from sqlalchemy import text
    try:
        db.execute(text(sql), params)
        db.commit()
    except Exception as exc:
        db.rollback()
        if "no such table" in str(exc):  # e.g. a DB swapped in by restore
            for ddl in _TABLES:
                db.execute(text(ddl))
            db.execute(text(sql), params)
            db.commit()
        else:
            _logger.warning("rate_limit_state: %s", exc)


def _load() -> None:
    for ddl in _TABLES:
        _db(ddl)
    now_wall, now_mono = time.time(), time.monotonic()
    _db("DELETE FROM rate_limit_state WHERE lockout_until <= :t", {"t": now_wall})
    _db("DELETE FROM login_known_addresses WHERE until <= :t", {"t": now_wall})
    for key, until in _db("SELECT key, lockout_until FROM rate_limit_state", fetch=True) or []:
        _lockouts[key] = now_mono + (until - now_wall)
    for key, until in _db("SELECT key, until FROM login_known_addresses", fetch=True) or []:
        _familiar[key] = until


def _persist(key: str, until_wall: float, db=None) -> None:
    _write(db, "INSERT INTO rate_limit_state (key, lockout_until) VALUES (:k, :t) "
               "ON CONFLICT(key) DO UPDATE SET lockout_until = :t", {"k": key, "t": until_wall})


def _forget(key: str, db=None) -> None:
    _write(db, "DELETE FROM rate_limit_state WHERE key = :k", {"k": key})


def _persist_familiar(key: str, until_wall: float, db=None) -> None:
    _write(db, "INSERT INTO login_known_addresses (key, until) VALUES (:k, :t) "
               "ON CONFLICT(key) DO UPDATE SET until = :t", {"k": key, "t": until_wall})


_load()


def _disabled() -> bool:
    return os.environ.get("ATHORIZE_DISABLE_RATE_LIMIT", "") == "1"  # old name: config alias


def _keys(ip: str, username: str) -> tuple[str, str, str]:
    return f"pair:{ip}|{username}", f"ip:{ip}", f"user:{username}"


def _recent(key: str, now: float) -> int:
    ts = [t for t in _failures.get(key, []) if now - t < WINDOW_SECONDS]
    if ts:
        _failures[key] = ts
    else:
        _failures.pop(key, None)
    return len(ts)


def _locked(key: str, now: float) -> bool:
    exp = _lockouts.get(key)
    if exp is None:
        return False
    if now >= exp:
        del _lockouts[key]
        return False
    return True


def is_familiar(ip: str, username: str) -> bool:
    exp = _familiar.get(f"{username}|{ip}")
    return exp is not None and exp > time.time()


ALLOW, DENY, CORRECT_ONLY = "allow", "deny", "correct_only"


def login_check(ip: str, username: str) -> str:
    """DENY = answer 429 without checking the password. CORRECT_ONLY = the
    address is locked but this username has no failures from it: check the
    password, sign in if correct, else 429 (never 401)."""
    if _disabled():
        return ALLOW
    now = time.monotonic()
    pair, ipk, user = _keys(ip, username)
    with _lock:
        if _locked(pair, now):
            return DENY
        if is_familiar(ip, username):
            return ALLOW
        if _locked(user, now):
            return DENY
        if _locked(ipk, now):
            return CORRECT_ONLY if _recent(pair, now) == 0 else DENY
        return ALLOW


def login_allowed(ip: str, username: str) -> bool:
    """False = answer 429 without checking the password (strict form of
    login_check: an address lock refuses everyone non-familiar)."""
    return login_check(ip, username) == ALLOW


def _lock_key(key: str, now: float) -> float:
    _lockouts[key] = now + LOCK_SECONDS
    return time.time() + LOCK_SECONDS


_MAX_TRACKED_KEYS = 50_000


def _sweep(now: float) -> None:
    """Bound memory under username/address spraying: drop keys whose failures
    have all aged out of the window."""
    for key in [k for k, ts in _failures.items() if not ts or now - ts[-1] >= WINDOW_SECONDS]:
        del _failures[key]


def record_failure(ip: str, username: str, db=None) -> None:
    if _disabled():
        return
    now = time.monotonic()
    pair, ipk, user = _keys(ip, username)
    new_locks: list[tuple[str, float]] = []
    with _lock:
        if len(_failures) > _MAX_TRACKED_KEYS:
            _sweep(now)
        for key, limit in ((pair, PAIR_MAX), (ipk, IP_MAX), (user, USER_MAX)):
            _failures.setdefault(key, []).append(now)
            if _recent(key, now) >= limit and not _locked(key, now):
                new_locks.append((key, _lock_key(key, now)))
                if key == user:
                    _logger.warning("login: account %r is under attack (%d failures from several addresses); "
                                    "sign-in now only from its familiar addresses for %d min",
                                    username, limit, LOCK_SECONDS // 60)
    for key, until_wall in new_locks:  # DB writes outside the in-memory lock
        _persist(key, until_wall, db)


def record_success(ip: str, username: str, db=None) -> None:
    """`db`: the request's Session — the writes go through its connection."""
    pair, _ipk, _user = _keys(ip, username)
    with _lock:
        _failures.pop(pair, None)
        was_locked = _lockouts.pop(pair, None) is not None
        until = time.time() + FAMILIAR_SECONDS
        _familiar[f"{username}|{ip}"] = until
    if was_locked:
        _forget(pair, db)
    _persist_familiar(f"{username}|{ip}", until, db)


def reset() -> None:
    """Clear all state (tests / operator recovery)."""
    with _lock:
        _failures.clear()
        _lockouts.clear()
        _familiar.clear()
        _endpoint_attempts.clear()
    _db("DELETE FROM rate_limit_state")
    _db("DELETE FROM login_known_addresses")


# First-run setup (both Setup-screen choices share one counter): wrong setup
# tokens from one address are limited like the per-endpoint helpers below.
def setup_attempt_allowed(ip: str) -> bool:
    return check_endpoint_rate_limit(f"setup|{ip}")


def record_setup_failure(ip: str) -> None:
    record_endpoint_call(f"setup|{ip}")


def check_endpoint_rate_limit(ip: str) -> bool:
    if _disabled():
        return True
    now = time.monotonic()
    with _lock:
        ts = [t for t in _endpoint_attempts.get(ip, []) if now - t < ENDPOINT_WINDOW_SECONDS]
        _endpoint_attempts[ip] = ts
        return len(ts) < ENDPOINT_MAX_ATTEMPTS


def record_endpoint_call(ip: str) -> None:
    if _disabled():
        return
    with _lock:
        _endpoint_attempts.setdefault(ip, []).append(time.monotonic())
