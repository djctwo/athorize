"""Settings: one source (env + .env), documented names, no public default keys.

SECCODE-6 / DOCKER-3 / DOCKER-5 / INTEGRITY-11. Each scenario runs config in a
fresh interpreter with a scratch HOME/DATA_DIR so nothing touches a real install.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
KEY = "a" * 64

PROBE = r'''
import json, logging, sys
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
import config
s = config.settings
print("PROBE" + json.dumps({
    "audit_key": s.audit_hmac_key, "secret_key": s.secret_key, "trust_xff": s.trust_xff,
    "cors": s.cors_origins, "data_dir": str(s.data_dir), "evidence_dir": str(s.evidence_dir),
    "backup_dir": str(s.backup_dir), "threat_feeds_env": __import__("os").environ.get("THREAT_FEEDS"),
    "backup_keep": s.backup_keep, "backup_keep_rollbacks": s.backup_keep_rollbacks,
    "debug": s.debug, "allowed_hosts": s.allowed_hosts, "db_url": s.db_url,
    "audit_key_source": getattr(config, "AUDIT_KEY_SOURCE", None),
}))
'''


def _run(tmp_path: Path, env_extra: dict[str, str], cwd: Path | None = None, dotenv: str | None = None,
         dotenv_is_config: bool = True):
    """dotenv is written to <cwd>/.env; by default it is also named as THE config
    file (ATHORIZE_ENV_FILE), standing in for backend/.env."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if k not in ("SECRET_KEY", "ATHORIZE_AUDIT_HMAC_KEY", "UNIVERSAL_AUDIT_HMAC_KEY", "AUDIT_HMAC_KEY",
                        "DATA_DIR", "EVIDENCE_DIR", "BACKUP_DIR", "DATABASE_URL", "ATHORIZE_TRUST_XFF",
                        "UNIVERSAL_TRUST_XFF", "ATHORIZE_BACKUP_KEEP", "BACKUP_KEEP", "BACKUP_KEEP_ROLLBACKS",
                        "ATHORIZE_BACKUP_KEEP_ROLLBACKS",
                        "ATHORIZE_DEMO_SEED", "CORS_ORIGINS", "THREAT_FEEDS", "ATHORIZE_ENV_FILE", "DEBUG",
                        "ATHORIZE_ALLOWED_HOSTS")}
    env.update(HOME=str(home), PYTHONPATH=str(BACKEND), PYTHONDONTWRITEBYTECODE="1")
    env.update(env_extra)
    workdir = cwd or tmp_path / "wd"
    workdir.mkdir(exist_ok=True)
    if dotenv is not None:
        (workdir / ".env").write_text(dotenv)
        if dotenv_is_config:
            env["ATHORIZE_ENV_FILE"] = str(workdir / ".env")
    res = subprocess.run([sys.executable, "-c", PROBE], cwd=str(workdir), env=env,
                         capture_output=True, text=True, timeout=60)
    out = None
    if res.returncode == 0 and "PROBE" in res.stdout:
        out = json.loads(res.stdout.split("PROBE", 1)[1].strip().splitlines()[0])
    return res, out


def test_documented_production_env_file_is_accepted_and_used(tmp_path):
    """SECCODE-6: docs/INSTALL.md §5's backend/.env used to crash startup
    ("Extra inputs are not permitted") and the audit key in it was ignored."""
    data = tmp_path / "data"
    res, out = _run(tmp_path, {}, dotenv=(
        f"SECRET_KEY={'b' * 64}\nATHORIZE_AUDIT_HMAC_KEY={KEY}\n"
        f"DATA_DIR={data}\nEVIDENCE_DIR={data}/evidence\nBACKUP_DIR={data}/backups\n"
        "ATHORIZE_TRUST_XFF=1\nCORS_ORIGINS=http://localhost:3000\nTHREAT_FEEDS=mock\n"))
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == KEY
    assert out["trust_xff"] is True
    assert out["cors"] == ["http://localhost:3000"]
    assert out["data_dir"] == str(data)
    # operational knobs read with os.getenv see .env values too
    assert out["threat_feeds_env"] == "mock"


def test_deprecated_audit_hmac_key_alias_is_honoured_with_warning(tmp_path):
    """DOCKER-3: AUDIT_HMAC_KEY (run-eval.sh, older docs) was silently ignored."""
    res, out = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), "AUDIT_HMAC_KEY": KEY})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == KEY
    assert "AUDIT_HMAC_KEY is deprecated" in res.stderr


def test_unset_audit_key_is_generated_persisted_and_stable(tmp_path):
    """SECCODE-6: no key configured used to mean the public default key."""
    d = tmp_path / "d"
    res, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert res.returncode == 0, res.stderr[-2000:]
    key = out["audit_key"]
    assert key and key != "audit-chain-default-key" and len(key) >= 32
    f = d / "secrets.env"
    assert f.is_file()
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    res2, out2 = _run(tmp_path, {"DATA_DIR": str(d)})
    assert out2["audit_key"] == key and out2["secret_key"] == out["secret_key"]


def test_legacy_eval_secrets_file_is_reused(tmp_path):
    """An install made by the old run-eval.sh keeps its generated key."""
    d = tmp_path / "d"
    d.mkdir()
    (d / "eval-secrets.env").write_text(f"SECRET_KEY={'c' * 64}\nAUDIT_HMAC_KEY={KEY}\n")
    res, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == KEY


@pytest.mark.parametrize("value", ["audit-chain-default-key", "change-me-to-a-random-string"])
def test_placeholder_audit_key_is_never_used(tmp_path, value):
    res, out = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), "ATHORIZE_AUDIT_HMAC_KEY": value})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] != value and len(out["audit_key"]) >= 32


def test_weak_audit_key_refused_outside_demo_allowed_in_demo(tmp_path):
    res, _ = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), "ATHORIZE_AUDIT_HMAC_KEY": "short"})
    assert res.returncode != 0
    assert "ATHORIZE_AUDIT_HMAC_KEY is too short" in res.stderr
    res, out = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), "ATHORIZE_AUDIT_HMAC_KEY": "short",
                               "ATHORIZE_DEMO_SEED": "1"})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == "short"


def test_evidence_and_backups_follow_data_dir(tmp_path):
    """DOCKER-5: EVIDENCE_DIR/BACKUP_DIR defaulted to ~/.athorize-universal even
    when DATA_DIR pointed elsewhere."""
    d = tmp_path / "custom"
    res, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["evidence_dir"] == str(d / "evidence")
    assert out["backup_dir"] == str(d / "backups")


def test_env_example_is_loadable(tmp_path):
    """.env.example used to carry values that crash (CORS list) or point nowhere
    (DATABASE_URL with '~', FRAMEWORKS_DIR relative to the wrong dir)."""
    example = (REPO / ".env.example").read_text()
    d = tmp_path / "d"
    example = "\n".join(l for l in example.splitlines() if not l.startswith(("DATA_DIR", "EVIDENCE_DIR", "BACKUP_DIR")))
    res, out = _run(tmp_path, {"DATA_DIR": str(d)}, dotenv=example)
    assert res.returncode == 0, res.stderr[-2000:]
    assert "DATABASE_URL=sqlite:///~" not in example
    assert "FRAMEWORKS_DIR=./frameworks" not in example


def test_run_eval_keeps_everything_under_data_dir():
    # Behaviour is covered end to end in tests/test_ops_scripts.py.
    script = (REPO / "scripts" / "run-eval.sh").read_text()
    assert "EVIDENCE_DIR" in script and "BACKUP_DIR" in script


def test_stray_env_in_working_directory_is_not_read(tmp_path):
    """R2INSTALL-13: a .env in whatever folder the app was started from (the
    desktop .exe: Downloads) redirected the DB and switched protections off."""
    d = tmp_path / "d"
    res, out = _run(tmp_path, {"DATA_DIR": str(d)}, dotenv_is_config=False, dotenv=(
        f"DATABASE_URL=sqlite:///{tmp_path}/other-project.db\nDEBUG=true\nATHORIZE_ALLOWED_HOSTS=*\n"))
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["db_url"] == f"sqlite:///{d}/data.db"
    assert out["debug"] is False
    assert out["allowed_hosts"] == []


@pytest.mark.parametrize("layout", ["evidence_is_data", "evidence_contains_data", "backups_inside_evidence"])
def test_overlapping_data_evidence_backup_dirs_are_refused(tmp_path, layout):
    """R2SEC-6: EVIDENCE_DIR == DATA_DIR made backups archive the live DB and
    restores move secrets.env out of DATA_DIR."""
    d = tmp_path / "d"
    env = {"evidence_is_data": {"DATA_DIR": str(d), "EVIDENCE_DIR": str(d)},
           "evidence_contains_data": {"DATA_DIR": str(d / "inner"), "EVIDENCE_DIR": str(d)},
           "backups_inside_evidence": {"DATA_DIR": str(d), "EVIDENCE_DIR": str(tmp_path / "ev"),
                                       "BACKUP_DIR": str(tmp_path / "ev" / "backups")}}[layout]
    res, _ = _run(tmp_path, env)
    assert res.returncode != 0
    assert "EVIDENCE_DIR" in res.stderr and "folder of its own" in res.stderr
    assert not (d / "secrets.env").exists()   # refused before anything was written


def test_separate_dirs_outside_data_dir_are_fine(tmp_path):
    res, out = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), "EVIDENCE_DIR": str(tmp_path / "ev"),
                               "BACKUP_DIR": str(tmp_path / "bk")})
    assert res.returncode == 0, res.stderr[-2000:]


def test_audit_key_source_is_recorded(tmp_path):
    d = tmp_path / "d"
    _, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert out["audit_key_source"] == "generated"
    _, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert out["audit_key_source"] == "file:secrets.env"
    _, out = _run(tmp_path, {"DATA_DIR": str(d), "ATHORIZE_AUDIT_HMAC_KEY": KEY})
    assert out["audit_key_source"] == "environment"


@pytest.mark.parametrize("old,new,value,field", [
    ("UNIVERSAL_AUDIT_HMAC_KEY", "ATHORIZE_AUDIT_HMAC_KEY", KEY, "audit_key"),
    ("UNIVERSAL_TRUST_XFF", "ATHORIZE_TRUST_XFF", "1", "trust_xff"),
    ("BACKUP_KEEP", "ATHORIZE_BACKUP_KEEP", "4", "backup_keep"),
    ("BACKUP_KEEP_ROLLBACKS", "ATHORIZE_BACKUP_KEEP_ROLLBACKS", "2", "backup_keep_rollbacks"),
])
def test_pre_rename_names_still_work_with_one_warning(tmp_path, old, new, value, field):
    """Decision #1: ATHORIZE_* names; the old ones are deprecated aliases."""
    res, out = _run(tmp_path, {"DATA_DIR": str(tmp_path / "d"), old: value})
    assert res.returncode == 0, res.stderr[-2000:]
    expected = {"audit_key": KEY, "trust_xff": True, "backup_keep": 4, "backup_keep_rollbacks": 2}[field]
    assert out[field] == expected
    assert res.stderr.count(f"{old} is deprecated; rename it to {new}") == 1


def test_docker_secrets_file_with_pre_rename_name_is_reused(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "secrets.env").write_text(f"SECRET_KEY={'c' * 64}\nUNIVERSAL_AUDIT_HMAC_KEY={KEY}\n")
    res, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == KEY


def test_desktop_secrets_file_with_pre_rename_name_is_reused(tmp_path):
    """Desktop builds before 2026-10 kept keys in desktop-secrets.env (some with
    the old UNIVERSAL_ name). The launcher no longer manages keys (R2SEC-5); the
    app reads that file itself and does not generate a new key."""
    d = tmp_path / "d"
    d.mkdir()
    (d / "desktop-secrets.env").write_text(f"SECRET_KEY={'c' * 64}\nUNIVERSAL_AUDIT_HMAC_KEY={KEY}\n")
    res, out = _run(tmp_path, {"DATA_DIR": str(d)})
    assert res.returncode == 0, res.stderr[-2000:]
    assert out["audit_key"] == KEY
    assert out["audit_key_source"] == "file:desktop-secrets.env"
    assert not (d / "secrets.env").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_data_dir_created_by_the_app_is_private(tmp_path):
    """R2INSTALL-15: bare uvicorn / desktop created DATA_DIR 0755 (DB 0644 inside)."""
    d = tmp_path / "new" / "data"
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in ("DATA_DIR", "EVIDENCE_DIR", "BACKUP_DIR",
                                                             "DATABASE_URL", "ATHORIZE_ENV_FILE")}
    env.update(HOME=str(home), DATA_DIR=str(d), PYTHONPATH=str(BACKEND), PYTHONDONTWRITEBYTECODE="1",
               SECRET_KEY="s" * 64, ATHORIZE_AUDIT_HMAC_KEY=KEY)
    res = subprocess.run([sys.executable, "-c", "import database"], cwd=str(tmp_path), env=env,
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr[-2000:]
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
