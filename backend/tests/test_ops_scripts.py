"""Shell-level behaviour of the install/ops scripts and of docs/INSTALL.md,
run for real in temp dirs (CI: release-tooling workflow).

- scripts/run-eval.sh: R2INSTALL-7 (old layout detected), R2INSTALL-15 (private
  data), R2SEC-5 (no second set of keys). The script runs from a copied bundle
  with a stub venv, so no dependencies are installed and no server starts; the
  stub records what the server would have been started with.
- scripts/reset-demo.sh: R2INSTALL-4.
- docs/INSTALL.md: R2INSTALL-11 (nginx headers), R2INSTALL-16 #1 (host names),
  R2INSTALL-14 (release file name).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

posix_only = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None,
                                reason="POSIX shell scripts")

STUB_PY = """#!/bin/sh
{ echo "ARGS=$*"; echo "UMASK=$(umask)"; echo "PWD=$(pwd)";
  env | grep -E '^(DATA_DIR|EVIDENCE_DIR|BACKUP_DIR|SECRET_KEY|ATHORIZE_AUDIT_HMAC_KEY|ATHORIZE_SERVE_FRONTEND)=';
} > "$PROBE_OUT"
"""


def _bundle(tmp: Path) -> Path:
    b = tmp / "bundle"
    shutil.rmtree(b, ignore_errors=True)
    (b / "scripts").mkdir(parents=True)
    shutil.copy(REPO / "scripts" / "run-eval.sh", b / "scripts" / "run-eval.sh")
    (b / "backend").mkdir()
    (b / "backend" / "requirements.txt").write_text("")
    vbin = b / ".venv" / "bin"
    vbin.mkdir(parents=True)
    for name in ("python", "uvicorn"):
        (vbin / name).write_text(STUB_PY)
        (vbin / name).chmod(0o755)
    return b


def _run_eval(tmp: Path, **env) -> tuple[subprocess.CompletedProcess, dict | None]:
    b = _bundle(tmp)
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    probe = tmp / "probe.txt"
    base = {k: v for k, v in os.environ.items()
            if k not in ("DATA_DIR", "EVIDENCE_DIR", "BACKUP_DIR", "SECRET_KEY", "ATHORIZE_AUDIT_HMAC_KEY",
                         "ATHORIZE_DATA_DIR", "ATHORIZE_IGNORE_LEGACY_DATA")}
    base.update(HOME=str(home), PROBE_OUT=str(probe), PORT="8072")
    base.update(env)
    res = subprocess.run(["bash", str(b / "scripts" / "run-eval.sh")], env=base,
                         capture_output=True, text=True, timeout=120)
    out = None
    if probe.exists():
        out = dict(line.split("=", 1) for line in probe.read_text().splitlines() if "=" in line)
    return res, out


@posix_only
def test_run_eval_stops_on_the_pre_2026_10_layout(tmp_path):
    """R2INSTALL-7: old run-eval kept only eval-secrets.env in ATHORIZE_DATA_DIR
    and the DB in ~/.athorize-universal; the new one opened an empty instance."""
    legacy = tmp_path / "home" / ".athorize-universal"
    legacy.mkdir(parents=True)
    (legacy / "data.db").write_text("the user's real data")
    x = tmp_path / "x"
    x.mkdir()
    (x / "eval-secrets.env").write_text("SECRET_KEY=" + "s" * 64 + "\nATHORIZE_AUDIT_HMAC_KEY=" + "a" * 64 + "\n")
    res, out = _run_eval(tmp_path, ATHORIZE_DATA_DIR=str(x))
    assert res.returncode == 3, res.stdout + res.stderr
    assert out is None, "the server was started on an empty instance"
    assert "not in " + str(x) in res.stderr and str(legacy) in res.stderr
    assert (legacy / "data.db").read_text() == "the user's real data"
    # Explicit opt-out starts anyway.
    res, out = _run_eval(tmp_path, ATHORIZE_DATA_DIR=str(x), ATHORIZE_IGNORE_LEGACY_DATA="1")
    assert res.returncode == 0 and out["DATA_DIR"] == str(x)


@posix_only
def test_run_eval_data_is_private_and_keys_come_from_the_app(tmp_path):
    """R2INSTALL-15 (umask 077, data dir 700) and R2SEC-5: run-eval no longer
    generates/exports its own keys — the app uses <DATA_DIR>/secrets.env like
    every other start path."""
    d = tmp_path / "eval"
    res, out = _run_eval(tmp_path, ATHORIZE_DATA_DIR=str(d))
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["DATA_DIR"] == str(d) and out["EVIDENCE_DIR"] == str(d / "evidence")
    assert out["BACKUP_DIR"] == str(d / "backups") and out["ATHORIZE_SERVE_FRONTEND"] == "1"
    assert out["UMASK"] in ("0077", "077")
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert "SECRET_KEY" not in out and "ATHORIZE_AUDIT_HMAC_KEY" not in out
    assert not (d / "eval-secrets.env").exists()


@posix_only
def test_run_eval_on_an_install_made_another_way_keeps_its_key(tmp_path):
    """R2SEC-5 repro: secrets.env from a first start the INSTALL.md way, then
    run-eval on the same folder used to export a brand-new key."""
    d = tmp_path / "d"
    d.mkdir()
    (d / "secrets.env").write_text("SECRET_KEY=" + "s" * 64 + "\nATHORIZE_AUDIT_HMAC_KEY=" + "a" * 64 + "\n")
    os.chmod(d, 0o755)
    res, out = _run_eval(tmp_path, ATHORIZE_DATA_DIR=str(d))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "ATHORIZE_AUDIT_HMAC_KEY" not in out
    assert sorted(p.name for p in d.iterdir()) == ["secrets.env"]
    assert stat.S_IMODE(d.stat().st_mode) == 0o700     # folders made by older versions are tightened


@posix_only
def test_run_eval_honours_the_apps_own_data_dir_name(tmp_path):
    d = tmp_path / "via-data-dir"
    res, out = _run_eval(tmp_path, DATA_DIR=str(d))
    assert res.returncode == 0 and out["DATA_DIR"] == str(d)


# --------------------------------------------------------------------------- reset-demo.sh

def _db(path: Path, org_settings: list[dict | None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE organizations (id INTEGER PRIMARY KEY, name TEXT, slug TEXT, settings JSON)")
    for i, st in enumerate(org_settings):
        con.execute("INSERT INTO organizations (name, slug, settings) VALUES (?, ?, ?)",
                    (f"Co {i}", f"co{i}", json.dumps(st) if st is not None else None))
    con.commit()
    con.close()


def _reset(tmp: Path, *args: str, **env) -> subprocess.CompletedProcess:
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    base = {k: v for k, v in os.environ.items() if k not in ("DATA_DIR", "ATHORIZE_DATA_DIR")}
    base.update(HOME=str(home), **env)
    return subprocess.run(["bash", str(REPO / "scripts" / "reset-demo.sh"), *args], env=base,
                          capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)


@posix_only
def test_reset_demo_never_falls_back_to_the_default_data_dir(tmp_path):
    """R2INSTALL-4: it deleted $HOME/.athorize-universal/data.db whatever
    DATA_DIR said, then printed Done with exit 0."""
    real = tmp_path / "home" / ".athorize-universal" / "data.db"
    _db(real, [{}])
    res = _reset(tmp_path, "--yes")
    assert res.returncode != 0
    assert real.exists()
    res = _reset(tmp_path, "--yes", DATA_DIR=str(tmp_path / "demo"))   # demo dir empty
    assert res.returncode == 0
    assert real.exists()


@posix_only
def test_reset_demo_refuses_a_real_instance(tmp_path):
    db = tmp_path / "inst" / "data.db"
    _db(db, [{"demo_data": True}, {"branding": "x"}])     # one real company
    res = _reset(tmp_path, "--yes", DATA_DIR=str(db.parent))
    assert res.returncode != 0 and "not a demo database" in res.stderr
    assert db.exists()


@posix_only
def test_reset_demo_needs_confirmation(tmp_path):
    db = tmp_path / "demo" / "data.db"
    _db(db, [{"demo_data": True}])
    res = _reset(tmp_path, DATA_DIR=str(db.parent))          # no --yes, stdin not a terminal
    assert res.returncode != 0 and db.exists()


@posix_only
def test_reset_demo_removes_only_the_demo_database(tmp_path):
    d = tmp_path / "demo"
    _db(d / "data.db", [{"demo_data": True}, {"demo_data": True}])
    (d / "data.db-wal").write_text("")
    (d / "secrets.env").write_text("ATHORIZE_AUDIT_HMAC_KEY=" + "a" * 64 + "\n")
    (d / "evidence").mkdir()
    res = _reset(tmp_path, "--yes", ATHORIZE_DATA_DIR=str(d))
    assert res.returncode == 0, res.stderr
    assert not (d / "data.db").exists() and not (d / "data.db-wal").exists()
    assert (d / "secrets.env").exists() and (d / "evidence").is_dir()
    assert "ATHORIZE_DEMO_SEED=1" in res.stdout


# --------------------------------------------------------------------------- docs/INSTALL.md

INSTALL = (REPO / "docs" / "INSTALL.md").read_text()


def _nginx_block() -> str:
    m = re.search(r"```nginx\n(.*?)```", INSTALL, re.S)
    assert m, "INSTALL.md §7 nginx example not found"
    return m.group(1)


def test_install_nginx_serves_the_ui_with_the_apps_security_headers():
    """R2INSTALL-11: nginx serves frontend/dist itself, so the CSP / frame
    protection the app adds on /api never reached the HTML document."""
    import main
    block = _nginx_block()
    ui = block[block.index("location / {"):block.index("location /api")]
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)" always;', ui)
    assert csp, "no CSP on the UI location"
    assert csp.group(1) == main._CSP
    for header, value in (("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff")):
        assert f'add_header {header} "{value}" always;' in ui


def test_install_examples_use_one_host_name():
    """R2INSTALL-16 #1: §5's ATHORIZE_ALLOWED_HOSTS and §7's server_name
    differed, so copying both gave 400 on every API call."""
    names = set(re.findall(r"server_name\s+([^;]+);", _nginx_block()))
    hosts = set(re.findall(r"^ATHORIZE_ALLOWED_HOSTS=(\S+)", INSTALL, re.M))
    assert names and hosts and hosts <= names


def test_install_uses_the_real_release_file_name():
    """R2INSTALL-14: the docs said athorize-universal-<v>.tar.gz; the script
    writes athorize-<v>.tar.gz."""
    script = (REPO / "scripts" / "package_release.sh").read_text()
    assert 'NAME="athorize-${VERSION}"' in script
    assert not re.search(r"athorize-universal-(<version>|\d)[^ ]*\.tar\.gz", INSTALL)
    for f in ("LICENSE", "NOTICE", "README.md"):
        assert f in script.split("Staging code", 1)[1].split("Prune", 1)[0], f"{f} not packaged"


def test_install_opt_tree_is_root_owned_and_traversable():
    """R2INSTALL-2 + security review: /opt/athorize-universal 755 root (nginx can
    read the UI, the service can't change code root later runs)."""
    assert "install -d -m 755 -o root -g root /opt/athorize-universal" in INSTALL
    assert "install -d -m 700 -o athorize -g athorize /opt/athorize-universal" not in INSTALL
    assert "sudo -u athorize python3 -m venv" not in INSTALL
