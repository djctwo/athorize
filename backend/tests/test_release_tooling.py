"""scripts/update.sh — the documented upgrade (docs/INSTALL.md §11) — run for
real against a simulated install in a temp dir.

R2INSTALL-1 (.env kept), R2INSTALL-3 (the service's venv is the one rebuilt),
plus the security review of the updater: stage-and-swap, nothing in the old
tree executed or written through, automatic rollback when the service does not
come back. The release is a minimal synthetic bundle with a one-wheel
wheelhouse, so pip runs offline. systemd is replaced by a recording stub.
Nothing outside tmp_path is touched.
"""
from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import zipfile
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UPDATE_SH = REPO / "scripts" / "update.sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None,
                                reason="update.sh is a bash script for Linux/macOS servers")


def _probe_wheel(dest: Path) -> None:
    """A minimal pure-Python wheel, so the dependency install runs offline."""
    dest.mkdir(parents=True, exist_ok=True)
    files = {
        "athz_probe/__init__.py": "VERSION = '1.0'\n",
        "athz_probe-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: athz-probe\nVersion: 1.0\n",
        "athz_probe-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    files["athz_probe-1.0.dist-info/RECORD"] = "".join(f"{n},,\n" for n in [*files, "athz_probe-1.0.dist-info/RECORD"])
    with zipfile.ZipFile(dest / "athz_probe-1.0-py3-none-any.whl", "w") as z:
        for name, body in files.items():
            z.writestr(name, body)


def _release(tmp: Path, version: str, requirement: str = "athz-probe==1.0") -> Path:
    src = tmp / "build" / f"athorize-{version}"
    (src / "backend").mkdir(parents=True)
    (src / "backend" / "main.py").write_text(f"# release {version}\n")
    (src / "backend" / "requirements.txt").write_text(requirement + "\n")
    _probe_wheel(src / "wheelhouse")
    (src / "frameworks").mkdir()
    (src / "scripts").mkdir()
    (src / "frontend" / "dist").mkdir(parents=True)
    (src / "frontend" / "dist" / "index.html").write_text(f"<!-- {version} -->")
    (src / "LICENSE").write_text("AGPL\n")
    (src / "VERSION").write_text(version + "\n")
    tarball = tmp / f"athorize-{version}.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(src, arcname=src.name)
    return tarball


ENV_TEXT = "DATA_DIR=/var/lib/athorize-universal\nATHORIZE_AUDIT_HMAC_KEY=" + "k" * 64 + "\n"


def _install(tmp: Path, venv_at: str | None = ".venv") -> Path:
    """An install laid out as docs/INSTALL.md §3-§5 describe."""
    inst = tmp / "opt" / "athorize-universal"
    (inst / "backend").mkdir(parents=True)
    (inst / "backend" / "main.py").write_text("# old\n")
    (inst / "frontend" / "dist").mkdir(parents=True)
    (inst / "frontend" / "dist" / "old.js").write_text("stale")
    (inst / "VERSION").write_text("0.0.1\n")
    env = inst / "backend" / ".env"
    env.write_text(ENV_TEXT)
    os.chmod(env, 0o600)
    if venv_at:
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(inst / venv_at)], check=True)
        (inst / venv_at / "OLD_VENV_MARKER").write_text("old")
    return inst


def _has_probe(venv: Path) -> bool:
    return any(venv.glob("lib/python*/site-packages/athz_probe/__init__.py"))


def _update(tarball: Path, inst: Path, *extra: str, env: dict | None = None,
            skip_service: bool = True) -> subprocess.CompletedProcess:
    args = ["bash", str(UPDATE_SH), "--release", str(tarball), "--install-dir", str(inst),
            "--user", "no-such-user-athorize-test", *extra]
    if skip_service:
        args.append("--skip-service")
    return subprocess.run(args, capture_output=True, text=True, timeout=300,
                          env={**os.environ, **(env or {})})


def _backups(inst: Path) -> list[Path]:
    return sorted(inst.parent.glob(inst.name + ".bak-*"))


def test_update_keeps_backend_env(tmp_path):
    """R2INSTALL-1: the upgrade deleted backend/.env (DATA_DIR, audit key, hosts)."""
    inst = _install(tmp_path)
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode == 0, res.stdout + res.stderr
    assert (inst / "backend" / "main.py").read_text() == "# release 9.9.10\n"   # code swapped
    env = inst / "backend" / ".env"
    assert env.is_file() and not env.is_symlink(), "backend/.env was deleted by the upgrade"
    assert env.read_text() == ENV_TEXT
    assert stat.S_IMODE(env.stat().st_mode) == 0o600   # non-root run: mode kept (root: root:<group> 640)
    assert (inst / "VERSION").read_text().strip() == "9.9.10"
    assert not (inst / "frontend" / "dist" / "old.js").exists()
    assert (inst / "LICENSE").is_file()
    assert [p.name for p in inst.parent.iterdir() if ".athorize-stage" in p.name] == []
    (bak,) = _backups(inst)
    assert (bak / "backend" / "main.py").read_text() == "# old\n"           # rollback copy


def test_update_rebuilds_the_venv_the_service_runs(tmp_path):
    """R2INSTALL-3: INSTALL + the unit run <install>/.venv; update.sh installed
    into a throw-away backend/.venv instead. The venv is now built fresh (the
    old one is never executed) and its scripts point at the final path."""
    inst = _install(tmp_path)
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode == 0, res.stdout + res.stderr
    venv = inst / ".venv"
    assert _has_probe(venv), "the service's venv did not get the release's dependencies"
    assert not (venv / "OLD_VENV_MARKER").exists()                     # fresh, not upgraded in place
    assert (_backups(inst)[0] / ".venv" / "OLD_VENV_MARKER").exists()  # old one kept for rollback
    assert not (inst / "backend" / ".venv").exists()
    assert subprocess.run([str(venv / "bin" / "python"), "-c", "import athz_probe"]).returncode == 0
    for f in [*(venv / "bin").iterdir(), venv / "pyvenv.cfg"]:
        if f.is_file() and not f.is_symlink():
            assert ".athorize-stage" not in f.read_text(errors="ignore"), f
    pip = venv / "bin" / "pip"
    if pip.exists():
        assert pip.read_text().splitlines()[0] == f"#!{venv}/bin/python" or str(venv) in pip.read_text()


def test_update_keeps_a_venv_inside_backend(tmp_path):
    """Installs whose unit runs backend/.venv keep a venv there."""
    inst = _install(tmp_path, venv_at="backend/.venv")
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode == 0, res.stdout + res.stderr
    assert _has_probe(inst / "backend" / ".venv")
    assert not (inst / ".venv").exists()


def test_failed_dependency_install_changes_nothing(tmp_path):
    inst = _install(tmp_path)
    res = _update(_release(tmp_path, "9.9.10", requirement="athz-missing==9"), inst)
    assert res.returncode != 0
    assert (inst / "backend" / "main.py").read_text() == "# old\n"
    assert (inst / ".venv" / "OLD_VENV_MARKER").exists()
    assert (inst / "backend" / ".env").read_text() == ENV_TEXT
    assert [p.name for p in inst.parent.iterdir() if p.name != inst.name] == []   # no stage, no .bak


@pytest.mark.parametrize("target", ["LICENSE", "VERSION", "frontend/dist", "backend/main.py", ".venv/bin/python"])
def test_planted_symlinks_in_the_old_tree_are_never_followed(tmp_path, target):
    """Security review: the updater runs as root, so a link planted in the
    install dir must never redirect a write or get executed."""
    inst = _install(tmp_path)
    victim = tmp_path / "outside" / "victim"
    victim.parent.mkdir()
    dest = inst / target
    if dest.is_dir() and not dest.is_symlink():
        shutil.rmtree(dest)
        victim.mkdir()
        (victim / "keep").write_text("keep")
    else:
        dest.unlink(missing_ok=True)
        victim.write_text("#!/bin/sh\necho EXECUTED > \"$0.ran\"\n")
        victim.chmod(0o755)
    dest.symlink_to(victim)
    before = sorted(p.name for p in victim.parent.iterdir())
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode == 0, res.stdout + res.stderr
    assert sorted(p.name for p in victim.parent.iterdir()) == before          # nothing written or run there
    if victim.is_dir():
        assert [p.name for p in victim.iterdir()] == ["keep"]
    else:
        assert victim.read_text().startswith("#!/bin/sh")
    new = inst / target
    assert not new.is_symlink() or target == ".venv/bin/python"   # venv's python is the system link


def test_env_symlink_is_refused(tmp_path):
    inst = _install(tmp_path)
    secret = tmp_path / "shadow"
    secret.write_text("root:secret-hash\n")
    env = inst / "backend" / ".env"
    env.unlink()
    env.symlink_to(secret)
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode != 0 and "symlink" in res.stderr
    assert (inst / "backend" / "main.py").read_text() == "# old\n"


def test_hardlinked_env_is_refused(tmp_path):
    inst = _install(tmp_path)
    other = tmp_path / "other-file"
    os.link(inst / "backend" / ".env", other)
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode != 0 and "hard links" in res.stderr
    assert (inst / "backend" / "main.py").read_text() == "# old\n"


def test_unknown_files_in_the_install_dir_stop_the_update(tmp_path):
    """Data kept under the install dir would silently move to the .bak copy."""
    inst = _install(tmp_path)
    (inst / "data").mkdir()
    (inst / "data" / "data.db").write_text("PRECIOUS")
    res = _update(_release(tmp_path, "9.9.10"), inst)
    assert res.returncode != 0 and "data" in res.stderr
    assert (inst / "data" / "data.db").read_text() == "PRECIOUS"
    assert (inst / "backend" / "main.py").read_text() == "# old\n"


def _fake_systemctl(tmp: Path) -> tuple[Path, Path]:
    bindir = tmp / "fakebin"
    bindir.mkdir()
    log = tmp / "systemctl.log"
    (bindir / "systemctl").write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n')
    (bindir / "systemctl").chmod(0o755)
    return bindir, log


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_service_is_restarted_and_health_checked(tmp_path):
    inst = _install(tmp_path)
    bindir, log = _fake_systemctl(tmp_path)
    www = tmp_path / "www"
    (www / "api").mkdir(parents=True)
    (www / "api" / "health").write_text('{"status":"ok"}')
    srv = HTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(www)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = _update(_release(tmp_path, "9.9.10"), inst, "--service", "athz-test",
                      "--health-url", f"http://127.0.0.1:{srv.server_port}/api/health",
                      env={"PATH": f"{bindir}:{os.environ['PATH']}"}, skip_service=False)
    finally:
        srv.shutdown()
    assert res.returncode == 0, res.stdout + res.stderr
    assert log.read_text().split("\n")[:2] == ["stop athz-test", "start athz-test"]
    assert (inst / "VERSION").read_text().strip() == "9.9.10"


def test_unhealthy_service_is_rolled_back_automatically(tmp_path):
    inst = _install(tmp_path)
    bindir, log = _fake_systemctl(tmp_path)
    res = _update(_release(tmp_path, "9.9.10"), inst, "--service", "athz-test",
                  "--health-url", f"http://127.0.0.1:{_free_port()}/api/health",
                  env={"PATH": f"{bindir}:{os.environ['PATH']}", "ATHORIZE_UPDATE_HEALTH_TIMEOUT": "3"},
                  skip_service=False)
    assert res.returncode != 0
    assert "Rolling back" in res.stderr
    assert (inst / "backend" / "main.py").read_text() == "# old\n"
    assert (inst / ".venv" / "OLD_VENV_MARKER").exists()
    assert (inst / "backend" / ".env").read_text() == ENV_TEXT
    assert log.read_text().strip().splitlines()[-1] == "start athz-test"   # old version started again


def test_update_twice_still_keeps_env(tmp_path):
    inst = _install(tmp_path)
    assert _update(_release(tmp_path / "a", "9.9.10"), inst).returncode == 0
    assert _update(_release(tmp_path / "b", "9.9.11"), inst).returncode == 0
    assert (inst / "backend" / ".env").read_text() == ENV_TEXT
    assert (inst / "VERSION").read_text().strip() == "9.9.11"


# --------------------------------------------------------------------------- demo seed packaging

def test_the_demo_seed_ships_with_the_backend_in_every_distribution():
    """The Setup screen's "Explore with demo data" must work in every build:
    the blank Windows exe, the Docker image, the release tarball and a bare
    checkout. The seed therefore lives in the backend package (which every
    distribution ships), not in scripts/ (stripped from standard builds)."""
    seed = REPO / "backend" / "services" / "demo_seed.py"
    assert seed.is_file(), "the demo seed must be a backend module"
    # Release tarball: only the scripts/ CLI helpers are stripped from standard builds.
    pkg = (REPO / "scripts" / "package_release.sh").read_text()
    stripped = [ln for ln in pkg.splitlines() if ln.strip().startswith("rm ") and "demo" in ln]
    assert stripped and all("backend" not in ln for ln in stripped), stripped
    # Docker image: the whole backend/ is copied; .dockerignore keeps services/.
    docker = (REPO / "Dockerfile").read_text()
    assert "COPY backend/ /app/backend/" in docker
    ignore = (REPO / ".dockerignore").read_text().splitlines()
    assert not any(p.strip().startswith(("backend/services", "**/services")) for p in ignore)
    # Desktop exe (blank AND demo): PyInstaller must bundle the module.
    spec = (REPO / "desktop" / "athorize.spec").read_text()
    assert '"services.demo_seed"' in spec
    # The demo build's refresh check no longer hashes the stripped script.
    launcher = (REPO / "desktop" / "launcher.py").read_text()
    assert 'scripts" / "seed_demo.py' not in launcher
