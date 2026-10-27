"""Desktop launcher demo-data refresh — the only launcher code that moves user
data, so every safety rail gets a test. R2INSTALL-9: it used to DELETE the whole
demo folder (uploaded evidence and backups too); it now sets it aside. The launcher itself is frozen-only,
but _refresh_stale_demo_data is plain Python and testable directly."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "desktop"))
import launcher  # noqa: E402


@pytest.fixture()
def demo_dir(tmp_path, monkeypatch):
    """A populated demo data dir + a launcher patched into 'demo build' mode."""
    d = tmp_path / ".athorize-universal-demo"
    d.mkdir()
    (d / "data.db").write_bytes(b"old sqlite bytes")
    (d / "evidence").mkdir()
    monkeypatch.setattr(launcher, "_is_demo_build", lambda: True)
    monkeypatch.setattr(launcher, "_seed_fingerprint", lambda: "current-hash")
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.delenv("ATHORIZE_DATA_DIR", raising=False)
    return d


def test_stale_demo_data_is_set_aside_not_deleted_and_marker_stamped(demo_dir, capsys):
    (demo_dir / "demo-seed-fingerprint").write_text("old-hash\n")
    (demo_dir / "evidence" / "1").mkdir()
    (demo_dir / "evidence" / "1" / "x.pdf").write_bytes(b"uploaded by the evaluator")
    (demo_dir / "backups").mkdir()
    (demo_dir / "backups" / "universal-backup-1.tar.gz").write_bytes(b"backup")
    moved = launcher._refresh_stale_demo_data(demo_dir)
    assert not (demo_dir / "data.db").exists()          # fresh dir -> will reseed
    assert (demo_dir / "demo-seed-fingerprint").read_text().strip() == "current-hash"
    assert moved is not None and moved.parent == demo_dir.parent
    assert moved.name.startswith(".athorize-universal-demo.old-")
    assert (moved / "data.db").read_bytes() == b"old sqlite bytes"
    assert (moved / "evidence" / "1" / "x.pdf").read_bytes() == b"uploaded by the evaluator"
    assert (moved / "backups" / "universal-backup-1.tar.gz").exists()
    assert str(moved) in capsys.readouterr().out          # the user is told where it went


def test_missing_marker_counts_as_stale(demo_dir):
    # Pre-marker builds have a DB but no fingerprint file.
    moved = launcher._refresh_stale_demo_data(demo_dir)
    assert not (demo_dir / "data.db").exists()
    assert (moved / "data.db").exists()


def test_two_refreshes_in_one_second_do_not_collide(demo_dir):
    first = launcher._refresh_stale_demo_data(demo_dir)
    (demo_dir / "data.db").write_bytes(b"second")
    (demo_dir / "demo-seed-fingerprint").write_text("older\n")
    second = launcher._refresh_stale_demo_data(demo_dir)
    assert first != second and (second / "data.db").read_bytes() == b"second"


def test_matching_marker_preserves_data(demo_dir):
    (demo_dir / "demo-seed-fingerprint").write_text("current-hash\n")
    launcher._refresh_stale_demo_data(demo_dir)
    assert (demo_dir / "data.db").read_bytes() == b"old sqlite bytes"


def test_fresh_dir_stamps_marker_without_deleting(demo_dir):
    (demo_dir / "data.db").unlink()  # first boot: no DB yet
    launcher._refresh_stale_demo_data(demo_dir)
    assert (demo_dir / "evidence").exists()  # nothing wiped
    assert (demo_dir / "demo-seed-fingerprint").read_text().strip() == "current-hash"


def test_never_wipes_a_differently_named_dir(tmp_path, monkeypatch):
    d = tmp_path / "my-precious-data"
    d.mkdir()
    (d / "data.db").write_bytes(b"real data")
    (d / "demo-seed-fingerprint").write_text("old-hash\n")
    monkeypatch.setattr(launcher, "_is_demo_build", lambda: True)
    monkeypatch.setattr(launcher, "_seed_fingerprint", lambda: "current-hash")
    monkeypatch.delenv("DATA_DIR", raising=False)
    launcher._refresh_stale_demo_data(d)
    assert (d / "data.db").read_bytes() == b"real data"


@pytest.mark.parametrize("var", ["DATA_DIR", "ATHORIZE_DATA_DIR"])
def test_env_overridden_data_dir_is_never_touched(demo_dir, monkeypatch, var):
    monkeypatch.setenv(var, str(demo_dir))
    (demo_dir / "demo-seed-fingerprint").write_text("old-hash\n")
    launcher._refresh_stale_demo_data(demo_dir)
    assert (demo_dir / "data.db").exists()


def test_blank_build_is_never_touched(demo_dir, monkeypatch):
    monkeypatch.setattr(launcher, "_is_demo_build", lambda: False)
    launcher._refresh_stale_demo_data(demo_dir)
    assert (demo_dir / "data.db").exists()


def test_data_dir_honours_both_names_and_is_private(tmp_path, monkeypatch):
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setenv("ATHORIZE_DATA_DIR", str(tmp_path / "eval"))
    d = launcher._data_dir()
    assert d == tmp_path / "eval"
    if sys.platform != "win32":
        assert d.stat().st_mode & 0o077 == 0     # R2INSTALL-15: not readable by other local users


def test_launcher_no_longer_keeps_its_own_keys():
    """R2SEC-5: one secrets location for every start path (the app's
    <DATA_DIR>/secrets.env); desktop-secrets.env is only read, by config."""
    assert not hasattr(launcher, "_ensure_secrets")


def test_seed_fingerprint_comes_from_the_bundled_marker(tmp_path, monkeypatch):
    """The demo seed is a backend module (frozen into the exe, no file to hash
    at run time), so the spec stamps its sha256 into DEMO_SEED_FINGERPRINT."""
    import _appbase
    monkeypatch.setattr(_appbase, "bundle_root", lambda: tmp_path)
    assert launcher._seed_fingerprint() is None          # blank build: no marker
    (tmp_path / "DEMO_SEED_FINGERPRINT").write_text("abc123\n")
    assert launcher._seed_fingerprint() == "abc123"


# --- options used by the Windows CI e2e job (defaults must stay as they were) ---

@pytest.fixture()
def clean_opts_env(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("ATHORIZE_NO_BROWSER", raising=False)


def test_options_default_is_free_port_and_browser(clean_opts_env):
    o = launcher._options([])
    assert o.port is None and o.no_browser is False


def test_options_port_flag_beats_env(clean_opts_env, monkeypatch):
    monkeypatch.setenv("PORT", "9100")
    assert launcher._options([]).port == 9100
    assert launcher._options(["--port", "9200"]).port == 9200


@pytest.mark.parametrize("val,expected", [("1", True), ("true", True), ("0", False), ("", False)])
def test_options_no_browser_env(clean_opts_env, monkeypatch, val, expected):
    monkeypatch.setenv("ATHORIZE_NO_BROWSER", val)
    assert launcher._options([]).no_browser is expected


def test_options_no_browser_flag_and_unknown_args_ignored(clean_opts_env):
    o = launcher._options(["--no-browser", "-psn_0_12345"])
    assert o.no_browser is True and o.port is None


def test_keep_alive_outlasts_short_client_pauses():
    # WIN-3: with uvicorn's 5 s keep-alive, a client that paused ~5 s and then
    # reused its pooled connection raced the server's close and got
    # ECONNRESET (seen on the Windows runner: 03-assessor, gap 5.09 s between
    # two API calls). Browsers retry that silently; API scripts do not.
    opts = launcher._uvicorn_options(8013)
    assert opts["timeout_keep_alive"] >= 60
    assert opts["host"] == "127.0.0.1" and opts["port"] == 8013
    assert opts["proxy_headers"] is False
