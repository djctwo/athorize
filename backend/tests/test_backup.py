"""Backup & restore: admin-gated, nonce-confirmed, round-trips data."""
import io


def _csrf_headers(csrf):
    return {"X-CSRF-Token": csrf} if csrf else {}


class TestBackupAccess:
    def test_info_requires_admin(self, client, seeded):
        # Unauthenticated
        assert client.get("/api/backup/info").status_code == 401

    def test_info_returns_nonce(self, auth_client):
        client, seeded, _ = auth_client
        r = client.get("/api/backup/info")
        assert r.status_code == 200
        body = r.json()
        assert "restore_nonce" in body and body["restore_nonce"]
        assert "db_size_bytes" in body


class TestBackupDownload:
    def test_download_returns_archive(self, auth_client):
        client, seeded, csrf = auth_client
        r = client.post("/api/backup/download", data={"passphrase": ""}, headers=_csrf_headers(csrf))
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/octet-stream"
        assert "universal-backup-" in r.headers["content-disposition"]
        assert len(r.content) > 0


class TestRestoreNonce:
    def test_restore_rejects_bad_nonce(self, auth_client):
        client, seeded, csrf = auth_client
        archive = io.BytesIO(b"not-a-real-archive")
        r = client.post(
            "/api/backup/restore",
            data={"nonce": "bogus", "passphrase": ""},
            files={"file": ("b.tar.gz", archive, "application/octet-stream")},
            headers=_csrf_headers(csrf),
        )
        assert r.status_code == 409

    def test_round_trip_backup_then_restore(self, auth_client):
        client, seeded, csrf = auth_client
        # 1. Download a real backup of the current (seeded) DB
        dl = client.post("/api/backup/download", data={"passphrase": ""}, headers=_csrf_headers(csrf))
        assert dl.status_code == 200
        blob = dl.content

        # 2. Get a fresh restore nonce
        nonce = client.get("/api/backup/info").json()["restore_nonce"]

        # 3. Restore it back
        r = client.post(
            "/api/backup/restore",
            data={"nonce": nonce, "passphrase": ""},
            files={"file": ("backup.tar.gz", io.BytesIO(blob), "application/octet-stream")},
            headers=_csrf_headers(csrf),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["restored_db"] is True
        assert "rollback_path" in body

    def test_encrypted_round_trip(self, auth_client):
        client, seeded, csrf = auth_client
        dl = client.post("/api/backup/download", data={"passphrase": "correct horse battery"}, headers=_csrf_headers(csrf))
        assert dl.status_code == 200
        assert dl.headers["content-disposition"].endswith('.tar.gz.enc"')
        blob = dl.content
        nonce = client.get("/api/backup/info").json()["restore_nonce"]
        r = client.post(
            "/api/backup/restore",
            data={"nonce": nonce, "passphrase": "correct horse battery"},
            files={"file": ("backup.tar.gz.enc", io.BytesIO(blob), "application/octet-stream")},
            headers=_csrf_headers(csrf),
        )
        assert r.status_code == 200
        assert r.json()["restored_db"] is True


class TestSafeExtract:
    def test_traversal_entry_rejected(self, tmp_path):
        import io, tarfile
        import pytest
        from services import backup as bsvc

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            payload = b"pwned"
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        buf.seek(0)

        dest = tmp_path / "stage"
        dest.mkdir()
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            with pytest.raises(bsvc.BackupError):
                bsvc._safe_extract(tar, dest)
        assert not (tmp_path / "escape.txt").exists()
