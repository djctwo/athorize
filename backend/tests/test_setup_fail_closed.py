"""SECCODE-9: first-run setup must fail closed when the token file is missing."""
from __future__ import annotations

from services import setup_token

BODY = {"org_name": "Org", "username": "firstadmin", "password": "Password1234!"}


def test_missing_token_file_does_not_open_setup(client, tmp_path, monkeypatch):
    token_file = tmp_path / "setup-token"
    monkeypatch.setattr(setup_token, "_TOKEN_PATH", token_file)
    assert not token_file.exists()
    r = client.post("/api/auth/setup", json=BODY)
    assert r.status_code == 403
    # ...and a fresh token was generated for the operator to use
    assert token_file.exists() and token_file.read_text().strip()
    assert client.get("/api/auth/status").json()["setup_token_required"] is True
    r = client.post("/api/auth/setup", json={**BODY, "setup_token": token_file.read_text().strip()})
    assert r.status_code == 200
    assert not token_file.exists()


def test_status_always_requires_a_token_before_setup(client, tmp_path, monkeypatch):
    monkeypatch.setattr(setup_token, "_TOKEN_PATH", tmp_path / "setup-token")
    assert client.get("/api/auth/status").json()["setup_token_required"] is True
