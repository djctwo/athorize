"""Integrity hunt (H6 "number re-check" + H7 "upgrade & restore").

Every number a user sees must re-derive from the raw rows, and data must
survive backups, restores, upgrades and interruptions. These tests assert the
CORRECT behavior. Where the app is currently wrong the test is marked
``xfail(strict=True, reason="INTEGRITY-<n>: ...")`` so the suite stays green
today and flips red the moment a fix lands (remove the marker then).

Findings are written up in the hunt findings file (INTEGRITY-<n> ids match).
All data here is synthetic (Acme / example.com).
"""
from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from models import (
    AuditEntry, Control, ControlImplementation, ControlMapping, EvidenceArtifact,
    Finding, FrameworkActivation, Organization, System, SystemAssignment, User,
)
from models.compliance_snapshot import ComplianceSnapshot
from services.auth import hash_password

BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

FW = "hunt-fw"          # synthetic framework used for score re-derivation
HUB = "nist-800-53-r5"  # crosswalk hub id (services.crosswalk.HUB_FRAMEWORK)


# --------------------------------------------------------------------------- helpers

def _login(client, username, password):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": client.cookies.get("universal_csrf")}


def _system(db, org, name="ERP", acronym=None):
    s = System(organization_id=org.id, name=name, acronym=acronym or name)
    db.add(s)
    db.flush()
    return s


def _catalog(db, framework_id, ids, baselines=None):
    for cid in ids:
        db.add(Control(framework_id=framework_id, control_id=cid, family=cid.split("-")[0],
                       family_name=cid.split("-")[0], title=f"{cid} title",
                       baselines=(baselines or {}).get(cid, [])))
    db.flush()


def _activate(db, org, *framework_ids):
    for fid in framework_ids:
        db.add(FrameworkActivation(organization_id=org.id, framework_id=fid, is_active=True))
    db.flush()


def _impl(db, system, framework_id, control_id, status, narrative=""):
    db.add(ControlImplementation(system_id=system.id, framework_id=framework_id,
                                 control_id=control_id, implementation_status=status,
                                 narrative=narrative))
    db.flush()


def _recompute_score(db, system_id, framework_id) -> float:
    """Independent re-derivation from raw rows, per Help.tsx: Implemented and
    Inherited count; Not Applicable leaves the denominator; Planned/Partially do
    not count; only controls that exist in the framework catalog are scored."""
    catalog = {c.control_id for c in db.query(Control).filter(Control.framework_id == framework_id)}
    rows = [i for i in db.query(ControlImplementation).filter(
        ControlImplementation.system_id == system_id,
        ControlImplementation.framework_id == framework_id) if i.control_id in catalog]
    na = sum(1 for i in rows if i.implementation_status == "NOT_APPLICABLE")
    sat = sum(1 for i in rows if i.implementation_status in ("IMPLEMENTED", "INHERITED"))
    denom = len(catalog) - na
    return round(sat / denom * 100, 1) if denom > 0 else 0.0


def _score_row(client, system_id, framework_id):
    rows = client.get(f"/api/dashboard/compliance?system_id={system_id}").json()
    return next(r for r in rows if r["framework_id"] == framework_id)


@pytest.fixture
def scored(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    sysA = _system(db, org, "ERP")
    ids = [f"HF-{n}" for n in range(1, 11)]
    _catalog(db, FW, ids)
    _activate(db, org, FW)
    # 10 controls: 3 implemented, 1 inherited, 2 N/A, 1 planned, 1 partially, 2 untouched
    for cid, st in [("HF-1", "IMPLEMENTED"), ("HF-2", "IMPLEMENTED"), ("HF-3", "IMPLEMENTED"),
                    ("HF-4", "INHERITED"), ("HF-5", "NOT_APPLICABLE"), ("HF-6", "NOT_APPLICABLE"),
                    ("HF-7", "PLANNED"), ("HF-8", "PARTIALLY")]:
        _impl(db, sysA, FW, cid, st)
    db.commit()
    return client, {"X-CSRF-Token": csrf}, org, sysA, ids


# =========================================================================== H6 — compliance score

class TestComplianceScoreRederives:
    def test_score_matches_independent_recompute(self, scored, db):
        client, _h, _org, sysA, _ids = scored
        row = _score_row(client, sysA.id, FW)
        # 4 satisfied / (10 - 2 N/A) = 50.0
        assert row["score_percentage"] == _recompute_score(db, sysA.id, FW) == 50.0
        assert row["total_controls"] == 10
        assert row["implemented"] == 4  # implemented + inherited

    def test_planned_from_crosswalk_never_counts(self, scored, db):
        client, h, _org, sysA, _ids = scored
        before = _score_row(client, sysA.id, FW)["score_percentage"]
        r = client.put(f"/api/controls/systems/{sysA.id}/{FW}/HF-9",
                       json={"implementation_status": "PLANNED"}, headers=h)
        assert r.status_code == 200
        assert _score_row(client, sysA.id, FW)["score_percentage"] == before

    def test_rows_outside_catalog_cannot_inflate_score(self, scored, db):
        client, h, _org, sysA, _ids = scored
        for n in range(12):
            client.put(f"/api/controls/systems/{sysA.id}/{FW}/NOT-IN-CATALOG-{n}",
                       json={"implementation_status": "IMPLEMENTED"}, headers=h)
        row = _score_row(client, sysA.id, FW)
        assert row["score_percentage"] <= 100.0
        assert row["score_percentage"] == _recompute_score(db, sysA.id, FW)

    def test_writes_for_unknown_control_ids_are_rejected(self, scored, db):
        """INTEGRITY-1 (write side): a framework with a loaded catalog refuses
        implementation rows for control ids it doesn't contain."""
        client, h, _org, sysA, _ids = scored
        r = client.put(f"/api/controls/systems/{sysA.id}/{FW}/BOGUS-1",
                       json={"implementation_status": "IMPLEMENTED"}, headers=h)
        assert r.status_code == 404
        r = client.post(f"/api/controls/systems/{sysA.id}/bulk",
                        json={"framework_id": FW, "control_ids": ["HF-9", "BOGUS-2"],
                              "implementation_status": "IMPLEMENTED"}, headers=h)
        assert r.status_code == 422
        assert db.query(ControlImplementation).filter(
            ControlImplementation.control_id.like("BOGUS-%")).count() == 0
        assert _score_row(client, sysA.id, FW)["score_percentage"] == _recompute_score(db, sysA.id, FW)

    def test_bulk_with_repeated_control_id_is_not_a_500(self, scored):
        client, h, _org, sysA, _ids = scored
        r = client.post(f"/api/controls/systems/{sysA.id}/bulk",
                        json={"framework_id": FW, "control_ids": ["HF-10", "HF-10"],
                              "implementation_status": "IMPLEMENTED"}, headers=h)
        assert r.status_code in (200, 422)


class TestFrameworkCatalogIsolation:
    def test_deactivate_in_one_company_does_not_touch_another(self, client, db):
        orgA = Organization(name="Acme A", slug="acme-a")
        orgB = Organization(name="Acme B", slug="acme-b")
        db.add_all([orgA, orgB])
        db.flush()
        db.add_all([
            User(organization_id=orgA.id, username="adminA", password_hash=hash_password("passwordA-1234"),
                 email="a@example.com", role="admin"),
            User(organization_id=orgB.id, username="adminB", password_hash=hash_password("passwordB-1234"),
                 email="b@example.com", role="admin"),
        ])
        sysA = _system(db, orgA, "ERP")
        db.commit()
        hA = _login(client, "adminA", "passwordA-1234")
        assert client.post("/api/frameworks/sox/activate", json={}, headers=hA).status_code == 200
        total_before = _score_row(client, sysA.id, "sox")["total_controls"]
        assert total_before > 0
        hB = _login(client, "adminB", "passwordB-1234")
        assert client.post("/api/frameworks/sox/activate", json={}, headers=hB).status_code == 200
        assert client.post("/api/frameworks/sox/deactivate", headers=hB).status_code == 200
        _login(client, "adminA", "passwordA-1234")
        assert _score_row(client, sysA.id, "sox")["total_controls"] == total_before
        assert len(client.get("/api/controls?framework_id=sox").json()) == total_before


# =========================================================================== H6 — finding counts

@pytest.fixture
def delayed(auth_client, db):
    client, seeded, csrf = auth_client
    org = seeded["org"]
    sysA = _system(db, org, "ERP")
    _activate(db, org, FW)
    _catalog(db, FW, ["HF-1"])  # company numbers count active frameworks with a loaded catalog (R2DATA-6)
    past = date.today() - timedelta(days=20)
    db.add_all([
        Finding(organization_id=org.id, system_id=sysA.id, framework_id=FW, title="open crit overdue",
                severity="CRITICAL", status="OPEN", due_date=past),
        Finding(organization_id=org.id, system_id=sysA.id, framework_id=FW, title="slipped crit overdue",
                severity="CRITICAL", status="DELAYED", due_date=past,
                scheduled_completion=date.today() + timedelta(days=30)),
        Finding(organization_id=org.id, system_id=sysA.id, framework_id=FW, title="closed",
                severity="CRITICAL", status="CLOSED", due_date=past),
    ])
    seeded["admin"].is_operator = True
    db.commit()
    return client, org, sysA


class TestFindingCountsAgree:
    def test_charts_rederive_from_rows(self, delayed):
        client, _org, _sys = delayed
        aging = client.get("/api/dashboard/finding-aging").json()
        sev = client.get("/api/dashboard/finding-severity").json()
        assert aging["overdue"] == 2  # both non-terminal findings are past due
        assert sev == {"CRITICAL": 2}

    def test_kpi_tiles_agree_with_charts_and_portfolio(self, delayed):
        client, org, _sys = delayed
        snap = client.get("/api/dashboard/snapshot").json()
        aging = client.get("/api/dashboard/finding-aging").json()
        sev = client.get("/api/dashboard/finding-severity").json()
        port = {c["id"]: c for c in client.get("/api/orgs/portfolio").json()["companies"]}[org.id]
        assert snap["open_findings"] == sum(aging.values()) == sum(sev.values()) == port["open_findings"] == 2
        assert snap["critical_findings"] == sev["CRITICAL"] == port["critical_findings"] == 2
        assert snap["overdue_findings"] == aging["overdue"] == port["overdue_findings"] == 2


    def test_score_cards_snapshots_and_trend_use_the_same_open_definition(self, delayed, db):
        """INTEGRITY-3: the per-framework score card, the stored daily snapshot and
        today's trend point all count the DELAYED finding as open, and overdue
        can never exceed open."""
        from services.history import take_snapshots
        client, org, sysA = delayed
        card = _score_row(client, sysA.id, FW)
        assert card["open_findings"] == 2 and card["critical_findings"] == 2
        take_snapshots(db)
        snap = db.query(ComplianceSnapshot).filter(ComplianceSnapshot.system_id == sysA.id,
                                                   ComplianceSnapshot.framework_id == FW).one()
        assert (snap.open_findings, snap.critical_findings, snap.overdue_findings) == (2, 2, 2)
        point = client.get("/api/dashboard/history").json()[-1]
        assert (point["open_findings"], point["overdue_findings"], point["critical_findings"]) == (2, 2, 2)

    def test_red_team_flags_an_overdue_delayed_finding(self, delayed, db):
        from services.redteam_analyzer import analyze_system
        _client, org, sysA = delayed
        res = analyze_system(db, sysA.id, FW, org.id, "hunt")
        titles = {f["title"] for f in res["findings"]}
        assert "Finding overdue: slipped crit overdue" in titles
        assert "Finding overdue: open crit overdue" in titles


class TestImportCounts:
    def test_identical_alerts_in_one_file_become_one_finding(self, auth_client, db):
        client, seeded, csrf = auth_client
        s = _system(db, seeded["org"], "ERP")
        _activate(db, seeded["org"], FW)  # imports need an active framework with a catalog (R2DATA-6)
        _catalog(db, FW, ["HF-1"])
        db.commit()
        line = json.dumps({"event_type": "alert", "timestamp": "2026-10-20T10:00:00Z", "src_ip": "10.0.0.5",
                           "dest_ip": "10.0.0.9", "alert": {"signature": "Synthetic dup probe",
                                                            "signature_id": 9990001, "severity": 2}})
        r = client.post("/api/siem/import/confirm", headers={"X-CSRF-Token": csrf},
                        data={"system_id": str(s.id), "framework_id": FW},
                        files={"file": ("eve.json", ((line + "\n") * 3).encode(), "application/json")})
        assert r.status_code == 200, r.text
        assert db.query(Finding).filter(Finding.title == "Synthetic dup probe").count() == 1


# =========================================================================== H6 — history / portfolio

class TestHistorySnapshots:
    def test_snapshot_is_idempotent_and_matches_score(self, scored, db):
        from services.compliance_score import score_system
        from services.history import take_snapshots
        _client, _h, _org, sysA, _ids = scored
        take_snapshots(db)
        take_snapshots(db)  # a restart / second tick the same day must not double-record
        rows = db.query(ComplianceSnapshot).filter(ComplianceSnapshot.system_id == sysA.id,
                                                   ComplianceSnapshot.framework_id == FW).all()
        assert len(rows) == 1
        assert rows[0].score_percentage == score_system(sysA.id, FW, db).score_percentage == 50.0

    def test_portfolio_score_tracks_live_score(self, scored, db):
        from services.history import take_snapshots
        client, h, org, sysA, ids = scored
        db.query(User).filter(User.organization_id == org.id).update({"is_operator": True})
        db.commit()
        take_snapshots(db)
        r = client.post(f"/api/controls/systems/{sysA.id}/bulk",
                        json={"framework_id": FW, "control_ids": ["HF-7", "HF-8", "HF-9", "HF-10"],
                              "implementation_status": "IMPLEMENTED"}, headers=h)
        assert r.status_code == 200
        live = _score_row(client, sysA.id, FW)["score_percentage"]
        assert live == 100.0
        port = {c["id"]: c for c in client.get("/api/orgs/portfolio").json()["companies"]}[org.id]
        assert port["avg_score"] == live
        hist = client.get("/api/dashboard/history").json()
        assert hist[-1]["avg_score"] == live


# =========================================================================== H6 — inspection prep

class TestInspectionPrep:
    def test_not_applicable_controls_do_not_drag_readiness(self, auth_client, db):
        client, seeded, _csrf = auth_client
        org = seeded["org"]
        s = _system(db, org, "ERP")
        _catalog(db, FW, ["HF-1", "HF-2"])
        _activate(db, org, FW)
        _impl(db, s, FW, "HF-1", "IMPLEMENTED", narrative="x" * 120)
        _impl(db, s, FW, "HF-2", "NOT_APPLICABLE", narrative="Out of scope: not in the baseline.")
        db.add(EvidenceArtifact(organization_id=org.id, system_id=s.id, filename="ev.pdf",
                                control_ids=["HF-1"], framework_ids=[FW],
                                expiration_date=date.today() + timedelta(days=200)))
        db.commit()
        prep = client.get(f"/api/inspection/prep?framework_id={FW}&system_ids={s.id}").json()
        assert _score_row(client, s.id, FW)["score_percentage"] == 100.0
        assert prep["readiness_score"] == 100.0
        assert [p["control_id"] for p in prep["punch_list"]] == []

    def test_evidence_counts_only_for_its_own_system(self, auth_client, db):
        client, seeded, _csrf = auth_client
        org = seeded["org"]
        erp, scada = _system(db, org, "ERP"), _system(db, org, "SCADA")
        _catalog(db, FW, ["HF-1"])
        _activate(db, org, FW)
        for s in (erp, scada):
            _impl(db, s, FW, "HF-1", "IMPLEMENTED", narrative="y" * 120)
        db.add(EvidenceArtifact(organization_id=org.id, system_id=erp.id, filename="erp-only.pdf",
                                control_ids=["HF-1"], framework_ids=[FW],
                                expiration_date=date.today() + timedelta(days=200)))
        db.commit()
        prep = client.get(f"/api/inspection/prep?framework_id={FW}&system_ids={scada.id}").json()
        assert prep["readiness_score"] == 0.0
        assert any("no evidence linked" in p["issues"] for p in prep["punch_list"])


    def test_readiness_rederives_from_rows(self, auth_client, db):
        """Readiness = ready pairs / (catalog controls x systems - N/A pairs);
        ready = satisfied AND narrative >= 80 chars AND fresh evidence for that
        system (tagged, or linked on the implementation via evidence_ids)."""
        client, seeded, _csrf = auth_client
        org = seeded["org"]
        erp, scada = _system(db, org, "ERP"), _system(db, org, "SCADA")
        _catalog(db, FW, ["HF-1", "HF-2", "HF-3", "HF-4"])
        _activate(db, org, FW)
        good = "z" * 90
        _impl(db, erp, FW, "HF-1", "IMPLEMENTED", narrative=good)      # ready (tagged evidence)
        _impl(db, erp, FW, "HF-2", "INHERITED", narrative=good)        # ready (linked evidence)
        _impl(db, erp, FW, "HF-3", "IMPLEMENTED", narrative="short")   # not ready: thin narrative
        _impl(db, erp, FW, "HF-4", "NOT_APPLICABLE")                   # out of the denominator
        _impl(db, scada, FW, "HF-1", "IMPLEMENTED", narrative=good)    # not ready: stale evidence
        fresh = date.today() + timedelta(days=90)
        db.add(EvidenceArtifact(organization_id=org.id, system_id=erp.id, filename="t.pdf",
                                control_ids=["HF-1", "HF-3"], framework_ids=[FW], expiration_date=fresh))
        linked = EvidenceArtifact(organization_id=org.id, system_id=erp.id, filename="l.pdf",
                                  control_ids=[], framework_ids=[], expiration_date=fresh)
        db.add(linked)
        db.add(EvidenceArtifact(organization_id=org.id, system_id=scada.id, filename="old.pdf",
                                control_ids=["HF-1"], framework_ids=[FW],
                                expiration_date=date.today() - timedelta(days=1)))
        db.flush()
        db.query(ControlImplementation).filter(ControlImplementation.system_id == erp.id,
                                               ControlImplementation.control_id == "HF-2") \
            .update({"evidence_ids": [linked.id]})
        db.commit()
        prep = client.get(f"/api/inspection/prep?framework_id={FW}&system_ids={erp.id}"
                          f"&system_ids={scada.id}").json()
        # 4 controls x 2 systems = 8 pairs, 1 N/A -> 7 assessed, 2 ready
        assert prep["assessed_items"] == 7 and prep["not_applicable"] == 1
        assert prep["readiness_score"] == round(2 / 7 * 100, 1)
        assert sum(f["ready"] for f in prep["families"]) == 2
        assert sum(f["total"] for f in prep["families"]) == 7
        assert len(prep["punch_list"]) == 7 - 2
        items = {(p["system_acronym"], p["control_id"]): p for p in prep["punch_list"]}
        assert items[("ERP", "HF-3")]["issues"] == ["narrative is thin or missing"]
        assert items[("SCADA", "HF-1")]["issues"] == ["evidence is expired"]
        assert ("ERP", "HF-4") not in items

    def test_scoped_user_cannot_read_another_systems_package(self, client, db):
        """INTEGRITY-19 / SECLIVE-2 / SECCODE-8 / E2E-7 (inspection part)."""
        org = Organization(name="Acme Scope", slug="acme-scope")
        db.add(org)
        db.flush()
        erp, scada = _system(db, org, "ERP"), _system(db, org, "SCADA")
        _catalog(db, FW, ["HF-1"])
        _activate(db, org, FW)
        _impl(db, erp, FW, "HF-1", "PARTIALLY")
        u = User(organization_id=org.id, username="plantonly", password_hash=hash_password("plant-pass-1234"),
                 email="p@example.com", role="evidence_contributor")
        db.add(u)
        db.flush()
        db.add(SystemAssignment(user_id=u.id, system_id=scada.id))
        db.commit()
        _login(client, "plantonly", "plant-pass-1234")
        base = f"/api/inspection/prep?framework_id={FW}"
        assert client.get(f"{base}&system_ids={erp.id}").status_code == 404
        assert client.get(f"{base}&system_ids={scada.id}&system_ids={erp.id}").status_code == 404
        assert client.get(f"/api/inspection/prep/punch-list.csv?framework_id={FW}"
                          f"&system_ids={erp.id}").status_code == 404
        own = client.get(f"{base}&system_ids={scada.id}")
        assert own.status_code == 200 and own.json()["system_ids"] == [scada.id]

    def test_punch_list_csv_neutralises_every_text_cell(self, auth_client, db):
        """E2E-11 / IMPORTS-14 / SECCODE-18: system acronym, control title and
        owner all come from user/import data."""
        client, seeded, _csrf = auth_client
        org = seeded["org"]
        s = _system(db, org, "Plant", acronym="=1+2")
        db.add(Control(framework_id=FW, control_id="HF-1", family="HF", family_name="HF",
                       title="+SUM(A1:A9)"))
        _activate(db, org, FW)
        db.add(ControlImplementation(system_id=s.id, framework_id=FW, control_id="HF-1",
                                     implementation_status="PARTIALLY",
                                     responsible_party="@SUM(1+1)*cmd|' /C calc'!A0"))
        db.commit()
        r = client.get(f"/api/inspection/prep/punch-list.csv?framework_id={FW}&system_ids={s.id}")
        rows = list(__import__("csv").DictReader(io.StringIO(r.text)))
        assert len(rows) == 1
        row = rows[0]
        assert row["System"] == "'=1+2" and row["Title"] == "'+SUM(A1:A9)"
        assert row["Owner"] == "'@SUM(1+1)*cmd|' /C calc'!A0"
        assert all(not v.startswith(("=", "+", "-", "@", "\t", "\r")) for v in row.values())


# =========================================================================== H6 — crosswalk

@pytest.fixture
def xwalk(auth_client, db):
    """Synthetic crosswalk: FWA/FWB/FWV all map into the hub.
    A-1 —equivalent/official→ HUB-1 ; B-1 —equivalent/official→ HUB-1
    A-2 —related/official→ HUB-2    ; B-2 —equivalent/official→ HUB-2
    V-1 —equivalent/vendor→ HUB-3   ; B-3 —equivalent/official→ HUB-3
    A-4 —intersects/official→ HUB-4 ; B-4 —equivalent/official→ HUB-4
    """
    client, seeded, csrf = auth_client
    org = seeded["org"]
    s = _system(db, org, "ERP")
    _catalog(db, "FWA", ["A-1", "A-2", "A-4"])
    _catalog(db, "FWB", ["B-1", "B-2", "B-3", "B-4"])
    _catalog(db, "FWV", ["V-1"])
    _catalog(db, HUB, ["HUB-1", "HUB-2", "HUB-3", "HUB-4"])
    _activate(db, org, "FWA", "FWB", "FWV", HUB)
    edges = [("FWA", "A-1", "HUB-1", "equivalent", "official"),
             ("FWB", "B-1", "HUB-1", "equivalent", "official"),
             ("FWA", "A-2", "HUB-2", "related", "official"),
             ("FWB", "B-2", "HUB-2", "equivalent", "official"),
             ("FWV", "V-1", "HUB-3", "equivalent", "vendor"),
             ("FWB", "B-3", "HUB-3", "equivalent", "official"),
             ("FWA", "A-4", "HUB-4", "intersects", "official"),
             ("FWB", "B-4", "HUB-4", "equivalent", "official")]
    for sf, sc, tc, rel, conf in edges:
        db.add(ControlMapping(source_framework_id=sf, source_control_id=sc, target_framework_id=HUB,
                              target_control_id=tc, relationship=rel, confidence=conf))
    for cid in ("B-1", "B-2", "B-3", "B-4"):
        _impl(db, s, "FWB", cid, "IMPLEMENTED")
    db.commit()
    return client, {"X-CSRF-Token": csrf}, s


class TestCrosswalkPropagation:
    def _suggested(self, client, s):
        return {(x["framework_id"], x["control_id"])
                for x in client.get(f"/api/crosswalk/suggestions?system_id={s.id}").json()["suggestions"]}

    def test_only_equivalent_or_superset_edges_propagate(self, xwalk):
        client, _h, s = xwalk
        got = self._suggested(client, s)
        assert ("FWA", "A-1") in got           # equivalent ∘ equivalent through the hub
        assert ("FWA", "A-2") not in got       # 'related' never propagates
        assert ("FWA", "A-4") not in got       # 'intersects' never propagates

    def test_review_queue_never_auto_applies(self, xwalk, db):
        client, h, s = xwalk
        before = {(i.framework_id, i.control_id): i.implementation_status
                  for i in db.query(ControlImplementation).filter(ControlImplementation.system_id == s.id)}
        client.get(f"/api/crosswalk/suggestions?system_id={s.id}")
        after = {(i.framework_id, i.control_id): i.implementation_status
                 for i in db.query(ControlImplementation).filter(ControlImplementation.system_id == s.id)}
        assert before == after
        r = client.post("/api/crosswalk/suggestions/accept", headers=h, json={
            "system_id": s.id, "framework_id": "FWA", "control_id": "A-1",
            "source_framework_id": "FWB", "source_control_id": "B-1"})
        assert r.status_code == 200 and r.json()["implementation_status"] == "PLANNED"
        assert _score_row(client, s.id, "FWA")["score_percentage"] == 0.0

    def test_finding_impact_matches_mapping_walk(self, xwalk, db):
        client, _h, s = xwalk
        f = Finding(organization_id=s.organization_id, system_id=s.id, framework_id="FWB",
                    control_id="B-1", title="impact probe", severity="HIGH", status="OPEN")
        db.add(f)
        db.commit()
        impacts = {(i["framework_id"], i["control_id"]): (i["relationship"], i["path"])
                   for i in client.get(f"/api/crosswalk/findings/{f.id}").json()["impacts"]}
        assert impacts == {(HUB, "HUB-1"): ("equivalent", "direct"),
                           ("FWA", "A-1"): ("equivalent", f"via {HUB}")}

    def test_vendor_leg_never_propagates_transitively(self, xwalk):
        client, _h, s = xwalk
        assert ("FWV", "V-1") not in self._suggested(client, s)


# =========================================================================== H6 — red-team aggregation

class TestRedTeamAggregation:
    def test_report_totals_follow_probable_loss_model(self):
        from services.risk_quantification import compute_report_totals
        highs = [100, 80, 60, 40, 20, 10, 5]
        fs = [{"estimated_exposure_low": v // 2, "estimated_exposure_high": v, "priority_score": v}
              for v in highs]
        expected_high = round(100 + 0.35 * (80 + 60 + 40 + 20) + 0.10 * (10 + 5))
        assert compute_report_totals(fs)["total_exposure_high"] == expected_high
        capped = compute_report_totals(fs, {"annual_revenue": 100})
        assert capped["total_exposure_high"] == 150  # 1.5x revenue cap
        assert capped["total_exposure_low"] <= capped["total_exposure_high"]


    @staticmethod
    def _model(vals):
        """Independent re-statement of the documented model (Help → Dollar exposure)."""
        o = sorted(vals, reverse=True)
        return round((o[0] if o else 0) + 0.35 * sum(o[1:5]) + 0.10 * sum(o[5:]))

    def test_attack_chain_exposure_follows_the_model_and_never_exceeds_the_report(self):
        """INTEGRITY-22: chain 'combined' used to be a straight sum of highs."""
        from services.redteam_analyzer import _build_attack_chains
        from services.risk_quantification import compute_report_totals
        highs = {"I1": 40_000_000, "I2": 30_000_000, "I3": 20_000_000,
                 "M1": 9_000_000, "M2": 8_000_000, "M3": 7_000_000, "M4": 6_000_000}
        fs = [{"id": k, "category": "Implementation Gap" if k[0] == "I" else "Finding Management",
               "estimated_exposure_low": v // 2, "estimated_exposure_high": v, "priority_score": v}
              for k, v in highs.items()]
        chain = next(c for c in _build_attack_chains(fs) if c["id"] == "AC-002")
        linked = [highs[i] for i in chain["finding_ids"]]
        assert chain["estimated_exposure_high"] == self._model(linked) < sum(linked)
        assert chain["estimated_exposure_low"] == self._model([v // 2 for v in linked])
        assert chain["estimated_exposure_high"] <= compute_report_totals(fs)["total_exposure_high"]
        capped = next(c for c in _build_attack_chains(fs, {"annual_revenue": 10_000_000})
                      if c["id"] == "AC-002")
        assert capped["estimated_exposure_high"] == 15_000_000  # 1.5x revenue cap
        assert capped["estimated_exposure_low"] <= capped["estimated_exposure_high"]

    def test_cross_report_total_uses_the_same_model_and_cap(self):
        """INTEGRITY-22: the briefing total was dominant + 35% of ALL others, no
        10% tail and no revenue cap (10 capped reports ~ 6.2x revenue)."""
        from services.risk_quantification import summarize_reports
        reports = [{"total_exposure_low": 100 - i, "total_exposure_high": 150 - i,
                    "top5_reduction_low": 10, "top5_reduction_high": 20, "quick_win_count": 1}
                   for i in range(10)]
        out = summarize_reports(reports)
        assert out["total_exposure_high"] == self._model([r["total_exposure_high"] for r in reports])
        assert out["total_exposure_low"] == self._model([r["total_exposure_low"] for r in reports])
        rest_high = self._model([r["total_exposure_high"] - 20 for r in reports])
        assert out["top5_reduction_high"] == out["total_exposure_high"] - rest_high
        assert out["quick_win_count"] == 10 and out["is_estimate"] is True
        capped = summarize_reports(reports, {"annual_revenue": 100})
        assert capped["total_exposure_high"] == 150  # never above 1.5x revenue
        assert 0 <= capped["top5_reduction_high"] <= capped["total_exposure_high"]

    def test_exposure_summary_endpoint_uses_latest_report_per_pair_within_scope(self, client, db):
        from datetime import datetime, timezone
        from models.redteam import RedTeamReport
        from services.risk_quantification import summarize_reports
        org = Organization(name="Acme RT", slug="acme-rt", settings={"risk_context": {"annual_revenue": 1000}})
        db.add(org)
        db.flush()
        erp, scada = _system(db, org, "ERP"), _system(db, org, "SCADA")

        def rep(s, fw, high, when):
            r = RedTeamReport(organization_id=org.id, system_id=s.id, framework_id=fw, run_by="t",
                              total_exposure_low=high // 2, total_exposure_high=high,
                              top5_reduction_low=high // 4, top5_reduction_high=high // 3,
                              quick_win_count=1, created_at=datetime(2026, 10, when, tzinfo=timezone.utc))
            db.add(r)
            return r
        rep(erp, "sox", 900, 1)          # superseded by the next one
        new_erp = rep(erp, "sox", 600, 2)
        new_scada = rep(scada, "sox", 500, 3)
        db.add_all([
            User(organization_id=org.id, username="rtadmin", password_hash=hash_password("rt-admin-12345"),
                 email="a@example.com", role="admin"),
            User(organization_id=org.id, username="rtscoped", password_hash=hash_password("rt-scope-12345"),
                 email="s@example.com", role="assessor"),
        ])
        db.flush()
        scoped = db.query(User).filter(User.username == "rtscoped").one()
        db.add(SystemAssignment(user_id=scoped.id, system_id=scada.id))
        db.commit()

        def as_dict(r):
            return {k: getattr(r, k) for k in ("total_exposure_low", "total_exposure_high",
                                               "top5_reduction_low", "top5_reduction_high", "quick_win_count")}
        _login(client, "rtadmin", "rt-admin-12345")
        got = client.get("/api/redteam/exposure-summary").json()
        want = summarize_reports([as_dict(new_erp), as_dict(new_scada)], {"annual_revenue": 1000})
        assert got["report_ids"] == sorted([new_erp.id, new_scada.id])
        assert {k: got[k] for k in want} == want
        _login(client, "rtscoped", "rt-scope-12345")
        assert client.get("/api/redteam/exposure-summary").json()["report_ids"] == [new_scada.id]


# =========================================================================== H7 — audit chain

class TestAuditChain:
    def test_concurrent_writers_keep_chain_valid(self, tmp_path):
        # Own engine/file (same PRAGMAs as the app) so the two-writer race can't
        # disturb the shared test DB; verification mirrors GET /api/audit/verify.
        from sqlalchemy import create_engine, event
        from database import Base
        from services import audit as audit_svc
        eng = create_engine(f"sqlite:///{tmp_path / 'race.db'}", connect_args={"check_same_thread": False})

        @event.listens_for(eng, "connect")
        def _pragmas(conn, _rec):
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

        Base.metadata.create_all(eng)
        org_id = 1
        Session = sessionmaker(bind=eng, autoflush=False, autocommit=False)
        s1, s2 = Session(), Session()
        try:
            audit_svc.record(s1, organization_id=org_id, actor_id=None, actor_username="tab-1",
                             action="UPDATE", entity_type="finding", entity_id=1)
            err = []

            def second_tab():
                try:
                    audit_svc.record(s2, organization_id=org_id, actor_id=None, actor_username="tab-2",
                                     action="UPDATE", entity_type="finding", entity_id=1)
                    s2.commit()
                except Exception as e:  # pragma: no cover - diagnostic
                    err.append(e)

            t = threading.Thread(target=second_tab)
            t.start()
            time.sleep(0.4)  # tab-2 has read the tail and is waiting for the write lock
            s1.commit()
            t.join(10)
            assert not err, err
        finally:
            s1.close()
            s2.close()
        check = Session()
        try:
            prev, broken = "0" * 64, None
            for e in check.query(AuditEntry).filter(AuditEntry.organization_id == org_id).order_by(AuditEntry.id):
                if e.integrity_hash != audit_svc.compute_hash(prev, e):
                    broken = e.id
                    break
                prev = e.integrity_hash
        finally:
            check.close()
            eng.dispose()
        assert broken is None, f"chain broken at audit entry {broken}"

    def test_rewritten_summary_is_detected(self, auth_client, db):
        from services import audit as audit_svc
        client, seeded, _csrf = auth_client
        e = audit_svc.record(db, organization_id=seeded["org"].id, actor_id=None, actor_username="admin",
                             action="UPDATE", entity_type="finding", entity_id=7,
                             summary="Finding 7 moved OPEN -> RISK_ACCEPTED")
        db.commit()
        assert client.get("/api/audit/verify").json()["valid"] is True
        db.query(AuditEntry).filter(AuditEntry.id == e.id).update({"summary": "Finding 7 viewed"})
        db.commit()
        assert client.get("/api/audit/verify").json()["valid"] is False

    def test_run_eval_exports_the_hmac_variable_the_app_reads(self):
        audit_src = (BACKEND / "services" / "audit.py").read_text()
        script = (REPO / "scripts" / "run-eval.sh").read_text()
        assert "ATHORIZE_AUDIT_HMAC_KEY" in audit_src  # canonical name since the ATHORIZE_* rename
        # R2SEC-5 (fix wave 2): run-eval no longer creates or exports keys at all —
        # the app reads <DATA_DIR>/secrets.env itself, like every start path — so
        # it can no longer export a name the app ignores (the original defect).
        # Behaviour: tests/test_ops_scripts.py.
        for stale in ("AUDIT_HMAC_KEY=", "export AUDIT_HMAC_KEY", "UNIVERSAL_AUDIT_HMAC_KEY"):
            assert stale not in script
        assert "export SECRET_KEY" not in script and "export ATHORIZE_AUDIT_HMAC_KEY" not in script


# =========================================================================== H7 — backup / restore

@pytest.fixture
def datadir(tmp_path, monkeypatch):
    """Point the backup service at a private, throw-away data dir."""
    from config import settings
    d = tmp_path / "data"
    (d / "evidence").mkdir(parents=True)
    monkeypatch.setattr(settings, "data_dir", d)
    # The backup service honours DATABASE_URL (IMPORTS-26); the test harness sets
    # it to ./test.db, so clear it to make DATA_DIR/data.db the live database.
    monkeypatch.setattr(settings, "database_url", "")
    monkeypatch.setattr(settings, "evidence_dir", d / "evidence")
    monkeypatch.setattr(settings, "backup_dir", d / "backups")
    return d


def _mkdb(path: Path, values: list[str], wal: bool = False):
    # Backup/restore refuse anything that is not an Athorize database (IMPORTS-21,
    # DOCKER-1), so the toy DB carries the real schema next to its probe table.
    from sqlalchemy import create_engine
    from database import Base
    eng = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(eng)
    eng.dispose()
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE IF NOT EXISTS t (v TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS pad (x BLOB)")
    for v in values:
        con.execute("INSERT INTO t VALUES (?)", (v,))
        con.execute("INSERT INTO pad VALUES (randomblob(2000))")
    con.commit()
    return con


def _archive_db_values(blob: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar, \
            __import__("tempfile").TemporaryDirectory() as td:
        p = Path(td) / "data.db"
        p.write_bytes(tar.extractfile("data.db").read())
        con = sqlite3.connect(p)
        try:
            return [r[0] for r in con.execute("SELECT v FROM t ORDER BY rowid")]
        finally:
            con.close()


def _manual_archive(db_src: Path, evidence: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        m = json.dumps({"version": 1}).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(m)
        tar.addfile(ti, io.BytesIO(m))
        tar.add(str(db_src), arcname="data.db")
        for name, data in (evidence or {}).items():
            ti = tarfile.TarInfo(f"evidence/{name}")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class TestBackupRestore:
    def test_round_trip_restores_rows_and_evidence_bytes(self, datadir):
        from services import backup
        _mkdb(datadir / "data.db", ["one", "two"]).close()
        (datadir / "evidence" / "1").mkdir()
        (datadir / "evidence" / "1" / "a.txt").write_bytes(b"evidence-a")
        blob, _name = backup.create_backup_bytes(None)
        # mutate after the backup
        con = sqlite3.connect(datadir / "data.db")
        con.execute("INSERT INTO t VALUES ('after')")
        con.commit()
        con.close()
        (datadir / "evidence" / "1" / "a.txt").write_bytes(b"tampered")
        backup.restore_from_bytes(blob)
        con = sqlite3.connect(datadir / "data.db")
        assert [r[0] for r in con.execute("SELECT v FROM t ORDER BY rowid")] == ["one", "two"]
        con.close()
        assert (datadir / "evidence" / "1" / "a.txt").read_bytes() == b"evidence-a"

    def test_backup_contains_committed_rows_still_in_wal(self, datadir):
        from services import backup
        live = _mkdb(datadir / "data.db", ["seed"], wal=True)
        try:
            live.execute("INSERT INTO t VALUES ('committed-after-seed')")
            live.commit()
            assert (datadir / "data.db-wal").stat().st_size > 0
            blob, _ = backup.create_backup_bytes(None)
        finally:
            live.close()
        assert _archive_db_values(blob) == ["seed", "committed-after-seed"]

    def test_restore_is_not_overridden_by_a_stale_wal(self, datadir):
        from services import backup
        src = datadir.parent / "src.db"
        _mkdb(src, ["restored"]).close()
        blob = _manual_archive(src)
        other_conn = _mkdb(datadir / "data.db", ["old"] * 50, wal=True)  # e.g. a concurrent request
        try:
            backup.restore_from_bytes(blob)
            con = sqlite3.connect(datadir / "data.db")
            values = {r[0] for r in con.execute("SELECT v FROM t")}
            con.close()
        finally:
            other_conn.close()
        assert values == {"restored"}

    def test_interrupted_restore_never_leaves_instance_without_a_database(self, datadir, monkeypatch):
        from services import backup
        _mkdb(datadir / "data.db", ["live"]).close()
        src = datadir.parent / "src.db"
        _mkdb(src, ["restored"]).close()
        blob = _manual_archive(src)

        # The restore no longer moves data.db at all (it installs the new content
        # through SQLite's backup API), so simulate SIGKILL / power loss at the
        # equivalent moment: everything staged and swapped, new DB not yet in.
        def crash(step):
            if step == "restore_dirs_swapped":
                raise SystemExit("killed")

        monkeypatch.setattr(backup, "_crash_point", crash)
        with pytest.raises(SystemExit):
            backup.restore_from_bytes(blob)
        assert (datadir / "data.db").is_file()
        backup.recover_interrupted_restore()  # what the next start runs
        con = sqlite3.connect(datadir / "data.db")
        assert [r[0] for r in con.execute("SELECT v FROM t")] == ["live"]
        con.close()

    def test_interrupted_backup_leaves_no_truncated_archive(self, datadir, monkeypatch):
        from services import backup
        _mkdb(datadir / "data.db", ["x"]).close()
        real = Path.write_bytes

        def half_write(self, data):
            if self.name.startswith("universal-backup-"):
                real(self, data[: len(data) // 2])
                raise SystemExit("killed mid-write")
            return real(self, data)

        # An implementation may instead stream the archive straight into a file
        # in the backups dir with tarfile: kill that mid-write too.
        real_addfile = tarfile.TarFile.addfile

        def addfile_then_kill(self, tarinfo, fileobj=None, *args, **kw):
            real_addfile(self, tarinfo, fileobj, *args, **kw)
            if self.name and str(datadir / "backups") in str(self.name):
                raise SystemExit("killed mid-write")

        monkeypatch.setattr(Path, "write_bytes", half_write)
        monkeypatch.setattr(tarfile.TarFile, "addfile", addfile_then_kill)
        with pytest.raises(SystemExit):
            backup.create_backup_bytes(None)
        monkeypatch.setattr(Path, "write_bytes", real)
        monkeypatch.setattr(tarfile.TarFile, "addfile", real_addfile)
        info = backup.backup_info()
        assert info["last_backup_name"] is None
        if info["last_backup_name"]:
            with tarfile.open(datadir / "backups" / info["last_backup_name"], "r:gz") as t:
                t.getmembers()  # must be a complete, readable archive

    def test_restore_really_invalidates_sessions(self, datadir):
        from services import backup
        src = datadir.parent / "src.db"
        _mkdb(src, ["backup-era"]).close()  # a real Athorize schema (restore refuses anything else)
        con = sqlite3.connect(src)
        con.execute("INSERT INTO user_sessions (id, user_id, expires_at) "
                    "VALUES ('cookie-of-a-since-removed-user', 1, '2099-01-01 00:00:00')")
        con.commit()
        con.close()
        _mkdb(datadir / "data.db", ["live"]).close()
        backup.restore_from_bytes(_manual_archive(src))
        con = sqlite3.connect(datadir / "data.db")
        n = con.execute("SELECT count(*) FROM user_sessions").fetchone()[0]
        con.close()
        assert n == 0

    def test_backup_includes_custom_frameworks(self, datadir):
        from services import backup
        _mkdb(datadir / "data.db", ["x"]).close()
        cf = datadir / "custom_frameworks" / "custom-acme"
        cf.mkdir(parents=True)
        (cf / "metadata.json").write_text(json.dumps({"id": "custom-acme", "name": "Acme policy"}))
        blob, _ = backup.create_backup_bytes(None)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            names = t.getnames()
        assert any(n.endswith("custom-acme/metadata.json") for n in names)


# =========================================================================== H7 — upgrade from old schema

def test_upgrade_from_june_2026_schema_keeps_every_row(tmp_path):
    """A synthetic DB written by the 2026-06-13 code (Acme demo data; catalog and
    mapping rows stripped to keep the fixture small) must open under today's
    code: inline migrations add the new columns, no row is lost, and the core
    pages answer 200."""
    data = tmp_path / "data"
    data.mkdir()
    (data / "data.db").write_bytes(gzip.decompress((FIXTURES / "athorize-2026-06-13-schema.db.gz").read_bytes()))
    con = sqlite3.connect(data / "data.db")
    before = {t: con.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
              for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    probe = r'''
import json, sys
import main
from fastapi.testclient import TestClient
out = {}
with TestClient(main.app) as c:
    out["login"] = c.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
    h = {"X-CSRF-Token": c.cookies.get("universal_csrf")}
    for p in ["/api/dashboard/snapshot", "/api/dashboard/compliance", "/api/dashboard/my-work",
              "/api/findings", "/api/systems", "/api/evidence", "/api/risks", "/api/redteam",
              "/api/crosswalk/nist-800-53-r5/AC-2", "/api/crosswalk/findings/1", "/api/audit/verify"]:
        out[p] = c.get(p).status_code
    out["verify"] = c.get("/api/audit/verify").json()
    out["put_control"] = c.put("/api/controls/systems/1/nist-800-53-r5/AC-2",
                               json={"implementation_status": "IMPLEMENTED"}, headers=h).status_code
print("PROBE" + json.dumps(out))
'''
    env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL",)}
    env.update(DATA_DIR=str(data), EVIDENCE_DIR=str(data / "evidence"), BACKUP_DIR=str(data / "backups"),
               HOME=str(tmp_path), SECRET_KEY="upgrade-test", PYTHONDONTWRITEBYTECODE="1",
               HISTORY_SNAPSHOT_INTERVAL_HOURS="0")
    for k in ("ATHORIZE_AUDIT_HMAC_KEY", "UNIVERSAL_AUDIT_HMAC_KEY", "AUDIT_HMAC_KEY"):
        env.pop(k, None)
    res = subprocess.run([sys.executable, "-c", probe], cwd=str(BACKEND), env=env,
                         capture_output=True, text=True, timeout=180)
    assert res.returncode == 0, res.stderr[-3000:]
    out = json.loads(res.stdout.split("PROBE", 1)[1].strip().splitlines()[0])
    assert out.pop("login") == 200
    verify = out.pop("verify")
    assert all(code == 200 for code in out.values()), out
    assert verify["valid"] is True
    con = sqlite3.connect(data / "data.db")
    after = {t: con.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
             for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    cols = {r[1] for r in con.execute("PRAGMA table_info(control_implementations)")}
    ucols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    con.close()
    assert "owner_id" in cols and "is_operator" in ucols
    for table, n in before.items():
        # these legitimately grow (login, the PUT above, crosswalk backfill, and
        # the INTEGRITY-21 startup refresh that re-loads the fixture's stripped catalogs)
        if table in ("audit_entries", "user_sessions", "control_implementations", "control_mappings", "controls"):
            assert after[table] >= n, table
        else:
            assert after[table] == n, (table, n, after[table])
