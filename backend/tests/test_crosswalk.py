"""Crosswalk: mapping loader, direct/transitive resolution, API filtering."""
import pytest

from models import Control, ControlImplementation, ControlMapping, EvidenceArtifact, Finding, FrameworkActivation, System
from services.crosswalk import resolve, _compose, _REVERSE


def _add_control(db, fw, cid, title=""):
    db.add(Control(framework_id=fw, control_id=cid, title=title or cid, family=cid.split("-")[0] if "-" in cid else ""))


def _add_edge(db, src_fw, src, dst_fw, dst, rel="equivalent", conf="official"):
    db.add(ControlMapping(
        source_framework_id=src_fw, source_control_id=src,
        target_framework_id=dst_fw, target_control_id=dst,
        relationship=rel, confidence=conf, rationale="test",
    ))


def _activate(db, org_id, *fw_ids):
    for fw in fw_ids:
        db.add(FrameworkActivation(organization_id=org_id, framework_id=fw, is_active=True))


class TestComposition:
    def test_reverse_is_involution(self):
        for rel, rev in _REVERSE.items():
            assert _REVERSE[rev] == rel

    def test_equivalent_chain_stays_equivalent(self):
        assert _compose("equivalent", "equivalent") == "equivalent"

    def test_related_taints_composition(self):
        assert _compose("related", "equivalent") == "related"
        assert _compose("equivalent", "related") == "related"

    def test_mixed_directions_degrade_to_intersects(self):
        assert _compose("subset", "superset") == "intersects"
        assert _compose("intersects", "equivalent") == "intersects"


class TestResolve:
    def test_direct_outbound_and_inbound(self, db, seeded):
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        db.commit()

        # outbound from the CMMC side
        out = resolve(db, "cmmc-2.0", "AC.L2-3.1.1", {"cmmc-2.0", "nist-800-53-r5"})
        assert [(e.framework_id, e.control_id, e.relationship, e.path) for e in out] == [
            ("nist-800-53-r5", "AC-2", "intersects", "direct"),
        ]
        # inbound from the hub side (reversed)
        inb = resolve(db, "nist-800-53-r5", "AC-2", {"cmmc-2.0", "nist-800-53-r5"})
        assert ("cmmc-2.0", "AC.L2-3.1.1") in {(e.framework_id, e.control_id) for e in inb}

    def test_subset_reverses_to_superset(self, db, seeded):
        _add_edge(db, "fedramp", "AC-2", "nist-800-53-r5", "AC-2", rel="subset")
        db.commit()
        inb = resolve(db, "nist-800-53-r5", "AC-2", {"fedramp"})
        assert inb[0].relationship == "superset"

    def test_transitive_via_hub(self, db, seeded):
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="equivalent")
        _add_edge(db, "fedramp", "AC-2", "nist-800-53-r5", "AC-2", rel="equivalent")
        db.commit()
        out = resolve(db, "cmmc-2.0", "AC.L2-3.1.1", {"cmmc-2.0", "fedramp", "nist-800-53-r5"})
        transitive = [e for e in out if e.framework_id == "fedramp"]
        assert len(transitive) == 1
        assert transitive[0].control_id == "AC-2"
        assert transitive[0].confidence == "derived"
        assert transitive[0].relationship == "equivalent"
        assert transitive[0].path == "via nist-800-53-r5"

    def test_hub_control_fans_out_to_spokes(self, db, seeded):
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        _add_edge(db, "fedramp", "AC-2", "nist-800-53-r5", "AC-2", rel="equivalent")
        db.commit()
        out = resolve(db, "nist-800-53-r5", "AC-2", {"cmmc-2.0", "fedramp"})
        got = {(e.framework_id, e.control_id) for e in out}
        assert got == {("cmmc-2.0", "AC.L2-3.1.1"), ("fedramp", "AC-2")}
        # both are direct inbound edges, not transitive
        assert all(e.path == "direct" for e in out)

    def test_inactive_framework_filtered(self, db, seeded):
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2")
        db.commit()
        out = resolve(db, "cmmc-2.0", "AC.L2-3.1.1", {"cmmc-2.0"})  # hub NOT active
        assert out == []

    def test_direct_beats_transitive_dedup(self, db, seeded):
        # fedramp maps directly to hub AND would also resolve transitively
        _add_edge(db, "fedramp", "AC-2", "nist-800-53-r5", "AC-2", rel="equivalent")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="equivalent")
        db.commit()
        out = resolve(db, "nist-800-53-r5", "AC-2", {"fedramp", "cmmc-2.0"})
        fed = [e for e in out if e.framework_id == "fedramp"]
        assert len(fed) == 1
        assert fed[0].path == "direct"


class TestLoader:
    def test_load_and_unload_mappings(self, db, seeded, tmp_path):
        import json
        from services.framework_loader import FrameworkLoader

        fw_dir = tmp_path / "demo-fw"
        fw_dir.mkdir()
        (fw_dir / "metadata.json").write_text(json.dumps({"id": "demo-fw", "name": "Demo"}))
        (fw_dir / "mappings.json").write_text(json.dumps({
            "framework_id": "demo-fw",
            "version": "1.0",
            "source": "test",
            "mappings": [
                {"control_id": "D-1", "target_framework": "nist-800-53-r5", "target_control": "AC-2",
                 "relationship": "equivalent", "confidence": "official"},
                {"control_id": "D-1", "target_framework": "nist-800-53-r5", "target_control": "AC-2",
                 "relationship": "equivalent", "confidence": "official"},  # duplicate — skipped
                {"control_id": "D-2", "target_framework": "nist-800-53-r5", "target_control": "AC-3",
                 "relationship": "BOGUS", "confidence": "official"},  # invalid — skipped
            ],
        }))
        loader = FrameworkLoader(tmp_path)
        count = loader.load_mappings("demo-fw", db)
        assert count == 1
        assert db.query(ControlMapping).count() == 1

        loader.unload_mappings("demo-fw", db)
        assert db.query(ControlMapping).count() == 0

    def test_missing_mappings_file_loads_zero(self, db, seeded, tmp_path):
        import json
        from services.framework_loader import FrameworkLoader
        fw_dir = tmp_path / "bare-fw"
        fw_dir.mkdir()
        (fw_dir / "metadata.json").write_text(json.dumps({"id": "bare-fw", "name": "Bare"}))
        loader = FrameworkLoader(tmp_path)
        assert loader.load_mappings("bare-fw", db) == 0


class TestApi:
    def test_endpoint_requires_auth(self, client):
        r = client.get("/api/crosswalk/cmmc-2.0/AC.L2-3.1.1")
        assert r.status_code == 401

    def test_endpoint_returns_titled_mappings(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "nist-800-53-r5", "AC-2", "Account Management")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        db.commit()

        r = client.get("/api/crosswalk/cmmc-2.0/AC.L2-3.1.1")
        assert r.status_code == 200
        body = r.json()
        assert body["mappings"] == [{
            "framework_id": "nist-800-53-r5",
            "control_id": "AC-2",
            "title": "Account Management",
            "relationship": "intersects",
            "confidence": "official",
            "path": "direct",
            "rationale": "test",
            "open_findings": 0,
        }]

    def test_endpoint_filters_inactive_frameworks(self, auth_client, db):
        client, seeded, _ = auth_client
        # nothing activated for this org
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2")
        db.commit()
        r = client.get("/api/crosswalk/cmmc-2.0/AC.L2-3.1.1")
        assert r.status_code == 200
        assert r.json()["mappings"] == []


class TestFindingImpact:
    def _seed_finding(self, db, org, status="OPEN"):
        system = System(organization_id=org.id, name="Sys", acronym="SYS",
                        description="", system_type="", environment="production",
                        criticality="moderate")
        db.add(system)
        db.flush()
        finding = Finding(organization_id=org.id, system_id=system.id,
                          framework_id="cmmc-2.0", control_id="AC.L2-3.1.1",
                          title="Stale accounts", status=status)
        db.add(finding)
        db.flush()
        return system, finding

    def test_finding_impact_lists_mapped_controls_with_impl_status(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "nist-800-53-r5", "AC-2", "Account Management")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        system, finding = self._seed_finding(db, org)
        db.add(ControlImplementation(system_id=system.id, framework_id="nist-800-53-r5",
                                     control_id="AC-2", implementation_status="IMPLEMENTED"))
        db.commit()

        r = client.get(f"/api/crosswalk/findings/{finding.id}")
        assert r.status_code == 200
        impacts = r.json()["impacts"]
        assert len(impacts) == 1
        assert impacts[0]["framework_id"] == "nist-800-53-r5"
        assert impacts[0]["control_id"] == "AC-2"
        assert impacts[0]["implementation_status"] == "IMPLEMENTED"

    def test_finding_impact_404_cross_org(self, auth_client, db):
        client, seeded, _ = auth_client
        r = client.get("/api/crosswalk/findings/99999")
        assert r.status_code == 404

    def test_finding_without_control_has_no_impacts(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        system = System(organization_id=org.id, name="S2", acronym="S2",
                        description="", system_type="", environment="production",
                        criticality="moderate")
        db.add(system)
        db.flush()
        f = Finding(organization_id=org.id, system_id=system.id,
                    framework_id="cmmc-2.0", control_id="", title="No control", status="OPEN")
        db.add(f)
        db.commit()
        r = client.get(f"/api/crosswalk/findings/{f.id}")
        assert r.status_code == 200
        assert r.json()["impacts"] == []

    def test_control_crosswalk_counts_active_findings_on_mapped_control(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "cmmc-2.0", "AC.L2-3.1.1", "Authorized Access Control")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        self._seed_finding(db, org, status="OPEN")
        self._seed_finding(db, org, status="CLOSED")  # terminal — not counted
        db.commit()

        # Viewing the hub control: the CMMC mapped control carries 1 active finding
        r = client.get("/api/crosswalk/nist-800-53-r5/AC-2")
        assert r.status_code == 200
        cmmc = [m for m in r.json()["mappings"] if m["framework_id"] == "cmmc-2.0"]
        assert cmmc[0]["open_findings"] == 1


class TestEvidenceSuggestions:
    def _seed_evidence(self, db, org, control_ids, framework_ids):
        system = System(organization_id=org.id, name="EvSys", acronym="EV",
                        description="", system_type="", environment="production",
                        criticality="moderate")
        db.add(system)
        db.flush()
        ev = EvidenceArtifact(organization_id=org.id, system_id=system.id,
                              filename="scan.pdf", control_ids=control_ids,
                              framework_ids=framework_ids)
        db.add(ev)
        db.flush()
        return system, ev

    def test_suggests_mapped_control_in_other_framework(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "cmmc-2.0", "AC.L2-3.1.1", "Authorized Access Control")
        _add_control(db, "nist-800-53-r5", "AC-2", "Account Management")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="intersects")
        _, ev = self._seed_evidence(db, org, ["AC.L2-3.1.1"], ["cmmc-2.0"])
        db.commit()

        r = client.get(f"/api/crosswalk/evidence/{ev.id}/suggestions")
        assert r.status_code == 200
        sugs = r.json()["suggestions"]
        assert len(sugs) == 1
        assert sugs[0]["framework_id"] == "nist-800-53-r5"
        assert sugs[0]["control_id"] == "AC-2"
        assert sugs[0]["source_control_id"] == "AC.L2-3.1.1"

    def test_already_linked_not_suggested(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "cmmc-2.0", "AC.L2-3.1.1")
        _add_control(db, "nist-800-53-r5", "AC-2")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="equivalent")
        _, ev = self._seed_evidence(db, org, ["AC.L2-3.1.1", "AC-2"], ["cmmc-2.0", "nist-800-53-r5"])
        db.commit()
        r = client.get(f"/api/crosswalk/evidence/{ev.id}/suggestions")
        assert r.json()["suggestions"] == []

    def test_related_mappings_excluded(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "cmmc-2.0", "AC.L2-3.1.1")
        _add_control(db, "nist-800-53-r5", "AC-2")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel="related")
        _, ev = self._seed_evidence(db, org, ["AC.L2-3.1.1"], ["cmmc-2.0"])
        db.commit()
        r = client.get(f"/api/crosswalk/evidence/{ev.id}/suggestions")
        assert r.json()["suggestions"] == []


class TestImplementationSuggestions:
    def _seed_system_with_impl(self, db, org, status="IMPLEMENTED"):
        system = System(organization_id=org.id, name="PSys", acronym="PS",
                        description="", system_type="", environment="production",
                        criticality="moderate")
        db.add(system)
        db.flush()
        impl = ControlImplementation(system_id=system.id, framework_id="cmmc-2.0",
                                     control_id="AC.L2-3.1.1",
                                     implementation_status=status,
                                     narrative="MFA enforced via IdP",
                                     evidence_ids=[7])
        db.add(impl)
        db.flush()
        return system, impl

    def _wire(self, db, org, rel="equivalent"):
        _activate(db, org.id, "cmmc-2.0", "nist-800-53-r5")
        _add_control(db, "nist-800-53-r5", "AC-2", "Account Management")
        _add_edge(db, "cmmc-2.0", "AC.L2-3.1.1", "nist-800-53-r5", "AC-2", rel=rel)

    def test_satisfied_impl_suggests_unimplemented_mapped_control(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        self._wire(db, org)
        system, _ = self._seed_system_with_impl(db, org)
        db.commit()

        r = client.get(f"/api/crosswalk/suggestions?system_id={system.id}")
        assert r.status_code == 200
        sugs = r.json()["suggestions"]
        assert len(sugs) == 1
        assert sugs[0]["framework_id"] == "nist-800-53-r5"
        assert sugs[0]["control_id"] == "AC-2"
        assert sugs[0]["source_status"] == "IMPLEMENTED"

    def test_intersects_relationship_not_suggested(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        self._wire(db, org, rel="intersects")
        system, _ = self._seed_system_with_impl(db, org)
        db.commit()
        r = client.get(f"/api/crosswalk/suggestions?system_id={system.id}")
        assert r.json()["suggestions"] == []

    def test_already_implemented_target_not_suggested(self, auth_client, db):
        client, seeded, _ = auth_client
        org = seeded["org"]
        self._wire(db, org)
        system, _ = self._seed_system_with_impl(db, org)
        db.add(ControlImplementation(system_id=system.id, framework_id="nist-800-53-r5",
                                     control_id="AC-2", implementation_status="IMPLEMENTED"))
        db.commit()
        r = client.get(f"/api/crosswalk/suggestions?system_id={system.id}")
        assert r.json()["suggestions"] == []

    def test_accept_creates_planned_row_with_provenance(self, auth_client, db):
        client, seeded, csrf = auth_client
        org = seeded["org"]
        self._wire(db, org)
        system, _ = self._seed_system_with_impl(db, org)
        db.commit()

        r = client.post("/api/crosswalk/suggestions/accept", json={
            "system_id": system.id,
            "framework_id": "nist-800-53-r5",
            "control_id": "AC-2",
            "source_framework_id": "cmmc-2.0",
            "source_control_id": "AC.L2-3.1.1",
        }, headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 200
        assert r.json()["implementation_status"] == "PLANNED"

        row = db.query(ControlImplementation).filter_by(
            system_id=system.id, framework_id="nist-800-53-r5", control_id="AC-2").first()
        assert row is not None
        assert row.implementation_status == "PLANNED"
        assert "[Crosswalk] Seeded from cmmc-2.0 AC.L2-3.1.1" in row.narrative
        assert "MFA enforced via IdP" in row.narrative
        assert row.evidence_ids == [7]

        # suggestion disappears once accepted (PLANNED != NOT_ASSESSED)
        r2 = client.get(f"/api/crosswalk/suggestions?system_id={system.id}")
        assert r2.json()["suggestions"] == []

    def test_accept_rejects_weak_mapping(self, auth_client, db):
        client, seeded, csrf = auth_client
        org = seeded["org"]
        self._wire(db, org, rel="intersects")
        system, _ = self._seed_system_with_impl(db, org)
        db.commit()
        r = client.post("/api/crosswalk/suggestions/accept", json={
            "system_id": system.id,
            "framework_id": "nist-800-53-r5",
            "control_id": "AC-2",
            "source_framework_id": "cmmc-2.0",
            "source_control_id": "AC.L2-3.1.1",
        }, headers={"X-CSRF-Token": csrf} if csrf else {})
        assert r.status_code == 409
