"""Asset-source imports: Tanium CSV + Cisco ISE CSV — detect, parse, map, dedup."""
import services.asset_import as A


class TestTanium:
    CSV = (
        "Computer Name,Operating System,IP Address,MAC Address,Manufacturer,Model,Chassis Type,Serial Number\n"
        "WS-FIN-04,Windows 11 Enterprise,10.20.5.40 fe80::1,00:1A:2B:3C:4D:5E,Dell Inc.,Latitude 7440,Laptop,ABC123\n"
        "APP-SRV-09,Red Hat Enterprise Linux 9.3,10.10.1.9,00:AA:BB:CC:DD:EE,VMware Inc.,Virtual Platform,Server,\n"
    )

    def test_detect(self):
        assert A.detect_source("inventory.csv", self.CSV) == "tanium_csv"

    def test_parse_maps_columns(self):
        rows = A.parse_assets(self.CSV, "tanium_csv")
        assert len(rows) == 2
        ws = rows[0]
        assert ws["asset_name"] == "WS-FIN-04"
        assert ws["os_family"] == "WINDOWS"
        assert ws["ip_address"] == "10.20.5.40"  # first IPv4, not the v6 tail
        assert ws["mac_address"] == "00:1A:2B:3C:4D:5E"
        assert ws["vendor"] == "Dell Inc."
        assert ws["asset_role"] == "LAPTOP"  # from Chassis Type
        assert "tanium" in ws["tags"]
        assert ws["notes"] == "Serial: ABC123"

    def test_role_and_os_inference(self):
        rows = A.parse_assets(self.CSV, "tanium_csv")
        srv = rows[1]
        assert srv["os_family"] == "LINUX"
        assert srv["asset_role"] == "SERVER"

    def test_dedup_key_is_mac_based(self):
        rows = A.parse_assets(self.CSV, "tanium_csv")
        # Same MAC (different separators/case) collapses to the same identity.
        k1 = A._dedup_key("00:1A:2B:3C:4D:5E", "WS-FIN-04", "WS-FIN-04")
        k2 = A._dedup_key("001a2b3c4d5e", "other", "other")
        assert rows[0]["_dedup"] == k1 == k2


class TestCiscoISE:
    CSV = (
        "MACAddress,EndPointPolicy,IdentityGroup,Hostname,OperatingSystem,IPAddress,Vendor\n"
        "AA:BB:CC:11:22:33,Workstation,Employees,LT-ENG-12,Windows 10,192.168.4.21,Intel\n"
        "DD:EE:FF:44:55:66,Cisco-IP-Phone,Phones,,,192.168.4.55,Cisco\n"
    )

    def test_detect(self):
        assert A.detect_source("ise_endpoints.csv", self.CSV) == "cisco_ise_csv"

    def test_parse_maps_columns(self):
        rows = A.parse_assets(self.CSV, "cisco_ise_csv")
        assert len(rows) == 2
        ws = rows[0]
        assert ws["asset_name"] == "LT-ENG-12"
        assert ws["asset_role"] == "WORKSTATION"  # from EndPointPolicy
        assert ws["ip_address"] == "192.168.4.21"
        assert "cisco-ise" in ws["tags"]
        assert "ISE policy: Workstation" in ws["notes"]

    def test_nameless_endpoint_falls_back_to_mac(self):
        rows = A.parse_assets(self.CSV, "cisco_ise_csv")
        phone = rows[1]
        assert phone["asset_name"] == "DD:EE:FF:44:55:66"  # no hostname → MAC
        assert phone["asset_role"] == "MOBILE"  # "phone" hint


class TestConnectorNormalizers:
    """Live-connector JSON → canonical rows (the version-stable, testable core)."""

    def test_tanium_result_mapping(self):
        from services import asset_connectors as C
        result_set = {
            "columns": [{"name": "Computer Name"}, {"name": "Operating System"},
                        {"name": "IP Address"}, {"name": "Chassis Type"}],
            "rows": [
                {"data": [[{"text": "WS-API-01"}], [{"text": "Windows 11 Pro"}],
                          [{"text": "10.1.2.3"}], [{"text": "Laptop"}]]},
            ],
        }
        rows = C.normalize_tanium_result(result_set)
        assert len(rows) == 1
        assert rows[0]["asset_name"] == "WS-API-01"
        assert rows[0]["os_family"] == "WINDOWS"
        assert rows[0]["ip_address"] == "10.1.2.3"
        assert rows[0]["asset_role"] == "LAPTOP"
        assert "tanium" in rows[0]["tags"]

    def test_ise_endpoint_mapping(self):
        from services import asset_connectors as C
        eps = [{
            "id": "abc", "name": "AA:BB:CC:00:11:22", "mac": "AA:BB:CC:00:11:22",
            "groupId": "grp-workstations",
            "customAttributes": {"customAttributes": {"Operating System": "Windows 10", "EndPointPolicy": "Workstation"}},
        }]
        rows = C.normalize_ise_endpoints(eps)
        assert rows[0]["asset_name"] == "AA:BB:CC:00:11:22"
        assert rows[0]["os_family"] == "WINDOWS"
        assert rows[0]["asset_role"] == "WORKSTATION"
        assert "cisco-ise" in rows[0]["tags"]
        assert "ISE policy: Workstation" in rows[0]["notes"]

    def test_status_unconfigured_by_default(self, monkeypatch):
        from services import asset_connectors as C
        for var in ("TANIUM_URL", "TANIUM_API_TOKEN", "TANIUM_SAVED_QUESTION_ID",
                    "CISCO_ISE_URL", "CISCO_ISE_USER", "CISCO_ISE_PASSWORD"):
            monkeypatch.delenv(var, raising=False)
        status = {s["key"]: s["configured"] for s in C.connector_status()}
        assert status == {"tanium": False, "cisco_ise": False}

    def test_fetch_unconfigured_raises(self, monkeypatch):
        from services import asset_connectors as C
        monkeypatch.delenv("TANIUM_URL", raising=False)
        try:
            C.fetch_tanium()
            assert False, "expected ConnectorError"
        except C.ConnectorError:
            pass


class TestDetectEdgeCases:
    def test_unknown_csv_returns_none(self):
        assert A.detect_source("data.csv", "time,src_ip,alert_name\n1,10.0.0.1,x\n") is None

    def test_ise_detected_by_macaddress_alone(self):
        assert A.detect_source("x.csv", "MACAddress,IPAddress\nAA:BB,1.1.1.1\n") == "cisco_ise_csv"

    def test_sources_and_parsers_in_sync(self):
        assert {s["key"] for s in A.SUPPORTED_SOURCES} == set(A.PARSERS)
