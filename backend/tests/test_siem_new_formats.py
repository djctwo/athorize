"""New scanner formats: Qualys CSV, Tenable CSV, OpenVAS XML — detect + parse."""
import services.siem_import as S


class TestQualys:
    CSV = '"QID","Title","Severity","IP","Port","CVE ID","Threat"\n"38173","SSL/TLS 64-bit block cipher suites supported (SWEET32)","4","10.0.0.5","443","CVE-2016-2183","3DES cipher suites enabled"\n'

    def test_detect(self):
        assert S.detect_format("scan.csv", self.CSV) == "qualys_csv"

    def test_parse_severity_is_5point_scale(self):
        r = S.parse_file(self.CSV, "qualys_csv")
        assert len(r) == 1
        assert r[0]["severity"] == "HIGH"  # Qualys 4 = high (not the "1=critical" convention)
        assert r[0]["extra_data"]["dst_ip"] == "10.0.0.5"
        assert r[0]["extra_data"]["rule_id"] == "38173"
        assert r[0]["extra_data"]["cve"] == "CVE-2016-2183"


class TestTenable:
    CSV = "Plugin ID,Plugin Name,Severity,IP Address,Port,CVE,Synopsis\n19506,TLS 1.0 Protocol Detection,Medium,10.0.0.9,443,CVE-2011-3389,Weak TLS\n"

    def test_detect(self):
        assert S.detect_format("export.csv", self.CSV) == "tenable_csv"

    def test_parse(self):
        r = S.parse_file(self.CSV, "tenable_csv")
        assert r[0]["severity"] == "MEDIUM"
        assert r[0]["extra_data"]["dst_ip"] == "10.0.0.9"
        assert r[0]["extra_data"]["plugin_id"] == "19506"

    def test_numeric_severity_not_inverted(self):
        # Tenable numeric 4 = Critical (NOT low). Regression for the inversion bug.
        csv = "Plugin ID,Plugin Name,Severity,IP Address\n1,X,4,10.0.0.1\n2,Y,1,10.0.0.2\n"
        r = S.parse_file(csv, "tenable_csv")
        assert r[0]["severity"] == "CRITICAL"
        assert r[1]["severity"] == "LOW"

    def test_tenable_with_risk_column_not_misdetected_as_nessus(self):
        csv = "Plugin,Plugin Name,Risk,Asset,Port\n1,TLS,Medium,10.0.0.9,443\n"
        assert S.detect_format("export.csv", csv) == "tenable_csv"


class TestDetectEdgeCases:
    def test_qid_substring_not_misdetected(self):
        # a 'uniqid' column must NOT route to Qualys
        csv = "time,uniqid,src_ip,alert_name\n1,abc,10.0.0.1,x\n"
        assert S.detect_format("data.csv", csv) == "splunk_csv"

    def test_unknown_xml_returns_none(self):
        assert S.detect_format("scap.xml", "<Benchmark><Rule/></Benchmark>") is None


class TestOpenVAS:
    XML = ('<report><results><result><name>OpenSSH Vuln</name><host>10.0.0.7</host>'
           '<port>22/tcp</port><threat>High</threat>'
           '<nvt oid="1.3.6.1"><refs><ref type="cve" id="CVE-2019-6111"/></refs></nvt>'
           '<description>scp client flaw</description></result></results></report>')

    def test_detect(self):
        assert S.detect_format("report.xml", self.XML) == "openvas_xml"

    def test_parse_threat_and_port(self):
        r = S.parse_file(self.XML, "openvas_xml")
        assert r[0]["severity"] == "HIGH"
        assert r[0]["extra_data"]["dst_ip"] == "10.0.0.7"
        assert r[0]["extra_data"]["dst_port"] == 22
        assert r[0]["extra_data"]["protocol"] == "tcp"
        assert r[0]["extra_data"]["cve"] == "CVE-2019-6111"

    def test_cvss_fallback_when_no_threat(self):
        xml = '<report><result><name>X</name><host>h</host><port>0</port><severity>9.8</severity></result></report>'
        r = S.parse_file(xml, "openvas_xml")
        assert r[0]["severity"] == "CRITICAL"

    def test_malformed_xml_returns_empty(self):
        assert S.parse_file("<not valid", "openvas_xml") == []


class TestWinEvent:
    # Get-WinEvent | Select TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message
    GWE = (
        "TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message\n"
        "2026-06-27T10:00:00,4625,Error,Microsoft-Windows-Security-Auditing,DC-01,An account failed to log on.\n"
        "2026-06-27T10:01:00,7045,Information,Service Control Manager,DC-01,A service was installed.\n"
    )
    # Event Viewer CSV export
    EV = (
        "Level,Date and Time,Source,Event ID,Task Category,Computer\n"
        "Warning,6/27/2026 10:02,DNS,4013,None,DC-01\n"
    )

    def test_detect_get_winevent(self):
        assert S.detect_format("events.csv", self.GWE) == "winevent_csv"

    def test_detect_event_viewer(self):
        assert S.detect_format("export.csv", self.EV) == "winevent_csv"

    def test_parse_levels(self):
        r = S.parse_file(self.GWE, "winevent_csv")
        assert len(r) == 2
        assert r[0]["severity"] == "HIGH"   # Error
        assert r[0]["extra_data"]["event_id"] == "4625"
        assert r[0]["extra_data"]["host"] == "DC-01"
        assert r[0]["extra_data"]["provider"].startswith("Microsoft-Windows")
        assert r[1]["severity"] == "LOW"    # Information

    def test_event_viewer_warning(self):
        r = S.parse_file(self.EV, "winevent_csv")
        assert r[0]["severity"] == "MEDIUM"  # Warning
        assert r[0]["extra_data"]["event_id"] == "4013"


def test_registry_has_17_formats():
    keys = {f["key"] for f in S.SUPPORTED_FORMATS}
    assert {"qualys_csv", "tenable_csv", "openvas_xml", "winevent_csv", "nessus_xml"} <= keys
    assert len(S.SUPPORTED_FORMATS) == 17
