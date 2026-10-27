from services.siem_import import (
    detect_format, parse_file, parse_splunk_csv, parse_suricata_eve,
    parse_snort_fast, parse_yara_json, parse_nessus_csv,
    parse_generic_cef,
)


def test_detect_splunk_csv():
    assert detect_format("alerts.csv", "alert_name,severity,src_ip") == "splunk_csv"


def test_detect_nessus_csv():
    assert detect_format("scan.csv", "Plugin ID,CVE,Risk,Host,Port") == "nessus_csv"


def test_detect_suricata_json():
    content = '{"timestamp":"2026-01-01","alert":{"signature":"test","severity":2}}'
    assert detect_format("eve.json", content) == "suricata_eve"


def test_detect_snort_fast():
    content = '01/01-12:00:00.123456 [**] [1:2001:1] ET MALWARE [**]'
    assert detect_format("alert.log", content) == "snort_fast"


def test_detect_cef():
    content = "CEF:0|Vendor|Product|1.0|100|Test|5|src=1.1.1.1"
    assert detect_format("events.log", content) == "generic_cef"


def test_parse_splunk_csv():
    csv_content = "alert_name,severity,src_ip,dst_ip\nSQL Injection Attempt,high,10.0.0.1,10.0.0.2\n"
    results = parse_splunk_csv(csv_content)
    assert len(results) == 1
    assert results[0]["title"] == "SQL Injection Attempt"
    assert results[0]["severity"] == "HIGH"
    assert results[0]["extra_data"]["source_type"] == "splunk"
    assert results[0]["extra_data"]["src_ip"] == "10.0.0.1"


def test_parse_suricata_eve():
    content = '{"timestamp":"2026-01-01T12:00:00","alert":{"signature":"ET MALWARE Test","severity":1,"signature_id":"2001001"},"src_ip":"192.168.1.1","dest_ip":"10.0.0.1","src_port":54321,"dest_port":80,"proto":"TCP"}'
    results = parse_suricata_eve(content)
    assert len(results) == 1
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["extra_data"]["protocol"] == "TCP"


def test_parse_snort_fast():
    line = '01/15-14:30:00.123456 [**] [1:2001:3] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.100:22 -> 10.0.0.50:54321'
    results = parse_snort_fast(line)
    assert len(results) == 1
    assert results[0]["severity"] == "HIGH"
    assert results[0]["extra_data"]["src_ip"] == "192.168.1.100"


def test_parse_yara_json():
    content = '[{"rule":"Mimikatz_Detector","tags":["malware","hacktool"],"file":"/tmp/suspicious.exe","strings":["sekurlsa"]}]'
    results = parse_yara_json(content)
    assert len(results) == 1
    assert results[0]["title"] == "YARA: Mimikatz_Detector"
    assert results[0]["severity"] == "HIGH"


def test_parse_nessus_csv():
    csv_content = "Plugin ID,CVE,Risk,Host,Port,Name,Synopsis\n12345,CVE-2014-0160,Critical,10.0.0.5,443,OpenSSL Heartbeat Information Disclosure (Heartbleed),Remote memory disclosure\n"
    results = parse_nessus_csv(csv_content)
    assert len(results) == 1
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["extra_data"]["dst_ip"] == "10.0.0.5"


def test_parse_cef():
    line = "CEF:0|Palo Alto|Firewall|10.0|100|Threat Detected|8|src=172.16.0.1 dst=10.0.0.5 spt=12345 dpt=443 proto=TCP"
    results = parse_generic_cef(line)
    assert len(results) == 1
    assert results[0]["severity"] == "HIGH"
    assert results[0]["extra_data"]["src_ip"] == "172.16.0.1"


def test_dedup_hash_unique():
    csv1 = "alert_name,severity,src_ip,dst_ip,_time\nAlert1,high,1.1.1.1,2.2.2.2,2026-01-01\n"
    csv2 = "alert_name,severity,src_ip,dst_ip,_time\nAlert1,high,1.1.1.1,2.2.2.2,2026-01-02\n"
    r1 = parse_splunk_csv(csv1)
    r2 = parse_splunk_csv(csv2)
    assert r1[0]["extra_data"]["dedup_hash"] != r2[0]["extra_data"]["dedup_hash"]


# ---- New formats (2026-06-11): Sentinel, CrowdStrike, Elastic, Wazuh, GuardDuty, syslog ----

def test_detect_sentinel_csv():
    assert detect_format("alerts.csv", "TimeGenerated,AlertName,AlertSeverity,Description") == "sentinel_csv"


def test_detect_crowdstrike_csv():
    assert detect_format("detects.csv", "DetectId,DetectName,SeverityName,ComputerName") == "crowdstrike_csv"


def test_detect_wazuh_json():
    line = '{"timestamp":"2026-06-01","rule":{"level":10,"description":"x","id":"5710"},"agent":{"name":"web01"}}'
    assert detect_format("alerts.json", line) == "wazuh_json"


def test_detect_elastic_json():
    line = '{"@timestamp":"2026-06-01T00:00:00Z","event":{"severity":3},"rule":{"name":"x"}}'
    assert detect_format("alerts.ndjson", line) == "elastic_json"


def test_detect_guardduty_json():
    content = '{"Findings":[{"Title":"x","Severity":8}]}'
    assert detect_format("findings.json", content) == "guardduty_json"


def test_detect_syslog_5424():
    assert detect_format("messages.log", "<34>1 2026-06-11T22:14:15Z host app 1 ID47 - msg") == "syslog_rfc5424"


def test_parse_sentinel_csv():
    content = (
        "TimeGenerated,AlertName,AlertSeverity,Description,SystemAlertId,CompromisedEntity\n"
        '2026-06-01T10:00:00Z,Suspicious sign-in,High,Impossible travel detected,abc-123,corp-dc01\n'
    )
    rows = parse_file(content, "sentinel_csv")
    assert len(rows) == 1
    assert rows[0]["title"] == "Suspicious sign-in"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["extra_data"]["source_type"] == "sentinel"
    assert rows[0]["extra_data"]["dedup_hash"]


def test_parse_crowdstrike_csv():
    content = (
        "DetectId,DetectName,SeverityName,ComputerName,LocalIP,Tactic,Technique,Timestamp\n"
        "ldt:1,Credential dumping detected,Critical,WS-042,10.1.2.3,Credential Access,OS Credential Dumping,2026-06-01T01:00:00Z\n"
    )
    rows = parse_file(content, "crowdstrike_csv")
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["extra_data"]["host"] == "WS-042"


def test_parse_elastic_json():
    content = (
        '{"@timestamp":"2026-06-01T00:00:00Z","rule":{"name":"Possible C2 beacon","id":"r1"},'
        '"event":{"severity_label":"high"},"source":{"ip":"10.0.0.5","port":51234},'
        '"destination":{"ip":"203.0.113.9","port":443},"message":"beacon-like traffic"}\n'
    )
    rows = parse_file(content, "elastic_json")
    assert len(rows) == 1
    assert rows[0]["title"] == "Possible C2 beacon"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["extra_data"]["dst_ip"] == "203.0.113.9"


def test_parse_wazuh_json_levels():
    lines = [
        '{"timestamp":"t1","rule":{"level":13,"description":"Shellshock attack","id":"31168"},"agent":{"name":"web01"},"data":{"srcip":"1.2.3.4"}}',
        '{"timestamp":"t2","rule":{"level":5,"description":"Login session opened","id":"5501"},"agent":{"name":"web01"},"data":{}}',
    ]
    rows = parse_file("\n".join(lines), "wazuh_json")
    assert [r["severity"] for r in rows] == ["CRITICAL", "MEDIUM"]


def test_parse_guardduty_json():
    content = (
        '{"Findings":[{"Id":"f1","Title":"EC2 instance communicating with crypto mining pool",'
        '"Type":"CryptoCurrency:EC2/BitcoinTool.B!DNS","Severity":8.0,"AccountId":"123456789012",'
        '"Region":"us-east-1","CreatedAt":"2026-06-01T00:00:00Z",'
        '"Description":"EC2 querying a domain associated with cryptocurrency mining.",'
        '"Resource":{"ResourceType":"Instance"},'
        '"Service":{"Action":{"ActionType":"DNS_REQUEST"}}}]}'
    )
    rows = parse_file(content, "guardduty_json")
    assert len(rows) == 1
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["extra_data"]["resource_type"] == "Instance"


def test_parse_syslog_rfc5424():
    content = (
        "<34>1 2026-06-11T22:14:15.003Z fw01 sshd 2310 ID47 - Failed password for root from 10.9.8.7\n"
        "<165>1 2026-06-11T22:15:00Z app03 myapp 4711 - - routine heartbeat\n"
    )
    rows = parse_file(content, "syslog_rfc5424")
    assert len(rows) == 2
    assert rows[0]["severity"] == "CRITICAL"  # PRI 34 → severity 2 (crit)
    assert rows[0]["extra_data"]["host"] == "fw01"
    assert rows[1]["severity"] == "LOW"       # PRI 165 → severity 5 (notice)
