"""
SIEM / IDS / Scanner file import engine.

Parses security tool output into Finding-compatible dicts.
Each parsed alert produces a Finding with network metadata in extra_data.
"""
import csv
import hashlib
import io
import json
import re

from services.import_common import ImportFileError, RowReport, csv_dicts


SUPPORTED_FORMATS = [
    # source_type = the extra_data.source_type every finding from this parser carries
    # (the Findings page "Source" filter is built from it).
    {"key": "splunk_csv", "label": "Splunk CSV", "extensions": [".csv"], "description": "Splunk saved search export", "source_type": "splunk", "source_label": "Splunk"},
    {"key": "suricata_eve", "label": "Suricata EVE JSON", "extensions": [".json"], "description": "Suricata EVE alert events", "source_type": "suricata", "source_label": "Suricata"},
    {"key": "snort_fast", "label": "Snort fast.log", "extensions": [".log", ".txt"], "description": "Snort/Suricata fast.log format", "source_type": "snort", "source_label": "Snort"},
    {"key": "yara_json", "label": "YARA JSON", "extensions": [".json"], "description": "YARA match output (JSON)", "source_type": "yara", "source_label": "YARA"},
    {"key": "nessus_csv", "label": "Nessus CSV", "extensions": [".csv"], "description": "Nessus vulnerability scan CSV export", "source_type": "nessus", "source_label": "Nessus"},
    {"key": "nessus_xml", "label": "Nessus (.nessus)", "extensions": [".nessus", ".xml"], "description": "Native Nessus export (NessusClientData_v2)", "source_type": "nessus", "source_label": "Nessus"},
    {"key": "generic_cef", "label": "Generic CEF", "extensions": [".log", ".txt"], "description": "Common Event Format (CEF) log lines", "source_type": "cef", "source_label": "CEF"},
    {"key": "sentinel_csv", "label": "Microsoft Sentinel CSV", "extensions": [".csv"], "description": "Sentinel SecurityAlert export (Log Analytics)", "source_type": "sentinel", "source_label": "Microsoft Sentinel"},
    {"key": "crowdstrike_csv", "label": "CrowdStrike Falcon CSV", "extensions": [".csv"], "description": "Falcon detections export", "source_type": "crowdstrike", "source_label": "CrowdStrike Falcon"},
    {"key": "elastic_json", "label": "Elastic ECS NDJSON", "extensions": [".json", ".ndjson"], "description": "Elastic Security alerts (ECS fields)", "source_type": "elastic", "source_label": "Elastic"},
    {"key": "wazuh_json", "label": "Wazuh alerts JSON", "extensions": [".json"], "description": "Wazuh alerts.json (NDJSON)", "source_type": "wazuh", "source_label": "Wazuh"},
    {"key": "guardduty_json", "label": "AWS GuardDuty JSON", "extensions": [".json"], "description": "GuardDuty findings export", "source_type": "guardduty", "source_label": "AWS GuardDuty"},
    {"key": "syslog_rfc5424", "label": "Syslog (RFC 5424)", "extensions": [".log", ".txt"], "description": "Structured syslog messages", "source_type": "syslog", "source_label": "Syslog"},
    {"key": "qualys_csv", "label": "Qualys VM CSV", "extensions": [".csv"], "description": "Qualys VM/VMDR vulnerability scan export", "source_type": "qualys", "source_label": "Qualys"},
    {"key": "tenable_csv", "label": "Tenable CSV", "extensions": [".csv"], "description": "Tenable.io / Tenable.sc findings export", "source_type": "tenable", "source_label": "Tenable"},
    {"key": "openvas_xml", "label": "OpenVAS / Greenbone XML", "extensions": [".xml"], "description": "OpenVAS (GVM) XML scan report", "source_type": "openvas", "source_label": "OpenVAS / Greenbone"},
    {"key": "winevent_csv", "label": "Windows Event Log CSV", "extensions": [".csv"], "description": "Get-WinEvent / Event Viewer CSV export", "source_type": "winevent", "source_label": "Windows Event Log"},
]

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MiB
# Cap on distinct findings per file. It counts findings produced (after
# in-file duplicates are merged), never input lines — a real eve.json is mostly
# flow/dns events. Anything past the cap is counted and reported, never silent.
MAX_ROWS = 5000

FORMAT_LABELS = {f["key"]: f["label"] for f in SUPPORTED_FORMATS}


# Header names each CSV parser reads for its ESSENTIAL fields. The parsers and
# the layout check below share these tuples, so they cannot drift apart: a file
# whose header carries none of a field's names fails with a clear error instead
# of importing rows with that field silently empty (a changed export layout).
SPLUNK_TITLE = ("alert_name", "search_name", "name", "signature", "rule_name")
NESSUS_TITLE = ("Name", "Plugin Name", "name")
NESSUS_RISK = ("Risk", "Severity", "risk", "severity")
NESSUS_HOST = ("Host", "IP", "host", "ip")
TENABLE_TITLE = ("Plugin Name", "Name", "name")
TENABLE_SEVERITY = ("Severity", "Risk", "severity")
TENABLE_HOST = ("IP Address", "Host", "Asset", "IP", "ip")
QUALYS_TITLE = ("Title", "title")
QUALYS_SEVERITY = ("Severity", "severity")
QUALYS_HOST = ("IP", "IP Address", "ip")
SENTINEL_TITLE = ("AlertName", "DisplayName", "alertname")
SENTINEL_SEVERITY = ("AlertSeverity", "Severity", "alertseverity")
CROWDSTRIKE_TITLE = ("DetectName", "Detect Name", "DetectDescription", "Name")
CROWDSTRIKE_SEVERITY = ("SeverityName", "Severity Name", "MaxSeverityDisplayName", "Severity")
WINEVENT_ID = ("Id", "EventID", "Event ID", "event_id")
WINEVENT_PROVIDER = ("ProviderName", "Provider Name", "Source", "provider")


def _split_cves(raw) -> list[str]:
    return [c.strip() for c in re.split(r"[,;\s]+", str(raw or "")) if c.strip()]


class ParseReport(RowReport):
    """RowReport that also folds rows sharing a dedup hash into one finding —
    the same identity a re-import uses — so a Nessus CSV that repeats a plugin
    row once per CVE yields one finding carrying every CVE."""

    def __init__(self, max_rows: int = MAX_ROWS):
        super().__init__(max_rows)
        self.merged = 0
        self._by_hash: dict[str, dict] = {}
        self._dropped: set[str] = set()

    def add(self, item: dict) -> None:
        h = (item.get("extra_data") or {}).get("dedup_hash", "")
        if h and h in self._by_hash:
            self._merge(self._by_hash[h], item)
            self.merged += 1
            return
        if h and h in self._dropped:
            self.merged += 1
            return
        if len(self.rows) >= self.max_rows:
            self.truncated += 1
            if h:
                self._dropped.add(h)
            return
        self.rows.append(item)
        if h:
            self._by_hash[h] = item

    @staticmethod
    def _merge(kept: dict, dup: dict) -> None:
        a, b = kept["extra_data"], dup.get("extra_data") or {}
        if a.get("cve") or b.get("cve"):
            cves = _split_cves(a.get("cve"))
            cves += [c for c in _split_cves(b.get("cve")) if c not in cves]
            a["cve"] = ", ".join(cves)

    def summary(self) -> dict:
        return {**super().summary(), "merged_duplicates": self.merged}

    def warnings(self, noun: str = "findings") -> list[str]:
        out = super().warnings(noun)
        if self.merged:
            out.insert(0, f"{self.merged:,} repeated row(s) describe a finding already in this file "
                          "and were merged into it (same identity a re-import uses).")
        return out


def _obj(value) -> dict:
    """A nested JSON value that should be an object — or {} when it is not."""
    return value if isinstance(value, dict) else {}


def _strip_type_line(content: str) -> str:
    """Windows PowerShell 5.1 Export-Csv writes '#TYPE <.NET type>' before the
    header unless -NoTypeInformation is given. Drop it."""
    if content.startswith("#TYPE"):
        nl = content.find("\n")
        return "" if nl == -1 else content[nl + 1:]
    return content


def _csv_rows(content: str):
    return csv_dicts(_strip_type_line(content))


_QUALYS_HEADER = {"qid", "title"}


def _find_header_line(content: str, required: set[str], max_lines: int = 60) -> int | None:
    """Char offset of the first of the leading lines whose CSV cells include all
    of ``required`` (case-insensitive) — for exports with report metadata rows
    above the real header (Qualys scan results)."""
    pos = 0
    for _ in range(max_lines):
        if pos >= len(content):
            return None
        nl = content.find("\n", pos)
        line = content[pos:] if nl == -1 else content[pos:nl]
        try:
            cells = next(csv.reader([line.rstrip("\r")]), [])
        except csv.Error:
            cells = []
        if required <= {c.strip().lower() for c in cells}:
            return pos
        if nl == -1:
            return None
        pos = nl + 1
    return None


# Column-name words that only vulnerability-scanner / EDR exports carry (whole
# words: a Splunk "uniqid" column is not a Qualys "QID").
_SCANNER_HINT = re.compile(r"\b(plugin|qid|cvss|detectid|detect name|alertseverity)")

_WS = re.compile(r"\s*")


def _first_json_record(text: str):
    """The first JSON value of a document (or the first element of a top-level
    array), decoded without parsing the rest — None when it is not valid JSON."""
    dec = json.JSONDecoder()
    try:
        if text.startswith("["):
            idx = _WS.match(text, 1).end()
            if text[idx:idx + 1] == "]":
                return None
            return dec.raw_decode(text, idx)[0]
        return dec.raw_decode(text)[0]
    except (ValueError, IndexError):
        return None


def _load_json(content: str, label: str):
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ImportFileError(f"The file is not valid {label}: {exc.msg} at line {exc.lineno}, column {exc.colno}.")

_SEVERITY_NORM = {
    "critical": "CRITICAL", "crit": "CRITICAL", "1": "CRITICAL",
    "high": "HIGH", "2": "HIGH",
    "medium": "MEDIUM", "med": "MEDIUM", "3": "MEDIUM",
    "low": "LOW", "informational": "LOW", "info": "LOW", "4": "LOW",
    "none": "LOW",
}

_YARA_TAG_SEVERITY = {
    "apt": "CRITICAL", "exploit": "CRITICAL", "ransomware": "CRITICAL",
    "malware": "HIGH", "trojan": "HIGH", "backdoor": "HIGH",
    "suspicious": "MEDIUM", "hacktool": "MEDIUM",
    "adware": "LOW", "pup": "LOW",
}


def _cvss_to_severity(score: float) -> str:
    """CVSS-style 0-10 score → severity band. Single source of truth."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _normalize_severity(raw: str) -> str:
    if not raw:
        return "MEDIUM"
    key = raw.strip().lower()
    if key in _SEVERITY_NORM:
        return _SEVERITY_NORM[key]
    try:
        return _cvss_to_severity(float(key))
    except ValueError:
        return "MEDIUM"


_CEF_TEXT_SEVERITY = {
    "unknown": "LOW", "low": "LOW", "medium": "MEDIUM", "high": "HIGH",
    "very-high": "CRITICAL", "veryhigh": "CRITICAL", "very high": "CRITICAL",
}


def _cef_severity(raw: str) -> str:
    """ArcSight CEF severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High,
    or the strings Unknown/Low/Medium/High/Very-High. Never the Nessus/Snort
    '1 = critical' table — in CEF 1 is the LOWEST severity."""
    key = (raw or "").strip().lower()
    if key in _CEF_TEXT_SEVERITY:
        return _CEF_TEXT_SEVERITY[key]
    try:
        return _cvss_to_severity(float(key))  # same bands: >=9 / >=7 / >=4
    except ValueError:
        return _normalize_severity(key)


def _dedup_hash(source_type: str, rule_id: str, src_ip: str, dst_ip: str, timestamp: str) -> str:
    key = f"{source_type}|{rule_id}|{src_ip}|{dst_ip}|{timestamp}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _safe_int(val: str) -> int | None:
    if not val:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _pick(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v:
            return str(v).strip()
    return ""


def detect_format(filename: str, content: str) -> str | None:
    """Pick a parser from the filename and the content. Pass the whole decoded
    file (or a large prefix): JSON arrays are sniffed by their first element,
    and CSV exports may carry a '#TYPE' line or metadata rows before the header."""
    lower = filename.lower()
    if lower.endswith(".csv"):
        content = _strip_type_line(content)
        first_line = content.split("\n", 1)[0].lower().replace('"', "")
        cols = [c.strip() for c in first_line.split(",")]
        if "qid" in cols:  # exact column, not a substring of e.g. "uniqid"
            return "qualys_csv"
        # Tenable BEFORE Nessus: a Tenable export with a "Risk" column would
        # otherwise be misread as Nessus (wrong provenance + empty host).
        if "plugin name" in first_line and ("ip address" in first_line or "asset" in first_line):
            return "tenable_csv"
        if "plugin" in first_line and "risk" in first_line:
            return "nessus_csv"
        if "alertname" in first_line.replace("_", "") and "alertseverity" in first_line.replace("_", ""):
            return "sentinel_csv"
        if "detectname" in first_line.replace("_", "").replace(" ", "") or "severityname" in first_line.replace("_", "").replace(" ", ""):
            return "crowdstrike_csv"
        norm = first_line.replace("_", "").replace(" ", "")
        # Windows Event Log exports — Get-WinEvent (ProviderName/Id/LevelDisplayName)
        # or Event Viewer CSV (Level/Source/Event ID/Computer).
        if "leveldisplayname" in norm or ("providername" in norm and "eventid" in norm) \
                or ("eventid" in norm and "source" in norm and "level" in norm):
            return "winevent_csv"
        # Qualys scan-results downloads start with report metadata rows; the
        # real "IP","DNS",…,"QID","Title" header comes a few lines later.
        # Only consulted when the first line matched nothing above.
        if _find_header_line(content, _QUALYS_HEADER):
            return "qualys_csv"
        # Scanner columns that matched no full signature above = a scanner export
        # whose layout changed. Never read it as Splunk (wrong source, host and
        # severity silently lost): report it as unrecognised instead.
        if any(_SCANNER_HINT.search(c) for c in cols):
            return None
        if set(cols) & set(SPLUNK_TITLE):
            return "splunk_csv"
        return None

    if lower.endswith((".json", ".ndjson")):
        stripped = content.lstrip()
        if '"Findings"' in stripped[:2000] or '"findings"' in stripped[:200] and '"Severity"' in stripped[:2000]:
            return "guardduty_json"
        first = stripped.split("\n", 1)[0]
        if '"rule"' in first and '"level"' in first and '"agent"' in first:
            return "wazuh_json"
        if '"@timestamp"' in first and ('"event"' in first or '"kibana' in first or '"ecs"' in first):
            return "elastic_json"
        sample = _first_json_record(stripped)
        if isinstance(sample, dict):
            if "signature" in _obj(sample.get("alert")):
                return "suricata_eve"
            rule = sample.get("rule")
            if isinstance(rule, dict) and "level" in rule and "agent" in sample:
                return "wazuh_json"  # pretty-printed (multi-line) Wazuh alert
            if "rule" in sample or "strings" in sample:
                return "yara_json"
        return "suricata_eve"

    if lower.endswith(".nessus"):
        return "nessus_xml"

    if lower.endswith(".xml"):
        head = content[:2000].lower()
        if "nessusclientdata" in head:  # before OpenVAS: a .nessus file also has <Report>
            return "nessus_xml"
        if "<report" in head or "<result" in head or "<results" in head or "openvas" in head:
            return "openvas_xml"
        return None  # unrecognized XML — surface "unknown format" instead of silently parsing 0

    if lower.endswith((".log", ".txt")):
        first_line = content.lstrip().split("\n", 1)[0]
        if first_line.startswith("CEF:"):
            return "generic_cef"
        if re.match(r"^<\d{1,3}>1 ", first_line):
            return "syslog_rfc5424"
        if re.match(r"\d{2}/\d{2}-\d{2}:\d{2}:\d{2}", first_line):
            return "snort_fast"
        if "CEF:" in content[:500]:
            return "generic_cef"
        return "snort_fast"

    return None


def parse_splunk_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        title = _pick(row, *SPLUNK_TITLE)
        if not title:
            rep.skip("no alert name (alert_name / search_name / name / signature column)")
            continue
        src_ip = _pick(row, "src_ip", "src", "source_ip", "src_addr")
        dst_ip = _pick(row, "dst_ip", "dest_ip", "dest", "dst", "destination_ip")
        src_port = _pick(row, "src_port", "source_port", "sport")
        dst_port = _pick(row, "dst_port", "dest_port", "dport", "destination_port")
        protocol = _pick(row, "protocol", "proto", "transport")
        rule_id = _pick(row, "rule_name", "sid", "signature_id", "rule_id")
        severity = _normalize_severity(_pick(row, "severity", "urgency", "priority"))
        cve = _pick(row, "cve", "CVE")
        ts = _pick(row, "_time", "timestamp", "event_time", "time")

        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": _pick(row, "description", "message", "msg")[:2000],
            "extra_data": {
                "source_type": "splunk",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": _safe_int(src_port), "dst_port": _safe_int(dst_port),
                "protocol": protocol,
                "rule_id": rule_id, "signature": title,
                "cve": cve, "timestamp": ts,
                "dedup_hash": _dedup_hash("splunk", rule_id or title, src_ip, dst_ip, ts),
            },
        })
    return rep.rows


def parse_suricata_eve(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    if content.lstrip().startswith("["):
        entries = _load_json(content, "Suricata EVE JSON")
        if not isinstance(entries, list):
            entries = [entries]
    else:
        entries = []
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                rep.skip("line is not valid JSON")

    # The cap counts ALERTS produced (ParseReport), not EVE events: a real
    # eve.json is mostly flow/dns/http/tls/stats events.
    for evt in entries:
        if not isinstance(evt, dict):
            rep.skip("record is not a JSON object")
            continue
        alert = evt.get("alert", {})
        if not isinstance(alert, dict) or not alert.get("signature"):
            rep.skip("not an alert event (flow, dns, http, stats, …)")
            continue

        sig = str(alert["signature"])[:500]
        sev_raw = str(alert.get("severity", "3"))
        suricata_sev_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
        severity = suricata_sev_map.get(sev_raw, _normalize_severity(sev_raw))

        src_ip = str(evt.get("src_ip", ""))
        dst_ip = str(evt.get("dest_ip", ""))
        src_port = evt.get("src_port")
        dst_port = evt.get("dest_port")
        proto = str(evt.get("proto", ""))
        sid = str(alert.get("signature_id", ""))
        ts = str(evt.get("timestamp", ""))

        rep.add({
            "title": sig,
            "severity": severity,
            "description": f"Suricata alert: {sig} (SID {sid})",
            "extra_data": {
                "source_type": "suricata",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": _safe_int(str(src_port)) if src_port else None,
                "dst_port": _safe_int(str(dst_port)) if dst_port else None,
                "protocol": proto,
                "rule_id": sid, "sid": sid, "signature": sig,
                "cve": "", "timestamp": ts,
                "dedup_hash": _dedup_hash("suricata", sid, src_ip, dst_ip, ts),
            },
        })
    return rep.rows


# fast.log: "<ts> [**] [gid:sid:rev] <signature> [**] [Classification: c]
# [Priority: n] {PROTO} src -> dst". Parsed in two linear steps — head, then
# the text after the signature's closing "[**]" — because one regex with a
# lazy signature group backtracks quadratically on a long malformed line and
# froze the server (R2SEC-4).
_SNORT_HEAD_RE = re.compile(r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+")
_SNORT_TAIL_RE = re.compile(
    r"\s+(?:\[Classification:\s*([^\]]*)\]\s+)?"
    r"\[Priority:\s*(\d+)\]\s+"
    r"\{(\w+)\}\s+"
    r"([0-9A-Fa-f:.\[\]]+)\s*->\s*([0-9A-Fa-f:.\[\]]+)"
)
_SNORT_MAX_LINE = 8192  # real alerts are well under 1 KB


def _match_snort(line: str):
    head = _SNORT_HEAD_RE.match(line)
    if not head:
        return None
    rest = line[head.end():]
    end = rest.find("[**]")
    sig = rest[:end].rstrip() if end > 0 else ""
    if not sig or sig == rest[:end]:  # the signature is followed by whitespace, then [**]
        return None
    tail = _SNORT_TAIL_RE.match(rest, end + 4)
    if not tail:
        return None
    classification, priority, proto, src_tok, dst_tok = tail.groups()
    return head.group(1), head.group(2), sig, classification or None, priority, proto, src_tok, dst_tok

_PORT_PROTOCOLS = {"TCP", "UDP", "SCTP"}


def _split_host_port(token: str, proto: str) -> tuple[str, str]:
    """fast.log address token -> (host, port). IPv4 'a.b.c.d:port',
    bracketed '[v6]:port', and bare IPv6 'v6:port' (Snort appends the port to
    TCP/UDP addresses, so the last ':' group is the port only for those)."""
    if token.startswith("["):
        host, _, rest = token[1:].partition("]")
        return host, rest.lstrip(":")
    if token.count(":") == 1:
        host, _, port = token.partition(":")
        return host, port
    if token.count(":") >= 2 and proto.upper() in _PORT_PROTOCOLS:
        host, _, port = token.rpartition(":")
        return host, port
    return token, ""


def parse_snort_fast(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    for line in content.splitlines():
        if not line.strip():
            continue
        if len(line) > _SNORT_MAX_LINE:
            rep.skip(f"line longer than {_SNORT_MAX_LINE // 1024} KB")
            continue
        m = _match_snort(line.strip())
        if not m:
            rep.skip("line is not a Snort/Suricata fast.log alert")
            continue
        ts, sid, sig, classification, priority, proto, src_tok, dst_tok = m
        src_ip, src_port = _split_host_port(src_tok, proto)
        dst_ip, dst_port = _split_host_port(dst_tok, proto)
        severity_map = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}
        severity = severity_map.get(priority, "MEDIUM")

        rep.add({
            "title": sig.strip()[:500],
            "severity": severity,
            "description": f"Snort alert: {sig.strip()}" + (f" [{classification}]" if classification else ""),
            "extra_data": {
                "source_type": "snort",
                "src_ip": src_ip or "", "dst_ip": dst_ip or "",
                "src_port": _safe_int(src_port or ""), "dst_port": _safe_int(dst_port or ""),
                "protocol": proto or "",
                "rule_id": sid, "sid": sid, "signature": sig.strip(),
                "classification": classification or "",
                "cve": "", "timestamp": ts,
                "dedup_hash": _dedup_hash("snort", sid, src_ip or "", dst_ip or "", ts),
            },
        })
    return rep.rows


def parse_yara_json(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    data = _load_json(content, "YARA JSON")
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ImportFileError("YARA JSON must be a match object or an array of match objects.")

    for match in data:
        if not isinstance(match, dict):
            rep.skip("record is not a JSON object")
            continue
        rule = str(match.get("rule") or "")
        if not rule:
            rep.skip("no rule name")
            continue

        tags = match.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        elif isinstance(tags, list):
            tags = [str(t) for t in tags if t is not None]
        else:
            tags = []

        severity = "MEDIUM"
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in _YARA_TAG_SEVERITY:
                severity = _YARA_TAG_SEVERITY[tag_lower]
                break

        file_path = str(match.get("file", match.get("file_path", match.get("target", ""))))
        strings_matched = match.get("strings", [])
        if isinstance(strings_matched, list):
            strings_matched = [str(s)[:200] for s in strings_matched[:20]]

        ts = str(match.get("timestamp", ""))

        rep.add({
            "title": f"YARA: {rule}"[:500],
            "severity": severity,
            "description": f"YARA rule match: {rule}" + (f" on {file_path}" if file_path else ""),
            "extra_data": {
                "source_type": "yara",
                "src_ip": "", "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": "",
                "rule_id": rule, "signature": rule,
                "file_path": file_path,
                "strings_matched": strings_matched,
                "tags": tags,
                "cve": "", "timestamp": ts,
                "dedup_hash": _dedup_hash("yara", rule, file_path, "", ts),
            },
        })
    return rep.rows


# Scanner "risk" values that mark an informational plugin, not a weakness.
_INFORMATIONAL_RISK = frozenset({"none", "0", "info", "informational"})


def parse_nessus_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        title = _pick(row, *NESSUS_TITLE)
        if not title:
            rep.skip("no plugin name")
            continue

        risk_raw = _pick(row, *NESSUS_RISK).strip()
        if risk_raw.lower() in _INFORMATIONAL_RISK:
            # Nessus "Risk = None" rows are informational plugins (scan info,
            # port scanner, traceroute) — dozens per host, never weaknesses.
            rep.skip("informational (Risk=None)")
            continue
        severity = _normalize_severity(risk_raw)
        dst_ip = _pick(row, *NESSUS_HOST)
        dst_port = _pick(row, "Port", "port")
        cve = _pick(row, "CVE", "cve")
        synopsis = _pick(row, "Synopsis", "synopsis", "Description", "description")
        plugin_id = _pick(row, "Plugin ID", "Plugin", "plugin_id")

        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": synopsis[:2000],
            "weakness_description": synopsis[:2000],
            "extra_data": {
                "source_type": "nessus",
                "src_ip": "", "dst_ip": dst_ip,
                "src_port": None, "dst_port": _safe_int(dst_port),
                "protocol": _pick(row, "Protocol", "protocol"),
                "rule_id": plugin_id, "plugin_id": plugin_id,
                "cve": cve, "timestamp": "",
                "dedup_hash": _dedup_hash("nessus", plugin_id or title, "", dst_ip, dst_port),
            },
        })
    return rep.rows


# Header fields may contain an escaped pipe or backslash (\| and \\, CEF spec),
# so a field is any run of escape pairs or non-pipe/non-backslash characters.
_CEF_FIELD = r"((?:\\.|[^|\\])*)"
_CEF_RE = re.compile(r"CEF:\d+" + (r"\|" + _CEF_FIELD) * 6 + r"\|(.*)")
_CEF_UNESCAPE = re.compile(r"\\([|\\])")


def _cef_unescape(field: str) -> str:
    return _CEF_UNESCAPE.sub(r"\1", field)


def _parse_cef_extensions(ext_str: str) -> dict[str, str]:
    result = {}
    key_positions = [(m.start(), m.group(1)) for m in re.finditer(r"(\w+)=", ext_str)]
    for i, (pos, key) in enumerate(key_positions):
        val_start = pos + len(key) + 1
        val_end = key_positions[i + 1][0] if i + 1 < len(key_positions) else len(ext_str)
        result[key] = ext_str[val_start:val_end].rstrip()
    return result


def parse_generic_cef(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    rep = rep if rep is not None else ParseReport()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        cef_idx = line.find("CEF:")
        if cef_idx == -1:
            rep.skip("line has no CEF header")
            continue
        cef_part = line[cef_idx:]
        m = _CEF_RE.match(cef_part)
        if not m:
            rep.skip("malformed CEF header")
            continue

        *header, extensions = m.groups()
        vendor, product, version, sig_id, name, severity_raw = (_cef_unescape(f) for f in header)
        ext = _parse_cef_extensions(extensions)

        src_ip = ext.get("src", ext.get("sourceAddress", ""))
        dst_ip = ext.get("dst", ext.get("destinationAddress", ""))
        src_port = ext.get("spt", ext.get("sourcePort", ""))
        dst_port = ext.get("dpt", ext.get("destinationPort", ""))
        proto = ext.get("proto", ext.get("transportProtocol", ""))
        ts = ext.get("rt", ext.get("deviceReceiptTime", ext.get("end", "")))

        severity = _cef_severity(severity_raw)

        rep.add({
            "title": (name or sig_id or "CEF Event").strip()[:500],
            "severity": severity,
            "description": f"{vendor} {product}: {name}".strip()[:2000],
            "extra_data": {
                "source_type": "cef",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": _safe_int(src_port), "dst_port": _safe_int(dst_port),
                "protocol": proto,
                "rule_id": sig_id, "signature": name,
                "vendor": vendor, "product": product,
                "cve": ext.get("cve", ""), "timestamp": ts,
                "dedup_hash": _dedup_hash("cef", sig_id or name, src_ip, dst_ip, ts),
            },
        })
    return rep.rows




_UNIT_SUFFIX = re.compile(r"\s*\[[^\]]*\]\s*$")


def parse_sentinel_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Microsoft Sentinel SecurityAlert table export (Log Analytics CSV)."""
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        # Log Analytics exports suffix datetime columns: "TimeGenerated [UTC]".
        row = {_UNIT_SUFFIX.sub("", k) if isinstance(k, str) else k: v for k, v in row.items()}
        title = _pick(row, *SENTINEL_TITLE)
        if not title:
            rep.skip("no alert name")
            continue
        severity = _normalize_severity(_pick(row, *SENTINEL_SEVERITY))
        ts = _pick(row, "TimeGenerated", "StartTime", "timegenerated")
        rule_id = _pick(row, "SystemAlertId", "AlertType", "VendorOriginalId")
        src_ip = _pick(row, "SourceIP", "src_ip", "IPAddress")
        host = _pick(row, "CompromisedEntity", "Computer", "HostName")
        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": _pick(row, "Description", "description")[:2000],
            "extra_data": {
                "source_type": "sentinel",
                "src_ip": src_ip, "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": "",
                "rule_id": rule_id, "signature": title,
                "host": host,
                "provider": _pick(row, "ProviderName", "ProductName"),
                "tactics": _pick(row, "Tactics", "tactics"),
                "timestamp": ts,
                "dedup_hash": _dedup_hash("sentinel", rule_id or title, src_ip, host, ts),
            },
        })
    return rep.rows


def parse_crowdstrike_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """CrowdStrike Falcon detections export."""
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        title = _pick(row, *CROWDSTRIKE_TITLE)
        if not title:
            rep.skip("no detection name")
            continue
        severity = _normalize_severity(_pick(row, *CROWDSTRIKE_SEVERITY))
        host = _pick(row, "ComputerName", "Computer Name", "Hostname")
        src_ip = _pick(row, "LocalIP", "Local IP", "local_ip")
        ts = _pick(row, "Timestamp", "DetectTime", "FirstBehavior", "ProcessStartTime")
        rule_id = _pick(row, "DetectId", "Detect ID", "CompositeId")
        tactic = _pick(row, "Tactic", "tactic")
        technique = _pick(row, "Technique", "technique")
        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": (_pick(row, "DetectDescription", "Description") or f"{tactic} / {technique}".strip(" /"))[:2000],
            "extra_data": {
                "source_type": "crowdstrike",
                "src_ip": src_ip, "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": "",
                "rule_id": rule_id, "signature": title,
                "host": host, "tactic": tactic, "technique": technique,
                "timestamp": ts,
                "dedup_hash": _dedup_hash("crowdstrike", rule_id or title, src_ip, host, ts),
            },
        })
    return rep.rows


def parse_elastic_json(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Elastic Security alerts as ECS NDJSON (one JSON object per line)."""
    rep = rep if rep is not None else ParseReport()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            rep.skip("line is not valid JSON")
            continue
        if not isinstance(evt, dict):
            rep.skip("record is not a JSON object")
            continue
        rule = _obj(evt.get("rule") or evt.get("kibana.alert.rule.parameters"))
        event = _obj(evt.get("event"))
        title = (
            rule.get("name")
            or evt.get("kibana.alert.rule.name")
            or event.get("reason", "")
            or evt.get("message", "")
        )
        if not title:
            rep.skip("no rule name or message")
            continue
        sev_label = (
            evt.get("kibana.alert.severity")
            or event.get("severity_label")
            or str(event.get("severity", ""))
        )
        src = evt.get("source") or {}
        dst = evt.get("destination") or {}
        # Pre-ECS (Logstash-shipped) events carry "host" as a plain string.
        host = evt.get("host")
        host = str(host.get("name", "")) if isinstance(host, dict) else str(host or "")
        ts = str(evt.get("@timestamp", ""))
        rule_id = rule.get("id") or evt.get("kibana.alert.rule.uuid", "")
        src_ip = src.get("ip", "") if isinstance(src, dict) else ""
        dst_ip = dst.get("ip", "") if isinstance(dst, dict) else ""
        rep.add({
            "title": str(title)[:500],
            "severity": _normalize_severity(str(sev_label)),
            "description": str(evt.get("message", ""))[:2000],
            "extra_data": {
                "source_type": "elastic",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": _safe_int(str(src.get("port", ""))) if isinstance(src, dict) else None,
                "dst_port": _safe_int(str(dst.get("port", ""))) if isinstance(dst, dict) else None,
                "protocol": str(_obj(evt.get("network")).get("transport", "")),
                "rule_id": str(rule_id), "signature": str(title),
                "host": host,
                "timestamp": ts,
                "dedup_hash": _dedup_hash("elastic", str(rule_id) or str(title), src_ip, dst_ip, ts),
            },
        })
    return rep.rows


_WAZUH_LEVELS = [(12, "CRITICAL"), (8, "HIGH"), (4, "MEDIUM"), (0, "LOW")]


def parse_wazuh_json(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Wazuh alerts.json — NDJSON with rule.level 0-15."""
    rep = rep if rep is not None else ParseReport()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            rep.skip("line is not valid JSON")
            continue
        if not isinstance(evt, dict):
            rep.skip("record is not a JSON object")
            continue
        rule = _obj(evt.get("rule"))
        title = rule.get("description", "")
        if not title:
            rep.skip("no rule description")
            continue
        level = rule.get("level", 0)
        try:
            level = int(level)
        except (TypeError, ValueError):
            level = 0
        severity = next(label for threshold, label in _WAZUH_LEVELS if level >= threshold)
        data = _obj(evt.get("data"))
        agent = _obj(evt.get("agent"))
        ts = str(evt.get("timestamp", ""))
        rule_id = str(rule.get("id", ""))
        src_ip = str(data.get("srcip", ""))
        rep.add({
            "title": str(title)[:500],
            "severity": severity,
            "description": str(evt.get("full_log", ""))[:2000],
            "extra_data": {
                "source_type": "wazuh",
                "src_ip": src_ip, "dst_ip": str(data.get("dstip", "")),
                "src_port": _safe_int(str(data.get("srcport", ""))),
                "dst_port": _safe_int(str(data.get("dstport", ""))),
                "protocol": "",
                "rule_id": rule_id, "signature": str(title),
                "host": str(agent.get("name", "")),
                "wazuh_level": level,
                "timestamp": ts,
                "dedup_hash": _dedup_hash("wazuh", rule_id or str(title), src_ip, str(agent.get("name", "")), ts),
            },
        })
    return rep.rows


def parse_guardduty_json(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """AWS GuardDuty findings export — {"Findings": [...]} or a bare list."""
    rep = rep if rep is not None else ParseReport()
    data = _load_json(content, "GuardDuty JSON")
    findings = data.get("Findings") if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise ImportFileError('GuardDuty JSON must be {"Findings": [...]} or an array of findings.')
    for f in findings:
        if not isinstance(f, dict):
            rep.skip("record is not a JSON object")
            continue
        title = f.get("Title") or f.get("Type", "")
        if not title:
            rep.skip("no title or type")
            continue
        sev_num = f.get("Severity", 0)
        try:
            sev_num = float(sev_num)
        except (TypeError, ValueError):
            sev_num = 0.0
        # GuardDuty severity bands (AWS docs): 1-3.9 Low, 4-6.9 Medium, 7-8.9 High
        severity = _cvss_to_severity(sev_num)
        service = _obj(f.get("Service"))
        action = _obj(service.get("Action"))
        remote = _obj(
            _obj(action.get("NetworkConnectionAction")).get("RemoteIpDetails")
            or _obj(action.get("AwsApiCallAction")).get("RemoteIpDetails")
        )
        src_ip = str((remote.get("IpAddressV4") or ""))
        fid = str(f.get("Id", ""))
        ts = str(f.get("CreatedAt", ""))
        rep.add({
            "title": str(title)[:500],
            "severity": severity,
            "description": str(f.get("Description", ""))[:2000],
            "extra_data": {
                "source_type": "guardduty",
                "src_ip": src_ip, "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": str(action.get("ActionType", "")),
                "rule_id": str(f.get("Type", "")), "signature": str(title),
                "account": str(f.get("AccountId", "")),
                "region": str(f.get("Region", "")),
                "resource_type": str(_obj(f.get("Resource")).get("ResourceType", "")),
                "timestamp": ts,
                "dedup_hash": _dedup_hash("guardduty", fid or str(title), src_ip, str(f.get("AccountId", "")), ts),
            },
        })
    return rep.rows


_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$"
)
_SYSLOG_SEVERITY = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "HIGH", 4: "MEDIUM"}


def parse_syslog_rfc5424(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """RFC 5424 structured syslog. Severity derives from PRI % 8."""
    rep = rep if rep is not None else ParseReport()
    for line in content.splitlines():
        if not line.strip():
            continue
        m = _SYSLOG_5424.match(line.strip())
        if not m:
            rep.skip("line is not RFC 5424 syslog")
            continue
        pri = int(m.group("pri"))
        sev_code = pri % 8
        severity = _SYSLOG_SEVERITY.get(sev_code, "LOW")
        rest = m.group("rest")
        # strip structured data block(s) to get the free-text message
        msg = rest
        while msg.startswith("["):
            end = msg.find("]")
            if end == -1:
                break
            msg = msg[end + 1:].lstrip()
        if msg.startswith("- "):
            msg = msg[2:]
        title = f"{m.group('app')}: {msg}".strip(": ")[:500]
        if not msg and m.group("msgid") == "-":
            rep.skip("no message")
            continue
        rep.add({
            "title": title or f"syslog event from {m.group('host')}",
            "severity": severity,
            "description": rest[:2000],
            "extra_data": {
                "source_type": "syslog",
                "src_ip": "", "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": "",
                "rule_id": m.group("msgid") if m.group("msgid") != "-" else m.group("app"),
                "signature": title,
                "host": m.group("host"), "app": m.group("app"),
                "syslog_severity": sev_code, "facility": pri // 8,
                "timestamp": m.group("ts"),
                "dedup_hash": _dedup_hash("syslog", m.group("app"), m.group("host"), msg[:80], m.group("ts")),
            },
        })
    return rep.rows

# Qualys VM uses a numeric 1–5 severity where 5 is most severe — the OPPOSITE
# of the Nessus/CEF "1 = critical" convention in _SEVERITY_NORM, so map it here.
_QUALYS_SEVERITY = {"5": "CRITICAL", "4": "HIGH", "3": "MEDIUM", "2": "LOW", "1": "LOW"}


def parse_qualys_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Qualys VM/VMDR scan CSV export (header-first, or a scan-results download
    with report metadata rows above the header)."""
    rep = rep if rep is not None else ParseReport()
    content = _strip_type_line(content)
    offset = _find_header_line(content, _QUALYS_HEADER)
    if offset:
        content = content[offset:]
    for row in _csv_rows(content):
        title = _pick(row, *QUALYS_TITLE)
        if not title:
            rep.skip("no title")
            continue
        sev_raw = _pick(row, *QUALYS_SEVERITY).strip()
        severity = _QUALYS_SEVERITY.get(sev_raw, _normalize_severity(sev_raw))
        dst_ip = _pick(row, *QUALYS_HOST)
        dst_port = _pick(row, "Port", "port")
        qid = _pick(row, "QID", "qid")
        cve = _pick(row, "CVE ID", "CVE", "cve")
        synopsis = _pick(row, "Threat", "Diagnosis", "Solution", "threat")
        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": synopsis[:2000],
            "weakness_description": synopsis[:2000],
            "extra_data": {
                "source_type": "qualys",
                "src_ip": "", "dst_ip": dst_ip,
                "src_port": None, "dst_port": _safe_int(dst_port),
                "protocol": _pick(row, "Protocol", "protocol"),
                "rule_id": qid, "plugin_id": qid,
                "cve": cve, "timestamp": "",
                "dedup_hash": _dedup_hash("qualys", qid or title, "", dst_ip, dst_port),
            },
        })
    return rep.rows


# Tenable's numeric Severity is 0–4 where 4 is most severe (Info..Critical) —
# the OPPOSITE of the "1 = critical" reading in _SEVERITY_NORM, so a numeric
# value must be mapped here, not through _normalize_severity.
_TENABLE_SEVERITY = {"4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}


def parse_tenable_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Tenable.io / Tenable.sc exported findings CSV."""
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        title = _pick(row, *TENABLE_TITLE)
        if not title:
            rep.skip("no plugin name")
            continue
        sev_raw = _pick(row, *TENABLE_SEVERITY).strip()
        if sev_raw.lower() in _INFORMATIONAL_RISK:
            rep.skip("informational (Severity=Info)")  # same plugins as Nessus Risk=None
            continue
        severity = _TENABLE_SEVERITY.get(sev_raw, _normalize_severity(sev_raw))
        dst_ip = _pick(row, *TENABLE_HOST)
        dst_port = _pick(row, "Port", "port")
        plugin_id = _pick(row, "Plugin ID", "Plugin", "plugin_id")
        cve = _pick(row, "CVE", "cve")
        synopsis = _pick(row, "Synopsis", "Description", "synopsis", "description")
        rep.add({
            "title": title[:500],
            "severity": severity,
            "description": synopsis[:2000],
            "weakness_description": synopsis[:2000],
            "extra_data": {
                "source_type": "tenable",
                "src_ip": "", "dst_ip": dst_ip,
                "src_port": None, "dst_port": _safe_int(dst_port),
                "protocol": _pick(row, "Protocol", "protocol"),
                "rule_id": plugin_id, "plugin_id": plugin_id,
                "cve": cve, "timestamp": "",
                "dedup_hash": _dedup_hash("tenable", plugin_id or title, "", dst_ip, dst_port),
            },
        })
    return rep.rows


_OPENVAS_THREAT = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "log": "LOW", "debug": "LOW", "false positive": "LOW"}


def parse_openvas_xml(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """OpenVAS / Greenbone (GVM) XML scan report — <result> elements."""
    rep = rep if rep is not None else ParseReport()
    from defusedxml import ElementTree as ET
    try:
        root = ET.fromstring(content)
    except Exception as exc:
        raise ImportFileError(
            "The XML could not be read as an OpenVAS/Greenbone report "
            f"({type(exc).__name__}). DTD entity declarations are not accepted."
        ) from exc
    for res in root.iter("result"):
        name = (res.findtext("name") or "").strip()
        if not name:
            rep.skip("result has no name")
            continue
        host = (res.findtext("host") or "").strip()
        port = (res.findtext("port") or "").strip()
        threat = (res.findtext("threat") or "").strip().lower()
        severity = _OPENVAS_THREAT.get(threat)
        if severity is None:
            try:
                severity = _cvss_to_severity(float(res.findtext("severity") or 0))
            except (TypeError, ValueError):
                severity = "LOW"
        nvt = res.find("nvt")
        oid = nvt.get("oid") if nvt is not None else ""
        cve = ""
        if nvt is not None:
            for ref in nvt.iter("ref"):
                if (ref.get("type") or "").lower() == "cve":
                    cve = ref.get("id", "")
                    break
        desc = (res.findtext("description") or name).strip()
        # OpenVAS port column is often "443/tcp" — split off the numeric port.
        port_num = port.split("/")[0] if "/" in port else port
        rep.add({
            "title": name[:500],
            "severity": severity,
            "description": desc[:2000],
            "weakness_description": desc[:2000],
            "extra_data": {
                "source_type": "openvas",
                "src_ip": "", "dst_ip": host,
                "src_port": None, "dst_port": _safe_int(port_num),
                "protocol": port.split("/")[1] if "/" in port else "",
                "rule_id": oid, "plugin_id": oid,
                "cve": cve, "timestamp": "",
                "dedup_hash": _dedup_hash("openvas", oid or name, "", host, port_num),
            },
        })
    return rep.rows


_NESSUS_SEVERITY = {"1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}


def parse_nessus_xml(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Native Nessus export (.nessus, NessusClientData_v2): one finding per
    ReportItem. Severity 0 (risk factor "None") is an informational plugin —
    scan info, port lists, traceroute — not a vulnerability, so it is skipped
    and counted as such (R2USER-16; same rule as the CSV import)."""
    rep = rep if rep is not None else ParseReport()
    from defusedxml import ElementTree as ET
    try:
        root = ET.fromstring(content)
    except Exception as exc:
        raise ImportFileError(
            "The file could not be read as a Nessus (.nessus) export "
            f"({type(exc).__name__}). DTD entity declarations are not accepted."
        ) from exc
    if root.tag != "NessusClientData_v2":
        raise ImportFileError("This is not a Nessus v2 export (expected a NessusClientData_v2 root element).")
    for host in root.iter("ReportHost"):
        host_name = host.get("name", "")
        props = {t.get("name"): (t.text or "").strip() for t in host.iter("tag")}
        ip = props.get("host-ip") or host_name
        for item in host.iter("ReportItem"):
            sev = (item.get("severity") or "").strip()
            severity = _NESSUS_SEVERITY.get(sev)
            if severity is None:
                rep.skip("informational (Risk=None)" if sev == "0" else f"unknown severity {sev!r}")
                continue
            title = (item.get("pluginName") or item.findtext("plugin_name") or "").strip()
            if not title:
                rep.skip("no plugin name")
                continue
            plugin_id = item.get("pluginID", "")
            port = item.get("port", "")
            cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.strip()]
            synopsis = (item.findtext("synopsis") or item.findtext("description") or title).strip()
            rep.add({
                "title": title[:500],
                "severity": severity,
                "description": synopsis[:2000],
                "weakness_description": synopsis[:2000],
                "extra_data": {
                    "source_type": "nessus",
                    "src_ip": "", "dst_ip": ip,
                    "src_port": None, "dst_port": _safe_int(port) or None,
                    "protocol": item.get("protocol", ""),
                    "rule_id": plugin_id, "plugin_id": plugin_id,
                    "cve": ", ".join(cves), "timestamp": "",
                    "solution": (item.findtext("solution") or "").strip()[:2000],
                    "dedup_hash": _dedup_hash("nessus", plugin_id or title, "", ip, port),
                },
            })
    return rep.rows


# Windows Event Log "Level" — text (Get-WinEvent LevelDisplayName) or numeric
# (1=Critical … 5=Verbose). Information/Verbose map to LOW.
_WINEVENT_SEVERITY = {
    "critical": "CRITICAL", "1": "CRITICAL",
    "error": "HIGH", "2": "HIGH",
    "warning": "MEDIUM", "3": "MEDIUM",
    "information": "LOW", "informational": "LOW", "4": "LOW",
    "verbose": "LOW", "5": "LOW",
}


def parse_winevent_csv(content: str, rep: "ParseReport | None" = None) -> list[dict]:
    """Windows Event Log CSV — Get-WinEvent or Event Viewer export."""
    rep = rep if rep is not None else ParseReport()
    for row in _csv_rows(content):
        event_id = _pick(row, *WINEVENT_ID)
        provider = _pick(row, *WINEVENT_PROVIDER)
        message = _pick(row, "Message", "Description", "message")
        if not event_id and not provider:
            rep.skip("no event id or provider")
            continue
        level_raw = _pick(row, "LevelDisplayName", "Level", "level").strip().lower()
        severity = _WINEVENT_SEVERITY.get(level_raw, "LOW")
        host = _pick(row, "MachineName", "Computer", "ComputerName", "machine")
        ts = _pick(row, "TimeCreated", "Date and Time", "TimeGenerated", "time")
        first_line = message.split("\n")[0].strip() if message else ""
        title = (first_line or f"{provider} event {event_id}".strip())[:500]
        rep.add({
            "title": title,
            "severity": severity,
            "description": message[:2000],
            "extra_data": {
                "source_type": "winevent",
                "src_ip": "", "dst_ip": "",
                "src_port": None, "dst_port": None,
                "protocol": "",
                "rule_id": event_id, "event_id": event_id, "signature": title,
                "provider": provider, "host": host,
                "level": level_raw, "timestamp": ts,
                "dedup_hash": _dedup_hash("winevent", event_id or provider, host, first_line[:80], ts),
            },
        })
    return rep.rows


PARSERS: dict[str, callable] = {
    "splunk_csv": parse_splunk_csv,
    "suricata_eve": parse_suricata_eve,
    "snort_fast": parse_snort_fast,
    "yara_json": parse_yara_json,
    "nessus_csv": parse_nessus_csv,
    "nessus_xml": parse_nessus_xml,
    "generic_cef": parse_generic_cef,
    "sentinel_csv": parse_sentinel_csv,
    "crowdstrike_csv": parse_crowdstrike_csv,
    "elastic_json": parse_elastic_json,
    "wazuh_json": parse_wazuh_json,
    "guardduty_json": parse_guardduty_json,
    "syslog_rfc5424": parse_syslog_rfc5424,
    "qualys_csv": parse_qualys_csv,
    "tenable_csv": parse_tenable_csv,
    "openvas_xml": parse_openvas_xml,
    "winevent_csv": parse_winevent_csv,
}

# Fail fast at import if the advertised formats and the dispatch table drift
# apart (a format with no parser, or a parser the UI never lists).
assert {f["key"] for f in SUPPORTED_FORMATS} == set(PARSERS), \
    "SUPPORTED_FORMATS and PARSERS are out of sync"


# CSV formats → (field, header names) the parser cannot do without.
_CSV_LAYOUT: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "splunk_csv": (("alert name", SPLUNK_TITLE),),
    "nessus_csv": (("plugin name", NESSUS_TITLE), ("risk", NESSUS_RISK), ("host", NESSUS_HOST)),
    "tenable_csv": (("plugin name", TENABLE_TITLE), ("severity", TENABLE_SEVERITY), ("host", TENABLE_HOST)),
    "qualys_csv": (("title", QUALYS_TITLE), ("severity", QUALYS_SEVERITY), ("IP", QUALYS_HOST)),
    "sentinel_csv": (("alert name", SENTINEL_TITLE), ("severity", SENTINEL_SEVERITY)),
    "crowdstrike_csv": (("detection name", CROWDSTRIKE_TITLE), ("severity", CROWDSTRIKE_SEVERITY)),
    "winevent_csv": (("event id or provider", WINEVENT_ID + WINEVENT_PROVIDER),),
}
assert set(_CSV_LAYOUT) <= set(PARSERS)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_LISTED_COLUMNS = 30
_MAX_COLUMN_NAME = 64


def _csv_header(content: str, format_key: str = "") -> list[str] | None:
    """The header cells exactly as the CSV parser will key its rows by, or None
    when the file has no readable header (the parser reports that itself)."""
    content = _strip_type_line(content)
    if format_key == "qualys_csv":
        offset = _find_header_line(content, _QUALYS_HEADER)
        if offset:
            content = content[offset:]
    try:
        for cells in csv.reader(io.StringIO(content[:1024 * 1024], newline="")):
            if cells:  # csv.DictReader takes the first non-empty record as its header
                if format_key == "sentinel_csv":
                    cells = [_UNIT_SUFFIX.sub("", c) for c in cells]
                return cells if any(c.strip() for c in cells) else None
    except csv.Error:
        return None
    return None


def describe_columns(header: list[str]) -> str:
    """Column NAMES only (never a data row), cleaned for display: control
    characters removed, each name trimmed and capped, the list capped."""
    names = []
    for raw in header[:_MAX_LISTED_COLUMNS]:
        name = _CONTROL_CHARS.sub("", str(raw)).strip()[:_MAX_COLUMN_NAME]
        names.append(f'"{name}"')
    more = len(header) - _MAX_LISTED_COLUMNS
    return ", ".join(names) + (f" (+{more} more)" if more > 0 else "")


def check_csv_layout(content: str, format_key: str) -> None:
    """Raise ImportFileError when a CSV lacks a column its parser needs, naming
    the missing field and the columns that ARE there (names only)."""
    spec = _CSV_LAYOUT.get(format_key)
    if not spec:
        return
    header = _csv_header(content, format_key)
    if header is None:
        return
    present = set(header)
    missing = [(field, names) for field, names in spec if not present.intersection(names)]
    if not missing:
        return
    def expected(names: tuple[str, ...]) -> str:
        seen: dict[str, str] = {}
        for n in names:
            seen.setdefault(n.lower(), n)
        return " / ".join(f'"{n}"' for n in seen.values())
    gaps = "; ".join(f"no {field} column (expected {expected(names)})" for field, names in missing)
    label = FORMAT_LABELS.get(format_key, format_key)
    raise ImportFileError(
        f"This file does not have the column layout of a {label} export: {gaps}. "
        f"Columns in the file: {describe_columns(header)}. Nothing was imported. If the tool's export "
        "format has changed, pick the right format under Format Override, or report the new layout "
        "(column names only, never the data)."
    )


def describe_unrecognized(filename: str, content: str) -> str:
    """Extra detail for a file whose format could not be detected: for a CSV,
    the header's column names (never a data row)."""
    if filename.lower().endswith(".csv"):
        header = _csv_header(content)
        if header:
            return f" Columns in the file: {describe_columns(header)}."
    return ""


def parse_file_report(content: str, format_key: str) -> ParseReport:
    """Parse ``content`` as ``format_key``; the report carries the rows plus
    every row skipped (with the reason), merged or cut off by the row cap.

    Raises ImportFileError (shown to the user as a 422) for an unknown format
    or a file that cannot be read as that format. A parser defect on an
    unexpected shape also surfaces as ImportFileError — never as a 500."""
    parser = PARSERS.get(format_key)
    if not parser:
        raise ImportFileError(f"Unknown format: {format_key}")
    check_csv_layout(content, format_key)
    rep = ParseReport()
    try:
        parser(content, rep)
    except ImportFileError:
        raise
    except Exception as exc:  # noqa: BLE001 — last-resort guard, reported to the user
        label = FORMAT_LABELS.get(format_key, format_key)
        raise ImportFileError(
            f"The file could not be read as {label} ({type(exc).__name__}). "
            "Check that it is an unmodified export, or pick the format manually."
        ) from exc
    return rep


def parse_file(content: str, format_key: str) -> list[dict]:
    """Rows only (no accounting); [] when the file cannot be parsed."""
    try:
        return parse_file_report(content, format_key).rows
    except ImportFileError:
        return []
