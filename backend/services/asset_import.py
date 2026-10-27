"""
Asset-inventory file import engine.

Parses asset/endpoint discovery exports (Tanium, Cisco ISE) into canonical
IT-asset import rows compatible with routers.it_assets._validate_import_row.

These are ASSET sources (they populate the inventory), distinct from the SIEM
engine (services/siem_import.py) which produces Findings. Both share the same
"detect format → parse → preview/confirm" shape.

Add a new source by: writing a parse_*() that returns canonical rows, adding it
to SUPPORTED_SOURCES + PARSERS, and adding a detect_source() branch.
"""
import hashlib
import re

from services.import_common import RowReport, csv_dicts


SUPPORTED_SOURCES = [
    {"key": "tanium_csv", "label": "Tanium CSV", "extensions": [".csv"],
     "description": "Tanium asset/inventory report export (Computer Name, Operating System, IP Address, …)"},
    {"key": "cisco_ise_csv", "label": "Cisco ISE CSV", "extensions": [".csv"],
     "description": "Cisco ISE endpoint export from Context Visibility (MACAddress, EndPointPolicy, IPAddress, …)"},
]

MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_ROWS = 5000

# Canonical OS families accepted by the IT-asset enum (routers/it_assets.py).
_OS_LINUX = ("linux", "ubuntu", "rhel", "red hat", "redhat", "centos", "debian",
             "suse", "fedora", "oracle linux", "amazon linux", "rocky", "alma")
_OS_MAC = ("mac os", "macos", "os x", "darwin")


def _os_family(raw: str) -> str:
    t = (raw or "").lower()
    if not t:
        return ""
    if "windows" in t or t.startswith("win"):
        return "WINDOWS"
    if any(k in t for k in _OS_LINUX):
        return "LINUX"
    if any(k in t for k in _OS_MAC):
        return "MACOS"
    if "android" in t:
        return "ANDROID"
    if "ios" in t or "ipados" in t:
        return "IOS"
    return "OTHER"


def _asset_role(*hints: str) -> str:
    """Infer a canonical asset_role from chassis/policy/profile hints. Empty when
    unknown — better to import without a role than to guess wrong."""
    t = " ".join(h.lower() for h in hints if h)
    if not t:
        return ""
    if "server" in t:
        return "SERVER"
    if any(k in t for k in ("laptop", "notebook", "portable")):
        return "LAPTOP"
    if any(k in t for k in ("desktop", "workstation", "tower")):
        return "WORKSTATION"
    if any(k in t for k in ("virtual", "vmware", "hyper-v", "hyperv")):
        return "VM"
    if "print" in t:
        return "PRINTER"
    if any(k in t for k in ("switch", "router", "firewall", "access point", "access-point", "wlc", "network device", "network-device")):
        return "NETWORK_DEVICE"
    if any(k in t for k in ("phone", "mobile", "tablet", "ipad", "iphone")):
        return "MOBILE"
    return ""


_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _first_ip(raw: str) -> str:
    """Tanium/ISE often pack multiple addresses in one cell (v4 + v6). Prefer the
    first IPv4; fall back to the first whitespace/comma-separated token."""
    if not raw:
        return ""
    m = _IPV4.search(raw)
    if m:
        return m.group(0)
    for tok in re.split(r"[,;\s]+", raw.strip()):
        if tok:
            return tok
    return ""


def _ci(row: dict) -> dict:
    """Lower-cased, stripped keys so column lookups are case-insensitive."""
    # Cells beyond the header land under the None key as a list — ignore them.
    return {k.strip().lower(): (v if isinstance(v, str) else "").strip()
            for k, v in row.items() if isinstance(k, str)}


def _pick(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k.lower())
        if v:
            return v
    return ""


def _dedup_key(mac: str, hostname: str, name: str) -> str:
    """Stable per-asset identity: MAC (separators stripped) > hostname > name."""
    base = re.sub(r"[^0-9a-f]", "", mac.lower()) if mac else (hostname.lower() or name.lower())
    return hashlib.sha256(base.encode()).hexdigest()[:16] if base else ""


def _norm_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", (mac or "").lower())


class AssetIdentityIndex:
    """Every identity an asset has — its MAC AND its hostname — so the same
    host seen by two sources (Tanium without a MAC column, Cisco ISE with one)
    is recognised (R2DATA-14). Two records with DIFFERENT MACs are different
    devices even when they share a hostname; a hostname match only counts when
    at least one side has no MAC."""

    def __init__(self) -> None:
        self._by_mac: dict[str, object] = {}
        self._by_host: dict[str, list[tuple[str, object]]] = {}

    def add(self, mac: str, hostname: str, name: str, ref: object = None) -> None:
        m, h = _norm_mac(mac), (hostname or name or "").strip().lower()
        if m:
            self._by_mac.setdefault(m, ref)
        if h:
            self._by_host.setdefault(h, []).append((m, ref))

    def match(self, mac: str, hostname: str, name: str) -> tuple[bool, object]:
        """(matched, ref of the matching record)."""
        m, h = _norm_mac(mac), (hostname or name or "").strip().lower()
        if m and m in self._by_mac:
            return True, self._by_mac[m]
        for other_mac, ref in self._by_host.get(h, []) if h else []:
            if not m or not other_mac:
                return True, ref
        return False, None


def _row(*, name, hostname="", ip="", mac="", os_raw="", vendor="", model="",
         role_hints=(), notes="", tags=None) -> dict:
    fam = _os_family(os_raw)
    clean = {
        "asset_name": name[:255],
        "hostname": hostname[:255],
        "ip_address": _first_ip(ip),
        "mac_address": mac[:64],
        "os_family": fam,
        "os_version": (os_raw or "")[:255],
        "vendor": vendor[:255],
        "model": model[:255],
        "asset_role": _asset_role(*role_hints),
        "notes": notes[:2000],
        "tags": tags or [],
        "_dedup": _dedup_key(mac, hostname or name, name),
    }
    # Drop empty optional fields so they don't override model defaults / trip enums.
    return {k: v for k, v in clean.items() if v not in ("", [], None) or k == "asset_name"}


def map_tanium_row(r: dict) -> dict | None:
    """Map one case-insensitive Tanium column dict → a canonical asset row.
    Shared by the CSV parser and the live-API connector so mapping lives in one
    place. Returns None when there's no usable name."""
    r = _ci(r)
    name = _pick(r, "computer name", "hostname", "device name", "name", "system name")
    if not name:
        return None
    serial = _pick(r, "serial number", "serial")
    return _row(
        name=name,
        hostname=_pick(r, "computer name", "hostname", "fqdn"),
        ip=_pick(r, "ip address", "ip addresses", "ipv4 address", "ip"),
        mac=_pick(r, "mac address", "mac addresses", "mac"),
        os_raw=_pick(r, "operating system", "os platform", "os"),
        vendor=_pick(r, "manufacturer", "vendor"),
        model=_pick(r, "model", "model number"),
        role_hints=(_pick(r, "chassis type", "computer role", "operating system"),),
        notes=(f"Serial: {serial}" if serial else ""),
        tags=["tanium"],
    )


def parse_tanium_csv(content: str, rep: RowReport | None = None) -> list[dict]:
    rep = rep if rep is not None else RowReport(MAX_ROWS)
    for raw in csv_dicts(content):
        mapped = map_tanium_row(raw)
        if mapped:
            rep.add(mapped)
        else:
            rep.skip("no computer name / hostname")
    return rep.rows


def parse_cisco_ise_csv(content: str, rep: RowReport | None = None) -> list[dict]:
    rep = rep if rep is not None else RowReport(MAX_ROWS)
    for raw in csv_dicts(content):
        r = _ci(raw)
        mac = _pick(r, "macaddress", "mac address", "mac")
        hostname = _pick(r, "hostname", "host-name", "endpointsource", "name")
        name = hostname or mac
        if not name:
            rep.skip("no MAC address or hostname")
            continue
        policy = _pick(r, "endpointpolicy", "endpoint policy", "endpointprofile", "devicetype", "device-type")
        group = _pick(r, "identitygroup", "identity group")
        rep.add(_row(
            name=name,
            hostname=hostname,
            ip=_pick(r, "ipaddress", "ip address", "ip"),
            mac=mac,
            os_raw=_pick(r, "operatingsystem", "operating system", "operatingsystemresult", "operating-system", "os"),
            vendor=_pick(r, "vendor", "oui", "device-platform"),
            role_hints=(policy,),
            notes=(f"ISE policy: {policy}" + (f"; group: {group}" if group else "")) if policy else "",
            tags=["cisco-ise"],
        ))
    return rep.rows


def detect_source(filename: str, content_start: str) -> str | None:
    first_line = content_start.split("\n")[0].lower().replace('"', "")
    norm = first_line.replace(" ", "").replace("_", "")
    # Tanium first: its hallmark "Computer Name" is decisive. (Check before ISE
    # because Tanium's "MAC Address" column normalizes to "macaddress" too.)
    if "computer name" in first_line or ("computername" in norm and "operatingsystem" in norm):
        return "tanium_csv"
    # Cisco ISE: MACAddress is the canonical key; EndPointPolicy is distinctive.
    if "macaddress" in norm or "endpointpolicy" in norm:
        return "cisco_ise_csv"
    return None


PARSERS: dict[str, callable] = {
    "tanium_csv": parse_tanium_csv,
    "cisco_ise_csv": parse_cisco_ise_csv,
}

# Fail fast if advertised sources and the dispatch table drift apart.
assert {s["key"] for s in SUPPORTED_SOURCES} == set(PARSERS), \
    "SUPPORTED_SOURCES and PARSERS are out of sync"


def parse_assets_report(content: str, source_key: str) -> RowReport:
    """Rows plus what was skipped (and why) or cut off by the row cap.
    Raises ImportFileError for malformed CSV."""
    rep = RowReport(MAX_ROWS)
    parser = PARSERS.get(source_key)
    if parser:
        parser(content, rep)
    return rep


def parse_assets(content: str, source_key: str) -> list[dict]:
    return parse_assets_report(content, source_key).rows
