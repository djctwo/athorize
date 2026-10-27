"""
Live asset-source API connectors (Tanium, Cisco ISE).

Pulls asset inventory directly from a customer's own Tanium / Cisco ISE over
their network — the same self-hosted, no-phone-home posture as the live threat
feeds (services/feed_refresh.py). Off by default; activated only when the
operator sets the connector's env vars.

Design: the pure normalize_*() functions (API JSON → canonical asset rows) are
unit-tested; the thin fetch_*() HTTP wrappers follow the feeds_nvd.py pattern.

⚠ The fetch_*() request/response shapes follow documented Tanium REST v2 and
Cisco ISE ERS APIs but vary by product version — validate against a real
instance before relying on them in production. The normalize_*() mapping is
version-stable and fully tested.

Env configuration:
  TANIUM_URL, TANIUM_API_TOKEN, TANIUM_SAVED_QUESTION_ID, TANIUM_VERIFY_TLS
  CISCO_ISE_URL, CISCO_ISE_USER, CISCO_ISE_PASSWORD, CISCO_ISE_VERIFY_TLS
"""
from __future__ import annotations

import os

import httpx

from services.asset_import import map_tanium_row, _row
from services.safe_http import INTERNAL, guarded_client

_TIMEOUT = 30
_MAX_BODY = 32 * 1024 * 1024
_MAX_ENDPOINTS = 5000


class ConnectorError(Exception):
    pass


def _env_bool(name: str, default: bool = True) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "no", "off")


# ---------------------------------------------------------------------------
# Normalizers (pure, unit-tested)
# ---------------------------------------------------------------------------

def normalize_tanium_result(result_set: dict) -> list[dict]:
    """Tanium result_data result_set ({columns:[{name}], rows:[{data:[[{text}]]}]})
    → canonical asset rows, via the shared Tanium column mapping."""
    columns = [c.get("name", "") for c in result_set.get("columns") or []]
    out: list[dict] = []
    for row in result_set.get("rows") or []:
        cells = row.get("data") or []
        record: dict = {}
        for idx, col in enumerate(columns):
            if idx >= len(cells):
                continue
            cell = cells[idx]
            # each cell is a list of {"text": ...} values
            if isinstance(cell, list):
                text = ", ".join(str(v.get("text", "")).strip() for v in cell if isinstance(v, dict) and v.get("text") not in (None, "[no results]"))
            else:
                text = str(cell)
            record[col] = text
        mapped = map_tanium_row(record)
        if mapped:
            out.append(mapped)
    return out


def normalize_ise_endpoints(endpoints: list[dict]) -> list[dict]:
    """Cisco ISE ERS endpoint objects → canonical asset rows.

    ERS gives MAC + group + (optionally) custom attributes; OS/policy come from
    customAttributes when Context Visibility populates them."""
    out: list[dict] = []
    for ep in endpoints or []:
        mac = ep.get("mac") or ep.get("name") or ""
        name = ep.get("name") or mac
        if not name:
            continue
        custom = ((ep.get("customAttributes") or {}).get("customAttributes")) or {}
        # custom attribute keys vary by deployment; match case-insensitively.
        ci = {(k or "").strip().lower(): v for k, v in custom.items()}
        os_raw = str(ci.get("operating system") or ci.get("operatingsystem") or ci.get("os") or "")
        policy = str(ci.get("endpointpolicy") or ci.get("endpoint policy") or "")
        group = ep.get("groupId") or ep.get("identityGroup") or ""
        notes_bits = []
        if policy:
            notes_bits.append(f"ISE policy: {policy}")
        if ep.get("description"):
            notes_bits.append(str(ep["description"]))
        mapped = _row(
            name=str(name),
            mac=str(mac),
            os_raw=os_raw,
            role_hints=(policy,),
            notes="; ".join(notes_bits),
            tags=["cisco-ise"],
        )
        if group:
            mapped.setdefault("tags", []).append(f"group:{group}")
        out.append(mapped)
    return out


# ---------------------------------------------------------------------------
# Config / status
# ---------------------------------------------------------------------------

def _tanium_configured() -> bool:
    return bool(os.getenv("TANIUM_URL") and os.getenv("TANIUM_API_TOKEN") and os.getenv("TANIUM_SAVED_QUESTION_ID"))


def _ise_configured() -> bool:
    return bool(os.getenv("CISCO_ISE_URL") and os.getenv("CISCO_ISE_USER") and os.getenv("CISCO_ISE_PASSWORD"))


def connector_status() -> list[dict]:
    """Which live connectors are configured (no secrets leaked)."""
    return [
        {"key": "tanium", "label": "Tanium", "configured": _tanium_configured(),
         "env": ["TANIUM_URL", "TANIUM_API_TOKEN", "TANIUM_SAVED_QUESTION_ID"]},
        {"key": "cisco_ise", "label": "Cisco ISE", "configured": _ise_configured(),
         "env": ["CISCO_ISE_URL", "CISCO_ISE_USER", "CISCO_ISE_PASSWORD"]},
    ]


# ---------------------------------------------------------------------------
# Fetchers (thin HTTP — validate against a real instance)
# ---------------------------------------------------------------------------

def _require_https(url: str, label: str) -> str:
    url = (url or "").rstrip("/")
    if not url.startswith("https://"):
        raise ConnectorError(f"{label} URL must be https://")
    return url


def fetch_tanium() -> list[dict]:
    if not _tanium_configured():
        raise ConnectorError("Tanium connector is not configured")
    base = _require_https(os.getenv("TANIUM_URL", ""), "Tanium")
    token = os.getenv("TANIUM_API_TOKEN", "")
    qid = os.getenv("TANIUM_SAVED_QUESTION_ID", "")
    verify = _env_bool("TANIUM_VERIFY_TLS", True)
    try:
        # On-prem by design (private ranges allowed) but pinned against DNS
        # rebinding and refused for cloud-metadata / link-local addresses.
        with guarded_client(INTERNAL, verify=verify, timeout=_TIMEOUT, follow_redirects=False,
                            headers={"session": token, "Accept": "application/json"}) as client:
            resp = client.get(f"{base}/api/v2/result_data/saved_question/{qid}")
            resp.raise_for_status()
            if len(resp.content) > _MAX_BODY:
                raise ConnectorError("Tanium response exceeded size cap")
            data = resp.json()
    except httpx.HTTPError as exc:
        raise ConnectorError(f"Tanium request failed: {exc}") from exc
    result_sets = (data.get("data") or {}).get("result_sets") or []
    if not result_sets:
        return []
    return normalize_tanium_result(result_sets[0])


def fetch_cisco_ise(limit: int = _MAX_ENDPOINTS) -> list[dict]:
    if not _ise_configured():
        raise ConnectorError("Cisco ISE connector is not configured")
    base = _require_https(os.getenv("CISCO_ISE_URL", ""), "Cisco ISE")
    auth = (os.getenv("CISCO_ISE_USER", ""), os.getenv("CISCO_ISE_PASSWORD", ""))
    verify = _env_bool("CISCO_ISE_VERIFY_TLS", True)
    endpoints: list[dict] = []
    try:
        with guarded_client(INTERNAL, verify=verify, timeout=_TIMEOUT, follow_redirects=False,
                            auth=auth, headers={"Accept": "application/json"}) as client:
            page = 1
            while len(endpoints) < limit:
                resp = client.get(f"{base}/ers/config/endpoint", params={"size": 100, "page": page})
                resp.raise_for_status()
                if len(resp.content) > _MAX_BODY:
                    raise ConnectorError("Cisco ISE response exceeded size cap")
                resources = ((resp.json().get("SearchResult") or {}).get("resources")) or []
                if not resources:
                    break
                for res in resources:
                    if len(endpoints) >= limit:
                        break
                    rid = res.get("id")
                    if not rid:
                        continue
                    d = client.get(f"{base}/ers/config/endpoint/{rid}")
                    d.raise_for_status()
                    ep = (d.json().get("ERSEndPoint")) or {}
                    if ep:
                        endpoints.append(ep)
                page += 1
    except httpx.HTTPError as exc:
        raise ConnectorError(f"Cisco ISE request failed: {exc}") from exc
    return normalize_ise_endpoints(endpoints)


CONNECTORS = {
    "tanium": fetch_tanium,
    "cisco_ise": fetch_cisco_ise,
}


def fetch_connector(key: str) -> list[dict]:
    fn = CONNECTORS.get(key)
    if not fn:
        raise ConnectorError(f"Unknown connector: {key}")
    return fn()
