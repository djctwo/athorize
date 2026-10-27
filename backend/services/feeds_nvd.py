"""NVD CVE feed — recent CRITICAL/HIGH CVEs matched against asset inventory.

Live mode queries the NVD API 2.0 for CVEs modified in the last N days
(one request per severity tier). Anonymous access is rate-limited to
5 requests/30s; set NVD_API_KEY for the 50/30s tier. Default is a bundled
fixture so demos and air-gapped installs work offline (FICTIONAL sample
data: made-up vendors and DEMO- ids, see services/sample_advisories.py).

API: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
from __future__ import annotations

import json
import os
from datetime import UTC, date, datetime, timedelta

import httpx

from _appbase import bundle_root
from services.sample_advisories import is_real_cve_id

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FIXTURE = bundle_root() / "backend" / "data" / "nvd_mock.json"
_MAX_BODY = 32 * 1024 * 1024


class NvdFeedError(Exception):
    pass


def _cpe_vendor_product(configurations: list) -> tuple[str, str]:
    """First application/OS CPE → (vendor, product), humanized."""
    for config in configurations or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                # cpe:2.3:<part>:<vendor>:<product>:...
                if len(parts) > 4 and parts[3] and parts[3] != "*":
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title() if parts[4] != "*" else ""
                    return vendor, product
    return "", ""


def normalize_nvd(vulnerabilities: list[dict]) -> list[dict]:
    out = []
    for item in vulnerabilities:
        cve = item.get("cve") or {}
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        desc = next(
            (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
            "",
        )
        metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or (cve.get("metrics") or {}).get("cvssMetricV30") or []
        score = None
        severity = "HIGH"
        if metrics:
            data = metrics[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = (data.get("baseSeverity") or "HIGH").upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "HIGH"
        vendor, product = _cpe_vendor_product(cve.get("configurations") or [])
        published = None
        if cve.get("published"):
            try:
                published = datetime.fromisoformat(cve["published"]).date()
            except ValueError:
                published = None
        out.append({
            "advisory_id": f"NVD-{cve_id}",
            "title": f"{cve_id}: {vendor} {product}".strip(": ") if vendor else cve_id,
            "summary": desc[:2000],
            "severity": severity,
            "cvss_score": str(score) if score is not None else None,
            "cve_ids": [cve_id],
            "affected_vendor": vendor,
            "affected_product": product,
            "affected_firmware_range": "",
            "recommended_mitigations": "Apply vendor patches per the CVE references; prioritize internet-facing assets.",
            "published_date": published,
            # Fixture DEMO- ids are fictional: no link to a (non-)record on NVD.
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if is_real_cve_id(cve_id) else "",
        })
    return out


def fetch_nvd(live: bool = False, days: int = 7, limit: int = 100) -> list[dict]:
    if not live:
        raw = json.loads(NVD_FIXTURE.read_text())
        return normalize_nvd(raw.get("vulnerabilities", []))

    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    collected: list[dict] = []
    try:
        with httpx.Client(timeout=30, follow_redirects=False, headers=headers) as client:
            for sev in ("CRITICAL", "HIGH"):
                resp = client.get(NVD_URL, params={
                    "cvssV3Severity": sev,
                    "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": limit,
                })
                resp.raise_for_status()
                if len(resp.content) > _MAX_BODY:
                    raise NvdFeedError("NVD response exceeded size cap")
                collected.extend(resp.json().get("vulnerabilities", []))
    except httpx.HTTPError as exc:
        raise NvdFeedError(str(exc)) from exc
    return normalize_nvd(collected)
