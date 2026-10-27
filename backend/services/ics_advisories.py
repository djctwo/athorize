"""ICS advisory / OT asset matching engine.

Confidence tiers (highest to lowest):
    EXACT            vendor + product + firmware all line up
    FIRMWARE_RANGE   vendor + product match and firmware parses into the declared affected range
    VENDOR_PRODUCT   vendor + product match but firmware unknown / OOB
    VENDOR_ONLY      only the vendor line matches
"""
from __future__ import annotations

import re
from typing import Iterable

from models.ot_asset import OTAsset


Confidence = str


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _tokens(value: str | None) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", _norm(value)) if t]


def _vendor_matches(advisory_vendor: str | None, asset_vendor: str | None) -> bool:
    a = _norm(advisory_vendor)
    b = _norm(asset_vendor)
    if not a or not b:
        return False
    return a in b or b in a


def _product_matches(advisory_product: str | None, asset_model: str | None) -> bool:
    a_tokens = _tokens(advisory_product)
    b_tokens = _tokens(asset_model)
    if not a_tokens or not b_tokens:
        return False
    a_set = {t for t in a_tokens if len(t) > 1}
    b_set = {t for t in b_tokens if len(t) > 1}
    if not a_set or not b_set:
        return False
    return bool(a_set & b_set)


_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _parse_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = _VERSION_RE.search(value)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _firmware_in_range(asset_firmware: str | None, range_expr: str | None) -> bool:
    if not range_expr or not asset_firmware:
        return False
    expr = range_expr.strip().lower()
    asset_v = _parse_version(asset_firmware)
    if asset_v is None:
        return False

    if "all firmware" in expr or "(all)" in expr or expr.endswith("all"):
        return True

    m = re.match(r"^\s*<=\s*(.+)$", expr)
    if m:
        bound = _parse_version(m.group(1))
        return bound is not None and asset_v <= bound

    m = re.match(r"^\s*<\s*(.+)$", expr)
    if m:
        bound = _parse_version(m.group(1))
        return bound is not None and asset_v < bound

    m = re.match(r"^\s*>=\s*(.+)$", expr)
    if m:
        bound = _parse_version(m.group(1))
        return bound is not None and asset_v >= bound

    m = re.match(r"^\s*>\s*(.+)$", expr)
    if m:
        bound = _parse_version(m.group(1))
        return bound is not None and asset_v > bound

    versions = _VERSION_RE.findall(expr)
    if len(versions) >= 2 and any(sep in expr for sep in ("–", " - ", " — ")):
        low = _parse_version(versions[0])
        high = _parse_version(versions[-1])
        if low is not None and high is not None:
            return low <= asset_v <= high

    exact = _parse_version(expr)
    if exact is not None:
        return asset_v == exact

    return False


def _firmware_exact(asset_firmware: str | None, range_expr: str | None) -> bool:
    if not range_expr or not asset_firmware:
        return False
    expr = range_expr.strip().lower()
    if any(tok in expr for tok in ("<", ">", "–", "-", "all", "(all)", "x")):
        return False
    bound = _parse_version(expr)
    asset_v = _parse_version(asset_firmware)
    return bound is not None and asset_v is not None and bound == asset_v


def match_advisory(advisory: dict, assets: Iterable[OTAsset]) -> list[dict]:
    matches: list[dict] = []
    adv_vendor = advisory.get("affected_vendor")
    adv_product = advisory.get("affected_product")
    adv_fw_range = advisory.get("affected_firmware_range")

    for asset in assets:
        if not _vendor_matches(adv_vendor, asset.vendor):
            continue

        product_hit = _product_matches(adv_product, asset.model)
        if not product_hit:
            matches.append(
                {
                    "ot_asset_id": asset.id,
                    "system_id": asset.system_id,
                    "confidence": "VENDOR_ONLY",
                }
            )
            continue

        if _firmware_exact(asset.firmware_version, adv_fw_range):
            confidence: Confidence = "EXACT"
        elif _firmware_in_range(asset.firmware_version, adv_fw_range):
            confidence = "FIRMWARE_RANGE"
        else:
            confidence = "VENDOR_PRODUCT"

        matches.append(
            {
                "ot_asset_id": asset.id,
                "system_id": asset.system_id,
                "confidence": confidence,
            }
        )

    return matches


def match_advisory_it(advisory: dict, assets: Iterable) -> list[dict]:
    """Match a feed item against IT assets (vendor/model and OS).

    KEV and CVE-style feeds name vendor+product (e.g. Microsoft / SQL Server,
    Palo Alto Networks / PAN-OS). Product tokens are checked against both the
    asset model and its OS family+version so OS-level vulnerabilities land on
    every host running that OS.
    """
    matches: list[dict] = []
    adv_vendor = advisory.get("affected_vendor")
    adv_product = advisory.get("affected_product")

    for asset in assets:
        vendor_hit = _vendor_matches(adv_vendor, asset.vendor)
        os_text = f"{asset.os_family or ''} {asset.os_version or ''}".strip()
        product_hit = _product_matches(adv_product, asset.model) or _product_matches(adv_product, os_text)

        if product_hit and vendor_hit:
            confidence = "VENDOR_PRODUCT"
        elif product_hit:
            # OS/product name matched without a vendor hit (e.g. 'Windows'
            # advisory vs asset vendor 'Lenovo') — still actionable.
            confidence = "VENDOR_ONLY"
        elif vendor_hit:
            confidence = "VENDOR_ONLY"
        else:
            continue

        matches.append(
            {
                "it_asset_id": asset.id,
                "system_id": asset.system_id,
                "confidence": confidence,
            }
        )
    return matches
