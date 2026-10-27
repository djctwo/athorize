"""Risk Quantification Engine — Athorize.

Estimates dollar-denominated exposure per red team finding using:
1. Industry-specific breach cost benchmarks (IBM/Ponemon 2024)
2. Framework-specific regulatory penalty data (statutory sources)
3. Organization context (revenue, contract value, record count)
4. Severity-based weighting

Every estimate shows a range (low/high) and cites its source.
"""

from __future__ import annotations

from datetime import date
from typing import Any

# Single source of truth for estimate provenance — surfaced on the Red Team
# page, the Executive Briefing, and the risk-context API so every monetary
# figure carries its citation. Bump last_reviewed whenever the benchmark
# tables below are refreshed against a newer report; the UI warns when this
# date is older than REVIEW_INTERVAL_DAYS.
BENCHMARK_METADATA = {
    "version": "2024.1",
    "last_reviewed": "2026-06-11",
    "breach_costs_source": "IBM Cost of a Data Breach Report 2024 (Ponemon Institute)",
    "penalty_sources": (
        "Published regulatory penalty structures: GDPR Art. 83, HIPAA 45 CFR 160.404 tiers, "
        "PCI DSS contractual fines, SOX §906, NERC CIP sanctions guidance, DORA Art. 51, "
        "CMMC/DFARS contract-loss exposure, state privacy statutes (CCPA/CPRA)"
    ),
    "disclaimer": (
        "All monetary figures are planning estimates derived from published industry benchmarks "
        "and statutory penalty ranges, weighted by finding severity and organization context. "
        "They are not actuarial predictions, legal advice, or guaranteed outcomes."
    ),
}
# Plain-language statement of the aggregation model — shown wherever a
# combined figure appears (Help, Red Team, Executive Briefing).
EXPOSURE_MODEL_TEXT = (
    "Combined figures are not a straight sum: the largest estimate counts in full, "
    "the next four add 35% each, every further one adds 10%, and the high end is "
    "capped at 1.5x annual revenue when revenue is set."
)
REVIEW_INTERVAL_DAYS = 548  # ~18 months — benchmarks older than this get flagged


def benchmark_info() -> dict[str, Any]:
    last = date.fromisoformat(BENCHMARK_METADATA["last_reviewed"])
    age_days = (date.today() - last).days
    return {
        **BENCHMARK_METADATA,
        "aggregation_model": EXPOSURE_MODEL_TEXT,
        "stale": age_days > REVIEW_INTERVAL_DAYS,
        "age_days": age_days,
    }


# ---------------------------------------------------------------------------
# Industry breach cost benchmarks — IBM/Ponemon Cost of a Data Breach 2024
# (avg_breach_cost in USD, per_record in USD)
# ---------------------------------------------------------------------------

INDUSTRY_BREACH_COSTS: dict[str, dict[str, Any]] = {
    "healthcare": {
        "avg_breach_cost": 9_770_000,
        "per_record": 259,
        "source": "IBM Cost of a Data Breach Report 2024, Healthcare",
    },
    "financial": {
        "avg_breach_cost": 6_080_000,
        "per_record": 181,
        "source": "IBM Cost of a Data Breach Report 2024, Financial Services",
    },
    "pharmaceuticals": {
        "avg_breach_cost": 5_010_000,
        "per_record": 188,
        "source": "IBM Cost of a Data Breach Report 2024, Pharmaceuticals",
    },
    "technology": {
        "avg_breach_cost": 5_450_000,
        "per_record": 174,
        "source": "IBM Cost of a Data Breach Report 2024, Technology",
    },
    "energy": {
        "avg_breach_cost": 4_720_000,
        "per_record": 179,
        "source": "IBM Cost of a Data Breach Report 2024, Energy",
    },
    "industrial": {
        "avg_breach_cost": 5_560_000,
        "per_record": 173,
        "source": "IBM Cost of a Data Breach Report 2024, Industrial",
    },
    "education": {
        "avg_breach_cost": 3_650_000,
        "per_record": 148,
        "source": "IBM Cost of a Data Breach Report 2024, Education",
    },
    "government": {
        "avg_breach_cost": 2_730_000,
        "per_record": 134,
        "source": "IBM Cost of a Data Breach Report 2024, Public Sector",
    },
    "retail": {
        "avg_breach_cost": 3_480_000,
        "per_record": 142,
        "source": "IBM Cost of a Data Breach Report 2024, Retail",
    },
    "default": {
        "avg_breach_cost": 4_880_000,
        "per_record": 165,
        "source": "IBM Cost of a Data Breach Report 2024, Global Average",
    },
}

# ---------------------------------------------------------------------------
# Framework-specific regulatory penalties
# ---------------------------------------------------------------------------

FRAMEWORK_PENALTIES: dict[str, dict[str, Any]] = {
    "cmmc-2.0": {
        "penalty_type": "contract_loss",
        "description": "Loss of DoD contract eligibility",
        "contract_loss_pct": 1.0,
        "source": "32 CFR Part 170, CMMC Program Rule (Oct 2024)",
    },
    "gdpr": {
        "penalty_type": "revenue_pct",
        "revenue_pct": 0.04,
        "flat_max": 20_000_000,
        "source": "GDPR Art. 83(5) — up to 4% annual global turnover or €20M",
    },
    "hipaa-security": {
        "penalty_type": "tiered",
        "per_violation_low": 100,
        "per_violation_high": 50_000,
        "annual_cap": 1_500_000,
        "source": "HITECH Act, 42 USC §17939 — $100-$50K per violation, $1.5M/year cap per category",
    },
    "pci-dss-v4": {
        "penalty_type": "monthly",
        "monthly_low": 5_000,
        "monthly_high": 100_000,
        "source": "PCI SSC — $5K-$100K/month non-compliance fines from acquiring bank",
    },
    "sox": {
        "penalty_type": "flat",
        "fine_low": 1_000_000,
        "fine_high": 5_000_000,
        "source": "Sarbanes-Oxley Act §906 — up to $5M fine for willful certification of non-compliant report",
    },
    "ccpa-cpra": {
        "penalty_type": "per_violation",
        "per_violation": 2_500,
        "per_intentional": 7_500,
        "source": "CCPA §1798.155 — $2,500/violation, $7,500/intentional violation",
    },
    "glba": {
        "penalty_type": "per_violation",
        "per_violation": 100_000,
        "source": "GLBA §525 — up to $100K per violation",
    },
    "nerc-cip": {
        "penalty_type": "daily",
        "per_day": 1_000_000,
        "source": "NERC — up to $1M per violation per day",
    },
    "dora": {
        "penalty_type": "revenue_pct",
        "revenue_pct": 0.02,
        "source": "DORA Art. 50 — up to 2% annual global turnover",
    },
    "fedramp": {
        "penalty_type": "contract_loss",
        "description": "Loss of ATO, federal contract termination",
        "contract_loss_pct": 1.0,
        "source": "FedRAMP Authorization Act (2022) — ATO revocation",
    },
    "nist-800-53-r5": {
        "penalty_type": "contract_loss",
        "description": "Federal system ATO revocation",
        "contract_loss_pct": 1.0,
        "source": "FISMA — non-compliance leads to ATO loss and potential contract termination",
    },
    "stateramp": {
        "penalty_type": "contract_loss",
        "description": "Loss of state contract eligibility",
        "contract_loss_pct": 0.5,
        "source": "StateRAMP — authorization revocation, state contract ineligibility",
    },
    "cjis": {
        "penalty_type": "access_loss",
        "description": "Loss of access to criminal justice information systems",
        "source": "FBI CJIS Security Policy — access termination",
    },
    "irs-1075": {
        "penalty_type": "access_loss",
        "description": "Loss of Federal Tax Information access",
        "source": "IRS Publication 1075 — FTI access revocation, contract termination",
    },
}

# ---------------------------------------------------------------------------
# Severity multipliers — what fraction of the base exposure a finding represents
# ---------------------------------------------------------------------------

SEVERITY_MULTIPLIERS = {
    "CRITICAL": {"low": 0.7, "high": 1.0},
    "HIGH": {"low": 0.35, "high": 0.6},
    "MEDIUM": {"low": 0.1, "high": 0.3},
    "LOW": {"low": 0.02, "high": 0.1},
}

# ---------------------------------------------------------------------------
# Remediation effort by finding category (hours, T-shirt size)
# ---------------------------------------------------------------------------

EFFORT_BY_CATEGORY: dict[str, dict[str, Any]] = {
    "Evidence Gap": {"size": "LOW", "hours_low": 2, "hours_high": 8},
    "Evidence Freshness": {"size": "LOW", "hours_low": 1, "hours_high": 4},
    "Documentation Gap": {"size": "MEDIUM", "hours_low": 4, "hours_high": 16},
    "Implementation Gap": {"size": "HIGH", "hours_low": 8, "hours_high": 40},
    "Assessment Finding": {"size": "HIGH", "hours_low": 8, "hours_high": 40},
    "Finding Management": {"size": "LOW", "hours_low": 1, "hours_high": 4},
    "Assessment Gap": {"size": "HIGH", "hours_low": 16, "hours_high": 80},
    "Deadline Management": {"size": "LOW", "hours_low": 1, "hours_high": 2},
}

DEFAULT_EFFORT = {"size": "MEDIUM", "hours_low": 4, "hours_high": 16}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_industries() -> list[dict[str, str]]:
    return [
        {"id": k, "label": k.replace("_", " ").title(), "source": v["source"]}
        for k, v in INDUSTRY_BREACH_COSTS.items()
        if k != "default"
    ]


def quantify_finding(
    finding: dict[str, Any],
    framework_id: str,
    org_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Enrich a single red team finding with exposure, effort, and priority."""
    ctx = org_context or {}
    industry = ctx.get("industry", "default")
    breach_data = INDUSTRY_BREACH_COSTS.get(industry, INDUSTRY_BREACH_COSTS["default"])
    severity = finding.get("severity", "MEDIUM")
    category = finding.get("category", "")
    sev_mult = SEVERITY_MULTIPLIERS.get(severity, SEVERITY_MULTIPLIERS["MEDIUM"])

    base_exposure = _compute_base_exposure(framework_id, breach_data, ctx)

    exposure_low = round(base_exposure * sev_mult["low"])
    exposure_high = round(base_exposure * sev_mult["high"])

    effort = EFFORT_BY_CATEGORY.get(category, DEFAULT_EFFORT)
    effort_hours_mid = (effort["hours_low"] + effort["hours_high"]) / 2
    exposure_mid = (exposure_low + exposure_high) / 2
    priority_score = round(exposure_mid / max(effort_hours_mid, 1))

    breakdown = _build_breakdown(
        framework_id, severity, category, breach_data, ctx, base_exposure,
        sev_mult, exposure_low, exposure_high,
    )

    return {
        "estimated_exposure_low": exposure_low,
        "estimated_exposure_high": exposure_high,
        "remediation_effort": effort["size"],
        "effort_hours_low": effort["hours_low"],
        "effort_hours_high": effort["hours_high"],
        "priority_score": priority_score,
        "cost_breakdown": breakdown,
    }


def quantify_findings(
    findings: list[dict[str, Any]],
    framework_id: str,
    org_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Enrich all findings and return them with quantification data merged in."""
    enriched = []
    for f in findings:
        quant = quantify_finding(f, framework_id, org_context)
        enriched.append({**f, **quant})
    return enriched


def _aggregate_exposure(values: list[int]) -> int:
    """Probable-loss aggregation across findings that share consequence events.

    A regulatory penalty or breach is not paid once per finding — multiple
    weaknesses raise the likelihood and blast radius of the SAME loss events.
    Straight summation therefore overstates wildly (it can exceed annual
    revenue). Model: the dominant finding contributes fully, the next four
    raise the loss materially (35% each), and the long tail contributes
    marginally (10% each).
    """
    if not values:
        return 0
    ordered = sorted(values, reverse=True)
    total = float(ordered[0])
    total += 0.35 * sum(ordered[1:5])
    total += 0.10 * sum(ordered[5:])
    return round(total)


def aggregate_exposure_range(
    lows: list[int],
    highs: list[int],
    org_context: dict[str, Any] | None = None,
) -> tuple[int, int]:
    """THE exposure aggregation for any group of estimates — a report's
    findings, an attack chain's findings, or several reports for the
    Executive Briefing. Probable-loss model (_aggregate_exposure) on each
    bound, then the high bound is capped at 1.5x annual revenue when revenue is
    known (low never exceeds high)."""
    ctx = org_context or {}
    total_low = _aggregate_exposure(lows)
    total_high = _aggregate_exposure(highs)
    revenue = ctx.get("annual_revenue") or 0
    if revenue:
        total_high = min(total_high, round(1.5 * revenue))
        total_low = min(total_low, total_high)
    return total_low, total_high


def chain_exposure(
    finding_ids: list[str],
    enriched_findings: list[dict[str, Any]],
    org_context: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Combined estimate for an attack chain: its constituent findings run
    through the same model and cap as the report total, so a chain can never
    exceed the report it belongs to."""
    wanted = set(finding_ids)
    linked = [f for f in enriched_findings if f.get("id") in wanted]
    low, high = aggregate_exposure_range(
        [f.get("estimated_exposure_low", 0) for f in linked],
        [f.get("estimated_exposure_high", 0) for f in linked],
        org_context,
    )
    return {"estimated_exposure_low": low, "estimated_exposure_high": high}


def summarize_reports(
    reports: list[dict[str, Any]],
    org_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Cross-report (organization) exposure for the Executive Briefing.

    Reports share org-level consequence events, so their totals are combined
    with the same probable-loss model and revenue cap as findings inside a
    report. "Fix each report's top 5" savings = combined total minus the
    combined total of what each report has left after its top 5 are fixed —
    computed through the same model so savings can never exceed the total."""
    total_low, total_high = aggregate_exposure_range(
        [r.get("total_exposure_low", 0) or 0 for r in reports],
        [r.get("total_exposure_high", 0) or 0 for r in reports],
        org_context,
    )
    rest_low, rest_high = aggregate_exposure_range(
        [max(0, (r.get("total_exposure_low", 0) or 0) - (r.get("top5_reduction_low", 0) or 0)) for r in reports],
        [max(0, (r.get("total_exposure_high", 0) or 0) - (r.get("top5_reduction_high", 0) or 0)) for r in reports],
        org_context,
    )
    return {
        "total_exposure_low": total_low,
        "total_exposure_high": total_high,
        "top5_reduction_low": max(0, total_low - rest_low),
        "top5_reduction_high": max(0, total_high - rest_high),
        "quick_win_count": sum(int(r.get("quick_win_count", 0) or 0) for r in reports),
        "report_count": len(reports),
        "is_estimate": True,
        "model": EXPOSURE_MODEL_TEXT,
    }


def compute_report_totals(
    enriched_findings: list[dict[str, Any]],
    org_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute report-level exposure totals from enriched findings.

    Uses probable-loss aggregation (see _aggregate_exposure) rather than a
    straight sum, and sanity-caps the high estimate at 1.5x annual revenue
    when the organization has provided revenue context — exposure beyond
    that is not a credible planning number.
    """
    total_low, total_high = aggregate_exposure_range(
        [f.get("estimated_exposure_low", 0) for f in enriched_findings],
        [f.get("estimated_exposure_high", 0) for f in enriched_findings],
        org_context,
    )

    # Top-5 savings = exposure delta if the five highest-priority findings
    # were remediated — computed through the same aggregation so savings can
    # never exceed the total.
    by_priority = sorted(enriched_findings, key=lambda f: f.get("priority_score", 0), reverse=True)
    rest = by_priority[5:]
    rest_low, rest_high = aggregate_exposure_range(
        [f.get("estimated_exposure_low", 0) for f in rest],
        [f.get("estimated_exposure_high", 0) for f in rest],
        org_context,
    )
    top5_reduction_low = max(0, total_low - rest_low)
    top5_reduction_high = max(0, total_high - rest_high)

    quick_wins = [
        f for f in enriched_findings
        if f.get("remediation_effort") == "LOW" and f.get("priority_score", 0) > 0
    ]
    quick_wins.sort(key=lambda f: f.get("priority_score", 0), reverse=True)

    return {
        "total_exposure_low": total_low,
        "total_exposure_high": total_high,
        "top5_reduction_low": top5_reduction_low,
        "top5_reduction_high": top5_reduction_high,
        "quick_win_count": len(quick_wins),
        "has_org_context": org_context_is_configured(org_context or {}),
    }


def org_context_is_configured(ctx: dict[str, Any]) -> bool:
    return bool(ctx.get("industry") or ctx.get("annual_revenue") or ctx.get("record_count"))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_base_exposure(
    framework_id: str,
    breach_data: dict[str, Any],
    ctx: dict[str, Any],
) -> float:
    """Compute the base exposure for this org+framework before severity weighting."""
    components: list[float] = []

    record_count = ctx.get("record_count", 0)
    if record_count:
        components.append(record_count * breach_data["per_record"])

    penalty_info = FRAMEWORK_PENALTIES.get(framework_id)
    if penalty_info:
        ptype = penalty_info["penalty_type"]
        revenue = ctx.get("annual_revenue", 0)
        contract_value = ctx.get("largest_contract_value", 0)

        if ptype == "revenue_pct" and revenue:
            pct_amount = revenue * penalty_info["revenue_pct"]
            flat_max = penalty_info.get("flat_max")
            components.append(min(pct_amount, flat_max) if flat_max else pct_amount)
        elif ptype == "contract_loss" and contract_value:
            components.append(contract_value * penalty_info.get("contract_loss_pct", 1.0))
        elif ptype == "tiered":
            components.append(penalty_info.get("annual_cap", 500_000))
        elif ptype == "monthly":
            avg_monthly = (penalty_info.get("monthly_low", 0) + penalty_info.get("monthly_high", 0)) / 2
            components.append(avg_monthly * 6)
        elif ptype == "per_violation":
            components.append(penalty_info.get("per_violation", 10_000) * 50)
        elif ptype == "daily":
            components.append(penalty_info.get("per_day", 100_000) * 30)
        elif ptype == "flat":
            avg_fine = (penalty_info.get("fine_low", 0) + penalty_info.get("fine_high", 0)) / 2
            components.append(avg_fine)

    if not components:
        components.append(breach_data["avg_breach_cost"] * 0.1)

    return max(components)


def _build_breakdown(
    framework_id: str,
    severity: str,
    category: str,
    breach_data: dict[str, Any],
    ctx: dict[str, Any],
    base_exposure: float,
    sev_mult: dict[str, float],
    exposure_low: int,
    exposure_high: int,
) -> list[dict[str, str]]:
    """Build a human-readable cost breakdown with sources."""
    breakdown: list[dict[str, str]] = []

    breakdown.append({
        "factor": "Industry benchmark",
        "detail": f"${breach_data['per_record']}/record, ${breach_data['avg_breach_cost']:,.0f} avg breach",
        "source": breach_data["source"],
    })

    penalty_info = FRAMEWORK_PENALTIES.get(framework_id)
    if penalty_info:
        breakdown.append({
            "factor": "Regulatory penalty",
            "detail": penalty_info.get("description", penalty_info["penalty_type"]),
            "source": penalty_info["source"],
        })

    if ctx.get("annual_revenue"):
        breakdown.append({
            "factor": "Org revenue",
            "detail": f"${ctx['annual_revenue']:,.0f} annual",
            "source": "Organization settings",
        })
    if ctx.get("largest_contract_value"):
        breakdown.append({
            "factor": "Contract at risk",
            "detail": f"${ctx['largest_contract_value']:,.0f}",
            "source": "Organization settings",
        })
    if ctx.get("record_count"):
        breakdown.append({
            "factor": "Records at risk",
            "detail": f"{ctx['record_count']:,} records × ${breach_data['per_record']}/record",
            "source": breach_data["source"],
        })

    breakdown.append({
        "factor": "Severity weight",
        "detail": f"{severity} = {sev_mult['low']:.0%}–{sev_mult['high']:.0%} of base exposure",
        "source": "Athorize risk model",
    })

    breakdown.append({
        "factor": "Estimated exposure",
        "detail": f"${exposure_low:,.0f} – ${exposure_high:,.0f}",
        "source": "Computed",
    })

    return breakdown
