"""Audit Binder — the one-click, evidence-backed package a customer hands an
auditor.

Builds a ZIP containing:
  binder.html   — self-contained, print-to-PDF-ready report: cover, compliance
                  summary + progress-over-time, control-by-control status with
                  narratives/owners, findings (POA&M) with milestones, and the
                  evidence inventory.
  evidence/     — the actual evidence files that exist on disk (uploaded
                  artifacts). Records whose file is absent (e.g. demo seeds or
                  externally-stored evidence) are listed in the inventory and
                  marked "not archived" rather than failing the export.

Everything is computed from the same org-scoped queries the app itself uses —
the binder is a rendering of the system of record, not a parallel data path.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from datetime import date, datetime, timezone
from html import escape
from pathlib import Path

from sqlalchemy import case
from sqlalchemy.orm import Session

from services.natural_sort import control_sort_key

from models import (
    Control, ControlImplementation, EvidenceArtifact, Finding, Organization,
    System, User,
)
from models.compliance_snapshot import ComplianceSnapshot
from services.branding import CANONICAL_LOGO_RE
from services.compliance_score import score_system
from services.evidence_store import resolve_evidence_path

STATUS_LABEL = {
    "IMPLEMENTED": "Implemented", "PARTIALLY": "Partially Implemented",
    "NOT_IMPLEMENTED": "Not Implemented", "NOT_APPLICABLE": "Not Applicable",
    "INHERITED": "Inherited", "PLANNED": "Planned", "NOT_ASSESSED": "Not Assessed",
}
STATUS_COLOR = {
    "IMPLEMENTED": "#1b7f3b", "INHERITED": "#1b7f3b", "PARTIALLY": "#b07d1a",
    "PLANNED": "#2563eb", "NOT_IMPLEMENTED": "#b91c1c",
    "NOT_APPLICABLE": "#6b7280", "NOT_ASSESSED": "#6b7280",
}

_CSS = """
body{font-family:Georgia,'Times New Roman',serif;color:#1a1a1a;margin:40px auto;max-width:900px;line-height:1.45}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;border-bottom:2px solid #1a1a1a;padding-bottom:4px;margin-top:36px}
h3{font-size:14px;margin:18px 0 6px}
table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}
th{background:#f0f0f0;text-align:left;padding:5px 7px;border:1px solid #999}
td{padding:5px 7px;border:1px solid #bbb;vertical-align:top}
.cover{text-align:center;padding:110px 0 60px;page-break-after:always}
.cover .logo{display:block;max-height:80px;max-width:280px;margin:0 auto 20px}
.cover .brand{font-size:13px;letter-spacing:3px;text-transform:uppercase;color:#555}
.meta{color:#444;font-size:13px}
.kpi{display:inline-block;margin:0 18px;text-align:center}
.kpi b{display:block;font-size:26px}
.status{font-weight:bold}
.narr{color:#333;font-size:11px}
.small{font-size:11px;color:#555}
.milestone-done{text-decoration:line-through;color:#666}
@media print{body{margin:12mm}}
"""


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archived_cell(zip_name: str, tampered: bool) -> str:
    if tampered:
        return ("<b style=color:#b91c1c>HASH MISMATCH — not archived</b> (the stored file no longer "
                "matches the SHA-256 recorded at upload)")
    return ("evidence/" + zip_name) if zip_name else "not archived"


def _esc(v) -> str:
    return escape(str(v)) if v not in (None, "") else "—"


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"


def build_binder(
    db: Session,
    organization_id: int,
    system_id: int,
    framework_id: str,
    framework_name: str,
    generated_by: str,
    style: str = "standard",
) -> bytes:
    """style='standard' → compact control table; style='rsaw' → NERC RSAW-like
    per-requirement worksheets (Compliance Assessment Approach / Registered
    Entity Response / Evidence Provided / Findings)."""
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    system = db.query(System).filter(System.id == system_id).first()
    score = score_system(system_id, framework_id, db)

    controls = sorted(db.query(Control).filter(
        Control.framework_id == framework_id
    ).all(), key=lambda c: control_sort_key(c.control_id))
    impls = {
        i.control_id: i
        for i in db.query(ControlImplementation).filter(
            ControlImplementation.system_id == system_id,
            ControlImplementation.framework_id == framework_id,
        ).all()
    }
    users = {u.id: (u.display_name or u.username) for u in db.query(User).filter(
        User.organization_id == organization_id).all()}

    findings = db.query(Finding).filter(
        Finding.organization_id == organization_id,
        Finding.system_id == system_id,
        Finding.framework_id == framework_id,
    ).order_by(
        # Open work first, then by severity rank (not alphabetically: Low < Medium).
        case((Finding.status.in_(("OPEN", "IN_PROGRESS", "DELAYED")), 0), else_=1),
        case(_SEVERITY_RANK, value=Finding.severity, else_=len(_SEVERITY_RANK)),
        Finding.status,
        Finding.id,
    ).all()
    findings_by_control: dict[str, int] = {}
    for f in findings:
        if f.status in ("OPEN", "IN_PROGRESS", "DELAYED") and f.control_id:
            findings_by_control[f.control_id] = findings_by_control.get(f.control_id, 0) + 1

    control_ids = {c.control_id for c in controls}
    evidence = [
        e for e in db.query(EvidenceArtifact).filter(
            EvidenceArtifact.organization_id == organization_id,
            EvidenceArtifact.system_id == system_id,
        ).order_by(EvidenceArtifact.filename).all()
        if framework_id in (e.framework_ids or []) or control_ids & set(e.control_ids or [])
    ]

    history = db.query(ComplianceSnapshot).filter(
        ComplianceSnapshot.organization_id == organization_id,
        ComplianceSnapshot.system_id == system_id,
        ComplianceSnapshot.framework_id == framework_id,
    ).order_by(ComplianceSnapshot.snapshot_date).all()
    if len(history) > 24:  # thin long series to ~24 evenly spaced rows
        step = len(history) / 24
        history = [history[int(i * step)] for i in range(24)] + [history[-1]]

    today = date.today()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    h: list[str] = [f"<!doctype html><html><head><meta charset='utf-8'>"
                    f"<title>Audit Binder — {_esc(system.name)} × {_esc(framework_name)}</title>"
                    f"<style>{_CSS}</style></head><body>"]

    # ---- Cover ----
    binder_title = "Audit Worksheets (RSAW-style)" if style == "rsaw" else "Audit Binder"
    entity_label = "Registered Entity" if style == "rsaw" else ""
    # Company logo (per-company branding). Upload validation canonicalizes the
    # stored value to a strict PNG/JPEG data URI; the regex gate here is
    # defense in depth for settings that arrived via backup restore or manual
    # DB edit rather than the API — anything non-canonical is simply omitted.
    logo_uri = ((org.settings or {}).get("branding") or {}).get("logo_data_uri") or ""
    logo_html = (
        f"<img class='logo' src='{logo_uri}' alt='{_esc(org.name)} logo'>"
        if CANONICAL_LOGO_RE.match(logo_uri) else ""
    )
    h.append(
        f"<div class='cover'>{logo_html}<div class='brand'>Athorize · Compliance Operations</div>"
        f"<h1>{binder_title}</h1>"
        f"<p class='meta'><b>{(entity_label + ': ') if entity_label else ''}{_esc(org.name)}</b><br>"
        f"System: <b>{_esc(system.name)} ({_esc(system.acronym)})</b><br>"
        f"Framework: <b>{_esc(framework_name)}</b><br>"
        f"Generated {now} by {_esc(generated_by)}</p>"
        f"<p><span class='kpi'><b>{score.score_percentage:.0f}%</b>compliance</span>"
        f"<span class='kpi'><b>{score.implemented}</b>implemented</span>"
        f"<span class='kpi'><b>{score.open_findings}</b>open findings</span>"
        f"<span class='kpi'><b>{len(evidence)}</b>evidence artifacts</span></p></div>"
    )

    # ---- Progress over time ----
    h.append("<h2>1. Compliance Progress</h2>")
    if history:
        h.append("<table><tr><th>Date</th><th>Score</th><th>Open findings</th><th>Overdue</th><th>Critical</th></tr>")
        for s in history:
            h.append(f"<tr><td>{s.snapshot_date}</td><td>{s.score_percentage:.1f}%</td>"
                     f"<td>{s.open_findings}</td><td>{s.overdue_findings}</td><td>{s.critical_findings}</td></tr>")
        h.append("</table>")
    else:
        h.append("<p class='small'>No historical snapshots recorded yet (daily snapshots begin automatically).</p>")

    # ---- Controls ----
    if style == "rsaw":
        # RSAW-like worksheets: one block per requirement, in the structure NERC
        # auditors expect — approach, entity response, evidence, findings.
        h.append(f"<h2>2. Requirement Worksheets ({len(controls)} requirements)</h2>")
        for c in controls:
            i = impls.get(c.control_id)
            status = i.implementation_status if i else "NOT_ASSESSED"
            owner = users.get(i.owner_id, "") if i and i.owner_id else (i.responsible_party if i else "")
            linked_ev = [e.filename for e in evidence if c.control_id in (e.control_ids or [])]
            open_f = findings_by_control.get(c.control_id, 0)
            h.append(
                f"<h3>{_esc(c.control_id)} — {_esc(c.title)} "
                f"<span class='status' style='color:{STATUS_COLOR.get(status, '#333')}'>"
                f"[{STATUS_LABEL.get(status, status)}]</span></h3>"
                f"<table>"
                f"<tr><th style='width:210px'>Compliance Assessment Approach</th>"
                f"<td class='small'>{_esc(c.description)}</td></tr>"
                f"<tr><th>Registered Entity Response</th>"
                f"<td class='narr'>{_esc(i.narrative if i and i.narrative else 'No implementation narrative recorded.')}"
                + (f"<div class='small'>Responsible: {_esc(owner)} · Assessed {_esc(i.assessed_date)}</div>"
                   if i and (owner or i.assessed_date) else "")
                + "</td></tr>"
                f"<tr><th>Evidence Provided</th>"
                f"<td class='small'>{_esc(', '.join(linked_ev)) if linked_ev else 'None linked'}</td></tr>"
                f"<tr><th>Open Findings</th>"
                f"<td class='small'>{open_f if open_f else 'None'}</td></tr>"
                f"</table>"
            )
    else:
        h.append(f"<h2>2. Control Implementation ({len(controls)} controls)</h2>")
        h.append("<table><tr><th style='width:90px'>Control</th><th>Title</th><th style='width:120px'>Status</th>"
                 "<th style='width:110px'>Owner</th><th style='width:80px'>Assessed</th><th>Open findings / evidence</th></tr>")
        for c in controls:
            i = impls.get(c.control_id)
            status = i.implementation_status if i else "NOT_ASSESSED"
            owner = users.get(i.owner_id, "") if i and i.owner_id else (i.responsible_party if i else "")
            linked_ev = [e.filename for e in evidence if c.control_id in (e.control_ids or [])]
            extra = []
            if findings_by_control.get(c.control_id):
                extra.append(f"{findings_by_control[c.control_id]} open finding(s)")
            if linked_ev:
                extra.append("evidence: " + ", ".join(linked_ev[:4]) + ("…" if len(linked_ev) > 4 else ""))
            h.append(
                f"<tr><td><b>{_esc(c.control_id)}</b></td><td>{_esc(c.title)}"
                + (f"<div class='narr'>{_esc(i.narrative)}</div>" if i and i.narrative else "")
                + f"</td><td><span class='status' style='color:{STATUS_COLOR.get(status, '#333')}'>"
                f"{STATUS_LABEL.get(status, status)}</span></td>"
                f"<td>{_esc(owner)}</td><td>{_esc(i.assessed_date if i else None)}</td>"
                f"<td class='small'>{_esc('; '.join(extra)) if extra else '—'}</td></tr>"
            )
        h.append("</table>")

    # ---- Findings / POA&M ----
    h.append(f"<h2>3. Findings &amp; Remediation (POA&amp;M) — {len(findings)} total</h2>")
    if findings:
        for f in findings:
            overdue = f.due_date and f.due_date < today and f.status in ("OPEN", "IN_PROGRESS", "DELAYED")
            h.append(
                f"<h3>{_esc(f.title)} <span class='small'>[{_esc(f.severity)} · {_esc(f.status)}"
                + (" · OVERDUE" if overdue else "") + "]</span></h3>"
                f"<p class='small'>Control {_esc(f.control_id)} · due {_esc(f.due_date)} · owner {_esc(f.owner_name)}</p>"
            )
            if f.remediation_plan:
                h.append(f"<p class='narr'>{_esc(f.remediation_plan)}</p>")
            milestones = f.milestones or []
            if milestones:
                h.append("<ul class='small'>")
                for m in milestones:
                    cls = " class='milestone-done'" if m.get("complete") else ""
                    h.append(f"<li{cls}>{_esc(m.get('title'))} — due {_esc(m.get('due'))}"
                             f"{' ✓' if m.get('complete') else ''}</li>")
                h.append("</ul>")
    else:
        h.append("<p class='small'>No findings recorded for this framework on this system.</p>")

    # ---- Evidence inventory ----
    h.append(f"<h2>4. Evidence Inventory ({len(evidence)} artifacts)</h2>")
    archived: list[tuple[str, Path]] = []
    if evidence:
        h.append("<table><tr><th>File</th><th>Type</th><th>Collected</th><th>Expires</th>"
                 "<th>Controls</th><th>Archived</th></tr>")
        used_names: set[str] = set()
        for e in evidence:
            fresh = "—"
            if e.expiration_date:
                fresh = "EXPIRED" if e.expiration_date < today else str(e.expiration_date)
            on_disk = resolve_evidence_path(e.file_path)
            zip_name = ""
            tampered = bool(on_disk and on_disk.is_file() and e.file_hash
                            and _sha256_file(on_disk) != e.file_hash)
            if tampered:
                # Same rule as the evidence download: bytes that no longer match
                # the SHA-256 recorded at upload are never handed out as the
                # evidence (R2SEC-14). The inventory row says why.
                pass
            elif on_disk and on_disk.is_file():
                zip_name = _safe_name(e.filename)
                n = 1
                while zip_name in used_names:
                    n += 1
                    zip_name = f"{n}_{_safe_name(e.filename)}"
                used_names.add(zip_name)
                archived.append((zip_name, on_disk))
            h.append(
                f"<tr><td>{_esc(e.filename)}<div class='narr'>{_esc(e.description)}</div></td>"
                f"<td>{_esc(e.artifact_type)}</td><td>{_esc(e.date_collected)}</td>"
                f"<td>{'<b style=color:#b91c1c>EXPIRED</b>' if fresh == 'EXPIRED' else _esc(fresh)}</td>"
                f"<td class='small'>{_esc(', '.join(e.control_ids or []))}</td>"
                f"<td class='small'>{_archived_cell(zip_name, tampered)}</td></tr>"
            )
        h.append("</table>")
    else:
        h.append("<p class='small'>No evidence linked to this framework on this system.</p>")

    h.append(f"<p class='small' style='margin-top:40px'>Generated by Athorize · {now} · "
             f"This binder reflects the compliance system of record at generation time.</p></body></html>")

    # ---- Zip it ----
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("binder.html", "".join(h))
        for zip_name, path in archived:
            try:
                z.write(path, f"evidence/{zip_name}")
            except OSError:
                pass  # listed as archived but unreadable — the inventory row stands
    return buf.getvalue()
