"""Migration importers — get a customer's EXISTING compliance data in fast.

Two shapes cover most of the switching market:
  - POA&M spreadsheets  → Findings (title, severity, status, dates, owner,
    milestones) — the universal remediation-tracking format.
  - SSP / implementation workbooks → ControlImplementations (control id,
    status, narrative, responsible party).

CSV only (Excel users: File → Save As → CSV) — no new dependencies, works
offline. Header matching is forgiving: case/space/punctuation-insensitive with
common synonyms, so real-world exports import without manual renaming.
Both importers preview first and never clobber human-entered data.
"""
from __future__ import annotations

from datetime import date, datetime

from services.import_common import csv_table, decode_text

# ---------------------------------------------------------------------------
# Header + value normalization

def _norm(s: str) -> str:
    return "".join(ch for ch in (s or "").lower() if ch.isalnum())


# canonical field -> accepted header spellings (normalized)
POAM_HEADERS = {
    # The POA&M's own item identifier (FedRAMP "POAM ID", eMASS "POA&M Item ID").
    # A bare "ID" column is deliberately NOT accepted: in generic sheets it is
    # often a row number, which would collide across different files.
    "poam_id": ["poamid", "poamitemid", "poamitemidentifier", "poamidentifier", "poamnumber", "poamno"],
    "title": ["title", "weakness", "weaknessname", "poamtitle", "finding", "findingtitle",
              "vulnerability", "deficiency", "issue", "controlvulnerabilitydescription"],
    # Order matters: when several columns map to one field, the earliest
    # synonym wins and later ones fill rows where it is blank (FedRAMP:
    # Adjusted Risk Rating, else Original Risk Rating).
    "description": ["description", "weaknessdescription", "details", "findingdescription"],
    "severity": ["severity", "adjustedriskrating", "risk", "risklevel", "rawseverity", "rawseverityvalue",
                 "originalriskrating", "criticality", "priority"],
    "status": ["status", "poamstatus", "state", "milestonestatus"],
    "control_id": ["control", "controls", "controlid", "securitycontrol", "controlnumber", "cci",
                   "securitycontrolnumber", "securitycontrolnumberncnacontrolsonly", "affectedcontrol"],
    "due_date": ["duedate", "scheduledcompletiondate", "scheduledcompletion", "plannedcompletion",
                 "plannedcompletiondate", "targetdate", "completiondate", "milestonedate"],
    "owner_name": ["owner", "poc", "pointofcontact", "assignedto", "responsibleparty", "ownername"],
    "owner_email": ["owneremail", "pocemail", "email", "contactemail"],
    "actual_completion": ["actualcompletion", "actualcompletiondate", "dateclosed", "closeddate",
                          "closuredate", "datecompleted"],
    "risk_rationale": ["riskrationale", "riskacceptancerationale", "riskacceptancejustification",
                       "deviationrationale", "acceptancerationale"],
    "remediation_plan": ["remediationplan", "overallremediationplan", "remediation", "mitigation", "mitigationplan",
                         "correctiveaction", "plannedmilestones", "milestones", "milestone"],
}

SSP_HEADERS = {
    "control_id": ["control", "controlid", "controlnumber", "securitycontrol", "id",
                   "controlacronym", "requirement", "requirementid"],
    "status": ["status", "implementationstatus", "implementation", "compliancestatus", "state"],
    "narrative": ["narrative", "implementationnarrative", "implementationdescription",
                  "description", "howimplemented", "implementationstatement", "comments"],
    "responsible_party": ["responsibleparty", "responsiblerole", "owner", "responsibleentity",
                          "implementedby"],
}

SEVERITY_MAP = {
    "critical": "CRITICAL", "veryhigh": "CRITICAL", "cati": "CRITICAL",
    "high": "HIGH", "catii": "HIGH", "1": "HIGH",
    "moderate": "MEDIUM", "medium": "MEDIUM", "catiii": "MEDIUM", "2": "MEDIUM",
    "low": "LOW", "verylow": "LOW", "informational": "LOW", "info": "LOW", "3": "LOW",
    # eMASS "Raw Severity" uses the DISA category numerals.
    "i": "CRITICAL", "ii": "HIGH", "iii": "MEDIUM",
}

FINDING_STATUS_MAP = {
    "open": "OPEN", "ongoing": "IN_PROGRESS", "inprogress": "IN_PROGRESS",
    "delayed": "DELAYED", "pending": "OPEN", "notstarted": "OPEN",
    "completed": "CLOSED", "complete": "CLOSED", "closed": "CLOSED", "done": "CLOSED",
    "riskaccepted": "RISK_ACCEPTED", "accepted": "RISK_ACCEPTED",
    "falsepositive": "FALSE_POSITIVE",
}

# Recognised statuses that have no exact Athorize equivalent: the row is
# mapped to the closest status AND the mapping is reported once per value, so a
# POA&M full of eMASS "Not Applicable"/"Archived" items can never silently
# inflate the open / overdue numbers (R2DATA-1).
_LOSSY_STATUS_RULES: tuple[tuple[str, str], ...] = (
    # (normalized prefix, status) — first match wins; checked after the exact map.
    ("notapplicable", "FALSE_POSITIVE"),     # eMASS item status
    ("na", "FALSE_POSITIVE"),
    ("archived", "CLOSED"),                  # eMASS item status
    ("cancel", "CLOSED"),
    ("closed", "CLOSED"),                    # "Closed - Verified", "Closed (validated)"
    ("riskaccepted", "RISK_ACCEPTED"),
    ("falsepositive", "FALSE_POSITIVE"),
    ("ongoing", "IN_PROGRESS"),
    ("inprogress", "IN_PROGRESS"),
)

_STATUS_LABEL = {"OPEN": "Open", "IN_PROGRESS": "In Progress", "DELAYED": "Delayed", "CLOSED": "Closed",
                 "RISK_ACCEPTED": "Risk Accepted", "FALSE_POSITIVE": "False Positive"}


def map_finding_status(raw: str) -> tuple[str, bool]:
    """POA&M status cell -> (Athorize status, recognised). Unrecognised
    non-empty values come back as ("OPEN", False) so the caller reports them."""
    n = _norm(raw)
    if not n:
        return "OPEN", True
    if n in FINDING_STATUS_MAP:
        return FINDING_STATUS_MAP[n], True
    if n.startswith(("completed", "complete")):
        # "Completed - Pending Verification/Validation" is not closed yet: the
        # fix still has to be verified, so it stays open (in progress).
        if "pending" in n or "awaiting" in n:
            return "IN_PROGRESS", True
        return "CLOSED", True
    for prefix, status in _LOSSY_STATUS_RULES:
        if n == prefix or (len(prefix) > 2 and n.startswith(prefix)):
            return status, True
    return "OPEN", False

IMPL_STATUS_MAP = {
    "implemented": "IMPLEMENTED", "inplace": "IMPLEMENTED", "compliant": "IMPLEMENTED",
    "satisfied": "IMPLEMENTED", "yes": "IMPLEMENTED", "complete": "IMPLEMENTED",
    "partiallyimplemented": "PARTIALLY", "partial": "PARTIALLY", "partially": "PARTIALLY",
    "partiallyinplace": "PARTIALLY",
    "notimplemented": "NOT_IMPLEMENTED", "notinplace": "NOT_IMPLEMENTED",
    "noncompliant": "NOT_IMPLEMENTED", "no": "NOT_IMPLEMENTED", "failed": "NOT_IMPLEMENTED",
    "planned": "PLANNED", "plannedtobeimplemented": "PLANNED",
    "notapplicable": "NOT_APPLICABLE", "na": "NOT_APPLICABLE",
    "inherited": "INHERITED", "commoncontrol": "INHERITED",
    "notassessed": "NOT_ASSESSED", "notreviewed": "NOT_ASSESSED",
}

_DATE_FORMATS = ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%d-%b-%Y", "%d %b %Y", "%B %d, %Y", "%Y/%m/%d")


def _parse_date(raw: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def _columns(header: list[str], spec: dict[str, list[str]]) -> dict[str, list[int]]:
    """canonical field -> column indexes, best synonym first (ties: leftmost)."""
    ranked: dict[str, list[tuple[int, int]]] = {}
    for pos, actual in enumerate(header):
        n = _norm(actual)
        for canonical, synonyms in spec.items():
            if n in synonyms:
                ranked.setdefault(canonical, []).append((synonyms.index(n), pos))
                break
    return {c: [pos for _, pos in sorted(v)] for c, v in ranked.items()}


def _mapped_columns(header: list[str], cols: dict[str, list[int]]) -> dict[str, str]:
    return {header[pos]: canonical for canonical, idxs in cols.items() for pos in idxs}


# Cells that mean "no value": FedRAMP's Adjusted Risk Rating is "N/A" when no
# adjustment was made, and that must not beat the Original Risk Rating in the
# next column (R2DATA-2). Only applied to fields where N/A can't be a value.
_BLANK_VALUES = frozenset({"na", "none", "tbd", ""})
_BLANKABLE_FIELDS = frozenset({"severity"})


def _is_blank(canonical: str, v: str) -> bool:
    if not v:
        return True
    if canonical in _BLANKABLE_FIELDS:
        return v.strip() in ("-", "--") or _norm(v) in _BLANK_VALUES
    return False


def _canon(cells: list[str], cols: dict[str, list[int]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for canonical, idxs in cols.items():
        for pos in idxs:
            v = cells[pos].strip() if pos < len(cells) else ""
            if not _is_blank(canonical, v):
                out[canonical] = v
                break
    return out


_HEADER_SCAN_ROWS = 30


def _read_table(raw: bytes, spec: dict[str, list[str]], key_field: str):
    """Decode + parse the CSV and locate the header row: templates (FedRAMP
    POA&M, agency SSP workbooks) often carry title rows above it. Returns
    (header, cols, [(record_number, cells), ...], notes). Raises ImportFileError."""
    notes: list[str] = []
    table = csv_table(decode_text(raw, notes))
    header_idx = next((i for i, r in enumerate(table[:_HEADER_SCAN_ROWS]) if key_field in _columns(r, spec)), None)
    if header_idx is None:
        header_idx = next((i for i, r in enumerate(table) if any(c.strip() for c in r)), 0)
    header = table[header_idx] if table else []
    rows = [(header_idx + 2 + j, cells) for j, cells in enumerate(table[header_idx + 1:])
            if any(c.strip() for c in cells)]
    return header, _columns(header, spec), rows, notes


# ---------------------------------------------------------------------------
# POA&M → findings

def poam_identity(poam_id: str, title: str) -> tuple[str, str]:
    """Dedup identity of a POA&M item — used in-file AND on re-import: the
    POA&M ID when the row has one (case/whitespace-insensitive), else the title.
    Real FedRAMP/eMASS POA&Ms repeat a weakness title once per asset with
    distinct IDs; those must stay separate findings."""
    pid = " ".join((poam_id or "").split()).casefold()
    if pid:
        return ("id", pid)
    return ("title", (title or "")[:300].casefold())


def parse_poam(raw: bytes) -> dict:
    header, cols, rows, notes = _read_table(raw, POAM_HEADERS, "title")
    header_map = _mapped_columns(header, cols)
    if "title" not in cols:
        return {"rows": [], "merged": 0, "issues": [
            "No title/weakness column recognized. Expected one of: "
            "Title, Weakness, Weakness Name, Finding, Vulnerability, Deficiency."
        ], "mapped_columns": header_map}

    parsed: list[dict] = []
    issues: list[str] = list(notes)
    if "severity" not in cols:
        issues.append("No severity / risk rating column recognized — every item is imported as Medium.")
    if "control_id" not in cols:
        issues.append("No control column recognized — findings are imported without a control id.")
    first_row_for: dict[str, int] = {}
    mapped_statuses: dict[str, list] = {}
    closed_without_date = 0
    merged = 0
    for idx, cells in rows:
        canon = _canon(cells, cols)
        title = canon.get("title", "")
        if not title:
            issues.append(f"Row {idx}: empty title — skipped")
            continue
        poam_id = canon.get("poam_id", "")[:100]
        key = poam_identity(poam_id, title)
        if key in first_row_for:
            # Same identity as an earlier row (same rule a re-import uses): keep the first.
            what = "POA&M ID" if key[0] == "id" else "title"
            merged += 1
            issues.append(f"Row {idx}: same {what} as row {first_row_for[key]} — merged into that finding")
            continue
        first_row_for[key] = idx
        sev_raw = canon.get("severity", "")
        severity = SEVERITY_MAP.get(_norm(sev_raw))
        if severity is None:
            severity = "MEDIUM"
            if sev_raw:
                issues.append(f"Row {idx}: unrecognized severity '{sev_raw[:40]}' — imported as Medium")
        status_raw = canon.get("status", "")
        status, recognised = map_finding_status(status_raw)
        if not recognised:
            issues.append(f"Row {idx}: unrecognized status '{status_raw[:40]}' — imported as Open")
        elif status_raw and _norm(status_raw) not in FINDING_STATUS_MAP:
            mapped_statuses.setdefault(status_raw.strip()[:40], [status, 0])[1] += 1
        due = _parse_date(canon.get("due_date", ""))
        if canon.get("due_date") and due is None:
            issues.append(f"Row {idx}: unrecognized date '{canon['due_date']}' — imported without a due date")
        # The rules every other path enforces for terminal statuses (R2DATA-11):
        # Closed needs a completion date, Risk Accepted needs a rationale.
        completed = _parse_date(canon.get("actual_completion", "")) if status == "CLOSED" else None
        if status == "CLOSED" and completed is None:
            completed = date.today()
            closed_without_date += 1
        rationale = canon.get("risk_rationale", "") if status == "RISK_ACCEPTED" else ""
        if status == "RISK_ACCEPTED" and not rationale:
            status = "OPEN"
            issues.append(f"Row {idx}: Risk Accepted without a risk rationale column/value — imported as Open "
                          "(accept it in Athorize with the rationale)")
        milestones = []
        if canon.get("remediation_plan"):
            milestones = [{"title": canon["remediation_plan"][:200],
                           "due": due.isoformat() if due else "", "complete": status == "CLOSED"}]
        parsed.append({
            "poam_id": poam_id,
            "title": title[:300],
            "description": canon.get("description", ""),
            "severity": severity,
            "status": status,
            "control_id": canon.get("control_id", "")[:40],
            "due_date": due.isoformat() if due else None,
            "owner_name": canon.get("owner_name", "")[:120],
            "owner_email": canon.get("owner_email", "")[:120],
            "remediation_plan": canon.get("remediation_plan", ""),
            "milestones": milestones,
            "actual_completion": completed.isoformat() if completed else None,
            "risk_rationale": rationale,
        })
    if closed_without_date:
        issues.append(f"{closed_without_date} closed item(s) have no completion date — recorded as completed "
                      f"on {date.today().isoformat()} (the import date)")
    for raw_status, (status, n) in mapped_statuses.items():
        issues.append(f"Status '{raw_status}' ({n} row{'s' if n != 1 else ''}) imported as {_STATUS_LABEL[status]}")
    return {"rows": parsed, "merged": merged, "issues": issues, "mapped_columns": header_map}


# ---------------------------------------------------------------------------
# SSP / implementation workbook → control implementations

def parse_ssp(raw: bytes) -> dict:
    header, cols, rows, notes = _read_table(raw, SSP_HEADERS, "control_id")
    header_map = _mapped_columns(header, cols)
    if "control_id" not in cols:
        return {"rows": [], "issues": [
            "No control-id column recognized. Expected one of: Control, Control ID, Requirement."
        ], "mapped_columns": header_map}

    parsed: list[dict] = []
    issues: list[str] = list(notes)
    seen: set[str] = set()
    for idx, cells in rows:
        canon = _canon(cells, cols)
        cid = canon.get("control_id", "").strip()
        if not cid:
            issues.append(f"Row {idx}: empty control id — skipped")
            continue
        if cid in seen:
            issues.append(f"Row {idx}: duplicate control id {cid} — first occurrence wins")
            continue
        seen.add(cid)
        status_raw = canon.get("status", "")
        status = IMPL_STATUS_MAP.get(_norm(status_raw))
        if status is None:
            status = "NOT_ASSESSED"
            if status_raw:
                issues.append(f"Row {idx}: unrecognized status '{status_raw}' — imported as Not Assessed")
        parsed.append({
            "control_id": cid[:40],
            "status": status,
            "narrative": canon.get("narrative", ""),
            "responsible_party": canon.get("responsible_party", "")[:120],
        })
    return {"rows": parsed, "issues": issues, "mapped_columns": header_map}
