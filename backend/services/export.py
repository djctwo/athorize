from typing import Iterable


def conmon_to_text(entries: Iterable[dict]) -> str:
    grouped: dict[str, list[dict]] = {}
    for e in entries:
        grouped.setdefault(e.get("activity_type", "OTHER"), []).append(e)
    out: list[str] = []
    for activity_type, rows in grouped.items():
        out.append(f"# {activity_type}")
        for r in rows:
            out.append(f"- {r.get('entry_date')}: {r.get('description', '')}")
        out.append("")
    return "\n".join(out)


def findings_to_text(findings: Iterable[dict]) -> str:
    out: list[str] = []
    for f in findings:
        out.append(f"## {f.get('title', 'Untitled')}")
        out.append(f"Framework: {f.get('framework_id', '?')} | Control: {f.get('control_id', '?')}")
        out.append(f"Severity: {f.get('severity', '?')} | Status: {f.get('status', '?')}")
        if f.get("description"):
            out.append(f.get("description", ""))
        out.append("")
    return "\n".join(out)
