from __future__ import annotations

from typing import Literal

Role = Literal["admin", "compliance_manager", "assessor", "system_owner", "evidence_contributor", "auditor"]
Action = Literal[
    "read:any",
    "edit:finding",
    "upload:evidence",
    "edit:conmon",
    "edit:risk",
    "edit:system",
    "assess:control",
    "approve:finding_close",
    "work:own_finding",
    "manage:users",
    "post:comment",
]

MATRIX: dict[Action, set[Role]] = {
    "read:any":              {"admin", "compliance_manager", "assessor", "system_owner", "evidence_contributor", "auditor"},
    "edit:finding":          {"admin", "compliance_manager"},
    "upload:evidence":       {"admin", "compliance_manager", "evidence_contributor"},
    "edit:conmon":           {"admin", "compliance_manager"},
    "edit:risk":             {"admin", "compliance_manager"},
    "edit:system":           {"admin", "compliance_manager"},
    "assess:control":        {"admin", "assessor"},
    "approve:finding_close": {"admin", "compliance_manager"},
    # The assigned owner of a finding may work it — move it between Open, In
    # Progress and Delayed and manage its milestones — even without
    # edit:finding (R2USER-12). Closing/accepting still needs the approver
    # roles; everything else still needs edit:finding. Not the read-only role.
    "work:own_finding":      {"admin", "compliance_manager", "assessor", "system_owner", "evidence_contributor"},
    "manage:users":          {"admin"},
    # Comments are discussion, not compliance data, but they notify people by
    # email. Auditors (the read-only role, and the default for SSO
    # auto-provisioned accounts) read threads; they don't post (SECCODE-17).
    "post:comment":          {"admin", "compliance_manager", "assessor", "system_owner", "evidence_contributor"},
}

WRITE_ROLES: set[Role] = {"admin", "compliance_manager"}


def can(role: str, action: Action) -> bool:
    return role in MATRIX.get(action, set())
