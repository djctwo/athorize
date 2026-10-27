from datetime import datetime, date
from pydantic import BaseModel, Field, field_validator


def _normalize_email(v):
    """Emails are matched case-insensitively (SSO, R2SEC-3): store them the
    way they are compared — trimmed and lower-cased."""
    return v.strip().lower() if isinstance(v, str) else v


class SetupRequest(BaseModel):
    org_name: str
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    email: str = ""
    display_name: str = ""
    setup_token: str = ""

    _email = field_validator("email", mode="before")(_normalize_email)


class DemoSetupRequest(BaseModel):
    setup_token: str = ""


class StartFreshRequest(BaseModel):
    password: str = Field(max_length=128)
    confirm: str = Field("", max_length=64)


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    display_name: str | None
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    organization_id: int
    # organization_name is not a User column — populated by /auth/me. Other
    # endpoints that return User ORM rows leave it None (default).
    organization_name: str | None = None
    # The ACTIVE company's logo data URI (settings['branding']), /auth/me only —
    # the sidebar and Settings read it from there (no extra polling fetch).
    organization_logo: str | None = None
    is_operator: bool = False
    # An SSO identity is bound to this account (Users page status; R2SEC-9).
    sso_linked: bool = False
    # /auth/me only: the instance holds demo-seeded data with public default
    # passwords → persistent in-app banner (DOCKER-4). Never on anonymous endpoints.
    demo_instance: bool = False
    # /auth/me only: this build re-seeds demo data into an empty database at
    # every start (ATHORIZE_DEMO_SEED=1 / DEMO_BUILD), so Settings offers
    # "Reset demo data" instead of "Start fresh" (services/start_fresh).
    demo_autoseed: bool = False

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    email: str = ""
    display_name: str = ""
    role: str = "evidence_contributor"

    _email = field_validator("email", mode="before")(_normalize_email)


class UserUpdate(BaseModel):
    email: str | None = None
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = None

    _email = field_validator("email", mode="before")(_normalize_email)


class SystemCreate(BaseModel):
    name: str
    acronym: str = ""
    description: str = ""
    system_type: str = ""
    environment: str = "production"
    criticality: str = "moderate"
    impact_level: str = "MODERATE"
    authorization_status: str = "NOT_AUTHORIZED"
    is_ot_enabled: bool = False
    owner_id: int | None = None
    extra_data: dict = {}


class FindingCreate(BaseModel):
    system_id: int
    framework_id: str
    control_id: str = ""
    title: str
    description: str = ""
    weakness_description: str = ""
    severity: str = "MEDIUM"
    owner_id: int | None = None
    owner_name: str = ""
    owner_email: str = ""
    due_date: date | None = None
    scheduled_completion: date | None = None
    remediation_plan: str = ""
    milestones: list[dict] = []
    extra_data: dict = {}


class FindingUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    weakness_description: str | None = None
    severity: str | None = None
    status: str | None = None
    control_id: str | None = None
    owner_id: int | None = None
    owner_name: str | None = None
    owner_email: str | None = None
    due_date: date | None = None
    scheduled_completion: date | None = None
    actual_completion: date | None = None
    closed_date: date | None = None
    remediation_plan: str | None = None
    risk_rationale: str | None = None
    reopen_reason: str | None = None
    milestones: list[dict] | None = None
    extra_data: dict | None = None
    # Optimistic concurrency (INTEGRITY-20): the finding's updated_at as the
    # editor last saw it. When sent and the row has changed since, the PATCH is
    # refused with 409 instead of silently overwriting someone else's edit.
    expected_updated_at: datetime | None = None


class EvidenceUpdate(BaseModel):
    description: str | None = None
    artifact_type: str | None = None
    control_ids: list[str] | None = None
    framework_ids: list[str] | None = None
    # Same bounds as upload (routers/evidence.MAX_EXPIRATION_DAYS): a huge value
    # overflowed date arithmetic into a 500.
    expiration_days: int | None = Field(None, ge=1, le=3650)
    # Or an explicit expiry date (R2USER-11); wins over expiration_days.
    expiration_date: date | None = None
    notes: str | None = None
    owner_id: int | None = None  # refresh-workflow assignee (org-validated in router)


class FrameworkActivateRequest(BaseModel):
    license_key: str = ""


class ControlImplementationUpsert(BaseModel):
    implementation_status: str
    narrative: str = ""
    inherited_from: str = ""
    responsible_party: str = ""
    assessed_date: date | None = None
    assessment_result: str = "NOT_ASSESSED"
    evidence_ids: list[int] = []
    owner_id: int | None = None  # assigned user (org-validated in router)
    # Optimistic concurrency (R2DATA-12): the updated_at the editor loaded. When
    # sent and the row has changed since, the save is refused with 409.
    expected_updated_at: datetime | None = None


class AssessmentCreate(BaseModel):
    system_id: int
    framework_id: str
    assessment_type: str
    assessor_id: int | None = None
    notes: str = ""


class AssessmentUpdate(BaseModel):
    status: str | None = None
    item_states: dict | None = None
    notes: str | None = None


class CalendarEventCreate(BaseModel):
    system_id: int | None = None
    framework_id: str = ""
    event_type: str = "CUSTOM"
    title: str
    description: str = ""
    event_date: date
    recurring: str | None = None


class CalendarEventUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    event_date: date | None = None
    event_type: str | None = None
    recurring: str | None = None


class ConMonCreate(BaseModel):
    system_id: int
    framework_id: str = ""
    entry_date: date
    activity_type: str
    description: str = ""
    performed_by: str = ""
    findings: str = ""
    actions_taken: str = ""
    follow_up_required: bool = False
    follow_up_date: date | None = None
    evidence_artifact_id: int | None = None

    # Optional free-text fields: a client that sends null for a blank field
    # means "empty", not "invalid" (E2E-4).
    @field_validator("framework_id", "description", "performed_by", "findings", "actions_taken", mode="before")
    @classmethod
    def _none_is_blank(cls, v):
        return "" if v is None else v


class ConMonUpdate(BaseModel):
    entry_date: date | None = None
    activity_type: str | None = None
    description: str | None = None
    performed_by: str | None = None
    findings: str | None = None
    actions_taken: str | None = None
    follow_up_required: bool | None = None
    follow_up_date: date | None = None
    evidence_artifact_id: int | None = None


class ITAssetCreate(BaseModel):
    system_id: int
    asset_name: str
    asset_role: str = ""
    vendor: str = ""
    model: str = ""
    os_family: str = ""
    os_version: str = ""
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    environment: str = ""
    criticality: str = ""
    data_classification: str = ""
    location: str = ""
    owner_name: str = ""
    cloud_provider: str = ""
    patch_status: str = ""
    patch_notes: str = ""
    last_patch_date: date | None = None
    stig_applicable: bool = False
    stig_id: str = ""
    stig_compliance_status: str = ""
    connected_to: list[str] = []
    tags: list[str] = []
    notes: str = ""


class ITAssetUpdate(BaseModel):
    asset_name: str | None = None
    asset_role: str | None = None
    vendor: str | None = None
    model: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    environment: str | None = None
    criticality: str | None = None
    data_classification: str | None = None
    location: str | None = None
    owner_name: str | None = None
    cloud_provider: str | None = None
    patch_status: str | None = None
    patch_notes: str | None = None
    last_patch_date: date | None = None
    stig_applicable: bool | None = None
    stig_id: str | None = None
    stig_compliance_status: str | None = None
    connected_to: list[str] | None = None
    tags: list[str] | None = None
    notes: str | None = None


class OTAssetCreate(BaseModel):
    system_id: int
    asset_name: str
    asset_type: str = ""
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    ip_address: str = ""
    mac_address: str = ""
    purdue_level: str = ""
    protocols: list[str] = []
    network_zone: str = ""
    patch_status: str = ""
    patch_notes: str = ""
    last_firmware_review: date | None = None
    stig_applicable: bool = False
    stig_id: str = ""
    stig_compliance_status: str = ""
    connected_to: list[str] = []
    notes: str = ""


class OTAssetUpdate(BaseModel):
    asset_name: str | None = None
    asset_type: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    purdue_level: str | None = None
    protocols: list[str] | None = None
    network_zone: str | None = None
    patch_status: str | None = None
    patch_notes: str | None = None
    last_firmware_review: date | None = None
    stig_applicable: bool | None = None
    stig_id: str | None = None
    stig_compliance_status: str | None = None
    connected_to: list[str] | None = None
    notes: str | None = None


class SystemUpdate(BaseModel):
    name: str | None = None
    acronym: str | None = None
    description: str | None = None
    system_type: str | None = None
    environment: str | None = None
    criticality: str | None = None
    impact_level: str | None = None
    authorization_status: str | None = None
    is_ot_enabled: bool | None = None
    owner_id: int | None = None
    extra_data: dict | None = None


class IcsAdvisoryPatch(BaseModel):
    status: str | None = None
    notes: str | None = None


class IcsSpawnSystem(BaseModel):
    system_id: int


class IcsSpawnConmon(BaseModel):
    system_id: int
    findings: str = ""


class RiskCreate(BaseModel):
    system_id: int
    title: str
    description: str = ""
    category: str = ""
    control_id: str = ""
    likelihood: str = ""
    impact: str = ""
    status: str = "OPEN"
    treatment: str = ""
    mitigation: str = ""
    residual_risk: str = ""
    owner_name: str = ""
    owner_email: str = ""
    review_date: date | None = None
    template_key: str = ""


class RiskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    control_id: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    status: str | None = None
    treatment: str | None = None
    mitigation: str | None = None
    residual_risk: str | None = None
    owner_name: str | None = None
    owner_email: str | None = None
    review_date: date | None = None
    template_key: str | None = None


class BulkImportPayload(BaseModel):
    rows: list[dict] = Field(max_length=5000)
    commit: bool = False
