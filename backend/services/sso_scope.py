"""Which company SSO may link and provision accounts in (R2SEC-3/-9).

An SSO identity is bound to one account by the IdP's stable (issuer, sub)
pair. Binding a NEW identity uses the email address, which every company's
admin can type freely — so it only ever happens inside ONE company:

- single-company install: that company;
- more than one company: the company named by OIDC_PROVISION_ORG_SLUG. Without
  it (or if the slug names no company) email linking and JIT provisioning are
  off; identities already bound keep signing in.

Accounts of every other company are ignored by email linking entirely, so no
tenant can block (a deactivated or duplicate address) or capture (the same
address) another tenant's SSO users.
"""
from sqlalchemy.orm import Session

from config import settings
from models.organization import Organization


def sso_link_company(db: Session) -> Organization | None:
    if settings.oidc_provision_org_slug:
        return db.query(Organization).filter(Organization.slug == settings.oidc_provision_org_slug).first()
    orgs = db.query(Organization).limit(2).all()
    return orgs[0] if len(orgs) == 1 else None


def sso_scope_warning(db: Session) -> str | None:
    """Startup warning when SSO is on but new identities cannot be linked."""
    from services import oidc as oidc_svc
    if not oidc_svc.is_enabled() or sso_link_company(db) is not None:
        return None
    if settings.oidc_provision_org_slug:
        return (f"WARNING: OIDC_PROVISION_ORG_SLUG={settings.oidc_provision_org_slug!r} names no company; "
                "SSO will not link or create accounts (already-linked users still sign in).")
    if db.query(Organization.id).first() is None:
        return None  # first-run setup has not created a company yet
    return ("WARNING: SSO is enabled on a multi-company install without OIDC_PROVISION_ORG_SLUG; SSO will "
            "not link or create accounts by email (already-linked users still sign in). Set "
            "OIDC_PROVISION_ORG_SLUG to the company your identity provider belongs to.")
