from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Index, text
from database import Base, UTCDateTime


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    username = Column(String, nullable=False, index=True)
    email = Column(String)
    password_hash = Column(String, nullable=False)
    display_name = Column(String)
    role = Column(String, nullable=False, default="evidence_contributor")
    # Operators are cross-company: they can list/create/switch organizations and
    # view any company's data from one install (consultant/MSP model). Regular
    # users stay locked to their single organization. Defaults False so every
    # existing/customer user is single-org.
    is_operator = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(UTCDateTime)
    # SSO identity this account is bound to: the IdP's stable (issuer, sub)
    # pair, set on the first SSO sign-in. Once bound, SSO signs in by this pair
    # only — never by email again (R2SEC-3/-9).
    oidc_issuer = Column(String)
    oidc_subject = Column(String)

    @property
    def sso_linked(self) -> bool:
        return bool(self.oidc_subject)

    __table_args__ = (
        Index("ux_users_oidc_identity", "oidc_issuer", "oidc_subject", unique=True,
              sqlite_where=text("oidc_subject IS NOT NULL"),
              postgresql_where=text("oidc_subject IS NOT NULL")),
    )
