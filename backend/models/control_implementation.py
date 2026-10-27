from datetime import datetime, date, timezone
from sqlalchemy import Column, Integer, String, Text, Date, JSON, ForeignKey, UniqueConstraint
from database import Base, UTCDateTime


class ControlImplementation(Base):
    __tablename__ = "control_implementations"
    __table_args__ = (
        UniqueConstraint("system_id", "framework_id", "control_id",
                         name="ux_control_impl_system_framework_control"),
    )

    id = Column(Integer, primary_key=True)
    system_id = Column(Integer, ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    framework_id = Column(String, nullable=False)
    control_id = Column(String, nullable=False)
    implementation_status = Column(String, default="NOT_ASSESSED")
    narrative = Column(Text)
    inherited_from = Column(String)
    responsible_party = Column(String)
    # Real user assignment (feeds "My Work"); responsible_party stays as the
    # free-text team/label for display and back-compat.
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assessed_date = Column(Date)
    assessment_result = Column(String, default="NOT_ASSESSED")
    evidence_ids = Column(JSON, default=list)
    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# R2USER-9: nothing ever wrote assessed_date, so the audit binder's "Assessed"
# column was always blank. Stamp it whenever the status actually changes (the
# editor, the row dropdown, bulk, baseline scoping, crosswalk, migration) unless
# the same write sets assessed_date explicitly. Back to NOT_ASSESSED clears it.
from sqlalchemy import event, inspect as _inspect  # noqa: E402


def _stamp_assessed_date(_mapper, _connection, target: ControlImplementation) -> None:
    state = _inspect(target)
    if any(v is not None for v in state.attrs.assessed_date.history.added):
        return  # an explicit date in the same write wins
    status_hist = state.attrs.implementation_status.history
    if not status_hist.added or status_hist.added[0] == (status_hist.deleted[0] if status_hist.deleted else None):
        return
    if target.implementation_status in (None, "NOT_ASSESSED"):
        target.assessed_date = None
    else:
        target.assessed_date = datetime.now(timezone.utc).date()


event.listen(ControlImplementation, "before_insert", _stamp_assessed_date)
event.listen(ControlImplementation, "before_update", _stamp_assessed_date)
