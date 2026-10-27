from datetime import date
from typing import Optional

EXPIRING_SOON_WINDOW_DAYS = 60


def freshness_status(expiration_date: Optional[date]) -> str:
    if expiration_date is None:
        return "NO_EXPIRATION"
    today = date.today()
    if expiration_date < today:
        return "EXPIRED"
    if (expiration_date - today).days <= EXPIRING_SOON_WINDOW_DAYS:
        return "EXPIRING_SOON"
    return "FRESH"
