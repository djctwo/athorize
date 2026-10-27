#!/usr/bin/env python3
"""
Load the Athorize demo data from the command line.

The demo itself lives in the backend (backend/services/demo_seed.py), so every
distribution can load it — this script is a thin wrapper. Most people never
need it: choose "Explore with demo data" on the Setup screen instead.

Only an EMPTY instance is seeded. A demo database from an older build that has
only Acme gets the extra demo companies added; a database holding any company
that is not demo data is refused (demo data is never mixed into real data).

Usage (with the same DATA_DIR etc. the server uses):
    cd backend && python ../scripts/seed_demo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from database import engine, Base, SessionLocal  # noqa: E402
from models import Organization  # noqa: E402
from services import demo_seed  # noqa: E402
from services.demo_marker import DEMO_KEY  # noqa: E402

Base.metadata.create_all(bind=engine)
db = SessionLocal()


def seed() -> bool:
    """Seed (or top up an older demo). Returns False when refused."""
    orgs = db.query(Organization).all()
    if demo_seed.instance_is_empty(db):
        try:
            demo_seed.seed_demo(db)
            db.commit()
        except BaseException:
            db.rollback()
            demo_seed.discard_demo_files()
            raise
        return True
    if orgs and all((o.settings or {}).get(DEMO_KEY) for o in orgs):
        print("Demo data already loaded — adding any missing demo companies.")
        demo_seed.seed_extra_companies(db)
        db.commit()
        return True
    print("REFUSING: this instance already holds data that is not demo data. Demo data is only "
          "loaded into an empty instance.", file=sys.stderr)
    return False


if __name__ == "__main__":
    ok = seed()
    db.close()
    sys.exit(0 if ok else 1)
