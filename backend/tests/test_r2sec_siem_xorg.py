"""R2SEC: a company-A admin must not import SIEM findings into company B's system."""
import io
from main import app
from models import Finding
from tests.hunts.test_permission_sweep import build_world, _client, custom_dir, FW  # noqa: F401


def test_siem_confirm_refuses_other_company_system(client, db, custom_dir):
    w = build_world(db)
    c = _client()
    csv = "alert_name,severity,host\nR2 probe alert,high,h1\n"
    r = c.post("/api/siem/import/confirm", headers={"Authorization": f"Bearer {w['tokens']['admin']}"},
               data={"system_id": str(w["b"]["system_id"]), "framework_id": FW},
               files={"file": ("a.csv", io.BytesIO(csv.encode()), "text/csv")})
    db.expire_all()
    leaked = db.query(Finding).filter(Finding.system_id == w["b"]["system_id"],
                                      Finding.title.like("%R2 probe%")).count()
    assert not r.is_success and leaked == 0, (r.status_code, r.text[:200], leaked)
