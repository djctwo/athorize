"""FIXW2DATA-1: every demo evidence record has a real (placeholder) file, so
downloads work on a demo instance and its backups/restores don't report the
demo records as missing files."""
import hashlib
import importlib.util

from main import bundle_root
from models import EvidenceArtifact
from services.evidence_store import resolve_evidence_path


def test_demo_seed_writes_a_file_for_every_evidence_record(db):
    spec = importlib.util.spec_from_file_location("seed_demo_test", bundle_root() / "scripts" / "seed_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.seed()
    finally:
        mod.db.close()
    rows = db.query(EvidenceArtifact).all()
    assert len(rows) >= 5
    for ev in rows:
        path = resolve_evidence_path(ev.file_path)
        assert path is not None and path.is_file(), ev.file_path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == ev.file_hash
    pdf = next(ev for ev in rows if ev.file_path.endswith(".pdf"))
    assert resolve_evidence_path(pdf.file_path).read_bytes().startswith(b"%PDF-1.4")
