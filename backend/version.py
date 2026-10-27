"""The Athorize release version — the single source of truth.

The API reports it (/api/health, OpenAPI), the UI's Settings → About reads it
from /api/health, and frontend/package.json is kept equal by a test
(tests/hunts/test_w2ux.py) so nothing else can drift.
"""
__version__ = "1.0.0"
