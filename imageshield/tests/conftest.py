import os
import sys
import tempfile
from pathlib import Path

# must be set BEFORE the app package is imported (config reads env at import time)
os.environ["IMAGESHIELD_DATA"] = tempfile.mkdtemp(prefix="imageshield_test_")
os.environ["IMAGESHIELD_API_KEYS"] = "test-key"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from app import db  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init():
    db.init_db()
