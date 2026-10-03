"""Make `bouncer` importable when pytest is started as `uv run pytest` (no package install)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
