"""Make the repo root (for `protocol`) and agent/ (flat imports) importable."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT, ROOT / "agent"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))