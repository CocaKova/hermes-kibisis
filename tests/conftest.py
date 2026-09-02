import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
for entry in (str(ROOT), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)
