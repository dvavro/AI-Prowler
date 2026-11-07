"""Print a short hash of every Estimator source file (to check the PC copy matches the tested copy)."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
files = []
for base in ("estimator", "tests/estimator"):
    for p in (ROOT / base).rglob("*"):
        if p.is_file() and "__pycache__" not in p.parts and (p.suffix in (".py", ".yaml", ".csv")
                                                             or (p.suffix == ".md" and base == "estimator")):
            files.append(p)
for p in sorted(files, key=lambda x: x.relative_to(ROOT).as_posix()):
    data = p.read_bytes().replace(b"\r\n", b"\n")
    print(hashlib.sha256(data).hexdigest()[:12], p.relative_to(ROOT).as_posix())
