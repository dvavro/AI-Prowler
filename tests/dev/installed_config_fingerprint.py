"""Prints a fingerprint of the installed ~/.ai-prowler files: SHA-256, size,
last-modified time and (for JSON) the KEY NAMES only — never the values, so
tokens/licenses aren't shown. Run before and after a test run to prove the
tests left them alone."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

base = Path(os.path.expanduser("~")) / ".ai-prowler"
for name in ("config.json", "users.json", "email_config.json", "remote_access.json",
             "license_seats.json"):
    p = base / name
    if not p.exists():
        print(f"{name:22} (not present)")
        continue
    data = p.read_bytes()
    mtime = dt.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    try:
        keys = sorted(json.loads(data.decode("utf-8-sig")).keys())
    except Exception:
        keys = ["(not a JSON object)"]
    print(f"{name:22} sha256={hashlib.sha256(data).hexdigest()[:16]} size={len(data)} "
          f"modified={mtime} keys={keys}")
