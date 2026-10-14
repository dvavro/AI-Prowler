"""Dev helper (2026-10-13): on THIS PC (personal) — the recorded Job Tracker /
SMS choices, what the in-use detection says, and why. Read-only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import tool_config_store as t  # noqa: E402

out = []
cfg = t.load_tool_config()
out.append(f"optional_groups recorded: {cfg.get('optional_groups')}")
out.append(f"jobs in use: {t._jobs_in_use()}")
try:
    from sms_backends import get_sms_backend, load_sms_config
    c = load_sms_config()
    out.append(f"sms config keys: {sorted((c or {}).keys())[:12]}")
    b = get_sms_backend(c)
    out.append(f"sms backend: {type(b).__name__} | validate_config: {b.validate_config()}")
except Exception as e:
    out.append(f"sms check error: {type(e).__name__} {e}")
res = Path(__file__).with_suffix(".out.txt")
res.write_text("\n".join(out), encoding="utf-8")
print("\n".join(out).encode("ascii", "backslashreplace").decode("ascii"), flush=True)
