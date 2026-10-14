"""2026-10-12: the Grok GUI tests (tests/gui/test_task_queue_panel_grok.py) had
no key-path isolation and wrote TEST values into the REAL key files. Remove a
key file ONLY when its content is exactly a known test placeholder, so the
install reads "no key saved" instead of a fake key. Never prints a key."""
from pathlib import Path

HOME = Path.home() / ".ai-prowler"
PLACEHOLDERS = {"anthropic-key", "grok-key", "grok-secret", "xai-test-key", "xai-k", "legacy-key",
                "xai-test-key-123"}
for name in ("claude_api_key.txt", "grok_api_key.txt"):
    p = HOME / name
    if not p.exists():
        print(f"{name}: not present")
        continue
    v = p.read_text(encoding="utf-8", errors="replace").strip()
    if v in PLACEHOLDERS:
        p.unlink()
        print(f"{name}: removed (held a test placeholder)")
    else:
        print(f"{name}: kept (not a test placeholder)")
