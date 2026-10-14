"""Dev helper (2026-10-12): did a test overwrite the REAL API key files? Prints
only existence, size, modified time and whether the content is one of the
known TEST placeholder values — never the key itself."""
import time
from pathlib import Path

HOME = Path.home() / ".ai-prowler"
PLACEHOLDERS = {"anthropic-key", "grok-key", "grok-secret", "xai-test-key", "xai-k", "legacy-key",
                "anthropic-key\n", "xai-test-key-123"}
for name in ("claude_api_key.txt", "grok_api_key.txt"):
    p = HOME / name
    if not p.exists():
        print(f"{name}: (not present)")
        continue
    v = p.read_text(encoding="utf-8", errors="replace").strip()
    print(f"{name}: {len(v)} chars, modified {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.stat().st_mtime))}, "
          f"TEST PLACEHOLDER={'YES' if v in PLACEHOLDERS else 'no'}")
