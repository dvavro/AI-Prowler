"""Quick test: import startup_log and verify it writes correctly."""
import sys
sys.path.insert(0, r'C:\Users\david\AI-Prowler_V812_to_V900_work\AI-Prowler')

from pathlib import Path

# Clear any old log
log = Path.home() / '.ai-prowler' / 'startup.log'
if log.exists():
    log.unlink()

import startup_log as sl
sl.begin('9.0.0')
sl.step("test step 1 — module import")
sl.step("test step 2 — RAG import OK")
sl.warn("test warning — Defender exclusion missing")
sl.check_hf_cache()
sl.check_defender_exclusions(Path(r'C:\Program Files\AI-Prowler'))
sl.step("RAGGui initialized — entering mainloop ✅")

print(f"Log written to: {log}")
print(f"Contents:")
print(log.read_text(encoding='utf-8'))
