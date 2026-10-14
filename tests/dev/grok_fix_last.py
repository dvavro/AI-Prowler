"""2026-10-12: last 5 Grok regression failures.
  rag_gui.py — key save/load/check/clear passed the auth MODE ('oauth' when
    Subscription is selected) to the API-key functions, which only accept
    anthropic/grok -> "Unknown API key provider: 'oauth'" on Clear Key. New
    helper _tqa_key_provider(): 'grok' if Grok is selected, else 'anthropic'.
  tests/analysis/test_task_queue_grok.py — claude.EXE may be upper-case;
    the queue prompts never mention pending_tasks.json (check the tool name).
ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def rw(rel, fn):
    p = ROOT / rel
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = fn(raw.replace("\r\n", "\n"))
    compile(s, rel, "exec")
    p.write_bytes(s.replace("\n", nl).encode("utf-8"))


def gui(s):
    old = '''                return "oauth"

            _tqa_row3 = tk.Frame(_tqa_inner, bg='#1a1e2e')'''
    new = '''                return "oauth"

            def _tqa_key_provider():
                """Which saved API key the key row works on: 'grok' when Grok is
                selected, otherwise 'anthropic' (also while Subscription is
                selected — the key functions only know anthropic/grok)."""
                return "grok" if _tqa_selected_provider() == "grok" else "anthropic"

            _tqa_row3 = tk.Frame(_tqa_inner, bg='#1a1e2e')'''
    assert s.count(old) == 1
    s = s.replace(old, new)
    n = 0
    for fn in ("has_api_key", "delete_api_key", "load_api_key"):
        a = f"_tqa.{fn}(_tqa_selected_provider())"
        n += s.count(a)
        s = s.replace(a, f"_tqa.{fn}(_tqa_key_provider())")
    s2, m = re.subn(r"_tqa\.save_api_key\(([^,()]+),\s*_tqa_selected_provider\(\)\)",
                    r"_tqa.save_api_key(\1, _tqa_key_provider())", s)
    print(f"rag_gui.py: {n + m} key call(s) now use _tqa_key_provider()")
    return s2


def tests(s):
    s = s.replace('''assert re.search(r'claude(\\.exe)?"? -p', content), "the Claude CLI is invoked"''',
                  '''assert re.search(r'claude(\\.exe)?"? -p', content, re.I), "the Claude CLI is invoked"''')
    s = s.replace('''        assert "pending_tasks.json" in p''',
                  '''        assert "get_pending_analysis_tasks" in p   # the queue prompts never named the file''')
    return s


rw("rag_gui.py", gui)
rw("tests/analysis/test_task_queue_grok.py", tests)
print("done")
