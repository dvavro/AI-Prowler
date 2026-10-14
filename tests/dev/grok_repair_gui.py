"""2026-10-12: indentation repairs after the Grok edits (write only if it compiles):
  rag_gui.py — the Task Queue intro labels ("Runs your queued analysis tasks
    ... Grok API", the Claude/Grok note, the Claude Pro note) are indented 4
    spaces instead of 8, so the GUI doesn't start
  tests/mcp_tests/test_how_to_use_ai_prowler.py — one assert indented 2 too far
ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fix(rel, edit):
    p = ROOT / rel
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.replace("\r\n", "\n").split("\n")
    n = edit(lines)
    s = "\n".join(lines)
    try:
        compile(s, str(p), "exec")
    except SyntaxError as e:
        print(f"{rel}: STILL BROKEN at {e.lineno}: {e.msg} (nothing written)")
        for k in range(max(1, e.lineno - 4), min(len(lines), e.lineno + 2) + 1):
            print(f"  {k:6}: {lines[k - 1][:140]}".encode("ascii", "backslashreplace").decode("ascii"))
        return
    p.write_bytes(s.replace("\n", nl).encode("utf-8"))
    print(f"{rel}: {n} line(s) re-indented — compiles")


def gui(lines):
    a = next(i for i, l in enumerate(lines)
             if "Runs your queued analysis tasks on a schedule via Claude Code or the Grok API" in l) - 1
    assert lines[a].startswith("    tk.Label(_tqa_inner,") and not lines[a].startswith("        "), lines[a]
    b = next(i for i in range(a, len(lines)) if lines[i].startswith("        if not _tqa_available:"))
    n = 0
    for i in range(a, b):
        if lines[i].strip():
            lines[i] = "    " + lines[i]
            n += 1
    return n


def test(lines):
    i = next(i for i, l in enumerate(lines)
             if l.startswith('          assert "Vicki Vavro" in vicki_result'))
    lines[i] = lines[i][2:]
    return 1


fix("rag_gui.py", gui)
fix("tests/mcp_tests/test_how_to_use_ai_prowler.py", test)
