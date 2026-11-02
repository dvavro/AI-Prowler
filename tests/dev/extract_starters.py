"""One-off (2026-11-01): move rag_gui's _ANALYSIS_TASKS literal into task_queue_gui.STARTERS."""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
src = (ROOT / "rag_gui.py").read_text(encoding="utf-8").splitlines()
start = next(i for i, l in enumerate(src) if l.strip() == "_ANALYSIS_TASKS = [")
end = next(i for i in range(start, len(src)) if src[i].rstrip() == "        ]")
literal = "\n".join(l[8:] if l.startswith("        ") else l for l in src[start:end + 1])
literal = literal.split("=", 1)[1].strip()
tasks = ast.literal_eval(literal)
for t in tasks:
    lines = [l for l in t["prompt"].splitlines() if "complete_analysis_task" not in l]
    t["prompt"] = "\n".join(lines).rstrip()
    t.pop("description", None) if False else None
print(len(tasks), [t["label"] for t in tasks])
out = ["STARTERS: list = ["]
for t in tasks:
    out.append("    {")
    for k, v in t.items():
        if isinstance(v, str) and "\n" in v:
            parts = v.split("\n")
            out.append(f"        {k!r}: (")
            for j, part in enumerate(parts):
                s = part + ("\n" if j < len(parts) - 1 else "")
                out.append(f"            {s!r}")
            out.append("        ),")
        else:
            out.append(f"        {k!r}: {v!r},")
    out.append("    },")
out.append("]")
gui = ROOT / "task_queue_gui.py"
text = gui.read_text(encoding="utf-8")
assert text.rstrip().endswith("STARTERS: list = []")
text = text.rstrip()[: -len("STARTERS: list = []")] + "\n".join(out) + "\n"
gui.write_text(text, encoding="utf-8")
ns = {}
exec(compile("\n".join(out), "x", "exec"), ns)
assert ns["STARTERS"] == tasks
print("ok", start + 1, end + 1)
