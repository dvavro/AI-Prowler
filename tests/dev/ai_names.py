"""2026-10-12 (David): "Claude" -> "Claude, Muse, or Grok" everywhere in the app,
the web apps and the user manual — AI-Prowler now serves all three over MCP HTTPS.
Scope (David): user-facing text, the guide/tool help the AI reads, and code
comments. NOT changed: product names (Claude Desktop, Claude Code, Claude.ai,
Claude Pro/Max/Team, model names ...), anything code compares against (short
one-word strings like "Claude"), identifiers, paths, URLs, and the tests.

    ai_names.py            dry run: counts per file + samples
    ai_names.py --apply    write the changes
In .py files only comments and string literals are touched (tokenize). ASCII output.
"""
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPLY = "--apply" in sys.argv
NEW = "Claude, Muse, or Grok"
NEW_POSS = "Claude/Muse/Grok's"

KEEP_AFTER = (r" Desktop| Code| Pro\b| Max\b| Team\b| Enterprise| Opus| Sonnet| Haiku| Fable| Mythos"
              r"| for (?:Chrome|Excel|Word|Slack|M365)| in Chrome| Agent SDK| API\b| Console| Tag\b"
              r"| Science| Security| app\b| apps\b| mobile app| account| subscription| plan\b"
              r"|\.ai|\.com|-|_|/Muse|, Muse| or Muse| CLI|\\\\|\\| phone app| desktop app| Desktop app")
# not part of a path (\Claude\ or /Claude/), an identifier, or a URL
RX = re.compile(r"(?<![\w./\\-])Claude(?:'s|\u2019s)?(?!" + KEEP_AFTER + r")(?![\w])")


def convert(text):
    count = 0

    def rep(m):
        nonlocal count
        s = m.group(0)
        before = text[max(0, m.start() - 12):m.start()]
        ls = text.rfind("\n", 0, m.start()) + 1
        le = text.find("\n", m.end())
        line = text[ls:le if le != -1 else len(text)]
        # a line that already names Muse or Grok is comparing the three AIs
        # (e.g. per-AI connection steps) — leave it exactly as written
        if "Anthropic" in before or "Muse" in line or "Grok" in line:
            return s
        count += 1
        return NEW_POSS if s.endswith(("'s", "\u2019s")) else NEW
    return RX.sub(rep, text), count


def convert_py(src):
    toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    lines = src.splitlines(keepends=True)
    offs = [0]
    for l in lines:
        offs.append(offs[-1] + len(l))
    edits, total = [], 0
    for t in toks:
        if t.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        val = t.string
        if t.type == tokenize.STRING:
            inner = re.sub(r"^[rbufRBUF]*('''|\"\"\"|'|\")", "", val)[:-1]
            if " " not in inner.strip() and len(inner) <= 24:
                continue                                  # one-word string: code may compare it
        new, n = convert(val)
        if n:
            a = offs[t.start[0] - 1] + t.start[1]
            b = offs[t.end[0] - 1] + t.end[1]
            edits.append((a, b, new))
            total += n
    for a, b, new in sorted(edits, reverse=True):
        src = src[:a] + new + src[b:]
    return src, total


targets = sorted({p for p in ROOT.glob("*.py")} |
                 {ROOT / f for f in ("jobs/index.html", "remote/index.html", "hr_admin/index.html",
                                     "hr_portal/index.html", "COMPLETE_USER_GUIDE.md", "README.md")})
targets = [p for p in targets if p.exists() and p.name not in
           ("cleanup_tmp.py", "wrap_cleanup.py", "clr.py", "fhr.py", "clear_att.py", "find_attendance.py",
            # Claude-CLI-only code: the per-user Claude CLI sign-in relay and the
            # unattended analysis runs drive the Claude Code CLI specifically
            "cli_signin_relay.py", "task_queue_automation.py")]
grand = 0
for p in targets:
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    text = raw.replace("\r\n", "\n")
    if p.suffix == ".py":
        new, n = convert_py(text)
        if n:
            compile(new, str(p), "exec")
    else:
        new, n = convert(text)
    if not n:
        continue
    grand += n
    print(f"{n:5}  {p.relative_to(ROOT)}")
    if not APPLY:
        shown = 0
        for ol, nlin in zip(text.splitlines(), new.splitlines()):
            if ol != nlin and shown < 2:
                print("        - " + ol.strip()[:110].encode("ascii", "backslashreplace").decode("ascii"))
                print("        + " + nlin.strip()[:110].encode("ascii", "backslashreplace").decode("ascii"))
                shown += 1
    if APPLY:
        p.write_bytes(new.replace("\n", nl).encode("utf-8"))
print(f"\n{'changed' if APPLY else 'would change'}: {grand} mention(s)")
