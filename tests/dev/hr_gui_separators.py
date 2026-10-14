"""2026-10-11: hide the separators that close the HR Admin and HR Portal URL
sections in rag_gui.py on personal installs (the sections are server only).
Each target is the separator directly before the section's end comment / the
next section's opening comment. Checks before writing. ASCII output."""
from pathlib import Path

F = Path(__file__).resolve().parents[2] / "rag_gui.py"
raw = F.read_bytes().decode("utf-8")
NL = "\r\n" if "\r\n" in raw else "\n"
s = raw.replace("\r\n", "\n")
SEP = "        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)\n"
GATED = ("        if self._is_business_server_mode():          # HR sections are server only\n"
         "            ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)\n")
targets = [
    SEP + "        # \u2500\u2500 end HR Admin Application",
    SEP + "        # \u2500\u2500 end HR Portal",
]
done = 0
for t in targets:
    if s.count(t) == 1:
        s = s.replace(t, GATED + t[len(SEP):])
        done += 1
    else:
        print("not found once:", repr(t[-40:]), s.count(t))
compile(s, "rag_gui.py", "exec")
F.write_bytes(s.replace("\n", NL).encode("utf-8"))
print(f"gated {done} separator(s)")
