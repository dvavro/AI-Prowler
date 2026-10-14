"""2026-10-12: COMPLETE_USER_GUIDE.md — move the new "HR Admin and HR Portal"
section out of the middle of the MCP Tool Configuration bullet list (to just
after "Personal and server mode keep separate settings ..."), and correct the
Reset to Defaults bullet (it no longer re-ticks every box). ASCII output."""
from pathlib import Path

F = Path(__file__).resolve().parents[2] / "COMPLETE_USER_GUIDE.md"
raw = F.read_bytes().decode("utf-8")
nl = "\r\n" if "\r\n" in raw else "\n"
s = raw.replace("\r\n", "\n")
start = s.index("\n#### HR Admin and HR Portal (AI-Prowler Server only)\n")
end = s.index("- The old `/hr/` address now opens HR Admin.\n", start) + len("- The old `/hr/` address now opens HR Admin.\n")
block = s[start:end]
s = s[:start] + "\n" + s[end:].lstrip("\n") if False else s[:start] + s[end:]
anchor = "so changing one never alters the other.\n"
i = s.index(anchor) + len(anchor)
s = s[:i] + block + s[i:]
old = "**↺ Reset to Defaults** only re-ticks every box in the panel; it too is saved only when you click Save."
new = ("**↺ Reset to Defaults** puts every box back to its default — on, except Job Tracker & Routing, "
       "SMS & WhatsApp and (on a server) HR apps, which default to off; it too is saved only when you click Save.")
assert s.count(old) == 1
s = s.replace(old, new)
F.write_bytes(s.replace("\n", nl).encode("utf-8"))
print("moved HR section; Reset to Defaults bullet corrected")
