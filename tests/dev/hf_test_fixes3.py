"""2026-10-12, third live run:
  HF-12 the self-report accepts only 'late' or 'absent'
  HF-19 a screen counts as open when navTo shows its pane (display != none) and
        sets state.currentTab — an empty pane (HR setup not finished) has no
        height, which Playwright reports as 'not visible'
ASCII output."""
from pathlib import Path

p = Path(__file__).resolve().parents[2] / "tests/gui_jobs_e2e_server/test_srv_hr_features.py"
s = p.read_text(encoding="utf-8")
pairs = [
    ('''{"status": "sick", "note": f"ZTEST self {RUN}",''', '''{"status": "absent", "note": f"ZTEST self {RUN}",'''),
    ('''        if not admin.locator(f"#tab-{tab}").is_visible():
            bad.append(f"HR Admin '{tab}' did not open")''',
     '''        shown = admin.evaluate(f"""() => {{ const p = document.getElementById('tab-{tab}');
            return !!p && getComputedStyle(p).display !== 'none' && state.currentTab === '{tab}'; }}""")
        if not shown:
            bad.append(f"HR Admin '{tab}' did not open")'''),
]
for old, new in pairs:
    assert s.count(old) == 1, f"not found once: {old[:70]!r}"
    s = s.replace(old, new)
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print("2 fixes applied")
