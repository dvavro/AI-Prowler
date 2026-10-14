"""2026-10-13: SRV-SCOPE-13 — since 2026-10-05 email_route_now checks the route
is APPROVED before looking it up, so on an empty day the reply is the approval
warning, not "Nothing to email". Both replies now name the crew whose route
was checked; accept either (still zero chance of a real email)."""
from pathlib import Path

p = Path(__file__).resolve().parents[2] / "tests/gui_jobs_e2e_server/test_srv_email_route.py"
s = p.read_text(encoding="utf-8")
pairs = [
    ('''    assert st == 200 and res.lstrip().startswith("⚠️") and "Nothing to email" in res, res[:200]''',
     '''    assert st == 200 and res.lstrip().startswith("⚠️") and _refused_nothing_sent(res), res[:200]'''),
    ('''    assert st == 200 and "Nothing to email" in res and f"({OTHER})".lower() in res.lower(), \\''',
     '''    assert st == 200 and _refused_nothing_sent(res) and f"({OTHER})".lower() in res.lower(), \\'''),
    ('''@pytest.fixture
def empty_day(clean_slate, owner_api):''',
     '''def _refused_nothing_sent(res):
    """No email went out: no route saved, or (since 2026-10-05) not approved.
    Both replies name the crew whose route was checked."""
    return "Nothing to email" in res or "only allowed for approved routes" in res


@pytest.fixture
def empty_day(clean_slate, owner_api):'''),
]
for old, new in pairs:
    assert s.count(old) == 1, f"not found once: {old[:70]!r}"
    s = s.replace(old, new)
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print("SRV-SCOPE-13 updated")
