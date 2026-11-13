"""Symbol Library pictures (2026-11-13, David): every AI-Prowler standard symbol has a drawing that ships with the
app (symbol_art.js), the library shows a Picture column, and the Examples / Found columns say what they mean."""
import re
from pathlib import Path

from estimator.api import router
from estimator.plan_engine import symbol_library as lib

API = "/estimator-api"
ROOT = Path(router.WEB_DIR).parents[2]


def _art_keys():
    art = (router.WEB_DIR / "symbol_art.js").read_text(encoding="utf-8")
    m = re.search(r"const SYMBOL_ART = \{(.*?)\n\};", art, re.S)
    assert m, "SYMBOL_ART not found in symbol_art.js"
    return set(re.findall(r"^\s{2}([a-z][a-z0-9_]+):", m.group(1), re.M))


def test_every_standard_symbol_has_a_picture():
    keys = _art_keys()
    missing = [e["item_type"] for e in lib.STANDARD if e["item_type"] not in keys]
    assert not missing, missing
    assert not keys - set(lib.BY_TYPE), "drawings for symbols the library doesn't have"


def test_symbol_art_loads_before_verify_and_ships_in_the_installer():
    html = (router.WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert html.index('src="symbol_art.js"') < html.index('src="verify.js"')
    iss = (ROOT / "AI-Prowler-Setup.iss").read_text(encoding="utf-8")
    assert 'Source: "estimator\\ui\\web\\symbol_art.js"' in iss


def test_library_screen_has_pictures_and_explains_the_columns():
    v = (router.WEB_DIR / "verify.js").read_text(encoding="utf-8")
    assert 'el("th", {}, "Picture")' in v and "symbolThumb(dfn)" in v
    assert '"Learned examples"' in v and '"Found on your plans"' in v and 'id: "symlib-columns"' in v


def test_library_list_carries_the_first_learned_example(call):
    r = call("GET", f"{API}/symbol-library")
    assert r.status == 200, r.body
    std = [lb for lb in r.json()["libraries"] if lb["level"] == "standard"][0]
    rows = [d for t in std["by_trade"].values() for d in t]
    assert len(rows) == len(lib.STANDARD)
    assert all("example_detection_id" in d and d["example_detection_id"] is None for d in rows)
