"""Web app <-> MCP parity (design spec "Parity rule"), checked as screens are built.

Each left-menu screen lists the MCP tools that do the same things. For screens
the web app already has, every listed tool must exist in the Estimator's MCP
registry. Tools the spec names but Coder 1 hasn't built yet are listed in
PENDING; the test fails when one of them appears, so the list stays honest.
"""
from estimator.api import nav
from estimator.mcp_tools import est_tools

# Spec'd for the Projects screen, not built yet as standalone tools (the Director has est_director_add_trade).
PENDING = {"est_add_trade", "est_remove_trade"}


def _registered() -> set[str]:
    return {fn.__name__ for fn in est_tools.TOOLS}


def test_ready_screens_have_their_mcp_tools():
    have = _registered()
    missing = {t for s in nav.SCREENS if s["status"] == "ready" for t in s["tools"]} - have - PENDING
    assert not missing, f"ready screens list tools that don't exist: {sorted(missing)}"


def test_pages_have_their_mcp_tools():
    """Sprint 2: the project page and the quick estimate page (opened from a screen, not the menu)."""
    missing = {t for p in nav.PAGES for t in p["tools"]} - _registered() - PENDING
    assert not missing, f"pages list tools that don't exist: {sorted(missing)}"


def test_page_buttons_match_what_the_service_layer_allows():
    """The page hides upload / quick-quote buttons using nav's lists; they must equal the server's own rules."""
    from estimator.drawing_model import store
    from estimator.estimating import service
    assert set(nav.UPLOAD_PLANS) == set(store.UPLOAD_ROLES)
    assert set(nav.QUICK_ESTIMATE) == set(service.QUICK_ROLES)


def test_pages_are_the_ones_the_page_can_draw():
    import re
    from estimator.api import router
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    table = re.search(r"const PAGES = \{([^}]*)\}", js).group(1)
    assert set(re.findall(r"(\w+)\s*:", table)) == {p["id"] for p in nav.PAGES}


def test_pending_list_is_still_pending():
    built = PENDING & _registered()
    assert not built, f"now built - remove from PENDING and wire into the screen: {sorted(built)}"


def test_screen_tool_names_follow_the_spec_prefixes():
    prefixes = ("est_", "plan_", "takeoff_", "pricebook_", "bid_", "runner_", "agent_config_", "symbol_",
                "review_", "how_to_estimate")
    for t in nav.all_tools():
        assert t.startswith(prefixes), t


def test_ready_screens_are_the_ones_the_page_can_draw():
    """A screen marked ready on the server must have a renderer in app.js, and the other way round."""
    import re
    from estimator.api import router
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    table = re.search(r"const SCREENS = \{([^}]*)\}", js).group(1)
    drawn = set(re.findall(r"(\w+)\s*:", table))
    ready = {s["id"] for s in nav.SCREENS if s["status"] == "ready"}
    assert ready == drawn
