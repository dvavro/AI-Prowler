"""Shared helpers for the Estimator E2E browser tests (tests/estimator/browser/test_e2e_sprintNN.py).

Seeds and role sign-in for human-mode Playwright tests. Every test still gets the
usual throwaway data folder (tests/estimator/conftest.py) and its own server
(browser/conftest.py: site fixture); nothing here touches real data.
"""
import json
from contextlib import contextmanager
from pathlib import Path

from estimator.context import personal_context
from estimator.drawing_model import store
from estimator.estimating import service
from estimator.takeoff import measurements as m

CTX = personal_context()

# ------------------------------------------------------------------ role sign-in
# The browser track signs in as owner via same-PC only. For the other roles the
# tests mint a Jobs-app token: estimator/api/auth.py resolves it through
# set_app_token_resolver (the same mechanism test_browser_sprint13.py uses for
# the reviewer phone token), and app.js sends it as Authorization: Bearer from
# localStorage "ap_auth". No production change, no password, no server-mode
# user seeding. The resolver maps one token per role.
ROLE_TOKENS = {role: f"e2e-{role}-token" for role in ("owner", "estimator", "reviewer", "office", "field")}

# token -> who, registered by sign_in_as / sign_in_many (a second company is a
# different company_id under the same token scheme, e.g. S11 M5's import target).
_TOKEN_MAP = {}


def _resolver(tok):
    return _TOKEN_MAP.get(tok)


def _token_for(role, company=None):
    company = company or CTX.company_id
    token = ROLE_TOKENS[role] if company == CTX.company_id else f"e2e-{role}-{company}-token"
    _TOKEN_MAP[token] = {"user_id": role, "role": role, "name": role.title(), "company_id": company}
    return token


def _apply_token(page, role, company=None):
    page.add_init_script("localStorage.setItem('ap_auth', " + json.dumps(json.dumps(
        {"mode": "personal", "token": _token_for(role, company)})) + ")")


@contextmanager
def sign_in_as(page, role, company=None):
    """Sign `page` in as `role` (in `company`, default the personal one) for the block."""
    from estimator.api import auth
    auth.set_app_token_resolver(_resolver)
    _apply_token(page, role, company)
    if page.url.startswith("http"):
        # The app read localStorage once, at its first load (app.js: APP_TOKEN).
        # A hash-only goto does not reload it, so force a full reload here.
        page.reload()
        page.wait_for_selector("#nav a[data-screen]", timeout=15000)
    try:
        yield
    finally:
        auth.set_app_token_resolver(None)


@contextmanager
def sign_in_many(pages_roles):
    """Sign several pages in at once (e.g. two browser contexts, two roles).
    Each entry is (page, role) or (page, role, company)."""
    from estimator.api import auth
    auth.set_app_token_resolver(_resolver)
    for entry in pages_roles:
        page, role = entry[0], entry[1]
        _apply_token(page, role, entry[2] if len(entry) > 2 else None)
        if page.url.startswith("http"):
            page.reload()
            page.wait_for_selector("#nav a[data-screen]", timeout=15000)
    try:
        yield
    finally:
        auth.set_app_token_resolver(None)


def dismiss_tour(page):
    """Close the first-open tour pop-up if it auto-started, so it cannot cover a control.

    Only for tests that are not themselves testing the tour (Sprint 18 uses the
    pop-up). Best-effort: the pop-up appears asynchronously after the progress fetch.
    """
    page.wait_for_timeout(400)
    pop = page.locator("#tour-pop:visible")
    if pop.count():
        page.click("#tour-skip")
        page.wait_for_selector("#tour-pop", state="hidden")


def nav_ids(page):
    """The screen ids in the left menu for whoever is signed in."""
    return page.evaluate("() => [...document.querySelectorAll('#nav a[data-screen]')].map(a => a.dataset.screen)")


# ------------------------------------------------------------------ seeded Rev A -> Rev B plan sets
# Copied from tests/estimator/webapp/test_web_sprint17.py (PLAN/revs): Rev B moves
# outlet 3, grows the slab, removes the GFI, adds a floor box and a REV CLOUD
# polyline, changes D1's size, and adds a sheet.

def _pt(x, y):
    return {"type": "point", "points": [[x, y]]}


def _poly(x0, y0, x1, y1):
    return {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]}


def PLAN(rev="A", image=None):
    b = rev == "B"
    outlets = [{"viewport": "plan", "kind": "symbol", "label": "OUTLET", "block_name": "DUPLEX", "source": "cad",
                "geometry": _pt(12 if (b and i == 3) else 2 + i, 3)} for i in range(5)]
    objs = outlets + [
        {"viewport": "plan", "kind": "polygon", "label": "SLAB", "source": "cad",
         "geometry": _poly(1, 1, 7 if b else 6, 5)},
        {"viewport": "plan", "kind": "polygon", "label": "PORCH", "source": "cad", "geometry": _poly(8, 1, 10, 5)},
        {"viewport": "plan", "kind": "opening", "tag": "D1", "label": "door", "source": "cad", "geometry": _pt(10, 12)},
    ]
    if not b:
        objs.append({"viewport": "plan", "kind": "symbol", "label": "GFI", "block_name": "GFI", "source": "cad",
                     "geometry": _pt(5, 8)})
    else:
        objs += [{"viewport": "plan", "kind": "symbol", "label": "FLOOR BOX", "block_name": "FBOX", "source": "cad",
                  "geometry": _pt(15, 15)},
                 {"viewport": "plan", "kind": "polyline", "label": "REV CLOUD", "layer": "REVISION", "source": "cad",
                  "geometry": {"type": "polyline", "points": [[11, 2], [13, 2], [13, 4]]}}]
    sheets = [{"page_no": 1, "sheet_no": "E-101", "title": "POWER PLAN", "discipline": "electrical",
               "units": "paper_in", "width": 36, "height": 24, "image_path": image,
               "viewports": [{"key": "plan", "label": "POWER PLAN", "scale_note": "1/4\" = 1'-0\""}],
               "objects": objs,
               "schedules": [{"schedule_type": "door", "rows": [
                   {"mark": "D1", "fields": {"size": "3'-0\" x 7'-0\"" if b else "3'-0\" x 6'-8\""}}]}]}]
    if b:
        sheets.append({"page_no": 2, "sheet_no": "E-102", "title": "LIGHTING", "discipline": "electrical",
                       "units": "paper_in", "width": 36, "height": 24,
                       "viewports": [{"key": "p", "label": "LIGHTING", "scale_note": "1/4\" = 1'-0\""}],
                       "objects": [{"viewport": "p", "kind": "symbol", "label": "CAN", "source": "cad",
                                    "geometry": _pt(3, 3)}]})
    return {"sheets": sheets}


def _pdf(path: Path, pages: int, note: str = "") -> str:
    """A real (renderable) PDF: one 36x24 plan page per page, so the tile and
    sheet-image endpoints can draw it. The drawing model still comes from
    save_results(..., "fake") in make_revs, exactly as in the webapp fixture."""
    from pdfmaker import make_pdf
    from test_plan_engine_sprint10 import legend, plan, shape
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    page = plan(lt, ll + shape("recept", 5, 5) + shape("recept", 7, 5))
    if note:
        # store.upload dedupes by file content (sha256), so two otherwise
        # identical PDFs (same page count, same drawing) must differ in the
        # bytes: stamp the note on the page. The drawing model still comes
        # from save_results(..., "fake"), so the extra text is harmless.
        page = {**page, "texts": list(page["texts"]) + [(1, 1, 12, f"REV {note}")]}
    return str(make_pdf(path, [page] * pages))


def _ids(conn, ctx, ps):
    out = {}
    for o in store.objects(conn, ctx, plan_set_id=ps)["objects"]:
        out.setdefault(o["label"] if o["kind"] != "opening" else o["tag"], []).append(o["id"])
    return out


def make_revs(db, tmp_path, title="Lopez remodel"):
    """Rev A + Rev B (B supersedes A) with measurements; returns the webapp revs dict."""
    est = service.create_estimate(db, CTX, title)["id"]
    a = store.upload(db, CTX, est, _pdf(tmp_path / "revA.pdf", 1, "A"), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, a, PLAN("A"), "fake")
    o = _ids(db, CTX, a)
    keep = m.propose(db, CTX, est, "roofing", o["OUTLET"][:3], kind="count", label="outlets 1-3",
                     confirm=True)["proposed"][0]["id"]
    moved = m.propose(db, CTX, est, "roofing", o["OUTLET"][2:5], kind="count", label="outlets 3-5",
                      confirm=True)["proposed"][0]["id"]
    slab = m.propose(db, CTX, est, "roofing", o["SLAB"], feeds="roof_area_sqft", confirm=True)["proposed"][0]["id"]
    gfi = m.propose(db, CTX, est, "roofing", o["GFI"], kind="count", label="gfi", confirm=True)["proposed"][0]["id"]
    porch = m.propose(db, CTX, est, "roofing", o["PORCH"], kind="area", label="porch", confirm=True)["proposed"][0]["id"]
    typed = m.manual(db, CTX, est, "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True)["measurement"]["id"]
    m.confirm_measurements(db, CTX, [keep, slab, porch], confirm=True)
    b = store.upload(db, CTX, est, _pdf(tmp_path / "revB.pdf", 2, "B"), supersedes_plan_set_id=a,
                     confirm=True)["plan_set_id"]
    store.save_results(db, CTX, b, PLAN("B"), "fake")
    db.commit()
    return {"est": est, "a": a, "b": b, "o": o, "keep": keep, "moved": moved, "slab": slab, "gfi": gfi,
            "porch": porch, "typed": typed}


def compare_in_browser(page, base, revs):
    """Drive the Reports > Plan revisions compare flow; returns the new report id."""
    page.goto(base + "#/reports?tab=revisions&estimate=" + str(revs["est"]))
    page.wait_for_selector("#rv-waiting")
    dismiss_tour(page)
    page.click(f"#rv-waiting [data-new='{revs['b']}']")
    page.wait_for_selector("#rv-confirm")
    page.click("#rv-confirm")
    page.wait_for_url("**#/revisions/*")
    # The revision render is async: navigating away before it lands lets its
    # replaceChildren overwrite the next screen. Wait until it is drawn.
    page.wait_for_selector("#rev-tiles")
    return int(page.url.split("#/revisions/")[1].split("?")[0])


def xlsx_supplier(tmp_path, name="suppliers.xlsx"):
    """A two-sheet supplier workbook (Prices + Cover), as in test_web_sprint19."""
    import pytest
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Prices"
    ws.append(["Item Code", "Description", "Unit", "Unit Price"])
    ws.append(["pw_driveway_sqft", "Driveway", "sqft", 0.19])
    ws.append(["bogus", "Nothing like this", "ea", 5])
    cover = wb.create_sheet("Cover")
    cover.append(["Note"])
    cover.append(["supplier cover sheet"])
    path = tmp_path / name
    wb.save(path)
    return path
