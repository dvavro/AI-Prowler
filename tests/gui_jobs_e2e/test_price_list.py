"""Price list (Services_Pricing) through the Database screen (spec §6.12) —
used the way the owner maintains it: Database → Pricing tab → + Add / Edit /
Delete. Every change is checked on screen AND read back from the database.

Test codes all start with ZTEST- (the write guard only lets the tests touch
those; the sweep deletes every ZTEST- code afterwards).

Not reachable from the screen, so covered by the server tests instead
(tests/mcp_tests/test_live_findings_2026_09_25.py): PR-07 / PR-14 (edit / delete a
code that doesn't exist — the screen only offers Edit/Delete on real rows),
and the "must be a number" message of PR-10 (the price boxes are number boxes,
so the browser won't even accept letters — checked here as that).

Run: run_tests_gui_jobs_e2e.bat --human -k test_price_list
"""
import re

import pytest
from playwright.sync_api import expect

from app import type_text

SHEET = "Services_Pricing"
FULL = {                       # PR-01: every field a person can type
    "Category": "Cleaning",
    "Name": "ZTEST Windows & Screens",
    "Base Price ($)": "150",
    "Unit Basis": "flat",
    "Min Charge ($)": "75",
    "Commission Multiplier": "0.1",
    "Tax Category": "Taxable",
    "Notes": "E2E test price — safe to delete",
}


# ── helpers ──────────────────────────────────────────────────────────────────
@pytest.fixture
def pricing(clean_slate, app, page):
    """Database screen, Pricing tab open."""
    app.goto("sheet")
    app.log("DATABASE open the Pricing tab")
    page.locator("#sheetTabs").get_by_role("button", name=re.compile("pric", re.I)).first.click()
    expect(page.locator("#sheetAddBtn")).to_be_visible()
    page.wait_for_timeout(600)
    return page


def _price(api, code):
    for r in api.read(SHEET):
        if r.get("Service Code", "") == code:
            return r
    return None


def _num(v):
    try:
        return float(str(v).replace("$", "").replace(",", "").strip())
    except ValueError:
        return None


def _field(page, col):
    return page.locator(f"#jfGenericInputs [data-col-name='{col}']").first


def _fill(app, page, col, value):
    el = _field(page, col)
    app.log(f"fill {col} = {value!r}")
    if el.evaluate("e => e.tagName") == "SELECT":
        el.select_option(value)
    else:
        el.fill("")
        type_text(page, el, value)


def _open_add(app, page):
    app.log("DATABASE tap + Add")
    page.locator("#sheetAddBtn").click()
    expect(page.locator("#jobFormModal")).to_be_visible()


def _save(app, page, tool):
    app.log("DATABASE tap Save / Create")
    with page.expect_response(lambda r: "/pwa-api" in r.url and tool in (r.request.post_data or ""),
                              timeout=30_000):
        page.locator("#jobFormSaveBtn").click()


def _add(app, page, code, **fields):
    _open_add(app, page)
    _fill(app, page, "Service Code", code)
    for col, val in fields.items():
        _fill(app, page, col, val)
    _save(app, page, "create_service_pricing")


def _row(page, code):
    return page.locator("tr", has=page.locator(f".sheet-row-edit-btn[data-rowid='{code}']"))


def _open_edit(app, page, code):
    app.log(f"DATABASE tap Edit on {code}")
    btn = page.locator(f".sheet-row-edit-btn[data-rowid='{code}']")
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(page.locator("#jobFormModal")).to_be_visible()


def _error(page):
    return page.locator("#jobFormError")


def _close_form(page):
    page.keyboard.press("Escape")
    if page.locator("#jobFormModal").is_visible():
        page.locator("#jobFormModal").click(position={"x": 5, "y": 5})


def _delete(app, page, code, accept: bool):
    """Tap Delete on the row; answer the 'are you sure' box. Returns the
    message the app pops up afterwards ('' if cancelled)."""
    said = []

    def answer(d):
        said.append(d.message)
        if d.type == "confirm":
            app.log(f"DIALOG {'OK' if accept else 'Cancel'}: {d.message[:80]}")
            d.accept() if accept else d.dismiss()
        else:
            app.log(f"DIALOG message: {d.message[:120]}")
            d.accept()

    page.on("dialog", answer)
    try:
        app.log(f"DATABASE tap Delete on {code}")
        page.locator(f".sheet-row-delete-btn[data-code='{code}']").click()
        page.wait_for_timeout(2500 if accept else 800)
    finally:
        page.remove_listener("dialog", answer)
    return said[1] if len(said) > 1 else ""


# ── add ──────────────────────────────────────────────────────────────────────
def test_PR_01_add_with_every_field(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-FULL", **FULL)
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    expect(_row(page, "ZTEST-FULL")).to_be_visible(timeout=15_000)
    r = _price(api, "ZTEST-FULL")
    assert r, "not in the database"
    for col, val in FULL.items():
        got = r.get(col, "")
        if col in ("Base Price ($)", "Min Charge ($)", "Commission Multiplier"):
            assert _num(got) == float(val), f"{col}: typed {val}, stored {got!r}"
        else:
            assert str(got) == val, f"{col}: typed {val!r}, stored {got!r}"
    assert str(r.get("Version", "")).strip() in ("1", "1.0"), f"Version: {r.get('Version')!r}"


def test_PR_02_add_existing_code_is_refused(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-DUP", Name="first", **{"Base Price ($)": "100"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _add(app, page, "ZTEST-DUP", Name="second", **{"Base Price ($)": "999"})
    expect(_error(page)).to_be_visible()
    expect(_error(page)).to_contain_text(re.compile(r"already exists|update", re.I))
    _close_form(page)
    r = _price(api, "ZTEST-DUP")
    assert r["Name"] == "first" and _num(r["Base Price ($)"]) == 100, f"overwritten: {r}"


def test_PR_03_case_only_difference_is_a_duplicate(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-WIN", Name="upper", **{"Base Price ($)": "100"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _add(app, page, "ztest-win", Name="lower", **{"Base Price ($)": "200"})
    expect(_error(page)).to_be_visible()
    _close_form(page)
    codes = [r["Service Code"] for r in api.read(SHEET) if r["Service Code"].upper() == "ZTEST-WIN"]
    assert codes == ["ZTEST-WIN"], f"case-duplicate accepted: {codes}"


@pytest.mark.parametrize("code", ["", "   "], ids=["empty", "spaces"])
def test_PR_04_code_is_required(pricing, app, api, code):
    page = pricing
    before = len(api.read(SHEET))
    _open_add(app, page)
    _fill(app, page, "Service Code", code)
    _fill(app, page, "Name", "ZTEST no code")
    _save(app, page, "create_service_pricing")
    expect(_error(page)).to_be_visible()
    # The app says: ❌ 'Service Code' is required and cannot be blank.
    expect(_error(page)).to_contain_text(re.compile(r"Service Code'? is required", re.I))
    _close_form(page)
    assert len(api.read(SHEET)) == before, "a row was written without a code"


# ── change ───────────────────────────────────────────────────────────────────
def test_PR_05_change_price_and_notes(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-EDIT", **FULL)
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    before = _price(api, "ZTEST-EDIT")
    _open_edit(app, page, "ZTEST-EDIT")
    _fill(app, page, "Base Price ($)", "175")
    _fill(app, page, "Notes", "price went up")
    _save(app, page, "update_job_spreadsheet")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    after = _price(api, "ZTEST-EDIT")
    assert _num(after["Base Price ($)"]) == 175 and after["Notes"] == "price went up", after
    for col in ("Category", "Name", "Unit Basis", "Tax Category"):
        assert after[col] == before[col], f"{col} changed: {before[col]!r} → {after[col]!r}"
    assert _num(after["Min Charge ($)"]) == _num(before["Min Charge ($)"])
    assert _num(after["Version"]) == _num(before["Version"]) + 1, f"Version {before['Version']} → {after['Version']}"


def test_PR_06_stale_edit_is_refused_not_overwritten(pricing, app, api):
    """Two people have the price list open. Someone else saves a change
    while this person's Edit form is open; this person then saves theirs.
    Their save must be refused ('reload and try again') — not silently
    wipe out the other person's change."""
    page = pricing
    _add(app, page, "ZTEST-RACE", Name="race", **{"Base Price ($)": "100", "Notes": "original"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _open_edit(app, page, "ZTEST-RACE")
    app.log("SOMEONE ELSE (another device) changes Notes while this form is open")
    api.call("update_job_spreadsheet", {"sheet_name": SHEET, "job_identifier": "ZTEST-RACE",
                                        "id_column": "Service Code",
                                        "updates": {"Notes": "changed by someone else"}})
    _fill(app, page, "Base Price ($)", "120")
    _save(app, page, "update_job_spreadsheet")
    page.wait_for_timeout(1500)
    r = _price(api, "ZTEST-RACE")
    assert r["Notes"] == "changed by someone else", \
        f"the other person's change was silently overwritten: Notes={r['Notes']!r}"
    expect(_error(page)).to_contain_text(re.compile(r"reload|try again|changed", re.I))
    _close_form(page)


def test_PR_09_edit_changes_exactly_that_code(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-P1", Name="one", **{"Base Price ($)": "10"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _add(app, page, "ZTEST-P10", Name="ten", **{"Base Price ($)": "100"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _open_edit(app, page, "ZTEST-P1")
    _fill(app, page, "Base Price ($)", "11")
    _save(app, page, "update_job_spreadsheet")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    assert _num(_price(api, "ZTEST-P1")["Base Price ($)"]) == 11
    assert _num(_price(api, "ZTEST-P10")["Base Price ($)"]) == 100, "ZTEST-P10 was edited instead"


def test_PR_10_price_boxes_take_numbers_only(pricing, app):
    page = pricing
    _open_add(app, page)
    for col in ("Base Price ($)", "Min Charge ($)", "Commission Multiplier"):
        el = _field(page, col)
        assert el.get_attribute("type") == "number", f"{col} isn't a number box"
        app.log(f"type 'abc' into {col}")
        el.click()
        el.press_sequentially("abc", delay=150)
        assert el.input_value() == "", f"{col} accepted letters: {el.input_value()!r}"
    _close_form(page)


def test_PR_11_negative_price_is_refused(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-NEG", Name="negative", **{"Base Price ($)": "-50"})
    expect(_error(page)).to_be_visible()
    _close_form(page)
    assert _price(api, "ZTEST-NEG") is None, "a negative price was stored"


# ── delete ───────────────────────────────────────────────────────────────────
def test_PR_12_cancel_delete_keeps_the_row(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-KEEP", Name="keep me", **{"Base Price ($)": "50"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _delete(app, page, "ZTEST-KEEP", accept=False)
    expect(_row(page, "ZTEST-KEEP")).to_be_visible()
    assert _price(api, "ZTEST-KEEP") is not None, "deleted even though Cancel was tapped"


def test_PR_13_delete_removes_the_row(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-GONE", Name="delete me", **{"Base Price ($)": "50"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    msg = _delete(app, page, "ZTEST-GONE", accept=True)
    assert re.search(r"backup", msg, re.I), f"no safety-backup path in the message: {msg!r}"
    expect(_row(page, "ZTEST-GONE")).to_have_count(0, timeout=15_000)
    assert _price(api, "ZTEST-GONE") is None


def test_PR_15_delete_removes_exactly_that_code(pricing, app, api):
    page = pricing
    _add(app, page, "ZTEST-D1", Name="one", **{"Base Price ($)": "10"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _add(app, page, "ZTEST-D10", Name="ten", **{"Base Price ($)": "100"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _delete(app, page, "ZTEST-D1", accept=True)
    assert _price(api, "ZTEST-D1") is None
    assert _price(api, "ZTEST-D10") is not None, "ZTEST-D10 was deleted too"


def test_PR_16_deleting_a_price_leaves_jobs_alone(pricing, app, api, data):
    page = pricing
    _add(app, page, "ZTEST-USED", Name="used on a job", **{"Base Price ($)": "150"})
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    jid = data.job("PR16", **{"Quote Amount ($)": 150})
    _delete(app, page, "ZTEST-USED", accept=True)
    assert _price(api, "ZTEST-USED") is None
    job = next(r for r in api.read("Jobs_Schedule") if r.get("JobID (JOB-####)") == jid)
    assert _num(job["Quote Amount ($)"]) == 150, f"job's own amount changed: {job['Quote Amount ($)']!r}"
