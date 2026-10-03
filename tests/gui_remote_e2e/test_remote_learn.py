"""Remote PWA — Learnings (REMOTE_PWA_E2E_TEST_SPEC.md §5.6, RL).
Every learning made here is titled 'ZTEST E2E …' and deleted by the sweep.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_learn
"""
import re

from playwright.sync_api import expect

from app import type_text

TITLE = "ZTEST E2E remote learning"
CONTENT = "Automated Remote PWA test learning — zqxremotelearn marker. Safe to delete."


def _type(remote, sel, text):
    remote.step(f"type into {sel}: {text[:40]!r}")
    box = remote.page.locator(sel)
    box.click()
    box.fill("")
    type_text(remote.page, box, text)


def _open_form(remote):
    remote.goto("learn")
    remote.step("tap + Add Learning")
    remote.page.get_by_role("button", name=re.compile(r"Add Learning")).click()
    expect(remote.page.locator("#learnForm")).to_be_visible()


def _save(remote):
    remote.step("tap ✓ Save Learning")
    remote.page.get_by_role("button", name=re.compile(r"Save Learning")).click()


def _in_server(rapi, text) -> bool:
    return text in rapi.text("list_learnings", {"limit": 500})


def test_RL_01_stats_and_list_load(remote, rapi):
    remote.goto("learn")
    expect(remote.page.locator("#learnList .spinner")).to_have_count(0, timeout=20_000)
    stats = remote.page.locator("#learnStats").inner_text()
    remote.step(f"learn stats: {stats!r}")
    assert re.search(r"\d", stats), f"no count shown: {stats!r}"


def test_RL_02_add_a_learning_with_every_field(remote, rapi, clean_slate):
    _open_form(remote)
    _type(remote, "#lnTitle", TITLE)
    _type(remote, "#lnContent", CONTENT)
    remote.step("choose Category = Best Practice, Outcome = Positive")
    remote.page.locator("#lnCategory").select_option("best_practice")
    remote.page.locator("#lnOutcome").select_option("positive")
    _type(remote, "#lnTags", "ztest, remote-e2e")
    _type(remote, "#lnContext", "Remote PWA E2E RL-02")
    _save(remote)
    expect(remote.page.locator("#learnForm")).to_be_hidden(timeout=20_000)
    expect(remote.page.locator("#learnList")).to_contain_text(TITLE, timeout=20_000)
    listing = rapi.text("list_learnings", {"limit": 500})
    block = next((b for b in re.split(r"\n\s*\n", listing) if TITLE in b), "")
    assert block, "the learning isn't on the server"
    for want in ("best_practice", "zqxremotelearn"):
        assert want in block.lower() or want in listing.lower(), f"{want!r} not stored: {block[:300]!r}"


def test_RL_03_title_and_content_are_required(remote, rapi):
    _open_form(remote)
    _save(remote)
    expect(remote.page.locator("#lnError")).to_have_text("Title is required")
    _type(remote, "#lnTitle", TITLE + " no content")
    _save(remote)
    expect(remote.page.locator("#lnError")).to_have_text("Content is required")
    assert not _in_server(rapi, TITLE + " no content"), "a learning without content was saved"


def test_RL_04_search_finds_the_learning(remote, rapi, clean_slate):
    rapi.call("record_learning", {"title": TITLE + " search", "content": CONTENT, "category": "general"})
    remote.goto("learn")
    _type(remote, "#learnSearch", "zqxremotelearn Remote PWA test learning")
    remote.page.locator("#learnSearch").press("Enter")
    expect(remote.page.locator("#learnList")).to_contain_text(TITLE + " search", timeout=30_000)


def test_RL_05_delete_the_learning(remote, rapi, clean_slate):
    rapi.call("record_learning", {"title": TITLE + " delete", "content": CONTENT, "category": "general"})
    remote.goto("learn")
    remote.page.get_by_role("button", name=re.compile("Refresh")).first.click()
    btn = remote.page.locator(f'button[data-action="delete-learning"][data-title="{TITLE} delete"]')
    expect(btn).to_be_visible(timeout=20_000)
    said = []
    remote.page.once("dialog", lambda d: (said.append(d.message), d.accept()))
    remote.step("tap 🗑 Delete and confirm")
    btn.click()
    expect(btn).to_have_count(0, timeout=20_000)
    assert said and "cannot be undone" in said[0], f"no confirmation was asked: {said}"
    assert not _in_server(rapi, TITLE + " delete"), "still on the server after Delete"


def test_RL_06_cancel_hides_the_form_and_saves_nothing(remote, rapi):
    _open_form(remote)
    _type(remote, "#lnTitle", TITLE + " cancelled")
    remote.step("tap Cancel")
    remote.page.locator("#learnForm").get_by_role("button", name="Cancel").click()
    expect(remote.page.locator("#learnForm")).to_be_hidden()
    assert not _in_server(rapi, TITLE + " cancelled")
