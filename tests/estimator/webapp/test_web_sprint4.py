"""Coder 2 Sprint 4: Jobs board and job page (the Director's quick lane), the Bids screen, and the Help screen's
how-to guides. Every call goes through the same Director and bid service functions as the MCP tools."""
import json
from pathlib import Path

import pytest

from estimator import config
from estimator.api import nav, router
from estimator.ui import help as guides

API = "/estimator-api"
QUICK = {"module_id": "pressure_washing", "answers": {"driveway_sqft": 1000}, "address": "5 Beach Rd"}
JANE = {"name": "Jane Smith", "email": "jane@example.com"}


def _quick(call, **kw):
    r = call("POST", f"{API}/quick", {**QUICK, **kw})
    assert r.status == 201, r.body
    return r.json()


def _next(call, jid, body, **kw):
    return call("POST", f"{API}/jobs/{jid}/next", body, **kw)


def _approved(call):
    """A quick quote approved by the owner (sample prices confirmed), waiting to be sent."""
    q = _quick(call)
    r = _next(call, q["job"]["id"], {"approve": True, "confirm_sample_prices": True, "customer": JANE})
    assert r.status == 200, r.body
    return q["job"]["id"], r.json()


def _sent(call, fake_host):
    jid, _ = _approved(call)
    r = _next(call, jid, {"send": True, "send_to": "jane@example.com", "confirm": True})
    assert r.status == 200, r.body
    assert len(fake_host.named("send_email")) == 1
    return jid, call("GET", f"{API}/jobs/{jid}").json()


# ---------------------------------------------------------------- quick quote -> Director job

def test_new_quick_quote_is_a_director_job(call):
    q = _quick(call)
    assert q["created"] is True and q["title"].endswith("– 5 Beach Rd")
    assert q["job"]["lane"] == "quick_quote" and q["job"]["estimate_id"] == q["id"]
    assert q["next_step"]["approval"] in ("one_tap", "full")                # waiting for a person's OK
    assert q["warnings"] and "sample" in q["warnings"][0].lower()
    board = call("GET", f"{API}/jobs").json()
    assert board["count"] == 1 and board["by_lane"]["quick_quote"][0]["id"] == q["job"]["id"]
    assert board["can_start"] is True


def test_quick_answers_on_an_existing_project_stay_off_the_board(call):
    e = call("POST", f"{API}/estimates", {"title": "Smith house"}).json()
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "pressure_washing",
                                       "answers": {"driveway_sqft": 500}})
    assert r.status == 200 and r.json()["created"] is False and "job" not in r.json()
    # 2026-11-12: the project has its own Director job (project lane) from the start; the quick answers don't add a
    # quick-quote job beside it.
    board = call("GET", f"{API}/jobs").json()
    assert board["count"] == 1 and set(board["by_lane"]) == {"project"} and e["director_job_id"] == board["jobs"][0]["id"]


def test_start_a_job_from_words(call):
    r = call("POST", f"{API}/jobs", {"request": "Pressure wash a 600 sq ft driveway", "module_id": "pressure_washing",
                                      "answers": {"driveway_sqft": 600}})
    assert r.status == 201, r.body
    assert r.json()["job"]["lane"] == "quick_quote"
    bad = call("POST", f"{API}/jobs", {})
    assert bad.status == 400 and "what the job is" in bad.json()["message"]


def test_reviewer_cant_start_jobs_but_can_see_the_board(call, session_for):
    rv = session_for("reviewer")
    assert call("POST", f"{API}/jobs", {"module_id": "pressure_washing"}, headers=rv).status == 403
    b = call("GET", f"{API}/jobs", headers=rv)
    assert b.status == 200 and b.json()["can_start"] is False


def test_board_filters(call):
    _quick(call)
    assert call("GET", f"{API}/jobs?mine=1").json()["count"] == 1        # Personal owner started it
    assert call("GET", f"{API}/jobs?done=1").json()["count"] == 1


# ---------------------------------------------------------------- the job page: approve, send, won, convert

def test_job_page_shows_next_step_estimate_and_steps(call):
    q = _quick(call)
    j = call("GET", f"{API}/jobs/{q['job']['id']}").json()
    assert j["job"]["id"] == q["job"]["id"] and j["next_step"]["say"]
    assert j["estimate_detail"]["id"] == q["id"] and j["bid"] is None
    assert any(s["stage"] == "triage" for s in j["steps"])
    assert call("GET", f"{API}/jobs/999999").status == 404


def test_approve_with_sample_prices_needs_the_extra_ok(call):
    q = _quick(call)
    r = _next(call, q["job"]["id"], {"approve": True}).json()
    assert r["estimate"]["status"] == "draft" and any("sample prices" in n for n in r["notes"])
    jid, r = _approved(call)
    assert r["estimate"]["status"] == "approved" and r["next_step"]["bid_id"]


def test_bid_paths_never_reach_the_browser(call):
    jid, r = _approved(call)
    for body in (json.dumps(r), call("GET", f"{API}/jobs/{jid}").body.decode()):
        assert "html_path" not in body and "pdf_path" not in body
        assert str(config.data_dir()) not in body and str(config.data_dir()).replace("\\", "\\\\") not in body


def test_send_asks_first_then_emails(call, fake_host):
    jid, r = _approved(call)
    ask = _next(call, jid, {"send": True, "send_to": "jane@example.com"})
    assert ask.status == 200 and ask.json()["needs_confirmation"] is True
    assert "jane@example.com" in ask.json()["question"] and "$" in ask.json()["question"]
    assert fake_host.named("send_email") == []                          # nothing sent without the yes
    jid, j = _sent(call, fake_host)
    assert j["bid"]["status"] == "sent" and j["bid"]["sent_to"] == "jane@example.com"
    assert j["next_step"].get("follow_up_on") is not None or j["job"]["stage"] == "follow_up"


def test_won_then_convert_asks_first_then_creates_the_job(call, fake_host):
    jid, _ = _sent(call, fake_host)
    r = _next(call, jid, {"outcome": "won"})
    assert r.status == 200 and "job" in r.json()["next_step"]["say"].lower()
    ask = _next(call, jid, {"convert": True, "service_date": "2026-12-01"}).json()
    assert ask["needs_confirmation"] is True and "2026-12-01" in ask["question"]
    assert fake_host.named("create_job") == []
    done = _next(call, jid, {"convert": True, "service_date": "2026-12-01", "confirm": True})
    assert done.status == 200, done.body
    job = fake_host.named("create_job")[0]
    assert job["updates"]["Service Date"] == "2026-12-01"
    assert call("GET", f"{API}/jobs/{jid}").json()["bid"]["job_id"] == "JOB-0001"


def test_lost_finishes_the_quote(call, fake_host):
    jid, _ = _sent(call, fake_host)
    _next(call, jid, {"outcome": "lost"})
    assert call("GET", f"{API}/jobs/{jid}").json()["bid"]["status"] == "lost"


@pytest.mark.parametrize("body, words", [
    ({"approve": "yes"}, "approve must be true or false"),
    ({"send": 1}, "send must be true or false"),
    ({"delete_everything": True}, "doesn't take: delete_everything"),
    ({"answers": "lots"}, "answers must be"),
    ({"customer": "Jane"}, "customer must be"),
    ({"rev": "x"}, "rev must be"),
])
def test_next_step_input_is_checked(call, body, words):
    q = _quick(call)
    r = _next(call, q["job"]["id"], body)
    assert r.status == 400 and words in r.json()["message"], r.body


def test_outcome_must_be_won_or_lost(call):
    q = _quick(call)
    assert _next(call, q["job"]["id"], {"outcome": "maybe"}).status == 400


def test_stale_rev_is_refused(call):
    q = _quick(call)
    rev = call("GET", f"{API}/jobs/{q['job']['id']}").json()["job"]["rev"]
    _next(call, q["job"]["id"], {"answers": {"driveway_sqft": 900}})
    assert _next(call, q["job"]["id"], {"approve": True, "rev": rev}).status == 409


def test_field_sees_the_job_without_costs(call, session_for):
    q = _quick(call)
    j = call("GET", f"{API}/jobs/{q['job']['id']}", headers=session_for("field"))
    assert j.status == 200 and "unit_cost_cents" not in j.body.decode()


def test_next_step_needs_the_app_header(call):
    q = _quick(call)
    r = _next(call, q["job"]["id"], {"approve": True}, write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"


# ---------------------------------------------------------------- Bids screen

def test_bids_list_and_preview(call, fake_host):
    jid, j = _sent(call, fake_host)
    lst = call("GET", f"{API}/bids").json()
    assert lst["count"] == 1 and lst["bids"][0]["status"] == "sent" and lst["bids"][0]["has_pdf"] is False
    assert call("GET", f"{API}/bids?status=won").json()["count"] == 0
    assert call("GET", f"{API}/bids?status=nonsense").status == 400
    p = call("GET", f"{API}/bids/{j['bid']['id']}").json()
    assert p["number"] == j["bid"]["number"] and p["text"] and p["lines"]
    assert "html_path" not in json.dumps(p)


@pytest.mark.parametrize("role, status", [("owner", 200), ("estimator", 200), ("office", 200),
                                          ("reviewer", 403), ("field", 200)])
def test_bids_screen_roles(call, session_for, role, status):
    assert call("GET", f"{API}/bids", headers=session_for(role)).status == status


def test_bid_html_is_served_sandboxed(call):
    jid, r = _approved(call)
    f = call("GET", f"{API}/bids/{r['next_step']['bid_id']}/file?kind=html")
    assert f.status == 200 and f.content_type.startswith("text/html") and b"<html" in f.body.lower()
    csp = f.headers["Content-Security-Policy"]
    assert "sandbox" in csp and "default-src 'none'" in csp and "script-src" not in csp
    assert f.headers["X-Content-Type-Options"] == "nosniff"


def test_bid_pdf_downloads_and_missing_pdf_is_explained(call, db):
    jid, r = _approved(call)
    bid_id = r["next_step"]["bid_id"]
    missing = call("GET", f"{API}/bids/{bid_id}/file?kind=pdf")
    assert missing.status == 404 and "HTML" in missing.json()["message"]
    html = Path(db.execute("SELECT html_path FROM bids WHERE id = ?", (bid_id,)).fetchone()[0])
    pdf = html.with_suffix(".pdf")
    pdf.write_bytes(b"%PDF-1.4 test")
    db.execute("UPDATE bids SET pdf_path = ? WHERE id = ?", (str(pdf), bid_id))
    db.commit()
    f = call("GET", f"{API}/bids/{bid_id}/file?kind=pdf")
    assert f.status == 200 and f.content_type == "application/pdf" and f.body == b"%PDF-1.4 test"
    assert f.headers["Content-Disposition"].startswith("attachment;")
    assert call("GET", f"{API}/bids/{bid_id}/file?kind=exe").status == 400


def test_bid_file_outside_the_data_folder_is_never_served(call, db, tmp_path):
    jid, r = _approved(call)
    bid_id = r["next_step"]["bid_id"]
    outside = tmp_path / "secret.html"
    outside.write_text("<html>secret</html>", encoding="utf-8")
    db.execute("UPDATE bids SET html_path = ? WHERE id = ?", (str(outside), bid_id))
    db.commit()
    f = call("GET", f"{API}/bids/{bid_id}/file?kind=html")
    assert f.status == 404 and b"secret" not in f.body


def test_send_from_the_bids_screen_asks_first(call, fake_host):
    jid, r = _approved(call)
    bid_id = r["next_step"]["bid_id"]
    ask = call("POST", f"{API}/bids/{bid_id}/send", {"to": "jane@example.com"}).json()
    assert ask["needs_confirmation"] is True and "jane@example.com" in ask["question"]
    assert "confirm=true" not in ask["question"]                         # the AI's wording is cut off
    assert fake_host.named("send_email") == []
    done = call("POST", f"{API}/bids/{bid_id}/send", {"to": "jane@example.com", "confirm": True}).json()
    assert done["status"] == "sent" and len(fake_host.named("send_email")) == 1 and "pdf_path" not in done


def test_bid_status_and_convert_from_the_bids_screen(call, fake_host):
    jid, j = _sent(call, fake_host)
    bid_id = j["bid"]["id"]
    assert call("POST", f"{API}/bids/{bid_id}/status", {}).status == 400
    assert call("POST", f"{API}/bids/{bid_id}/status", {"status": "viewed"}).json()["status"] == "viewed"
    ask = call("POST", f"{API}/bids/{bid_id}/convert", {}).json()
    assert ask["needs_confirmation"] is True and fake_host.named("create_job") == []
    done = call("POST", f"{API}/bids/{bid_id}/convert", {"confirm": True}).json()
    assert done["job_id"] == "JOB-0001" and done["status"] == "won"
    again = call("POST", f"{API}/bids/{bid_id}/convert", {"confirm": True}).json()
    assert again["already_converted"] is True and len(fake_host.named("create_job")) == 1


def test_office_and_field_send_quotes_but_reviewer_cannot(call, session_for, fake_host):
    """David 2026-11-08: field staff send quotes too (the same roles as bid_send); they never see costs."""
    jid, r = _approved(call)
    bid_id = r["next_step"]["bid_id"]
    for role in ("office", "field"):
        ask = call("POST", f"{API}/bids/{bid_id}/send", {"to": "jane@example.com"}, headers=session_for(role))
        assert ask.status == 200 and ask.json()["needs_confirmation"] is True, role
    field = session_for("field")
    p = call("GET", f"{API}/bids/{bid_id}", headers=field)
    assert p.status == 200 and p.json()["total_cents"] > 0 and "cost" not in p.body.decode().lower()
    done = call("POST", f"{API}/bids/{bid_id}/send", {"to": "jane@example.com", "confirm": True}, headers=field)
    assert done.status == 200 and done.json()["status"] == "sent" and len(fake_host.named("send_email")) == 1
    assert call("POST", f"{API}/bids/{bid_id}/send", {}, headers=session_for("reviewer")).status == 403
    other = call("GET", f"{API}/bids/{bid_id}", headers=session_for("owner", company="acme"))
    assert other.status == 404                                         # another company never sees it


def test_bids_screen_roles_are_the_ones_that_can_send():
    from estimator.estimating import service
    bids_screen = next(s for s in nav.SCREENS if s["id"] == "bids")
    assert set(bids_screen["roles"]) == set(service.QUICK_ROLES)
    assert {r for r, p in nav.PERMISSIONS.items() if p["send_bids"]} == set(service.QUICK_ROLES)


# ---------------------------------------------------------------- the Director asks first in chat too (2026-11-08)

def _t():
    from estimator.mcp_tools import est_tools
    return est_tools


def test_director_send_asks_first_and_changes_nothing(db, fake_host):
    from estimator.director import engine
    from estimator.errors import ConfirmationRequired
    from estimator.context import personal_context
    ctx = personal_context()
    r = engine.start(db, ctx, "pressure wash", module_id="pressure_washing", answers={"driveway_sqft": 1000},
                     customer=JANE)
    before = engine.status(db, ctx, r["job"]["id"])
    with pytest.raises(ConfirmationRequired) as e:
        engine.next_step(db, ctx, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True)
    assert "jane@example.com" in e.value.message and "$" in e.value.message and "confirm=true" in e.value.message
    after = engine.status(db, ctx, r["job"]["id"])
    assert after["job"]["rev"] == before["job"]["rev"] and after["estimate"]["status"] == "draft"   # not even approved
    assert fake_host.named("send_email") == []
    done = engine.next_step(db, ctx, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True, confirm=True)
    assert done["job"]["stage"] == "follow_up" and len(fake_host.named("send_email")) == 1
    # Once sent, asking to send again is a no-op, so there's nothing to ask.
    engine.next_step(db, ctx, r["job"]["id"], send=True)


def test_director_send_with_no_email_just_says_it_needs_one(db, fake_host):
    from estimator.director import engine
    from estimator.context import personal_context
    ctx = personal_context()
    r = engine.start(db, ctx, "pressure wash", module_id="pressure_washing", answers={"driveway_sqft": 1000})
    r = engine.next_step(db, ctx, r["job"]["id"], approve=True, confirm_sample_prices=True, send=True)
    assert any("email address" in n for n in r["notes"]) and fake_host.named("send_email") == []


def test_director_convert_asks_first_in_chat(db, fake_host):
    t = _t()
    r = json.loads(t.est_director_start("pressure wash", module_id="pressure_washing",
                                        answers={"driveway_sqft": 1000}, customer=JANE))
    job = r["job"]["id"]
    ask = json.loads(t.est_director_next(job, approve=True, confirm_sample_prices=True, send=True))
    assert ask["error"] == "needs_confirmation" and "jane@example.com" in ask["message"]
    json.loads(t.est_director_next(job, approve=True, confirm_sample_prices=True, send=True, confirm=True))
    json.loads(t.est_director_next(job, outcome="won"))
    ask = json.loads(t.est_director_next(job, convert=True, service_date="2026-12-01"))
    assert ask["error"] == "needs_confirmation" and "2026-12-01" in ask["message"] and "Jane Smith" in ask["message"]
    assert fake_host.named("create_job") == []
    done = json.loads(t.est_director_next(job, convert=True, service_date="2026-12-01", confirm=True))
    assert done["job"]["state"] == "done" and len(fake_host.named("create_job")) == 1


def test_director_says_confirm_true_in_its_instructions(db):
    from estimator.agents import queue as agent_queue
    from estimator.director import engine
    src = Path(engine.__file__).read_text(encoding="utf-8")
    assert "send=true)" not in src.replace("send=true, confirm=true", "")        # every send hint names confirm
    assert "confirm=true" in agent_queue.prompt("director")


# ---------------------------------------------------------------- how_to_estimate returns the guides (2026-11-08)

def test_how_to_estimate_lists_and_finds_the_guides(db):
    t = _t()
    overview = json.loads(t.how_to_estimate())
    assert {g["id"] for g in overview["guides"]} >= {"quote_a_service_job", "send_and_follow_up_a_quote"}
    assert "est_director_start" in overview["instructions"]                     # the overview is still there
    g = json.loads(t.how_to_estimate(topic="how do I send a quote to a customer?"))
    assert g["guide"]["id"] == "send_and_follow_up_a_quote" and "📨 Send the quote…" in g["guide"]["text"]
    assert json.loads(t.how_to_estimate(topic="set_up_your_price_book"))["guide"]["id"] == "set_up_your_price_book"
    assert json.loads(t.how_to_estimate(topic="Set up your price book"))["guide"]["id"] == "set_up_your_price_book"
    none = json.loads(t.how_to_estimate(topic="zzzz qqqq"))
    assert none["guide"] is None and none["guides"]
    assert "Takeoff" in json.loads(t.how_to_estimate("takeoff"))["instructions"]   # roles still work


# ---------------------------------------------------------------- Help: how-to guides

def test_guides_list_and_open(call):
    g = call("GET", f"{API}/help/guides").json()
    ids = {x["id"] for x in g["guides"]}
    assert {"quote_a_service_job", "send_and_follow_up_a_quote", "turn_a_won_quote_into_a_job",
            "set_up_your_price_book", "use_the_jobs_board"} <= ids
    one = call("GET", f"{API}/help/guides/quote_a_service_job").json()["guide"]
    assert one["title"].startswith("Quote a service job") and one["steps"] >= 5 and "<!--" not in one["text"]
    assert call("GET", f"{API}/help/guides/nope").status == 404
    assert call("GET", f"{API}/help/guides/..%2F..%2Fsecret").status == 404


def test_guide_search_and_screen_filter(call):
    found = call("GET", f"{API}/help/guides?q=how do I send a quote to the customer").json()["guides"]
    assert found[0]["id"] == "send_and_follow_up_a_quote"
    found = call("GET", f"{API}/help/guides?q=supplier csv").json()["guides"]
    assert found[0]["id"] == "set_up_your_price_book"
    jobs = call("GET", f"{API}/help/guides?screen=jobs").json()["guides"]
    assert jobs and all(x["screen"] == "jobs" for x in jobs)


def test_every_role_can_read_help(call, session_for):
    for role in nav.ALL:
        assert call("GET", f"{API}/help/guides", headers=session_for(role)).status == 200, role


def test_every_guide_belongs_to_a_real_screen_and_has_steps():
    places = {s["id"] for s in nav.SCREENS} | {p["id"] for p in nav.PAGES}
    for g in guides.list_guides():
        assert g["screen"] in places, g
        assert g["steps"] >= 3, g


def test_guides_name_real_buttons():
    """The steps quote the page's button labels - check they're really in app.js, so a renamed button fails here."""
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for label in ("⚡ Quick estimate", "Price it", "Next: approve and send →", "📋 Jobs board", "✓ Approve",
                  "📨 Send the quote…", "👍 Customer said yes", "Make it a job in AI-Prowler…", "Save changes…",
                  "Check the list…", "Mine only", "Show finished", "Use the sample prices anyway"):
        assert label in js, label


# ---------------------------------------------------------------- nav and page

def test_sprint4_screens_are_ready_and_pages_listed():
    ready = {s["id"] for s in nav.SCREENS if s["status"] == "ready"}
    assert {"bids", "help"} <= ready
    assert {"jobs", "job", "bid", "guide"} <= {p["id"] for p in nav.PAGES}
    assert {"est_jobs_board", "est_director_next", "bid_list", "how_to_estimate"} <= nav.all_tools()


def test_web_page_has_the_sprint4_screens():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needle in ("/jobs/", "/next", "/bids/", "/file?kind=", "/help/guides", "needs_confirmation", 'sandbox: ""'):
        assert needle in js, needle
    assert "innerHTML" not in js and "eval(" not in js
