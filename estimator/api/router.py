"""The Estimator Web App's JSON API and static files - plain Python, no web framework.

route(Request) -> Response. The HTTP host (estimator/api/server.py, or later
AI-Prowler's own middleware) only turns bytes into a Request and a Response back
into bytes, so every path, permission and error case here is unit tested
directly, the same way as the Service Desk's desk_http.route().

Every API call goes through the SAME service layer the MCP tools use
(estimator.estimating.service, .setup ...) with a RequestContext that names the
user, so the web app, chat and API-key agents follow one set of rules.

API (all JSON; /estimator-api/...):
  GET  /health                      no login: app is up, version, mode
  POST /auth/login                  {username, password} -> session cookie (+ token for the PWA)
  POST /auth/logout
  GET  /me                          who I am, my role, permissions and left menu
  GET  /dashboard                   counts by status, recent estimates, setup checklist
  GET  /estimates?status=&limit=    list
  POST /estimates                   {title, customer_id, address, due_date}
  GET  /estimates/<id>              one estimate (margins hidden for roles that can't see them)
  GET  /estimates/<id>/events       audit trail
  GET  /updates?since=<cursor>      live-update polling
  GET  /events                      server-sent events (streamed by the host; see server.py)
Sprint 2 (Coder 2):
  GET  /estimates/<id>/project      project page: estimate, per-trade subtotals and run (est_project_status), plan sets
  GET  /estimates/<id>/plans        plan sets on the estimate (plan_status estimate_id=...)
  POST /estimates/<id>/plans/stage?name=<file>[&supersedes=<plan set>]
                                    raw file body (streamed to disk, up to 300 MB); checked with plan_upload's
                                    checks and NOT attached yet: returns stage_id + what will be attached
  POST /estimates/<id>/plans/attach {stage_id, supersedes_plan_set_id} -> plan_upload confirm=true
  DELETE /estimates/<id>/plans/stage/<stage_id>   cancel a staged upload
  GET  /modules?path=quick          trade/service modules (est_list_modules)
  GET  /modules/<id>/questions      intake questions (est_quick_questions)
  POST /quick                       {module_id, answers, title?, address?, due_date?, customer_id?}
                                    or {estimate_id, rev, module_id, answers}: price it (est_quick_answer),
                                    creating the project first when there's no estimate_id
Sprint 3 (Coder 2), owner and estimator only:
  GET  /price-book?module_id=&samples_only=1     prices, yours or sample (pricebook_get)
  POST /price-book {prices: {key: "dollars"}, effective_date?, confirm?}     (pricebook_update; asks first)
  POST /price-book/import {csv_text, mapping?, add_new?, effective_date?, confirm?}   (pricebook_import; asks first)
Sprint 4 (Coder 2):
  GET  /jobs?mine=1&done=1          Jobs board (est_jobs_board)
  POST /jobs {request?, module_id?, answers?, address?, customer?}   start a job (est_director_start)
  GET  /jobs/<id>                   one job: next step, steps, estimate, latest bid (est_job_status)
  POST /jobs/<id>/next {answers?, approve?, confirm_sample_prices?, checklist_done?, reviewed?, customer?,
                        send?, send_to?, outcome?, convert?, service_date?, rev?, confirm?}   (est_director_next;
                        send and convert ask first: they need confirm=true)
  POST /quick (no estimate_id) now starts a quick-quote Director job, so the quote shows on the Jobs board
  Bids (owner, estimator, office): GET /bids?status=&estimate_id=, GET /bids/<id> (bid_preview),
       GET /bids/<id>/file?kind=html|pdf, POST /bids/<id>/send {to?, message?, confirm?} (asks first),
       POST /bids/<id>/status {status}, POST /bids/<id>/convert {customer?, service_date?, confirm?} (asks first)
  GET  /help/guides?q=&screen=      how-to guides; GET /help/guides/<id> one guide
Static: /estimator and /estimator/<file> from estimator/ui/web/.
"""
from __future__ import annotations

import json
import logging
import mimetypes
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import estimator
from estimator.api import auth, live, nav
from estimator.errors import EstimatorError

log = logging.getLogger("estimator.api")

API = "/estimator-api"
APP = "/estimator"
WEB_DIR = Path(__file__).resolve().parents[1] / "ui" / "web"
MAX_JSON_BODY = 1024 * 1024
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
                ".ico": "image/x-icon", ".json": "application/json", ".webmanifest": "application/manifest+json"}
ERROR_STATUS = {"not_found": 404, "invalid_input": 400, "stale_revision": 409, "not_editable": 409,
                "permission_denied": 403, "needs_confirmation": 428}
# Keys never sent to a role that can't see margins (spec: field staff don't see margins).
MARGIN_WORDS = ("cost", "margin", "overhead", "profit", "burden", "markup")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    # Sprint 3: the Jobs app (same site, port 8000) shows the Estimator in its Estimates tab, so it may be
    # framed by pages from its own origin only - never by another site.
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    # Self-contained app (spec: no CDN, no web fonts): only our own files may load.
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; "
                               "script-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'",
}


@dataclass
class Request:
    method: str
    path: str                       # may include ?query
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    client_ip: str = "127.0.0.1"
    secure: bool = False            # HTTPS (sets the cookie's Secure flag)
    stream: object = None           # plan uploads: the socket to read the body from (not read by the host)
    length: int = 0                 # ... and how many bytes it holds (Content-Length)

    def __post_init__(self):
        parts = urlsplit(self.path)
        self.path = unquote(parts.path) or "/"
        self.query = {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        self.method = self.method.upper()


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: dict = field(default_factory=dict)

    def json(self) -> dict:
        return json.loads(self.body.decode("utf-8"))


def _json(status: int, payload: dict, headers: dict | None = None) -> Response:
    h = {"Cache-Control": "no-store", **SECURITY_HEADERS, **(headers or {})}
    return Response(status, "application/json", json.dumps(payload, default=str).encode("utf-8"), h)


def _ok(**payload) -> Response:
    return _json(200, {"ok": True, **payload})


def _fail(status: int, error: str, message: str, **extra) -> Response:
    return _json(status, {"ok": False, "error": error, "message": message, **extra})


def _body(req: Request) -> dict:
    if not req.body:
        return {}
    if len(req.body) > MAX_JSON_BODY:
        raise _Refuse(413, "too_large", "the request is too large")
    try:
        data = json.loads(req.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Refuse(400, "invalid_input", "the request body is not valid JSON") from None
    if not isinstance(data, dict):
        raise _Refuse(400, "invalid_input", "the request body must be a JSON object")
    return data


class _Refuse(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


def _open_db():
    from estimator.database import open_database
    return open_database()


# ------------------------------------------------------------------ role redaction

def redact(value, see_margins: bool):
    """Drop cost and margin fields for roles that may not see them."""
    if see_margins:
        return value
    if isinstance(value, dict):
        return {k: redact(v, see_margins) for k, v in value.items()
                if k != "calc" and not any(w in k.lower() for w in MARGIN_WORDS)}
    if isinstance(value, list):
        return [redact(v, see_margins) for v in value]
    return value


# ------------------------------------------------------------------ entry point

def route(req: Request, open_db=None) -> Response:
    """Handle one request. Never raises: every failure becomes a JSON (or text) error."""
    try:
        if req.path == APP or req.path.startswith(APP + "/"):
            return static(req.path)
        if req.path == API or req.path.startswith(API + "/"):
            return _api(req, open_db or _open_db)
        return _fail(404, "not_found", "no such page")
    except _Refuse as e:
        return _fail(e.status, e.error, e.message)
    except EstimatorError as e:
        return _json(ERROR_STATUS.get(e.code, 400), e.as_dict())
    except Exception:  # noqa: BLE001 - never show a stack trace to the browser
        log.exception("Estimator web API error on %s %s", req.method, req.path)
        return _fail(500, "server_error", "something went wrong in the Estimator; see the Estimator log")


def _me(caller: auth.Caller) -> dict:
    ctx = caller.ctx
    return {"user_id": ctx.user_id, "name": caller.name, "role": ctx.role, "mode": ctx.mode,
            "company_id": ctx.company_id, "signed_in_by": caller.how,
            "can_sign_out": caller.how == "session",
            "permissions": nav.permissions(ctx.role), "menu": nav.menu_for(ctx.role),
            "version": estimator.__version__}


def _api(req: Request, open_db) -> Response:
    sub = req.path[len(API):] or "/"
    m = req.method

    if sub == "/health" and m == "GET":
        return _ok(app="AI-Prowler Estimator", version=estimator.__version__, mode=auth.mode())

    if not auth.write_allowed(m, req.headers):
        return _fail(403, "csrf", "this change must come from the Estimator web app")

    if sub == "/auth/login" and m == "POST":
        b = _body(req)
        try:
            token, caller = auth.login(str(b.get("username", "")), str(b.get("password", "")), req.client_ip)
        except auth.LoginError as e:
            return _fail({"locked": 429, "invalid_input": 400, "not_configured": 503,
                          "permission_denied": 403}.get(e.code, 401), e.code, e.message)
        return _json(200, {"ok": True, "token": token, "me": _me(caller)},
                     {"Set-Cookie": auth.cookie_header(token, req.secure)})

    caller = auth.resolve(req.headers, req.client_ip)

    if sub == "/auth/logout" and m == "POST":
        if caller is not None and caller.token:
            auth.end_session(caller.token)
        return _json(200, {"ok": True}, {"Set-Cookie": auth.clear_cookie_header()})

    if caller is None:
        return _fail(401, "login_required", "sign in to use the Estimator", mode=auth.mode())

    if sub == "/me" and m == "GET":
        return _ok(me=_me(caller))

    conn = open_db()
    try:
        return _api_data(m, sub, req, caller, conn)
    finally:
        conn.close()


_EST = re.compile(r"^/estimates/(\d+)$")
_EST_EVENTS = re.compile(r"^/estimates/(\d+)/events$")
_PROJECT = re.compile(r"^/estimates/(\d+)/project$")
_PLANS = re.compile(r"^/estimates/(\d+)/plans$")
_STAGE = re.compile(r"^/estimates/(\d+)/plans/stage$")
_STAGE_ONE = re.compile(r"^/estimates/(\d+)/plans/stage/([A-Za-z0-9_-]{8,64})$")
_ATTACH = re.compile(r"^/estimates/(\d+)/plans/attach$")
_QUESTIONS = re.compile(r"^/modules/([A-Za-z0-9_]{1,64})/questions$")
QUICK_PATHS = ("quick_estimate", "both")


def is_upload(method: str, path: str) -> bool:
    """True for the one call whose body the host must NOT read into memory (plan files up to 300 MB)."""
    p = unquote(urlsplit(path).path)
    return method.upper() == "POST" and p.startswith(API + "/") and bool(_STAGE.match(p[len(API):]))


def _api_data(m: str, sub: str, req: Request, caller: auth.Caller, conn) -> Response:
    from estimator.estimating import service

    ctx = caller.ctx
    see = nav.permissions(ctx.role).get("see_margins", False)

    if sub == "/dashboard" and m == "GET":
        listing = service.list_estimates(conn, ctx, limit=500)["estimates"]
        by_status: dict[str, int] = {}
        for e in listing:
            by_status[e["status"]] = by_status.get(e["status"], 0) + 1
        setup = None
        if ctx.role == "owner":
            try:
                from estimator.estimating.setup import setup_status
                setup = setup_status(conn, ctx)
            except EstimatorError:
                setup = None
        # Sprint 2: what needs a person now - estimates waiting for review, and my assigned work and notices.
        waiting_review = [e for e in listing if e["status"] == "in_review" and not e.get("practice")]
        try:
            from estimator.team import my_work
            mine = my_work(conn, ctx)
            mine = {k: mine[k] for k in ("estimates", "jobs", "notices", "summary")}
        except EstimatorError:
            mine = None
        return _ok(counts=by_status, total=len(listing), recent=redact(listing[:8], see), setup=setup,
                   attention=redact(waiting_review[:20], see), my_work=mine,
                   can_quick=ctx.role in service.QUICK_ROLES, cursor=live.latest_cursor(conn, ctx))

    if sub == "/estimates" and m == "GET":
        limit = req.query.get("limit") or 50
        status = req.query.get("status") or None
        try:
            limit = int(limit)
        except ValueError:
            raise _Refuse(400, "invalid_input", "limit must be a whole number") from None
        return _json(200, redact(service.list_estimates(conn, ctx, status=status, limit=limit), see))

    if sub == "/estimates" and m == "POST":
        b = _body(req)
        title = str(b.get("title") or "").strip()
        if not title:
            raise _Refuse(400, "invalid_input", "give the project a name")
        if len(title) > 200:
            raise _Refuse(400, "invalid_input", "the project name is too long (200 characters at most)")
        est = service.create_estimate(conn, ctx, title, customer_id=_opt(b, "customer_id"),
                                      address=_opt(b, "address"), due_date=_opt(b, "due_date"))
        return _json(201, redact(est, see))

    mm = _EST.match(sub)
    if mm and m == "GET":
        return _json(200, redact(service.get_estimate(conn, ctx, int(mm.group(1))), see))

    mm = _EST_EVENTS.match(sub)
    if mm and m == "GET":
        evs = service.events(conn, ctx, int(mm.group(1)))
        if not see:
            evs = [{k: v for k, v in e.items() if k != "after_json"} for e in evs]
        return _ok(events=evs)

    if sub == "/updates" and m == "GET":
        since = live.parse_cursor(req.query.get("since")) if req.query.get("since", "") != "" else None
        return _json(200, live.updates(conn, ctx, since))

    # ---------------------------------------------------------- Sprint 2: project page and plan uploads
    mm = _PROJECT.match(sub)
    if mm and m == "GET":
        from estimator.drawing_model import store
        from estimator.runner import runner
        eid = int(mm.group(1))
        est = service.get_estimate(conn, ctx, eid)
        status = runner.project_status(conn, ctx, eid)
        plans = store.list_plan_sets(conn, ctx, eid)["plan_sets"]
        return _ok(estimate=redact(est, see), status=redact(status, see), plan_sets=plans,
                   can_upload=ctx.role in store.UPLOAD_ROLES, can_quick=ctx.role in service.QUICK_ROLES,
                   editable=est["status"] in service.EDITABLE_STATUSES)

    mm = _PLANS.match(sub)
    if mm and m == "GET":
        from estimator.drawing_model import engine, store
        out = store.list_plan_sets(conn, ctx, int(mm.group(1)))
        return _ok(plan_sets=out["plan_sets"], count=out["count"], engine=engine.engine_info())

    mm = _STAGE.match(sub)
    if mm and m == "POST":
        return _stage_plan(req, ctx, conn, int(mm.group(1)))

    mm = _ATTACH.match(sub)
    if mm and m == "POST":
        from estimator.api import staging
        from estimator.drawing_model import store
        eid, b = int(mm.group(1)), _body(req)
        stage_id = str(b.get("stage_id") or "")
        path = staging.get(stage_id, ctx, eid)
        try:
            out = store.upload(conn, ctx, eid, str(path), _int_opt(b.get("supersedes_plan_set_id")), confirm=True)
        finally:
            staging.drop(stage_id)
        return _json(201, out)

    mm = _STAGE_ONE.match(sub)
    if mm and m == "DELETE":
        from estimator.api import staging
        staging.get(mm.group(2), ctx, int(mm.group(1)))      # only the person who uploaded it can cancel it
        staging.drop(mm.group(2))
        return _ok(cancelled=True)

    # ---------------------------------------------------------- Sprint 2: quick estimate screen
    if sub == "/modules" and m == "GET":
        from estimator.modules import get_registry
        reg = get_registry()
        want = (req.query.get("path") or "").strip()
        mods = [x.summary() for x in reg.list()
                if not want or (want == "quick" and x.path in QUICK_PATHS) or x.path == want]
        mods.sort(key=lambda x: (x["category"] != "service", x["name"].lower()))
        return _ok(modules=mods, count=len(mods))

    mm = _QUESTIONS.match(sub)
    if mm and m == "GET":
        from estimator.estimating import quick
        return _json(200, quick.questions(mm.group(1)))

    if sub == "/quick" and m == "POST":
        return _quick(req, ctx, conn, see)

    # ---------------------------------------------------------- Sprint 3: Price Book screen (basic)
    if sub.startswith("/price-book"):
        return _price_book(m, sub, req, ctx, conn)

    # ---------------------------------------------------------- Sprint 4: Jobs board, Bids screen, Help
    if sub == "/jobs" or sub.startswith("/jobs/"):
        return _jobs(m, sub, req, ctx, conn, see)
    if sub == "/bids" or sub.startswith("/bids/"):
        return _bids(m, sub, req, ctx, conn, see)
    if sub == "/help/guides" or sub.startswith("/help/guides/"):
        return _help(m, sub, req)

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")


def _question(message: str) -> str:
    """The service layer's confirm question without the 'call again with confirm=true' part meant for the AI."""
    cut = re.split(r"\s+(?:Call again|Show the user)\b", message, maxsplit=1)[0]
    return cut.strip()


def _ask_first(fn) -> Response:
    """Run a write that asks first: the page shows the question and the details, then sends confirm=true."""
    from estimator.errors import ConfirmationRequired
    try:
        return _ok(**fn())
    except ConfirmationRequired as e:
        return _ok(needs_confirmation=True, question=_question(e.message), **e.details)


def _price_book(m: str, sub: str, req: Request, ctx, conn) -> Response:
    """GET  /price-book?module_id=&samples_only=1     pricebook_get
       POST /price-book {prices, effective_date, confirm}                         pricebook_update
       POST /price-book/import {csv_text, mapping, add_new, effective_date, confirm}   pricebook_import (pasted CSV)
    Costs are company secrets: only the roles that open the Price Book screen may read them here."""
    from estimator.pricing import importer, price_book

    if not nav.can_open(ctx.role, "price_book"):
        raise _Refuse(403, "permission_denied", "your role can't see the price book")
    if sub == "/price-book" and m == "GET":
        out = price_book.list_prices(conn, ctx.company_id, (req.query.get("module_id") or "").strip() or None,
                                     req.query.get("samples_only", "") in ("1", "true", "yes"))
        return _json(200, out)
    if sub == "/price-book" and m == "POST":
        b = _body(req)
        prices = b.get("prices")
        if not isinstance(prices, dict) or not prices:
            raise _Refuse(400, "invalid_input", "change at least one price")
        if len(prices) > 500:
            raise _Refuse(400, "invalid_input", "change at most 500 prices at a time")
        return _ask_first(lambda: price_book.update_prices(conn, ctx, {str(k): str(v) for k, v in prices.items()},
                                                           confirm=b.get("confirm") is True,
                                                           effective_date=_opt(b, "effective_date")))
    if sub == "/price-book/import" and m == "POST":
        b = _body(req)
        text = b.get("csv_text")
        if not isinstance(text, str) or not text.strip():
            raise _Refuse(400, "invalid_input", "paste the price list (CSV with a header row)")
        mapping = b.get("mapping") or None
        if mapping is not None and not isinstance(mapping, dict):
            raise _Refuse(400, "invalid_input", "mapping must be an object, e.g. {\"cost\": \"Unit Price\"}")
        return _ask_first(lambda: importer.import_prices(conn, ctx, csv_text=text, mapping=mapping,
                                                         effective_date=_opt(b, "effective_date"),
                                                         add_new=b.get("add_new") is True,
                                                         confirm=b.get("confirm") is True))
    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")


# ------------------------------------------------------------------ Sprint 4: Jobs board (Director)

_JOB = re.compile(r"^/jobs/(\d+)$")
_JOB_NEXT = re.compile(r"^/jobs/(\d+)/next$")
_BID = re.compile(r"^/bids/(\d+)$")
_BID_ACT = re.compile(r"^/bids/(\d+)/(send|status|convert|file)$")
_GUIDE = re.compile(r"^/help/guides/([a-z0-9_]{1,64})$")
# What the page may hand est_director_next. Flags must be literal true/false (never "yes" or 1).
NEXT_FLAGS = ("approve", "confirm_sample_prices", "checklist_done", "reviewed", "send", "convert")
NEXT_TEXT = ("module_id", "send_to", "outcome", "service_date")
NEXT_KEYS = set(NEXT_FLAGS) | set(NEXT_TEXT) | {"answers", "customer", "rev", "confirm"}
# Where the bid files live on the PC or server: the browser gets them through /bids/<id>/file, never the path.
LOCAL_PATHS = ("html_path", "pdf_path")


def _flag(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes")


def _no_paths(value):
    """Drop local file paths (C:\\Users\\...) from what goes to the browser; say whether a PDF exists instead."""
    if isinstance(value, dict):
        out = {k: _no_paths(v) for k, v in value.items() if k not in LOCAL_PATHS}
        if "pdf_path" in value:
            out["has_pdf"] = bool(value["pdf_path"])
        return out
    if isinstance(value, list):
        return [_no_paths(v) for v in value]
    return value


def _answers(b: dict) -> dict:
    a = b.get("answers")
    if a is None:
        return {}
    if not isinstance(a, dict):
        raise _Refuse(400, "invalid_input", "answers must be an object of question id -> answer")
    return a


def _customer(value) -> dict | None:
    if value in (None, {}):
        return None
    if not isinstance(value, dict):
        raise _Refuse(400, "invalid_input", "customer must be an object with name, email, phone, address")
    return {str(k): ("" if v is None else str(v).strip())[:200] for k, v in value.items()}


def _jobs(m: str, sub: str, req: Request, ctx, conn, see: bool) -> Response:
    """GET  /jobs?mine=1&done=1            est_jobs_board
       POST /jobs {request?, module_id?, answers?, address?, due_date?, customer?}   est_director_start
       GET  /jobs/<id>                     est_job_status, plus the estimate and its latest bid
       POST /jobs/<id>/next {...}          est_director_next (send and convert ask first: confirm=true)"""
    from estimator.bids import service as bids
    from estimator.director import engine as director
    from estimator.estimating import service

    if sub == "/jobs" and m == "GET":
        out = director.board(conn, ctx, mine=_flag(req.query.get("mine")), include_done=_flag(req.query.get("done")))
        return _json(200, {**redact(out, see), "can_start": ctx.role in service.QUICK_ROLES})

    if sub == "/jobs" and m == "POST":
        if ctx.role not in service.QUICK_ROLES:
            raise _Refuse(403, "permission_denied", f"only {', '.join(service.QUICK_ROLES)} can start a job")
        b = _body(req)
        request, module_id = _opt(b, "request"), _opt(b, "module_id")
        if not request and not module_id:
            raise _Refuse(400, "invalid_input", "say what the job is (e.g. \"wash a 1,000 sq ft driveway\"), or pick "
                                                "a service")
        out = director.start(conn, ctx, request or "", module_id=module_id, answers=_answers(b),
                             address=_opt(b, "address"), due_date=_opt(b, "due_date"),
                             customer=_customer(b.get("customer")), customer_id=_opt(b, "customer_id"))
        return _json(201, _no_paths(redact(out, see)))

    mm = _JOB.match(sub)
    if mm and m == "GET":
        out = director.status(conn, ctx, int(mm.group(1)))
        eid = out["job"]["estimate_id"]
        est = service.get_estimate(conn, ctx, eid) if eid else None
        bid = bids.latest_for_estimate(conn, ctx, eid) if eid else None
        return _json(200, _no_paths(redact({**out, "estimate_detail": est, "bid": bids._public(bid) if bid else None,
                                            "can_open_bids": nav.can_open(ctx.role, "bids")}, see)))

    mm = _JOB_NEXT.match(sub)
    if mm and m == "POST":
        jid, b = int(mm.group(1)), _body(req)
        unknown = sorted(set(b) - NEXT_KEYS)
        if unknown:
            raise _Refuse(400, "invalid_input", "the Director doesn't take: " + ", ".join(unknown))
        kw: dict = {}
        for f in NEXT_FLAGS:
            if f in b:
                if not isinstance(b[f], bool):
                    raise _Refuse(400, "invalid_input", f"{f} must be true or false")
                kw[f] = b[f]
        for f in NEXT_TEXT:
            if f in b:
                kw[f] = _opt(b, f)
        if "answers" in b:
            kw["answers"] = _answers(b)
        if "customer" in b:
            kw["customer"] = _customer(b["customer"])
        if b.get("rev") is not None:
            try:
                kw["rev"] = int(b["rev"])
            except (TypeError, ValueError):
                raise _Refuse(400, "invalid_input", "rev must be a whole number") from None
        if (kw.get("send") or kw.get("convert")) and b.get("confirm") is not True:
            return _ok(needs_confirmation=True, question=_next_question(conn, ctx, jid, kw))
        return _json(200, _no_paths(redact(director.next_step(conn, ctx, jid, **kw), see)))

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")


def _next_question(conn, ctx, jid: int, kw: dict) -> str:
    """The yes/no question the page shows before the Director emails a customer or creates a job in AI-Prowler."""
    from estimator.bids import service as bids
    from estimator.core.units.money import format_cents
    from estimator.director import engine as director

    st = director.status(conn, ctx, jid)
    eid = st["job"]["estimate_id"]
    bid = bids.latest_for_estimate(conn, ctx, eid) if eid else None
    total = bid["total_cents"] if bid else (st.get("estimate") or {}).get("total_cents", 0)
    money = format_cents(total)
    if kw.get("convert"):
        when = f" for {kw['service_date']}" if kw.get("service_date") else ""
        return (f"Turn this {money} quote into a job{when}? This creates the customer (if new), an approved quote "
                "and a job in AI-Prowler.")
    to = kw.get("send_to") or ((kw.get("customer") or {}).get("email")) or (bid["customer"].get("email") if bid else "")
    return f"Email the {money} quote to {to}?" if to else f"Email the {money} quote to the customer?"


# ------------------------------------------------------------------ Sprint 4: Bids screen

def _bids(m: str, sub: str, req: Request, ctx, conn, see: bool) -> Response:
    """GET  /bids?status=&estimate_id=     bid_list
       GET  /bids/<id>                     bid_preview
       GET  /bids/<id>/file?kind=html|pdf  the bid as the customer sees it (HTML shown sandboxed; PDF downloads)
       POST /bids/<id>/send {to?, message?, confirm?}               bid_send (asks first)
       POST /bids/<id>/status {status}                              bid_set_status
       POST /bids/<id>/convert {customer?, service_date?, confirm?} bid_convert_to_job (asks first)"""
    from estimator.bids import service as bids

    if not nav.can_open(ctx.role, "bids"):
        raise _Refuse(403, "permission_denied", "your role can't open the Bids screen")
    if sub == "/bids" and m == "GET":
        out = bids.list_bids(conn, ctx, status=(req.query.get("status") or "").strip() or None,
                             estimate_id=_int_opt(req.query.get("estimate_id")))
        return _json(200, _no_paths(redact(out, see)))
    mm = _BID.match(sub)
    if mm and m == "GET":
        return _json(200, _no_paths(redact(bids.preview(conn, ctx, int(mm.group(1))), see)))
    mm = _BID_ACT.match(sub)
    if not mm:
        return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
    bid_id, act = int(mm.group(1)), mm.group(2)
    if act == "file" and m == "GET":
        return _bid_file(conn, ctx, bid_id, (req.query.get("kind") or "html").strip().lower())
    if m != "POST":
        return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
    b = _body(req)
    if act == "send":
        return _ask_first(lambda: _no_paths(bids.send(conn, ctx, bid_id, to=_opt(b, "to"), message=_opt(b, "message"),
                                                      confirm=b.get("confirm") is True)))
    if act == "status":
        status = _opt(b, "status")
        if not status:
            raise _Refuse(400, "invalid_input", "status is missing (viewed, won, lost, expired or void)")
        return _json(200, _no_paths(bids.set_status(conn, ctx, bid_id, status)))
    return _ask_first(lambda: _no_paths(bids.convert_to_job(conn, ctx, bid_id, confirm=b.get("confirm") is True,
                                                            customer=_customer(b.get("customer")),
                                                            service_date=_opt(b, "service_date"))))


def _bid_file(conn, ctx, bid_id: int, kind: str) -> Response:
    from estimator import config
    from estimator.bids import service as bids

    if kind not in ("html", "pdf"):
        raise _Refuse(400, "invalid_input", "kind is html or pdf")
    b = bids._load(conn, ctx, bid_id)                      # not found / another company's bid
    stored = b["html_path"] if kind == "html" else b["pdf_path"]
    if not stored:
        raise _Refuse(404, "not_found", f"quote {b['number']} has no PDF (the PDF printer wasn't available); "
                                        "use the HTML copy")
    path, root = Path(stored).resolve(), config.data_dir().resolve()
    if root not in path.parents or not path.is_file():      # only files the Estimator wrote, in its own folder
        raise _Refuse(404, "not_found", f"the {kind.upper()} file for quote {b['number']} is missing")
    headers = {"Cache-Control": "no-store", **SECURITY_HEADERS}
    if kind == "html":
        # Shown in a frame on the Bids screen: no scripts, no network, nothing from outside the file itself.
        headers["Content-Security-Policy"] = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
                                              "frame-ancestors 'self'; sandbox")
        return Response(200, "text/html; charset=utf-8", path.read_bytes(), headers)
    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; sandbox"
    headers["Content-Disposition"] = f'attachment; filename="{re.sub(r"[^A-Za-z0-9_.-]", "_", b["number"])}.pdf"'
    return Response(200, "application/pdf", path.read_bytes(), headers)


# ------------------------------------------------------------------ Sprint 4: Help (how-to guides)

def _help(m: str, sub: str, req: Request) -> Response:
    """GET /help/guides?q=&screen=   the how-to guides (searchable)
       GET /help/guides/<id>         one guide's steps (Markdown text)"""
    from estimator.ui import help as guides

    if m != "GET":
        return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
    if sub == "/help/guides":
        q = (req.query.get("q") or "").strip()[:200]
        found = guides.search(q) if q else guides.list_guides()
        screen = (req.query.get("screen") or "").strip()
        if screen:
            found = [g for g in found if g["screen"] == screen]
        return _ok(guides=found, count=len(found))
    mm = _GUIDE.match(sub)
    if mm:
        return _ok(guide=guides.get_guide(mm.group(1)))
    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")


def _int_opt(value) -> int | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise _Refuse(400, "invalid_input", "that should be a whole number") from None
    if n < 1:
        raise _Refuse(400, "invalid_input", "that should be a positive number")
    return n


def _stage_plan(req: Request, ctx, conn, eid: int) -> Response:
    """Receive a plan file from the browser, check it like plan_upload, and hold it until the user confirms."""
    import io

    from estimator.api import staging
    from estimator.drawing_model import store, uploads
    from estimator.errors import ConfirmationRequired
    from estimator.estimating import service

    # Everything that can be refused is refused BEFORE reading a byte of the (up to 300 MB) body.
    if ctx.role not in store.UPLOAD_ROLES:
        raise _Refuse(403, "permission_denied", f"only {', '.join(store.UPLOAD_ROLES)} can upload plans")
    service._load_row(conn, ctx, eid)                       # not found / another company's estimate
    name = (req.query.get("name") or "").strip()
    if not name:
        raise _Refuse(400, "invalid_input", "the file name is missing")
    ext = Path(staging.safe_name(name)).suffix
    if ext not in uploads.EXTENSIONS:
        raise _Refuse(400, "invalid_input", f"{ext or 'files without an extension'} can't be used; plans can be "
                                            "PDF, PNG, JPG, TIFF, DXF or DWG")
    length = req.length if req.stream is not None else len(req.body)
    if length <= 0:
        raise _Refuse(400, "invalid_input", f"{name} is empty")
    if length > uploads.MAX_BYTES:
        raise _Refuse(413, "too_large", f"{name} is {length // (1024 * 1024)} MB; the limit is "
                                        f"{uploads.MAX_BYTES // (1024 * 1024)} MB. Split the set or upload the "
                                        "sheets you need")
    supersedes = _int_opt(req.query.get("supersedes"))
    stage_id, path = staging.new(ctx, eid, name)
    try:
        got = staging.receive(req.stream if req.stream is not None else io.BytesIO(req.body), length, path)
        if got != length:
            raise _Refuse(400, "upload_incomplete", "the upload was cut off; please try again")
        try:
            store.upload(conn, ctx, eid, str(path), supersedes, confirm=False)
        except ConfirmationRequired as e:
            question = e.message.replace(" Call again with confirm=true.", "")
            return _ok(needs_confirmation=True, stage_id=stage_id, question=question, details=e.details)
        raise _Refuse(500, "server_error", "the upload wasn't checked; please try again")   # never attach unasked
    except BaseException:
        staging.drop(stage_id)
        raise


def _quick(req: Request, ctx, conn, see: bool) -> Response:
    """Price a quick estimate: answers checked first, then (if needed) the project created, then est_quick_answer."""
    from estimator.estimating import quick, service
    from estimator.modules import get_registry

    if ctx.role not in service.QUICK_ROLES:
        raise _Refuse(403, "permission_denied", f"only {', '.join(service.QUICK_ROLES)} can give quick quotes")
    b = _body(req)
    module_id = str(b.get("module_id") or "").strip()
    if not module_id:
        raise _Refuse(400, "invalid_input", "pick a service")
    mod = get_registry().get(module_id)                     # not_found lists the modules
    if mod.path not in QUICK_PATHS:
        raise _Refuse(400, "invalid_input", f"{mod.name} doesn't have a quick estimate; use a project instead")
    answers = b.get("answers")
    if not isinstance(answers, dict):
        raise _Refuse(400, "invalid_input", "answers must be an object of question id -> answer")
    quick.resolve_answers(mod, answers)                     # bad answers never leave an empty project behind
    eid = _int_opt(b.get("estimate_id"))
    if eid is None:
        # Sprint 4: a new quick quote is a Director job (quick quote lane), so it shows on the Jobs board and the
        # page can carry on to approve, send and convert it - the same steps est_director_start gives in chat.
        from estimator.director import engine as director
        address = _opt(b, "address")
        title = _opt(b, "title") or (f"{mod.name} – {address}" if address else mod.name)
        if len(title) > 200:
            raise _Refuse(400, "invalid_input", "the project name is too long (200 characters at most)")
        out = director.start(conn, ctx, title, module_id=module_id, answers=answers, address=address,
                             due_date=_opt(b, "due_date"), customer_id=_opt(b, "customer_id"),
                             customer=_customer(b.get("customer")))
        est = service.get_estimate(conn, ctx, out["job"]["estimate_id"])
        return _json(201, _no_paths(redact({**est, "warnings": out.get("notes") or [], "job": out["job"],
                                            "next_step": out["next_step"], "created": True}, see)))
    try:
        rev = int(b.get("rev"))
    except (TypeError, ValueError):
        raise _Refuse(400, "invalid_input", "rev is needed to change an existing estimate") from None
    result = quick.answer(conn, ctx, eid, module_id, answers, rev)
    return _json(200, {**redact(result, see), "created": False})


def _opt(b: dict, key: str) -> str | None:
    v = b.get(key)
    if v is None:
        return None
    v = str(v).strip()
    if len(v) > 500:
        raise _Refuse(400, "invalid_input", f"{key} is too long")
    return v or None


# ------------------------------------------------------------------ static files

def static(path: str) -> Response:
    if path == APP:   # relative links in index.html need the trailing slash
        return Response(301, "text/plain; charset=utf-8", b"", {"Location": APP + "/", **SECURITY_HEADERS})
    rel = path[len(APP):].lstrip("/") or "index.html"
    if rel.endswith("/"):
        rel += "index.html"
    try:
        target = (WEB_DIR / rel).resolve()
        target.relative_to(WEB_DIR.resolve())
    except (ValueError, OSError):
        return _fail(404, "not_found", "no such file")
    ext = target.suffix.lower()
    if ext not in STATIC_TYPES or not target.is_file():
        # Unknown screens (#/plans etc. are hash routes, but a typed /estimator/plans also works).
        if "." not in Path(rel).name:
            target, ext = WEB_DIR / "index.html", ".html"
        else:
            return _fail(404, "not_found", "no such file")
    data = target.read_bytes()
    headers = {**SECURITY_HEADERS, "Cache-Control": "no-cache"}
    return Response(200, STATIC_TYPES.get(ext) or mimetypes.guess_type(target.name)[0] or "application/octet-stream",
                    data, headers)
