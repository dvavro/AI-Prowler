"""
desk_http.py — AI-Prowler Service Desk, Phase 1: the /desk-api routes and the
/desk/ app files.

ai_prowler_mcp.py's request middleware (personal and server routers) does
only two things for Service Desk: works out WHO is calling (owner token in
personal mode; a signed-in user's access token in server mode) and hands the
request to route() here. route() is plain Python — no ASGI — so every path,
permission and stale-edit case is unit tested directly.

Routes (all JSON unless noted; caller already authenticated):
  GET  /desk-api/me                          caller, edition, settings
  GET  /desk-api/tickets?open_only=1&mine=1&state=&kind=&text=&overdue=1
  GET  /desk-api/updates?since=<cursor>      live-update polling
  GET  /desk-api/tickets/<id>                full ticket as the caller may see it
  POST /desk-api/tickets                     file a ticket
  POST /desk-api/tickets/<id>/state          {to_state, reason, expected_version}
  POST /desk-api/tickets/<id>/assign         {assignee, expected_version}
  POST /desk-api/tickets/<id>/update         {fields, reason, expected_version}
  POST /desk-api/tickets/<id>/messages       {body, visibility}
  POST /desk-api/tickets/<id>/attachments    multipart: file(s), visibility, message_id
  GET  /desk-api/attachments/<n>[?thumb=1]   the file itself (auth-checked)
  GET  /desk-api/settings | POST /desk-api/settings {key, value}
  GET  /desk-api/contacts?type=customer      contacts for the filing form (staff)
"""
from __future__ import annotations

import email.parser
import email.policy
import json
import mimetypes
import re
from pathlib import Path
from urllib.parse import unquote

import desk_attachments
import desk_db
import desk_rules as rules

APP_DIR = Path(__file__).resolve().parent / "desk"
JSON = b"application/json"
_TID = r"(T-\d{4,})"


def _j(status: int, payload) -> tuple:
    return status, JSON, json.dumps(payload, default=str).encode("utf-8")


def _ok(**payload) -> tuple:
    return _j(200, {"ok": True, **payload})


def _fail(status: int, error: str, message: str) -> tuple:
    return _j(status, {"ok": False, "error": error, "message": message})


def _parse_json(body: bytes) -> dict:
    if not body:
        return {}
    try:
        v = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise desk_db.DeskError("the request body is not valid JSON")
    if not isinstance(v, dict):
        raise desk_db.DeskError("the request body must be a JSON object")
    return v


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def parse_multipart(body: bytes, content_type: str) -> tuple[dict, list]:
    """(form fields, [(filename, bytes), ...]) from a multipart/form-data body."""
    if "multipart/form-data" not in (content_type or "").lower():
        raise desk_db.DeskError("upload must be multipart/form-data")
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body)
    fields, files = {}, []
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        fname = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if fname:
            files.append((fname, payload))
        elif name:
            fields[name] = payload.decode("utf-8", "replace")
    return fields, files


# How a customer reached the team when someone files a customer request for
# them in the app (2026-10-29). "pwa" = not said.
PWA_SOURCES = ("phone", "sms", "email", "walk_in", "pwa")


def public_ticket(t: dict, actor) -> dict:
    """A ticket row trimmed for list views; outside parties lose internals."""
    keep = ("ticket_id", "title", "kind", "type", "priority", "state", "assignee",
            "contact_id", "customer_id", "job_id", "due_resolve_at", "created_at",
            "last_edited_at", "version", "sms_fallback", "visibility", "queue_id", "filed_by",
            "csat_score")
    out = {k: t.get(k) for k in keep}
    if rules.is_external(actor):
        for k in ("assignee", "visibility", "queue_id", "filed_by", "sms_fallback"):
            out.pop(k, None)
    return out


def directory(db: str, actor, services: dict, query: str = "") -> list[dict]:
    """Every email address the team may pick from (2026-10-28, David: "all
    emails, including customers, past ticket contacts, saved contacts and team
    members"): services["directory"](actor) supplies the team, the caller's
    saved contacts (crew: their own private list) and the Jobs app's customers;
    past ticket contacts come from the tickets database. One entry per address,
    first source wins. Outside parties get nothing."""
    if rules.is_external(actor):
        raise desk_db.DeskError("only the team can look up addresses")
    entries = []
    fn = services.get("directory")
    if fn:
        try:
            entries.extend(fn(actor) or [])
        except Exception:  # noqa: BLE001 — a lookup must never break the app
            pass
    conn = desk_db.get_connection(db)
    try:
        for r in conn.execute("SELECT name, email, phone, contact_type FROM customer_contacts "
                              "WHERE email IS NOT NULL AND email != '' ORDER BY name"):
            entries.append({"name": r["name"] or "", "email": r["email"], "phone": r["phone"] or "",
                            "source": "past " + ("customer" if r["contact_type"] == "customer"
                                                 else "subcontractor")})
    finally:
        conn.close()
    seen, out = set(), []
    for e in entries:
        em = str(e.get("email") or "").strip().lower()
        if not em or em in seen or not desk_db._EMAIL_RE.match(em):
            continue
        seen.add(em)
        out.append({"name": str(e.get("name") or ""), "email": em, "phone": str(e.get("phone") or ""),
                    "source": str(e.get("source") or ""), "user_id": str(e.get("user_id") or "")})
    qq = (query or "").strip().lower()
    if qq:
        out = [e for e in out if qq in e["email"] or qq in e["name"].lower()]
    return out[:1000]


def route(method: str, path: str, *, query: dict, body: bytes, content_type: str,
          actor, edition: str, db_path: str, services: dict | None = None) -> tuple:
    """Handle one /desk-api request. Returns (status, content_type, body_bytes).
    services: {"base_url": "https://…", "create_job": fn(updates) -> text} from
    ai_prowler_mcp.py (status links and Jobs app re-do jobs)."""
    sub = path[len("/desk-api"):] or "/"
    try:
        return _route(method.upper(), sub, query or {}, body or b"", content_type or "",
                      actor, edition, db_path, services or {})
    except desk_db.StaleRowError as e:
        return _fail(409, "stale", str(e))
    except desk_db.NotFoundError as e:
        return _fail(404, "not_found", str(e))
    except desk_db.DeskError as e:
        return _fail(403 if "only" in str(e) or "cannot" in str(e) else 400, "refused", str(e))


# Setup changes the app's API refuses on a server (desk_rules.SERVER_LOCK_MSG) — they're
# made in AI-Prowler on the server only. /import is checked in its route (a dry run is fine).
SERVER_LOCKED_POSTS = ("/settings", "/agent/photo", "/agent/photo/delete", "/import/undo",
                       "/backups/restore")


def _route(method, sub, q, body, ctype, actor, edition, db, services):
    a = rules.normalize_actor(actor)
    if method == "POST" and rules.server_locked(edition) and (
            sub in SERVER_LOCKED_POSTS or sub.startswith("/team/")):
        raise desk_db.DeskError(rules.SERVER_LOCK_MSG)

    m = re.fullmatch(rf"/tickets/{_TID}/(link|job)", sub)
    if m and method == "POST":
        tid, what = m.group(1), m.group(2)
        t = desk_db.get_ticket(db, tid, actor=actor, edition=edition)
        if t is None:
            raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
        if what == "link":
            if t["kind"] == rules.INTERNAL or not t.get("contact_id"):
                raise desk_db.DeskError("only customer and subcontractor tickets have status links")
            if not rules.can(actor, "reply_customer", t, edition=edition) or rules.is_external(actor):
                raise desk_db.DeskError("only the assignee, a manager or the owner can share a status link")
            import desk_portal
            token = desk_portal.issue_link(db, tid, t["contact_id"])
            return _ok(url=desk_portal.link_url(services.get("base_url", ""), token))
        if not services.get("create_job"):
            raise desk_db.DeskError("the Jobs app is not available on this AI-Prowler")
        b = _parse_json(body)
        import desk_tools
        text = desk_tools.create_job_from_ticket(
            db, actor, edition, ticket_id=tid, service_date=b.get("service_date", ""),
            service_type=b.get("service_type", ""), customer_id=b.get("customer_id", ""),
            notes=b.get("notes", ""), notify_customer=bool(b.get("notify_customer", True)),
            create_job_fn=services["create_job"])
        return _ok(message=text) if text.startswith("✅") else _fail(400, "refused", text.lstrip("❌ ").strip())

    m = re.fullmatch(rf"/tickets/{_TID}/watchers", sub)
    if m and method in ("GET", "POST"):
        tid = m.group(1)
        if rules.is_external(actor):
            raise desk_db.DeskError("only the team can see who watches a ticket")
        if desk_db.get_ticket(db, tid, actor=actor, edition=edition) is None:
            raise desk_db.NotFoundError(f"no ticket {tid} that you can see")
        if method == "GET":
            return _ok(watchers=desk_db.list_watchers(db, tid))
        b = _parse_json(body)
        return _ok(watchers=desk_db.set_watcher(db, tid, b.get("email", ""), name=b.get("name", ""),
                                                 remove=bool(b.get("remove")), actor=actor, edition=edition))

    if sub == "/directory" and method == "GET":
        entries = directory(db, actor, services, q.get("q", ""))
        team = []
        try:
            team = [{"id": u["id"], "name": u.get("name", ""), "role": u.get("role", ""),
                     "email": u.get("email", "")} for u in (services.get("team") or (lambda: []))()]
        except Exception:  # noqa: BLE001
            team = []
        return _ok(entries=entries, team=team)

    # ── Service Desk Agent: settings card + its virtual-assistant photo (2026-10-29)
    if sub.startswith("/agent"):
        import desk_agent_settings as das
        if rules.is_external(actor):
            raise desk_db.NotFoundError("not found")
        if sub == "/agent" and method == "GET":
            import desk_agent_store
            s = desk_db.get_settings(db)
            shown = {k: s[k] for k in das.DEFAULTS}
            shown["agent_provider"] = das.effective_provider(s, edition)   # no Claude CLI on a server
            jb = desk_agent_store.settings()                               # the Jobs agent's own database
            shown.update(jb)
            return _ok(settings=shown,
                       persona=das.persona(s, services.get("business", "")),
                       options=das.ui_options(edition), flow=das.flow(shown, edition),
                       bk_options=das.bk_ui_options(), bk_flow=das.booking_flow(shown, edition),
                       jb_options=das.jb_ui_options(), jb_flow=das.jobs_flow(jb, edition),
                       rt_flow=das.route_flow(jb, edition),
                       prompt_identity=das.prompt_identity(s, services.get("business", "")))
        # The Jobs agent's settings live in their own database (jobs-agent-spec, decision 4).
        if sub == "/agent/jobs" and method == "POST":
            import desk_agent_store
            if a["role"] != rules.OWNER:
                raise desk_db.DeskError("only the owner can change the Jobs agent's settings")
            if rules.server_locked(edition):
                raise desk_db.DeskError(rules.SERVER_LOCK_MSG)
            b = _parse_json(body)
            vals = b.get("settings") if isinstance(b.get("settings"), dict) else {b.get("key"): b.get("value")}
            desk_agent_store.set_settings({str(k): val for k, val in vals.items()}, actor=actor,
                                          edition=edition)                # all or nothing (F-6)
            jb = desk_agent_store.settings()
            return _ok(settings=jb, jb_flow=das.jobs_flow(jb, edition), rt_flow=das.route_flow(jb, edition))
        if sub == "/agent/jobs/flow" and method == "POST":            # redraw for unsaved choices
            import desk_agent_store
            b = _parse_json(body)
            o = b.get("settings") or {}
            return _ok(jb_flow=desk_agent_store.flow(edition, overrides=o),
                       rt_flow=desk_agent_store.flow(edition, overrides=o, which="route"))
        if sub == "/agent/photo" and method == "GET":
            data = das.photo_bytes(db)
            if data is None:
                raise desk_db.NotFoundError("no agent photo")
            return 200, b"image/jpeg", data
        if sub == "/agent/photo" and method == "POST":
            fields, files = parse_multipart(body, ctype)
            if not files:
                raise desk_db.DeskError("no picture in the upload")
            das.set_photo(db, files[0][1], actor=actor, edition=edition)
            return _ok(persona=das.persona(desk_db.get_settings(db)))
        if sub == "/agent/photo/delete" and method == "POST":
            das.clear_photo(db, actor=actor, edition=edition)
            return _ok(persona=das.persona(desk_db.get_settings(db)))
        # 🤖 Agent inbox (desk_agent.py, 2026-10-30): what the agent suggested, approve / edit / reject.
        if sub in ("/agent/inbox", "/agent/proposals") or sub.startswith("/agent/proposals/"):
            import desk_agent
            if a["role"] not in (rules.OWNER, rules.MANAGER):
                raise desk_db.DeskError("only the owner or a manager can review the agent's work")
            import desk_tools as _dt
            adb = _dt._jobs_agent_db()                 # the Jobs agent's suggestions, ids "J…"
            hdb = _dt._hr_agent_db()                   # the HR agent's, ids "H…" (decision 2: who may see them)
            if sub == "/agent/inbox" and method == "GET":
                # 2026-11-03 (David): a suggestion whose agent is off is "paused" — shown, rejectable, not approvable.
                pend = desk_agent.mark_paused(db, desk_agent.inbox(db, status="pending"))
                prac = desk_agent.inbox(db, status="practice", limit=40, unrated=True)
                st = desk_agent.status(db)
                if adb:
                    pend += [dict(x, proposal_id=f"J{x['proposal_id']}")
                             for x in desk_agent.mark_paused(adb, desk_agent.inbox(adb, status="pending"))]
                    prac += [dict(x, proposal_id=f"J{x['proposal_id']}")
                             for x in desk_agent.inbox(adb, status="practice", limit=40, unrated=True)]
                    js = desk_agent.status(adb)
                    st = dict(st, jobs_enabled=True, jobs_waiting=js["waiting"], jobs_pending=js["pending"],
                              rated_good=st["rated_good"] + js["rated_good"],
                              rated_not_right=st["rated_not_right"] + js["rated_not_right"],
                              rated_by={**st["rated_by"], **js["rated_by"]})
                # David 2026-11-05: a manager sees what they may see, as in a chat (desk_tools._agent_may).
                pend = [x for x in pend if _dt._agent_may(db, actor, edition, x["kind"], x["ref"])]
                prac = [x for x in prac if _dt._agent_may(db, actor, edition, x["kind"], x["ref"])]
                if hdb:
                    mine = _dt._hr_reviewable(hdb, actor, desk_agent.inbox(hdb, status="pending"))
                    pend += [dict(x, proposal_id=f"H{x['proposal_id']}") for x in desk_agent.mark_paused(hdb, mine)]
                    st = dict(st, hr_enabled=True, hr_pending=len(mine))
                return _ok(pending=pend, practice=prac, status=st)
            m = re.fullmatch(r"/agent/proposals/([JH]?)(\d{1,9})/(approve|edit|reject|up|down)", sub)
            if sub == "/agent/proposals/run-now" and method == "POST":
                if a["role"] != rules.OWNER:
                    raise desk_db.DeskError("only the owner can start the agent")
                desk_agent.retry_errors(db)
                why = desk_agent.why_not_run(db, desk_db.get_settings(db), edition=edition,
                                             now=desk_agent._now(), force=True)
                jstarted = False
                if adb:
                    import desk_agent_store
                    js = desk_agent_store.sync_shared(db, adb)
                    desk_agent.retry_errors(adb)
                    if not desk_agent.why_not_run(adb, js, edition=edition, now=desk_agent._now(), force=True):
                        jstarted = desk_agent.run_in_background(adb, edition=edition, force=True,
                                                                business=services.get("business", ""))
                if why:
                    return _ok(started=jstarted, why="" if jstarted else why, jobs_started=jstarted)
                started = desk_agent.run_in_background(db, edition=edition, business=services.get("business", ""),
                                                       force=True)
                return _ok(started=started, why="" if started else "a run is already going", jobs_started=jstarted)
            if m and method == "POST":
                b = _parse_json(body)
                if m.group(1) == "J" and not adb:
                    raise desk_db.NotFoundError("the Jobs agent is off")
                if m.group(1) == "H" and not hdb:
                    raise desk_db.NotFoundError("the HR agent is off")
                target = {"J": adb, "H": hdb}.get(m.group(1), db)
                if m.group(1) != "H":                      # HR has its own rule (who may review, desk_agent.review)
                    row = _dt._agent_row(target, "agent_proposals", "proposal_id", int(m.group(2)))
                    if row and not _dt._agent_may(db, actor, edition, row["kind"], row["ref"]):
                        raise desk_db.DeskError("that suggestion is outside what you can see")
                out = desk_agent.review(target, int(m.group(2)), m.group(3), actor_=actor,
                                        edition=edition,
                                        edits=b.get("edits") if isinstance(b.get("edits"), dict) else None,
                                        business=services.get("business", ""))
                return _ok(**out)

    # ── 📅 Bookings to approve (booking-spec.md §7a, Phase 2) ───────────────────
    if sub.startswith("/bookings"):
        return _route_bookings(method, sub, q, body, actor, edition, db, services)
    # ── + → Customer request → Book a visit / New service request (§9.2, Phase 3) ──
    if sub == "/book" or sub.startswith("/book/"):
        import desk_staff_booking as dsb
        if rules.is_external(actor):
            raise desk_db.DeskError("customers book from the booking page")
        if sub == "/book" and method == "GET":
            return _ok(**dsb.options(db, actor=actor, edition=edition, team=services.get("team")))
        if sub == "/book/windows" and method == "GET":
            return _ok(windows=dsb.windows(db, q.get("service", ""), actor=actor, edition=edition,
                                           from_date=q.get("from") or None))
        if sub == "/book" and method == "POST":
            b = _parse_json(body)
            custom = b.get("custom") if isinstance(b.get("custom"), dict) else None
            out = dsb.book(db, actor=actor, edition=edition, path=str(b.get("path") or "book"),
                           name=str(b.get("name") or ""), phone=str(b.get("phone") or ""),
                           email=str(b.get("email") or ""),
                           address=b.get("address") if isinstance(b.get("address"), dict) else {},
                           service_code=str(b.get("service_code") or ""), service=str(b.get("service") or ""),
                           window_key=str(b.get("window_key") or ""), custom=custom,
                           crew=str(b.get("crew") or ""),
                           notify=(bool(b["notify"]) if "notify" in b else None),
                           description=str(b.get("description") or ""), preferred=str(b.get("preferred") or ""),
                           source=str(b.get("source") or "phone"), base_url=services.get("base_url") or "")
            return 201, b"application/json", json.dumps(dict(out, ok=True)).encode()

    if sub == "/me" and method == "GET":
        s = desk_db.get_settings(db)
        import booking_flow
        import desk_portal
        return _ok(portal_channels=desk_portal.channels(),
                   can_approve_bookings=(("book" in desk_portal.page_paths(s) or bool(s.get("staff_booking")))
                                         and booking_flow.can_approve(actor, edition, s)),
                   can_book_for_customers=__import__("desk_staff_booking").can_book(actor, edition, s),
                   actor={"id": a["id"], "role": a["role"], "name": a.get("name", ""),
                          "email": a.get("email", "")},
                   # 2026-11-03: the 🤖 tab stays visible while suggestions wait, even with the agent off
                   agent_pending=(__import__("desk_agent").pending_count(db)
                                  if a["role"] in (rules.OWNER, rules.MANAGER) else 0),
                   edition=edition, settings=s,
                   kinds=[k for k in rules.KINDS
                          if rules.can(actor, "create", edition=edition, kind=k,
                                       options=desk_db.options_from_settings(s))],
                   states=list(rules.STATES),
                   transitions={s: [t for t in rules.STATES if t in rules.TRANSITIONS[s]]
                                for s in rules.STATES},
                   needs_reason=[[f, t] for f in rules.STATES for t in rules.TRANSITIONS[f]
                                 if rules.needs_reason(f, t)],
                   features={f: rules.feature_enabled(edition, f) for f in rules.FEATURES})

    if sub == "/tickets" and method == "GET":
        rows = desk_db.list_tickets(
            db, actor=actor, edition=edition, state=q.get("state") or None,
            open_only=_truthy(q.get("open_only", "1")) and not q.get("state"),
            assignee=(a["id"] if _truthy(q.get("mine", "0")) else q.get("assignee") or None),
            kind=q.get("kind") or None, priority=q.get("priority") or None,
            overdue=_truthy(q.get("overdue", "0")), text=q.get("text") or None,
            limit=int(q.get("limit") or 200))
        return _ok(tickets=[public_ticket(t, actor) for t in rows],
                   cursor=desk_db.current_cursor(db))

    if sub == "/updates" and method == "GET":
        out = desk_db.get_ticket_updates(db, q.get("since", ""), actor=actor, edition=edition)
        return _ok(tickets=[public_ticket(t, actor) for t in out["tickets"]], cursor=out["cursor"])

    if sub == "/tickets" and method == "POST":
        b = _parse_json(body)
        kind = (b.get("kind") or rules.EXTERNAL).strip().lower()
        cid = b.get("contact_id") or None
        if not cid and (b.get("contact_phone") or b.get("contact_email")) and not rules.is_external(actor):
            cid = desk_db.upsert_contact(
                db, name=b.get("contact_name", ""), phone=b.get("contact_phone"),
                email=b.get("contact_email"),
                contact_type="subcontractor" if kind == rules.SUBCONTRACTOR_KIND else "customer",
                actor=actor)["contact_id"]
        if kind == rules.EXTERNAL and not rules.is_external(actor) and not (
                cid or b.get("customer_id")):
            raise desk_db.DeskError("add the customer's phone or email so they can get updates")
        # 2026-10-29: the owner (Solo) or anyone on the team (Business) files a
        # customer request for a customer who phoned, texted, emailed or walked
        # in. Record how they reached us; anything else stays "pwa".
        src = str(b.get("source") or "").strip().lower()
        if rules.is_external(actor) or kind != rules.EXTERNAL or src not in PWA_SOURCES:
            src = "pwa"
        import desk_tools
        t = desk_db.create_ticket(
            db, title=b.get("title", ""), kind=kind, actor=actor, edition=edition,
            description=b.get("description", ""), type=b.get("type", ""),
            priority=(b.get("priority") or "P3").upper(), source=src, contact_id=cid,
            customer_id=b.get("customer_id") or None, job_id=b.get("job_id") or None,
            visibility="private" if b.get("private") else "normal",
            assignee=b.get("assignee") or None,
            due_resolve_at=desk_tools.due_iso(b.get("due", "")),
            sms_fallback=b.get("sms_fallback"))
        return _j(201, {"ok": True, "ticket": public_ticket(t, actor)})

    m = re.fullmatch(rf"/tickets/{_TID}", sub)
    if m and method == "GET":
        d = desk_db.get_ticket_detail(db, m.group(1), actor=actor, edition=edition)
        # The moves THIS person may make (2026-10-28: crew saw a Close button
        # the server then refused). reason="x" so "needs a reason" doesn't hide one.
        d["moves"] = [s for s in rules.STATES if s in rules.TRANSITIONS.get(d["state"], ())
                      and rules.can(actor, "change_state", d, edition=edition, to_state=s, reason="x")]
        return _ok(ticket=d)

    m = re.fullmatch(rf"/tickets/{_TID}/(state|assign|update|messages|attachments)", sub)
    if m and method == "POST":
        tid, action = m.group(1), m.group(2)
        if action == "attachments":
            fields, files = parse_multipart(body, ctype)
            if not files:
                raise desk_db.DeskError("no file in the upload")
            mid = int(fields["message_id"]) if fields.get("message_id") else None
            saved = [desk_attachments.store_attachment(
                db, tid, data, name, actor=actor, edition=edition, message_id=mid,
                visibility=fields.get("visibility") or "public",
                keep_gps=_truthy(fields.get("keep_gps", "0"))) for name, data in files]
            return _j(201, {"ok": True, "attachments": saved})
        b = _parse_json(body)
        ev = b.get("expected_version")
        if action == "state":
            t = desk_db.change_state(db, tid, b.get("to_state", ""), actor=actor, edition=edition,
                                     reason=b.get("reason", ""), expected_version=ev)
        elif action == "assign":
            t = desk_db.assign_ticket(db, tid, b.get("assignee", ""), actor=actor,
                                      edition=edition, expected_version=ev)
        elif action == "update":
            fields = dict(b.get("fields") or {})
            if "due" in fields:
                import desk_tools
                fields["due_resolve_at"] = desk_tools.due_iso(fields.pop("due"))
            t = desk_db.update_ticket(db, tid, fields, actor=actor, edition=edition,
                                      reason=b.get("reason", ""), expected_version=ev)
        else:  # messages
            msg = desk_db.add_message(db, tid, b.get("body", ""), actor=actor, edition=edition,
                                      visibility=b.get("visibility") or "internal", channel="pwa")
            return _j(201, {"ok": True, "message": msg})
        return _ok(ticket=public_ticket(t, actor))

    m = re.fullmatch(r"/attachments/(\d+)", sub)
    if m and method == "GET":
        att, path = desk_db.get_attachment(db, int(m.group(1)), actor=actor, edition=edition)
        if _truthy(q.get("thumb", "0")) and att.get("thumb_path"):
            path = path.parent.parent / att["thumb_path"]
        if not path.exists():
            return _fail(404, "missing_file", "that file is missing on the server")
        mime = (att.get("mime") if path.name == att["filename"] else "image/jpeg") or \
            mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        return 200, mime.encode(), path.read_bytes()

    if sub == "/settings" and method == "GET":
        return _ok(settings=desk_db.get_settings(db))
    if sub == "/settings" and method == "POST":
        b = _parse_json(body)
        # {"key", "value"} for one setting, or {"values": {...}} for a whole card — all or nothing (F-6)
        vals = b.get("values") if isinstance(b.get("values"), dict) else {b.get("key", ""): b.get("value")}
        if any(k in desk_db.LOCAL_ONLY_SETTINGS for k in vals):
            raise desk_db.DeskError("the backup folder can only be changed in AI-Prowler on this PC "
                                    "(🏢 Small Business tab → Service Desk → Data & backups)")
        return _ok(settings=desk_db.set_settings(db, vals, actor=actor, edition=edition))

    if sub == "/contacts" and method == "GET":
        if rules.is_external(actor):
            return _fail(403, "refused", "contacts are for your team only")
        ctype_ = q.get("type") or None
        conn = desk_db.get_connection(db)
        try:
            rows = [dict(r) for r in conn.execute(
                "SELECT contact_id, contact_type, name, phone, email FROM customer_contacts "
                "WHERE (? IS NULL OR contact_type = ?) ORDER BY name LIMIT 500", (ctype_, ctype_))]
        finally:
            conn.close()
        return _ok(contacts=rows)

    out = _route_phase3(method, sub, q, body, ctype, actor, edition, db)
    if out is not None:
        return out
    return _fail(404, "unknown_route", f"no Service Desk route {method} {sub}")


def _route_bookings(method, sub, q, body, actor, edition, db, services):
    """GET /bookings · GET /bookings/windows · POST /bookings/<job>/(approve|suggest|decline).
    Only approvers (the owner; managers on a server when allowed) — everyone else gets 403."""
    import booking_flow
    import desk_portal
    s = desk_db.get_settings(db)
    if rules.is_external(actor) or not booking_flow.can_approve(actor, edition, s):
        raise desk_db.DeskError("only the owner" + (" or a manager" if edition == rules.BUSINESS
                                                    and s.get("booking_approve_managers", True) else "")
                                + " can see and approve bookings")
    jobs_db = desk_portal._jobs_db()
    if not jobs_db:
        raise desk_db.DeskError("the Jobs app is not available on this AI-Prowler")
    try:
        if sub == "/bookings" and method == "GET":
            crews = []
            if edition == rules.BUSINESS:
                names = {}
                try:
                    names = {u["id"]: u.get("name") or u["id"] for u in (services.get("team") or (lambda: []))()}
                except Exception:  # noqa: BLE001
                    names = {}
                crews = [{"id": c.crew_id, "name": names.get(c.crew_id, c.crew_id)}
                         for c in booking_flow.crews_for(jobs_db, edition) if c.crew_id != "team"]
            rows = booking_flow.to_approve(jobs_db)
            try:                                          # 🤖 suggests … / flags (booking agent)
                import desk_agent
                for r in rows:
                    r["agent"] = desk_agent.for_booking(db, r["job_id"])
            except Exception:  # noqa: BLE001
                pass
            return _ok(bookings=rows, crews=crews,
                       upcoming=booking_flow.upcoming(jobs_db),
                       crew_mode=s.get("booking_crew_mode", "approver"), approval=s.get("booking_approval"))
        if sub == "/bookings/windows" and method == "GET":
            import datetime as _dt
            frm = _dt.date.fromisoformat(q["from"]) if q.get("from") else None
            return _ok(windows=booking_flow.windows(jobs_db, s, q.get("service", ""), edition, online_only=False,
                                                   from_date=frm,
                                                   to_date=(frm + _dt.timedelta(days=13)) if frm else None))
        m = re.fullmatch(r"/bookings/([A-Za-z0-9_-]{1,40})/(approve|suggest|decline)", sub)
        if m and method == "POST":
            jid, what = m.group(1), m.group(2)
            b = _parse_json(body)
            if what == "approve":
                out = booking_flow.approve(jobs_db, db, jid, actor=actor, edition=edition, settings=s,
                                           window_key=str(b.get("window_key") or ""),
                                           crew=(str(b["crew"]) if b.get("crew") else None))
            elif what == "suggest":
                out = booking_flow.suggest(jobs_db, db, jid, str(b.get("window_key") or ""), actor=actor,
                                           edition=edition, settings=s, note=str(b.get("note") or ""))
            else:
                out = booking_flow.decline(jobs_db, db, jid, actor=actor, edition=edition, settings=s,
                                           message=str(b.get("message") or ""),
                                           keep_request=bool(b.get("keep_request")))
            return _ok(**out)
    except (booking_flow.BookingError, ValueError) as e:
        raise desk_db.DeskError(str(e)) from None
    raise desk_db.NotFoundError("not found")


def _route_phase3(method, sub, q, body, ctype, actor, edition, db):
    """Reports, export/import, backups, team setup (Phase 3)."""
    import desk_backup
    import desk_data
    import desk_reports
    import desk_routing as rt

    if sub.startswith("/push/"):
        import desk_push
        if sub == "/push/key" and method == "GET":
            return _ok(key=desk_push.keys(db)[0])
        if sub == "/push/subscribe" and method == "POST":
            return _ok(**desk_push.subscribe(db, _parse_json(body).get("subscription") or {}, actor=actor))
        if sub == "/push/unsubscribe" and method == "POST":
            desk_push.unsubscribe(db, _parse_json(body).get("endpoint", ""))
            return _ok()

    if sub == "/report" and method == "GET":
        rep = desk_reports.report(db, actor=actor, edition=edition, since=q.get("since", ""),
                                  until=q.get("until", ""), group_by=q.get("group_by", ""))
        return _ok(report=rep, text=desk_reports.report_text(rep))

    if sub == "/export" and method == "GET":
        name, data, mime = desk_data.export(
            db, q.get("format", "xlsx"), actor=actor, edition=edition,
            ticket_id=q.get("ticket_id", ""), include_internal=_truthy(q.get("include_internal", "0")),
            filters={k: q.get(k, "") for k in ("since", "until", "state", "kind", "customer_id")})
        return 200, mime.encode(), data

    if sub == "/import" and method == "POST":
        fields, files = parse_multipart(body, ctype)
        if not files:
            raise desk_db.DeskError("choose a file to import")
        name, data = files[0]
        if rules.server_locked(edition) and not _truthy(fields.get("dry_run", "1")):
            raise desk_db.DeskError(rules.SERVER_LOCK_MSG)
        cmap = json.loads(fields["column_map"]) if fields.get("column_map") else None
        out = desk_data.import_tickets(db, data, name, actor=actor, edition=edition,
                                       dry_run=_truthy(fields.get("dry_run", "1")), column_map=cmap,
                                       backup_fn=lambda trig: desk_backup.backup_now(db, trig))
        return _ok(result=out)
    if sub == "/import/undo" and method == "POST":
        b = _parse_json(body)
        return _ok(result=desk_data.undo_import(db, b.get("batch_id", ""), actor=actor, edition=edition))

    if sub.startswith("/backups"):
        if not rules.can(actor, "backup", edition=edition):
            return _fail(403, "refused", "only the owner can manage Service Desk backups")
        if sub == "/backups" and method == "GET":
            s = desk_db.get_settings(db)
            return _ok(backups=desk_backup.list_backups(db),
                       settings={k: s[k] for k in s if k.startswith("backup_")},
                       folder=str(desk_backup.backup_dir(db)), help=desk_backup.BACKUP_HELP)
        if sub == "/backups" and method == "POST":
            return _ok(backup=desk_backup.backup_now(db, "manual"))
        if sub == "/backups/restore" and method == "POST":
            b = _parse_json(body)
            return _ok(result=desk_backup.restore(db, b.get("name", ""), actor=actor, edition=edition,
                                                  confirm=bool(b.get("confirm")),
                                                  ticket_id=b.get("ticket_id", "")))
        m = re.fullmatch(r"/backups/(desk-[0-9]{8}-[0-9]{6}-[a-z-]+\.zip)", sub)
        if m and method == "GET":
            p = desk_backup.backup_dir(db) / m.group(1)
            if not p.exists():
                return _fail(404, "not_found", "no such backup")
            return 200, b"application/zip", p.read_bytes()

    if sub == "/team" and method == "GET":
        return _ok(queues=rt.list_queues(db), rules=rt.list_rules(db), types=rt.list_types(db))
    if sub.startswith("/team/") and method == "POST":
        b = _parse_json(body)
        what = sub[len("/team/"):]
        if what == "queue":
            members = b.get("members") or []
            if isinstance(members, str):
                members = [m.strip() for m in members.split(",")]
            return _ok(queue=rt.upsert_queue(db, b.get("queue_id", ""), name=b.get("name", ""),
                                             members=members, default_assignee=b.get("default_assignee") or None,
                                             actor=actor, edition=edition))
        if what == "queue/delete":
            rt.delete_queue(db, b.get("queue_id", ""), actor=actor, edition=edition)
            return _ok()
        if what == "rule":
            return _ok(rule=rt.upsert_rule(db, b.get("rule_id", ""), match=b.get("match") or {},
                                           action=b.get("action") or {}, sort_order=int(b.get("order", 100)),
                                           enabled=bool(b.get("enabled", True)), actor=actor, edition=edition))
        if what == "rule/delete":
            rt.delete_rule(db, b.get("rule_id", ""), actor=actor, edition=edition)
            return _ok()
        if what == "type":
            return _ok(type=rt.upsert_type(db, b.get("type_id", ""), name=b.get("name", ""),
                                           kind=b.get("kind", "external"),
                                           default_queue=b.get("default_queue") or None,
                                           default_priority=b.get("default_priority", "P3"),
                                           actor=actor, edition=edition))
    return None


# ── /desk/ app files ─────────────────────────────────────────────────────────

def static_file(path: str) -> tuple:
    """(status, content_type, body, relative_name) for a /desk/ request. Unknown
    paths fall back to index.html (single-page app); paths outside the app
    folder are refused."""
    rel = unquote(path[len("/desk"):]).lstrip("/") or "index.html"
    root = APP_DIR.resolve()
    fp = (root / rel).resolve()
    if fp != root and root not in fp.parents:
        return 403, b"text/plain", b"Forbidden", rel
    if not fp.is_file():
        fp, rel = root / "index.html", "index.html"
        if not fp.is_file():
            return 404, b"text/plain", b"Service Desk app not installed", rel
    ctype = (mimetypes.guess_type(fp.name)[0] or "application/octet-stream").encode()
    return 200, ctype, fp.read_bytes(), rel
