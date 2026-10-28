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


def public_ticket(t: dict, actor) -> dict:
    """A ticket row trimmed for list views; outside parties lose internals."""
    keep = ("ticket_id", "title", "kind", "type", "priority", "state", "assignee",
            "contact_id", "customer_id", "job_id", "due_resolve_at", "created_at",
            "last_edited_at", "version", "sms_fallback", "visibility", "queue_id", "filed_by")
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


def _route(method, sub, q, body, ctype, actor, edition, db, services):
    a = rules.normalize_actor(actor)

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

    if sub == "/me" and method == "GET":
        s = desk_db.get_settings(db)
        return _ok(actor={"id": a["id"], "role": a["role"], "name": a.get("name", ""),
                          "email": a.get("email", "")},
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
        import desk_tools
        t = desk_db.create_ticket(
            db, title=b.get("title", ""), kind=kind, actor=actor, edition=edition,
            description=b.get("description", ""), type=b.get("type", ""),
            priority=(b.get("priority") or "P3").upper(), source="pwa", contact_id=cid,
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
        return _ok(settings=desk_db.set_setting(db, b.get("key", ""), b.get("value"),
                                                actor=actor, edition=edition))

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
                       settings={k: s[k] for k in s if k.startswith("backup_")})
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
