"""desk_agent_settings.py — Service Desk Agent settings and its virtual-assistant
persona (2026-10-29, David). Spec: desk-agent-spec.md §9, §12.

David 2026-10-29: "set the agent configuration settings in AI-Prowler Service Desk
section ... the agent identity name and photo". (A reply-delay setting was added
the same day and removed 2026-10-30 at David's request: replies go out as soon as
they're approved, at any hour.)
Decision the same day: the agent is a named VIRTUAL ASSISTANT, never presented as
a person. So the persona always carries a label from LABELS ("Sam · Virtual
assistant"), the label can't be switched off or replaced with free text, and the
agent's instructions (prompt_identity) say to admit it's an assistant when asked.

Stored with the other Service Desk settings (desk_db.SETTING_DEFAULTS merges
DEFAULTS; desk_db.set_setting calls validate()). Edited from:
  * the Service Desk app  → ⚙︎ Settings → 🤖 Agent        (desk/index.html)
  * AI-Prowler            → Business tab → Service Desk   (desk_gui_agent.py)

The photo is a 256 px square JPEG, no EXIF, at <tickets root>/agent/avatar.jpg.

No module-level import of desk_db (desk_db imports this file).
"""
from __future__ import annotations

import io
import re
from pathlib import Path

PROVIDERS = (
    ("chat_only", "Chat — Claude.ai, Muse or Grok.com (no key; someone pastes the prompt)"),
    ("claude_api", "Claude API key — runs on its own when tickets arrive"),
    ("grok_api", "Grok bot (xAI API key) — runs on its own when tickets arrive"),
)
# David 2026-11-01: "Remove CLI everywhere" — the Claude subscription (Claude CLI) runner is gone on
# every install. It can't be saved, and an old saved value counts as chat_only (effective_provider()).
REMOVED_PROVIDERS = ("claude_code",)
NOT_ON_SERVER = REMOVED_PROVIDERS            # kept for older callers
CLI_REMOVED_MSG = ("the Claude subscription (Claude CLI) runner was removed — the agents run on an API key: "
                   "choose the Claude API key or the Grok bot and save the key in 🔑 Agent API Key at the top "
                   "of the Small Business tab")
CLI_ON_SERVER_MSG = CLI_REMOVED_MSG
# David 2026-11-01: "note that all agents need an API key, remove the Paste AI into a chat method"
# (server). On a server every agent runs on its own with an API key; the chat runner isn't offered
# and can't be saved. An unset / old chat_only value still means "doesn't run on its own" internally
# (effective_provider), and the server's screens show it as not chosen yet.
HIDDEN_ON_SERVER = ("chat_only",)
CHAT_ON_SERVER_MSG = ("on a server every agent runs on its own with an API key — choose the Claude API key "
                      "or the Grok bot (the key goes in 🔑 Agent API Key at the top of the Small Business tab)")

# Plain-English help shown under each stage, as hover text, and in the flow diagram.
STAGE_SHORT = {"intake": "Intake", "first_reply": "First reply", "resolution": "Resolution help",
               "follow_through": "Follow-through", "learn": "Learn"}
STAGE_HELP = {
    "intake": ("When a ticket arrives, the agent reads it, sets its type and priority, flags "
               "duplicates and notes anything missing. On a team (Business) it also picks who the "
               "ticket goes to. It never lowers a priority, and a person always sees P1s first."),
    "first_reply": ("Writes the first message to the customer: what we understood, what happens "
                    "next, and the link where they can follow their request."),
    "resolution": ("Looks through past fixed tickets and saved learnings, then leaves an internal "
                   "note for whoever has the ticket with the likely cause and fix. Customers never "
                   "see it. It may also suggest a re-do job, which always needs a person's OK."),
    "follow_through": ("Watches for tickets going quiet — a customer waiting with no reply, a "
                       "ticket On Hold past its date, a question after it was Fixed — and nudges "
                       "the person who has it, or drafts a check-in to the customer."),
    "learn": ("When a ticket closes with a fix, suggests a learning so the next similar problem "
              "is solved faster. A person always accepts or rejects it."),
}
MODE_HELP = {
    "off": "Off — the agent skips this step.",
    "suggest": ("Suggest — the agent prepares it, then it waits in the Agent list until a person "
                "taps Approve, Edit or Reject. Nothing happens until then."),
    "auto": ("Auto — the agent does it straight away. Risky things (merges, re-do jobs, "
             "learnings, any P1 or private ticket) still wait for a person."),
}
PRACTICE_HELP = ("Practice mode — the agent works every step that isn't Off, but only shows what it "
                 "would have done (with 👍 / 👎 so you can judge it). Nothing is changed and nothing "
                 "is sent to customers. Turn it off when you trust it.")
SIGNOFF_HELP = ("The words after the assistant's name at the end of every customer message, e.g. "
                "\"— Sam (virtual assistant), Blue Wave Window Cleaning\". Leave blank to use your "
                "business name.")
STAGES = (
    ("intake", "Intake — type, priority, routing, duplicates"),
    ("first_reply", "First reply to the customer"),
    ("resolution", "Resolution help — internal note with likely fix"),
    ("follow_through", "Follow-through — nudges when a ticket goes quiet"),
    ("learn", "Learn — propose a learning when a ticket closes"),
)
STAGE_MODES = ("off", "suggest", "auto")
STAGE_MODE_LABELS = {"off": "Off", "suggest": "Suggest (a person approves)", "auto": "Auto"}

# Always shown with the name. Fixed list on purpose: customers must be able to
# tell they're talking to an assistant, not a person (see the module docstring).
LABELS = ("Virtual assistant", "AI assistant", "Digital assistant")
DEFAULT_LABEL = LABELS[0]

PHOTO_REL = "agent/avatar.jpg"
PHOTO_SIDE = 256
PHOTO_MAX_BYTES = 8 * 1024 * 1024
NAME_MAX = 40
SIGNOFF_MAX = 80

DEFAULTS = {
    "agent_enabled": False,               # master switch (also the kill switch)
    "agent_provider": "chat_only",
    "agent_shadow": True,                 # propose only — nothing is applied
    **{f"agent_stage_{k}": "suggest" for k, _ in STAGES},
    "agent_name": "",                     # blank = just "Virtual assistant"
    "agent_label": DEFAULT_LABEL,
    "agent_photo": "",                    # set by set_photo(); "" = no photo
    "agent_hours": [0, 24],               # local hours the automatic runners work (default: always)
    "agent_monthly_budget_usd": 20,
    "agent_budget_alert_pct": 80,         # warn the owner at this % of the monthly budget (0 = no budget alerts)
    "agent_batch_seconds": 90,
    "agent_max_items": 10,
    "agent_wait_hours": 4,
    "agent_reply_signoff": "",            # blank = the business name
    "agent_include_service_link": False,
}

CHOICES = {
    "agent_provider": tuple(p for p, _ in PROVIDERS),
    "agent_label": LABELS,
    "agent_photo": ("", PHOTO_REL),
    **{f"agent_stage_{k}": STAGE_MODES for k, _ in STAGES},
}

RANGES = {
    "agent_monthly_budget_usd": (0, 10000),
    "agent_budget_alert_pct": (0, 100),
    "agent_batch_seconds": (0, 3600),
    "agent_max_items": (1, 50),
    "agent_wait_hours": (1, 168),
}

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]*$")


def validate(key: str, value, edition: str | None = None) -> None:
    """Extra checks for agent_* settings (the type check is desk_db's).
    edition "business" = a server install. Raises ValueError with a plain message."""
    if key == "agent_provider" and value in REMOVED_PROVIDERS:
        raise ValueError(CLI_REMOVED_MSG)
    if key == "agent_provider" and edition == "business" and value == "chat_only":
        raise ValueError(CHAT_ON_SERVER_MSG)
    if key in CHOICES and value not in CHOICES[key]:
        raise ValueError(f"{key} must be one of: {', '.join(repr(c) for c in CHOICES[key])}")
    if key in RANGES:
        lo, hi = RANGES[key]
        if not lo <= value <= hi:
            raise ValueError(f"{key} must be between {lo} and {hi}")
    if key == "agent_name":
        v = value.strip()
        if len(v) > NAME_MAX:
            raise ValueError(f"the agent's name can be at most {NAME_MAX} characters")
        if v and not _NAME_RE.match(v):
            raise ValueError("the agent's name can use letters, spaces, . ' and - only")
    if key == "agent_reply_signoff" and len(value.strip()) > SIGNOFF_MAX:
        raise ValueError(f"the sign-off can be at most {SIGNOFF_MAX} characters")
    if key.startswith("agent_jb_"):
        validate_jb(key, value)
    if key.startswith("agent_hr_"):
        validate_hr(key, value)
    if key == "agent_hours":
        if (len(value) != 2 or not all(type(h) is int for h in value)
                or not 0 <= value[0] < value[1] <= 24):
            raise ValueError("agent_hours must be [start, end] hours with 0 <= start < end <= 24")


# ── The persona ──────────────────────────────────────────────────────────────

def persona(settings: dict, business: str = "") -> dict:
    """What customers see. display always includes the assistant label."""
    name = (settings.get("agent_name") or "").strip()
    label = settings.get("agent_label") or DEFAULT_LABEL
    if label not in LABELS:
        label = DEFAULT_LABEL
    display = f"{name} · {label}" if name else label
    who = f"{name} ({label.lower()})" if name else label
    tail = (settings.get("agent_reply_signoff") or "").strip() or (business or "").strip()
    return {"name": name, "label": label, "display": display,
            "signature": f"— {who}" + (f", {tail}" if tail else ""),
            "photo": settings.get("agent_photo") == PHOTO_REL}


def prompt_identity(settings: dict, business: str = "") -> str:
    """The identity paragraph every provider's prompt starts with (spec §11.1)."""
    p = persona(settings, business)
    biz = (business or "").strip() or "this business"
    me = f"{p['name']}, the {p['label'].lower()}" if p["name"] else f"the {p['label'].lower()}"
    return (f"You are {me} for {biz}. You are an AI assistant, not a person. Never say or "
            f"suggest you are a human, and never invent a personal life. If anyone asks whether "
            f"they are talking to a person or a bot, say plainly that you are {biz}'s virtual "
            f"assistant and offer to have someone from the team follow up. End customer "
            f"messages with: {p['signature']}")


# ── The photo ────────────────────────────────────────────────────────────────

def photo_path(root: Path) -> Path:
    return Path(root) / PHOTO_REL


def make_avatar(data: bytes) -> bytes:
    """Any phone/desktop picture → a 256 px square JPEG with no EXIF (no GPS,
    no camera details). Raises ValueError for anything that isn't a picture."""
    if not data:
        raise ValueError("the file is empty")
    if len(data) > PHOTO_MAX_BYTES:
        raise ValueError(f"the picture is too big (max {PHOTO_MAX_BYTES // (1024 * 1024)} MB)")
    from PIL import Image, ImageOps, UnidentifiedImageError
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except Exception:  # noqa: BLE001 — HEIC is a bonus, not a requirement
        pass
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError) as e:
        raise ValueError("that file isn't a picture we can read (use JPG, PNG, WebP or HEIC)") from e
    img = ImageOps.exif_transpose(img).convert("RGB")
    img = ImageOps.fit(img, (PHOTO_SIDE, PHOTO_SIDE), Image.Resampling.LANCZOS)
    out = io.BytesIO()
    img.save(out, "JPEG", quality=88, optimize=True)
    return out.getvalue()


def _root(db_path: str) -> Path:
    import desk_db
    return desk_db.root_for(db_path)


def _owner_only(actor, edition):
    import desk_db
    import desk_rules as rules
    desk_db._check(rules.can(actor, "manage_settings", edition=edition))


def set_photo(db_path: str, data: bytes, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    try:
        jpeg = make_avatar(data)
    except ValueError as e:
        raise desk_db.DeskError(str(e)) from e
    p = photo_path(_root(db_path))
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(jpeg)
    tmp.replace(p)
    return desk_db.set_setting(db_path, "agent_photo", PHOTO_REL, actor=actor, edition=edition)


def clear_photo(db_path: str, *, actor=None, edition: str = "business") -> dict:
    import desk_db
    _owner_only(actor, edition)
    try:
        photo_path(_root(db_path)).unlink()
    except FileNotFoundError:
        pass
    return desk_db.set_setting(db_path, "agent_photo", "", actor=actor, edition=edition)


def photo_bytes(db_path: str) -> bytes | None:
    import desk_db
    if desk_db.get_settings(db_path).get("agent_photo") != PHOTO_REL:
        return None
    p = photo_path(_root(db_path))
    return p.read_bytes() if p.exists() else None


def public_profile(db_path: str, business: str = "") -> dict:
    """For the customer status page: only what customers see."""
    import desk_db
    s = desk_db.get_settings(db_path)
    p = persona(s, business)
    has = p["photo"] and photo_path(_root(db_path)).exists()
    ver = int(photo_path(_root(db_path)).stat().st_mtime) if has else 0
    return {"enabled": bool(s.get("agent_enabled")), "name": p["name"], "label": p["label"],
            "display": p["display"], "photo_url": f"/support-api/agent/photo?v={ver}" if has else ""}


def providers_for(edition: str | None) -> list:
    """The runners this install may use (on a server: API keys only — no Claude CLI, no chat)."""
    return [p for p in PROVIDERS if not (edition == "business" and p[0] in HIDDEN_ON_SERVER)]


def effective_provider(settings: dict, edition: str | None) -> str:
    p = settings.get("agent_provider") or "chat_only"
    if p == "chat_only":
        return p                    # not running on its own (on a server: no runner chosen yet)
    return p if p in {k for k, _ in providers_for(edition)} else "chat_only"


def ui_options(edition: str | None = None) -> dict:
    """The choices both settings screens show (keeps the app and the GUI in step)."""
    return {"providers": [list(p) for p in providers_for(edition)], "stages": [list(s) for s in STAGES],
            "stage_modes": [[m, STAGE_MODE_LABELS[m]] for m in STAGE_MODES],
            "stage_help": STAGE_HELP, "mode_help": MODE_HELP, "practice_help": PRACTICE_HELP,
            "signoff_help": SIGNOFF_HELP, "labels": list(LABELS), "name_max": NAME_MAX}


# ── The ticket-flow diagram (David 2026-10-30) ───────────────────────────────
# "Show the ticket flow state machine to the right of the agent settings, light up
# the states and flows the agent will run." One model, drawn by the app (SVG) and
# AI-Prowler's Business tab (Tk canvas) — coordinates are in a 560 x 250 box.

FLOW_W, FLOW_H = 560, 250
MODE_COLORS = {"inactive": "#9ca3af", "off": "#9ca3af", "practice": "#7c3aed",
               "suggest": "#d97706", "auto": "#16a34a"}
# Pale versions for filling boxes where there is no transparency (AI-Prowler's Tk canvas).
MODE_TINTS = {"#9ca3af": "#f3f4f6", "#7c3aed": "#ede9fe", "#d97706": "#fef3c7", "#16a34a": "#dcfce7"}
MODE_WORDS = {"inactive": "agent off", "off": "off", "practice": "practice only",
              "suggest": "waits for OK", "auto": "automatic"}
_SW, _SH, _AW, _AH = 90, 32, 100, 52            # state box, agent-step box
_STATES = {"Open": (15, 120), "Assigned": (125, 120), "In Progress": (235, 120),
           "Fixed": (350, 120), "Closed": (460, 120), "On Hold": (235, 200)}
_STEPS = {"intake": (10, 20), "first_reply": (120, 20), "resolution": (230, 20),
          "learn": (455, 20), "follow_through": (345, 192)}
_STATE_EDGES = [((105, 136), (125, 136), False), ((215, 136), (235, 136), False),
                ((325, 136), (350, 136), False), ((440, 136), (460, 136), False),
                ((280, 152), (280, 200), True)]          # In Progress ⇄ On Hold
_STEP_EDGES = {"intake": [((60, 72), (60, 120), "Open")],
               "first_reply": [((170, 72), (170, 120), "Assigned")],
               "resolution": [((280, 72), (280, 120), "In Progress")],
               "learn": [((505, 72), (505, 120), "Closed")],
               "follow_through": [((345, 216), (325, 216), "On Hold"), ((395, 192), (395, 152), "Fixed")]}
_STRENGTH = {"auto": 3, "suggest": 2, "practice": 1}


def stage_mode(settings: dict, stage: str) -> str:
    """inactive (agent off) · off · practice · suggest · auto — what actually happens."""
    if not settings.get("agent_enabled"):
        return "inactive"
    m = settings.get(f"agent_stage_{stage}", "suggest")
    if m == "off":
        return "off"
    return "practice" if settings.get("agent_shadow") else m


def _flow(settings: dict, edition, *, stages, short, help_, positions, state_edges, step_edges, states_xy,
          prefix, enabled, practice, state_label=None, step_help=None, extra_summary="") -> dict:
    """One flow picture (ticket or booking). Each 🤖 step is ALWAYS coloured by its own
    Off/Suggest/Auto choice; practice mode adds a purple dashed ring and "· practice" instead of
    hiding the choice; a state lights up in the colour of the strongest step that works on it."""
    chosen = {k: settings.get(f"{prefix}{k}", "suggest") for k, _ in stages}
    modes = {k: ("inactive" if not enabled else "off" if chosen[k] == "off" else "practice" if practice
                 else chosen[k]) for k, _ in stages}
    # Vicki 2026-10-31: "when turning things to Auto the color coding does not work" — with the agent
    # (or that section) off every step stayed grey "agent off", so picking Auto / Suggest showed
    # nothing. Now each step keeps its own Auto / Suggest / Off colour even while the agent is off,
    # drawn dashed and faint (mode "inactive"), and the summary says what will run once it's on.
    look = dict(chosen)
    live = {k for k, m in modes.items() if m in ("practice", "suggest", "auto")}
    best: dict = {}
    for k in live:
        for *_, st in step_edges[k]:
            if _STRENGTH[chosen[k]] > _STRENGTH.get(best.get(st), 0):
                best[st] = chosen[k]
    states = []
    for s, (x, y) in states_xy.items():
        lit = s in best
        color = MODE_COLORS[best[s]] if lit else "#94a3b8"
        states.append({"id": s, "label": state_label(s) if state_label else s,
                       "x": x, "y": y, "w": _SW, "h": _SH, "lit": lit, "color": color,
                       "tint": MODE_TINTS.get(color, "#ffffff") if lit else "#ffffff"})
    steps = []
    for k, (x, y) in positions.items():
        color = MODE_COLORS[look[k]]
        ring = enabled and practice and chosen[k] != "off"   # drawn as a purple ring + "practice" line
        steps.append({"id": k, "label": short[k], "mode": modes[k], "chosen": chosen[k],
                      "practice": ring, "color": color, "tint": MODE_TINTS[color], "word": MODE_WORDS[look[k]],
                      "help": step_help(k) if step_help else help_[k], "x": x, "y": y, "w": _AW, "h": _AH})
    edges = [{"x1": a[0], "y1": a[1], "x2": b[0], "y2": b[1], "kind": "state", "color": "#94a3b8",
              "dash": False, "both": both} for a, b, both in state_edges]
    for k, lst in step_edges.items():
        for a, b, _st in lst:
            edges.append({"x1": a[0], "y1": a[1], "x2": b[0], "y2": b[1], "kind": "step",
                          "color": MODE_COLORS[look[k]], "dash": modes[k] in ("off", "inactive"), "both": False})
    names = lambda ks: ", ".join(short[k] for k in ks)  # noqa: E731
    parts = []
    for m, word in (("auto", "Does on its own"), ("suggest", "Waits for your OK"), ("off", "Off")):
        ks = [k for k, _ in stages if chosen[k] == m]
        if ks:
            parts.append(f"{word}: {names(ks)}.")
    plan = " ".join(parts) + (f" {extra_summary}" if extra_summary else "")
    if not enabled:
        summary = ("Agent is off — nothing runs (the faint dashed boxes show your choices). When you turn it on"
                   + (" (practice mode is on, so it will only show what it would do)" if practice else "")
                   + ": " + plan)
    elif not live:
        summary = "Agent is on, but every step is Off — nothing runs."
    else:
        summary = plan
        if practice:
            summary = ("Practice mode is ON — nothing is changed and nothing is sent to customers; the "
                       "agent only shows what it would do. When you turn practice off: " + summary)
    legend = [["auto", MODE_COLORS["auto"], "automatic"], ["suggest", MODE_COLORS["suggest"], "waits for OK"],
              ["practice", MODE_COLORS["practice"], "practice ring (shows only)"],
              ["off", MODE_COLORS["off"], "off"]]
    return {"w": FLOW_W, "h": FLOW_H, "states": states, "steps": steps, "edges": edges,
            "summary": summary, "legend": legend, "practice": enabled and practice}


def flow(settings: dict, edition: str | None = None) -> dict:
    """The ticket-flow picture (2026-10-30). David, same day: "I don't see the states turn
    green when selected on." So each 🤖 step is ALWAYS coloured by its own Off/Suggest/Auto
    choice; practice mode adds a purple dashed ring and "· practice" instead of hiding the
    choice; a state lights up in the colour of the strongest step that works on it."""
    solo = edition != "business"
    return _flow(settings, edition, stages=STAGES, short=STAGE_SHORT, help_=STAGE_HELP, positions=_STEPS,
                 state_edges=_STATE_EDGES, step_edges=_STEP_EDGES, states_xy=_STATES, prefix="agent_stage_",
                 enabled=bool(settings.get("agent_enabled")), practice=bool(settings.get("agent_shadow")),
                 state_label=lambda s: "Assigned (you)" if s == "Assigned" and solo else s,
                 step_help=lambda k: STAGE_HELP[k] + (" (Solo: every ticket stays yours, so it doesn't route.)"
                                                      if k == "intake" and solo else ""))


# ── The Booking & scheduling agent (booking-agent-spec.md; David 2026-10-30: "yes for 1-5") ──
# The same assistant (name, photo, provider, hours, budget) with a second set of stages for
# bookings and the schedule, its own on/off and its own practice mode. Decisions confirmed:
# (1) it may confirm bookings only when "Let the agent confirm bookings" is ticked, Decide is
# Auto, practice is off and every guardrail holds; (2) its own practice switch; (3) weather check
# for outdoor services, offers only; (4) filling openings follows Keep on track's setting;
# (5) settings + diagram first, then the shared engine.

BK_STAGES = (
    ("check", "Check — address, service area, duplicates, history"),
    ("decide", "Decide — recommend approve / another time / decline, and the crew"),
    ("offer", "Offer times for requests with no date"),
    ("reply", "Answer customers about their visit"),
    ("track", "Keep on track — chase answers, fill openings, weather"),
    ("learn", "Learn — real job times and customer preferences"),
)
BK_STAGE_SHORT = {"check": "Check", "decide": "Decide", "offer": "Offer times", "reply": "Answer",
                  "track": "Keep on track", "learn": "Learn"}
BK_STAGE_HELP = {
    "check": ("When a booking or request arrives, the agent checks the address is on the map and in your area, "
              "looks for duplicate bookings, reads the customer's history (returning, notes, past visits) and "
              "notes anything missing, as one internal note with flags."),
    "decide": ("For each booking waiting in 📅 To approve, the agent recommends Approve (their time or a backup), "
               "Suggest a better time (close to that day's other jobs), or Decline — and picks the crew. You see "
               "\"🤖 suggests…\" on the card with one tap to use it. It confirms bookings itself only if you tick "
               "\"Let the agent confirm bookings\"."),
    "offer": ("For requests with no date yet (new service requests, released bookings), the agent picks 1–3 good "
              "open times and offers them to the customer, who accepts one on their request page."),
    "reply": ("Answers customers' questions about their visit, files things like a gate code or pets on the job, "
              "and turns \"can you come earlier?\" into an offer from the open times."),
    "track": ("Chases suggestions nobody answered, reminds approvers before a booking would be released, offers "
              "freed-up times to the waitlist or to waiting requests, checks tomorrow's weather for outdoor "
              "services and offers a new time if rain (60 %+) or wind (25 mph+) is forecast. With the waitlist on, "
              "this stage decides each offer: Suggest = you OK it in 🤖 Agent, Auto = offered at once, Off = the "
              "waitlist offers by itself."),
    "learn": ("When booked jobs are done, compares the real time on site with the service's \"Takes\" minutes and "
              "proposes an update after a pattern; proposes customer notes like \"prefers mornings\". A person "
              "always accepts or rejects these."),
}
BK_PRACTICE_HELP = ("Practice mode for bookings — the agent works every booking step that isn't Off, but only "
                    "shows what it would have done. Nothing is booked, offered or sent. Separate from the ticket "
                    "agent's practice switch, so you can trust one and still rehearse the other.")
BK_CONFIRM_HELP = ("Lets the agent confirm a booking itself — only when Decide is Auto, practice is off, and every "
                   "check passes: the time is still open and is the customer's own choice or backup, your "
                   "instant-booking limits allow it, the address is found and in your area, nothing was flagged, "
                   "the agent is at least 80 % sure, and it hasn't hit its daily limit. Otherwise you confirm.")
BK_WEATHER_HELP = ("Checks tomorrow's forecast for services you mark as outdoor (Web forms → Services offered "
                   "online) and offers the customer a new time when rain or high wind is likely. The visit stays "
                   "unless the customer accepts.")

DEFAULTS.update({
    "agent_bk_enabled": False,           # the booking & scheduling section (needs agent_enabled too)
    "agent_bk_shadow": True,             # its own practice mode
    **{f"agent_bk_stage_{k}": "suggest" for k, _ in BK_STAGES},
    "agent_bk_can_confirm": False,       # let the agent confirm bookings (guardrails, spec §5.3)
    "agent_bk_confirm_per_day": 5,
    "agent_bk_weather": True,
    "agent_bk_check_hour": 16,           # when tomorrow's visits are checked (weather, overfull days)
})
CHOICES.update({f"agent_bk_stage_{k}": STAGE_MODES for k, _ in BK_STAGES})
RANGES.update({"agent_bk_confirm_per_day": (1, 50), "agent_bk_check_hour": (0, 23)})

_BK_STATES = {"Requested": (15, 120), "To approve": (125, 120), "Suggested": (210, 200),
              "Scheduled": (300, 120), "Done": (460, 120)}
_BK_STEPS = {"check": (10, 20), "decide": (120, 20), "reply": (290, 20), "learn": (455, 20),
             "offer": (15, 192), "track": (345, 192)}
_BK_STATE_EDGES = [((105, 136), (125, 136), False), ((215, 136), (300, 136), False),
                   ((390, 136), (460, 136), False), ((170, 152), (230, 200), False),   # Suggest
                   ((280, 200), (320, 152), False)]                                   # Accept
_BK_STEP_EDGES = {"check": [((40, 72), (40, 120), "Requested"), ((90, 72), (150, 120), "To approve")],
                  "decide": [((175, 72), (175, 120), "To approve")],
                  "reply": [((340, 72), (340, 120), "Scheduled")],
                  "learn": [((505, 72), (505, 120), "Done")],
                  "offer": [((60, 192), (60, 152), "Requested"), ((115, 216), (210, 216), "Suggested")],
                  "track": [((395, 192), (370, 152), "Scheduled"), ((345, 216), (300, 216), "Suggested")]}


def bk_stage_mode(settings: dict, stage: str) -> str:
    """inactive (agent or its booking section off) · off · practice · suggest · auto."""
    if not (settings.get("agent_enabled") and settings.get("agent_bk_enabled")):
        return "inactive"
    m = settings.get(f"agent_bk_stage_{stage}", "suggest")
    if m == "off":
        return "off"
    return "practice" if settings.get("agent_bk_shadow") else m


def can_confirm(settings: dict) -> bool:
    """The switch half of spec §5.3: the guardrails themselves are checked per booking."""
    return (bk_stage_mode(settings, "decide") == "auto" and bool(settings.get("agent_bk_can_confirm")))


def booking_flow(settings: dict, edition: str | None = None) -> dict:
    """The booking-flow picture with the booking agent's steps (same drawing code as flow())."""
    enabled = bool(settings.get("agent_enabled")) and bool(settings.get("agent_bk_enabled"))
    if can_confirm(settings):
        extra = (f"It may confirm bookings itself (at most {settings.get('agent_bk_confirm_per_day', 5)} a day, "
                 "only when every check passes).")
    elif settings.get("agent_bk_can_confirm"):
        extra = "\"Let the agent confirm bookings\" is ticked, but only works with Decide on Auto and practice off."
    else:
        extra = "A person always confirms bookings."
    out = _flow(settings, edition, stages=BK_STAGES, short=BK_STAGE_SHORT, help_=BK_STAGE_HELP, positions=_BK_STEPS,
                state_edges=_BK_STATE_EDGES, step_edges=_BK_STEP_EDGES, states_xy=_BK_STATES,
                prefix="agent_bk_stage_", enabled=enabled, practice=bool(settings.get("agent_bk_shadow")),
                extra_summary=extra)
    if not settings.get("agent_enabled"):
        out["summary"] = "The agent is off (Agent on, above) — booking steps don't run either."
    elif not settings.get("agent_bk_enabled"):
        out["summary"] = "Booking & scheduling is off — nothing runs. Your choices are kept for when you turn it on."
    return out


def bk_ui_options() -> dict:
    return {"stages": [list(s) for s in BK_STAGES], "stage_help": BK_STAGE_HELP, "practice_help": BK_PRACTICE_HELP,
            "confirm_help": BK_CONFIRM_HELP, "weather_help": BK_WEATHER_HELP}


# ── The Jobs agent (jobs-agent-spec.md; David 2026-10-30/31: "Yes for 1, 2; 3 = it only suggests
# dates at first, and never moves a fixed-time job or anything today; 4 = a separate agent
# database; 5 = settings and diagram first"). Its settings and its queue live in their own
# database (desk_agent_store.py), so it works with or without Service Desk.

JB_STAGES = (
    ("quotes", "Quotes — follow up open quotes, turn approved ones into jobs"),
    ("schedule", "Schedule — suggest dates for unscheduled jobs"),
    ("prep", "Prep the day — check tomorrow's route, details and weather"),
    ("onsite", "On site — jobs running long, crews still clocked in"),
    ("closeout", "Close out & invoice — draft the invoice when a job is done"),
    ("collect", "Get paid — reminders for unpaid invoices"),
    ("repeat", "Repeat & win back — next recurring visit, quiet customers"),
    ("learn", "Learn — real job times and customer notes"),
)
JB_STAGE_SHORT = {"quotes": "Quotes", "schedule": "Schedule", "prep": "Prep the day", "onsite": "On site",
                  "closeout": "Close out", "collect": "Get paid", "repeat": "Repeat", "learn": "Learn"}
JB_STAGE_HELP = {
    "quotes": ("A quote still open after the follow-up days gets a friendly follow-up message drafted for the "
               "customer. When a quote is approved, the agent proposes the job from it (service, quoted price, "
               "address) as Unscheduled."),
    "schedule": ("For each Unscheduled job the agent suggests the best date and stop order from the Route Advisor — "
                 "close to that day's other jobs, the customer's preferred days, your Working Days. It only "
                 "SUGGESTS dates (you tap Use this), and never moves a fixed-time (Hard) job or anything today. "
                 "The weekly sort and the day's routes are in the Route flow below."),
    "prep": ("At the prep hour it checks tomorrow: an overfull day, a missing address or gate code, rain or wind "
             "for outdoor jobs. It leaves notes for the crew and suggests a better day; the route itself is the "
             "Route flow's Route and Send routes steps."),
    "onsite": ("Flags a job running more than 50 % over its estimate, a crew still clocked in after hours, a job "
               "marked done with no time logged, and gaps in the day's mileage log. Internal notes only — "
               "it never edits time or mileage."),
    "closeout": ("When a job is Complete it checks it's ready to bill (time, notes, photos) and drafts the invoice "
                 "from the job's price. Sending the invoice waits for you unless you tick \"Let the agent send "
                 "invoices\". It sends the receipt after you mark an invoice paid."),
    "collect": ("Unpaid invoices get polite reminders at the reminder days (7, 14 and 30 by default), the last one "
                "firmer, then a note to you to call. Amounts always come from the invoice; it never changes an "
                "amount and never marks anything paid."),
    "repeat": ("When a recurring customer's job is done it sets up the next visit on their usual frequency (monthly, "
               "quarterly …) — on Suggest you OK it first — and it drafts a \"time for your next service?\" message "
               "to customers who've gone quiet."),
    "learn": ("Compares real time on site with the job's estimate after a pattern (5+ jobs, 20 %+ off) and "
              "proposes a new estimate, plus customer notes like \"call on arrival\". A person always accepts "
              "or rejects these."),
}
JB_PRACTICE_HELP = ("Practice mode for the Jobs agent — it works every step that isn't Off but only shows what it "
                    "would have done. Nothing is scheduled, invoiced or sent. Separate from the other sections' "
                    "practice switches.")
JB_SEND_HELP = ("Lets the agent send an invoice itself — only with Close out on Auto and practice off, and only when "
                "every check holds: it drafted the invoice from the job with no changes, the amount matches the job "
                "(or the approved quote), the customer can be reached and didn't opt out, time was logged, it's "
                "under the amount limit and the daily limit. Otherwise you send it.")
JB_REMIND_HELP = "Days after the invoice date for the 1st, 2nd and 3rd payment reminder (the 3rd is firmer)."
JB_WEATHER_HELP = "Prep the day checks tomorrow's forecast for outdoor jobs and suggests a better day when it's bad."

DEFAULTS.update({
    "agent_jb_enabled": False,            # the Jobs agent on (its own switch — works without Service Desk)
    "agent_jb_shadow": True,              # its own practice mode
    **{f"agent_jb_stage_{k}": ("auto" if k == "onsite" else "suggest") for k, _ in JB_STAGES},
    "agent_jb_can_send_invoices": False,  # decision 1: yes, behind this switch, off by default
    "agent_jb_invoice_max": 1000,         # $ ceiling for an invoice the agent sends itself
    "agent_jb_invoices_per_day": 10,
    "agent_jb_quote_days": 5,             # follow up a quote still open after this many days
    "agent_jb_remind_days": [7, 14, 30],  # decision 2: payment reminders, the 3rd firmer
    "agent_jb_prep_hour": 16,             # tomorrow's check
    "agent_jb_weather": True,
})
CHOICES.update({f"agent_jb_stage_{k}": STAGE_MODES for k, _ in JB_STAGES})
RANGES.update({"agent_jb_invoice_max": (0, 100000), "agent_jb_invoices_per_day": (1, 100),
               "agent_jb_quote_days": (1, 60), "agent_jb_prep_hour": (0, 23)})
JB_KEYS = tuple(k for k in DEFAULTS if k.startswith("agent_jb_"))


def validate_jb(key: str, value) -> None:
    if key == "agent_jb_remind_days":
        if (not 1 <= len(value) <= 3 or not all(type(d) is int and 1 <= d <= 120 for d in value)
                or list(value) != sorted(set(value))):
            raise ValueError("agent_jb_remind_days must be 1-3 different days, smallest first, each 1-120")


# Layout (560 x 250, the same box as the other diagrams): the job's life runs left to right
# along the top row and comes back right to left along the bottom row; Repeat goes back up.
_JB_STATES = {"Quote": (10, 78), "Unscheduled": (150, 78), "Scheduled": (290, 78), "In Progress": (440, 78),
              "Paid": (60, 140), "Invoiced": (230, 140), "Complete": (440, 140)}
_JB_STEPS = {"quotes": (5, 0), "schedule": (150, 0), "prep": (295, 0), "onsite": (445, 0),
             "repeat": (5, 198), "collect": (125, 198), "closeout": (245, 198), "learn": (455, 198)}
_JB_STATE_EDGES = [((100, 94), (150, 94), False), ((240, 94), (290, 94), False), ((380, 94), (440, 94), False),
                   ((485, 110), (485, 140), False), ((440, 156), (320, 156), False),
                   ((230, 156), (150, 156), False), ((120, 140), (175, 110), False)]       # Paid → next visit
_JB_STEP_EDGES = {"quotes": [((55, 52), (55, 78), "Quote")],
                  "schedule": [((200, 52), (200, 78), "Unscheduled")],
                  "prep": [((345, 52), (345, 78), "Scheduled")],
                  "onsite": [((495, 52), (495, 78), "In Progress")],
                  "repeat": [((70, 198), (90, 172), "Paid")],
                  "collect": [((190, 198), (250, 172), "Invoiced")],
                  "closeout": [((345, 215), (450, 172), "Complete")],
                  "learn": [((505, 198), (505, 172), "Complete")]}


def jb_stage_mode(settings: dict, stage: str) -> str:
    """inactive (Jobs agent off) · off · practice · suggest · auto."""
    if not settings.get("agent_jb_enabled"):
        return "inactive"
    m = settings.get(f"agent_jb_stage_{stage}", "suggest")
    if m == "off":
        return "off"
    return "practice" if settings.get("agent_jb_shadow") else m


def can_send_invoices(settings: dict) -> bool:
    return jb_stage_mode(settings, "closeout") == "auto" and bool(settings.get("agent_jb_can_send_invoices"))


def jobs_flow(settings: dict, edition: str | None = None) -> dict:
    """The Jobs-flow picture with the Jobs agent's steps (same drawing code as flow())."""
    enabled = bool(settings.get("agent_jb_enabled"))
    if can_send_invoices(settings):
        extra = (f"It may send invoices itself (up to ${settings.get('agent_jb_invoice_max', 1000):,} each, "
                 f"{settings.get('agent_jb_invoices_per_day', 10)} a day, only when every check passes).")
    elif settings.get("agent_jb_can_send_invoices"):
        extra = "\"Let the agent send invoices\" is ticked, but only works with Close out on Auto and practice off."
    else:
        extra = "You send every invoice."
    extra += " Dates are only ever suggested; fixed-time jobs and today's jobs are never moved. No payments."
    out = _flow(settings, edition, stages=JB_STAGES, short=JB_STAGE_SHORT, help_=JB_STAGE_HELP, positions=_JB_STEPS,
                state_edges=_JB_STATE_EDGES, step_edges=_JB_STEP_EDGES, states_xy=_JB_STATES,
                prefix="agent_jb_stage_", enabled=enabled, practice=bool(settings.get("agent_jb_shadow")),
                extra_summary=extra)
    if not enabled:
        out["summary"] = "The Jobs agent is off — nothing runs. Your choices are kept for when you turn it on."
    return out


def jb_ui_options() -> dict:
    return {"stages": [list(s) for s in JB_STAGES], "stage_help": JB_STAGE_HELP, "practice_help": JB_PRACTICE_HELP,
            "send_help": JB_SEND_HELP, "remind_help": JB_REMIND_HELP, "weather_help": JB_WEATHER_HELP,
            "route_stages": [list(s) for s in RT_STAGES], "route_help": RT_STAGE_HELP,
            "route_practice_help": RT_PRACTICE_HELP, "route_enabled_help": RT_ENABLED_HELP,
            "route_scopes": [list(x) for x in RT_SCOPES], "weekdays": list(WEEKDAYS),
            "route_scope_help": RT_SCOPE_HELP, "sort_day_help": RT_SORT_HELP, "send_hour_help": RT_SEND_HELP}


# ── The Route flow (David 2026-10-31: "also show the route flow (with an agent) … first weekly
# sort, then jobs scheduled for the week, then scheduled jobs routed for the day or routes for the
# weeks, then crew gets their route"). A second diagram in the Jobs section, with its own stages,
# built on the Route Advisor tools (propose_week_moves / apply_week_moves, suggest_route_schedule,
# optimize_route, approve_route_schedule, email_route_now, replan_route_day). Decision 3 holds
# here too: it never moves a fixed-time (Hard) job or anything today.

RT_STAGES = (
    ("sort", "Sort the week — which day each job goes on"),
    ("plan", "Schedule the week — put the sorted jobs on the calendar"),
    ("route", "Route — the stop order for each day, or the whole week"),
    ("send", "Send routes — approve and give each crew their route"),
    ("replan", "Re-plan the day — cancellations, running late, a new urgent job"),
)
RT_STAGE_SHORT = {"sort": "Sort the week", "plan": "Schedule week", "route": "Route", "send": "Send routes",
                  "replan": "Re-plan day"}
RT_STAGE_HELP = {
    "sort": ("On the sort day, the agent takes next week's unscheduled and flexible (Soft) jobs and proposes which "
             "day each goes on — grouping nearby jobs, keeping customers' preferred days and your Working Days, "
             "and spreading the work evenly (the Route Advisor's week plan). Fixed-time (Hard) jobs stay put."),
    "plan": ("Puts the sorted week on the calendar: each job gets its day (and arrival window if it has one). On "
             "Suggest you see the week plan and tap Use this; nothing today and no Hard job is ever moved."),
    "route": ("Orders the stops for each day — or for the whole week at once — to keep driving short, honouring "
              "arrival windows and Hard times (the Route Advisor's suggest / optimise)."),
    "send": ("Approves the routes and gives each crew theirs — the route email / app route with maps links, the "
             "evening before (or at the hour you set). On Suggest you approve each day's route first."),
    "replan": ("During the day: when a job is cancelled, a crew runs late, or an urgent job comes in, it re-orders "
               "the rest of that day and tells the crew. It never adds a job to today on its own — that waits for "
               "you."),
}
RT_SCOPES = (("day", "Each day"), ("week", "The whole week at once"))
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
RT_SCOPE_HELP = "Route each day on its own, or the whole week at once (better when jobs can move between days)."
RT_SORT_HELP = "The day the agent sorts the coming week (Friday = plan next week at the end of this one)."
RT_SEND_HELP = "When each crew gets tomorrow's route (18 = 6 pm the evening before; 6 = 6 am the same morning)."

RT_PRACTICE_HELP = ("Practice mode for the Route flow only — it works every route step that isn't Off but only shows "
                    "what it would have done. No job is moved, no route approved or sent. Separate from the jobs "
                    "practice switch.")
RT_ENABLED_HELP = ("The Route flow's own on/off switch (David 2026-10-31: a separate enable and practice mode for "
                   "the route flow). Works whether the Jobs agent is on or off.")

DEFAULTS.update({
    "agent_jb_rt_enabled": False,         # the Route flow on (its own switch, separate from the jobs one)
    "agent_jb_rt_shadow": True,           # its own practice mode
    **{f"agent_jb_rt_stage_{k}": "suggest" for k, _ in RT_STAGES},   # decision 3: suggest first
    "agent_jb_route_scope": "day",
    "agent_jb_sort_weekday": 4,           # Friday
    "agent_jb_route_send_hour": 18,       # the evening before
})
CHOICES.update({**{f"agent_jb_rt_stage_{k}": STAGE_MODES for k, _ in RT_STAGES},
                "agent_jb_route_scope": tuple(k for k, _ in RT_SCOPES)})
RANGES.update({"agent_jb_sort_weekday": (0, 6), "agent_jb_route_send_hour": (0, 23)})
JB_KEYS = tuple(k for k in DEFAULTS if k.startswith("agent_jb_"))

# Layout (560 x 250): the week's life left to right on top, the day's back along the bottom.
_RT_STATES = {"Unscheduled": (10, 78), "Week plan": (150, 78), "Scheduled": (290, 78), "Routed": (440, 78),
              "Done": (60, 140), "On the road": (230, 140), "Crew has route": (440, 140)}
_RT_STEPS = {"sort": (5, 0), "plan": (150, 0), "route": (295, 0), "send": (445, 0), "replan": (245, 198)}
_RT_STATE_EDGES = [((100, 94), (150, 94), False), ((240, 94), (290, 94), False), ((380, 94), (440, 94), False),
                   ((485, 110), (485, 140), False), ((440, 156), (320, 156), False), ((230, 156), (150, 156), False)]
_RT_STEP_EDGES = {"sort": [((55, 52), (55, 78), "Unscheduled")],
                  "plan": [((200, 52), (200, 78), "Week plan")],
                  "route": [((345, 52), (345, 78), "Scheduled")],
                  "send": [((495, 52), (495, 78), "Routed"), ((550, 52), (525, 140), "Crew has route")],
                  "replan": [((295, 198), (280, 172), "On the road")]}


def route_flow(settings: dict, edition: str | None = None) -> dict:
    """The route-flow picture (same drawing code and colours as the others)."""
    enabled = bool(settings.get("agent_jb_rt_enabled"))
    scope = dict(RT_SCOPES).get(settings.get("agent_jb_route_scope", "day"), "Each day").lower()
    day = WEEKDAYS[int(settings.get("agent_jb_sort_weekday", 4)) % 7]
    extra = (f"Sorts the coming week on {day}s; routes {scope}; crews get tomorrow's route at "
             f"{int(settings.get('agent_jb_route_send_hour', 18)):02d}:00. Fixed-time jobs and today's jobs are "
             "never moved.")
    out = _flow(settings, edition, stages=RT_STAGES, short=RT_STAGE_SHORT, help_=RT_STAGE_HELP, positions=_RT_STEPS,
                 state_edges=_RT_STATE_EDGES, step_edges=_RT_STEP_EDGES, states_xy=_RT_STATES,
                 prefix="agent_jb_rt_stage_", enabled=enabled, practice=bool(settings.get("agent_jb_rt_shadow")),
                state_label=lambda s: (("Crew's route" if edition == "business" else "Your route")
                                       if s == "Crew has route" else s),
                extra_summary=extra)
    if not enabled:
        out["summary"] = "The Route flow is off — routes are planned the way you do it now."
    return out


def rt_stage_mode(settings: dict, stage: str) -> str:
    """inactive (Route flow off) · off · practice · suggest · auto — the Route flow's own switches."""
    if not settings.get("agent_jb_rt_enabled"):
        return "inactive"
    m = settings.get(f"agent_jb_rt_stage_{stage}", "suggest")
    if m == "off":
        return "off"
    return "practice" if settings.get("agent_jb_rt_shadow") else m


def jb_any_on(settings: dict) -> bool:
    """The Jobs section runs when the Jobs agent or the Route flow is on."""
    return bool(settings.get("agent_jb_enabled") or settings.get("agent_jb_rt_enabled"))


# ── The HR agent (hr-agent-spec.md; Vicki 2026-10-31: "1 = make configurable, 2 = make
# configurable, 3 = make configurable, 4 = its own database inside the HR data folder,
# 5 = only AIs with API keys and the Claude CLI (no chat — so not Muse), 6 = settings and
# diagram first"). Its settings and queue live in the HR data folder (desk_agent_hr_store.py).
# Deliberately narrow: it watches deadlines, prepares paperwork and drafts answers; people make
# every decision about a person.

HR_STAGES = (
    ("recruit", "Recruit — acknowledge applicants, keep candidates moving"),
    ("onboard", "Onboard — I-9, W-4, new-hire report, first-week checklist"),
    ("timeoff", "Time off & schedules — check requests, recommend approve / deny"),
    ("timeclock", "Time clock — missed punches, overtime coming, after-hours"),
    ("compliance", "Documents & training — expiring licences, training due"),
    ("answer", "Employee questions — draft answers from the handbook"),
    ("incidents", "Incidents & concerns — acknowledged, assigned, deadlines"),
    ("offboard", "Offboard — final pay date, equipment, access, notices"),
    ("learn", "Learn — handbook gaps, steps that are always late"),
)
HR_STAGE_SHORT = {"recruit": "Recruit", "onboard": "Onboard", "timeoff": "Time off", "timeclock": "Time clock",
                  "compliance": "Docs & training", "answer": "Questions", "incidents": "Incidents",
                  "offboard": "Offboard", "learn": "Learn"}
HR_STAGE_HELP = {
    "recruit": ("Drafts an acknowledgement to new applicants, reminds HR about candidates waiting too long and drafts "
                "interview-time emails from the times HR gives. It never scores, ranks, rejects or advances anyone."),
    "onboard": ("Watches each new hire's checklist — I-9 by the 3rd business day, W-4, the state new-hire report, "
                "direct deposit, handbook acknowledgement, required training — says what's missing and drafts the "
                "nudge. It checks documents are there and readable; a person always verifies them."),
    "timeoff": ("For each time-off request, shift swap or schedule change it checks the balance, notice, blackout "
                "dates, who else is off and (with the Jobs app) booked jobs, then recommends approve or deny with the "
                "reason. It approves on its own only if you tick \"Let the agent approve time off\"; denials are "
                "always a person."),
    "timeclock": ("Flags missed clock-outs, someone still clocked in after hours, hourly (non-exempt) staff heading "
                  "for overtime, and clock-ins away from their location. Notes only — it never edits a time entry."),
    "compliance": ("Licences, certifications and work authorization expiring soon, required training past due, and "
                   "state rules or forms that changed. It drafts the reminder and the HR task."),
    "answer": ("Drafts answers to employees' HR Portal messages from your handbook, policies, holidays and that "
               "employee's own balances and schedule. Anything sensitive — harassment, injury, medical, leave rights, "
               "pay disputes, resignations — goes straight to a person."),
    "incidents": ("Makes sure every incident report is acknowledged and assigned to HR within a business day and "
                  "tracks the deadlines (OSHA log 7 days, workers' comp notice). It never investigates and never "
                  "contacts anyone named in a report. Whether it may read the report is your choice below."),
    "offboard": ("After HR starts a termination: the final-pay deadline for your state, equipment to return, "
                 "AI-Prowler and HR Portal access to turn off (a person does it), COBRA and other required notices."),
    "learn": ("Questions employees keep asking that the handbook doesn't answer, policies that conflict with your "
              "state's rules, checklist steps that are always late — as suggestions for HR. It never changes a "
              "policy."),
}
HR_PRACTICE_HELP = ("Practice mode for HR — the agent works every HR step that isn't Off but only shows what it "
                    "would have done. Nothing is approved, sent or assigned. Separate from the other sections' "
                    "practice switches.")
HR_TIMEOFF_HELP = ("Lets the agent approve simple time off itself — only with Time off on Auto and practice off, "
                   "and only when every check holds: paid time off or sick days (never unpaid, FMLA, jury duty or "
                   "\"other\"), the balance covers it, at most the max days, at least the notice days, no blackout or "
                   "holiday clash, no more than the limit off that day, no booked jobs for them, nothing flagged on "
                   "the employee, and under the daily limit. Everything else is a recommendation; a person always "
                   "denies.")
HR_REVIEWERS = (("hr_admin", "The owner and HR Admin users"),
                ("hr_admin_managers", "…and managers, for their own team's time off and swaps"))
HR_REVIEWERS_HELP = ("Who approves, edits or rejects what the HR agent suggests. Managers (if allowed) only see time "
                     "off, swaps and schedule changes for their own team — never documents, incidents or offboarding, "
                     "and never their own requests.")
HR_INCIDENTS = (("type_only", "Type only — it sees that a report came in and its type"),
                ("read", "Read the report — to judge urgency and deadlines"))
HR_INCIDENTS_HELP = ("\"Type only\": the AI is told a report arrived, its type (injury, safety, conduct, other) and "
                     "its dates — never what it says. \"Read the report\": it also reads the text so it can judge "
                     "urgency and deadlines. Either way it never investigates or contacts anyone named in it.")
HR_RUNNER_HELP = ("HR data only goes to an AI that runs on its own with a key you control: a Claude API key or the "
                  "Grok bot (xAI API key). It never runs from a chat (Claude.ai, Muse, Grok.com).")
HR_RUNNERS = ("claude_api", "grok_api")

DEFAULTS.update({
    "agent_hr_enabled": False,               # its own on/off
    "agent_hr_shadow": True,                 # its own practice mode
    **{f"agent_hr_stage_{k}": ("auto" if k == "timeclock" else "suggest") for k, _ in HR_STAGES},
    "agent_hr_can_approve_timeoff": False,   # decision 1: configurable, off by default
    "agent_hr_timeoff_max_days": 2,
    "agent_hr_timeoff_notice_days": 14,
    "agent_hr_timeoff_max_off": 1,           # people off the same day (per team / crew)
    "agent_hr_timeoff_per_day": 5,           # approvals a day
    "agent_hr_reviewers": "hr_admin",        # decision 2: configurable
    "agent_hr_incidents_access": "type_only",  # decision 3: configurable
    "agent_hr_overtime_warn_hours": 36,      # non-exempt staff, per week
    "agent_hr_quiet_hours": [8, 18],         # messages to employees only between these hours
    "agent_hr_expiry_days": [60, 30, 7],     # document / licence warnings
    "agent_hr_ack_sensitive": True,          # sensitive messages get "HR will get back to you"
})
CHOICES.update({**{f"agent_hr_stage_{k}": STAGE_MODES for k, _ in HR_STAGES},
                "agent_hr_reviewers": tuple(k for k, _ in HR_REVIEWERS),
                "agent_hr_incidents_access": tuple(k for k, _ in HR_INCIDENTS)})
RANGES.update({"agent_hr_timeoff_max_days": (1, 10), "agent_hr_timeoff_notice_days": (0, 90),
               "agent_hr_timeoff_max_off": (1, 20), "agent_hr_timeoff_per_day": (1, 50),
               "agent_hr_overtime_warn_hours": (20, 60)})
HR_KEYS = tuple(k for k in DEFAULTS if k.startswith("agent_hr_"))


def validate_hr(key: str, value) -> None:
    if key == "agent_hr_quiet_hours":
        if (len(value) != 2 or not all(type(h) is int for h in value) or not 0 <= value[0] < value[1] <= 24):
            raise ValueError("agent_hr_quiet_hours must be [start, end] hours with 0 <= start < end <= 24")
    if key == "agent_hr_expiry_days":
        if (not 1 <= len(value) <= 3 or not all(type(d) is int and 1 <= d <= 365 for d in value)
                or list(value) != sorted(set(value), reverse=True)):
            raise ValueError("agent_hr_expiry_days must be 1-3 different days, largest first, each 1-365")


def hr_stage_mode(settings: dict, stage: str) -> str:
    """inactive (HR agent off) · off · practice · suggest · auto."""
    if not settings.get("agent_hr_enabled"):
        return "inactive"
    m = settings.get(f"agent_hr_stage_{stage}", "suggest")
    if m == "off":
        return "off"
    return "practice" if settings.get("agent_hr_shadow") else m


def can_approve_timeoff(settings: dict) -> bool:
    return hr_stage_mode(settings, "timeoff") == "auto" and bool(settings.get("agent_hr_can_approve_timeoff"))


def hr_runner(settings: dict, edition: str | None) -> tuple:
    """(provider, why_not): decision 5 — the HR agent runs only on a key-based runner, never from a chat
    (2026-11-01: the Claude CLI runner was removed)."""
    p = effective_provider(settings, edition)
    if p in HR_RUNNERS:
        return p, ""
    return "", ("HR data only goes to an AI with a key you control — choose a Claude API key or the Grok bot "
                "as the agent's runner. It never runs from a chat.")


# Layout (560 x 250, the same box as the other diagrams). Top row: hired → working; bottom row:
# leave and leaving. The 9 steps sit above and below the states they work on.
_HR_STATES = {"Candidate": (10, 78), "Hired": (120, 78), "Onboarding": (230, 78), "Active": (340, 78),
              "On leave": (450, 78), "Former": (10, 140), "Offboarding": (120, 140)}
_HR_STEPS = {"recruit": (5, 0), "onboard": (115, 0), "compliance": (225, 0), "answer": (335, 0),
             "timeoff": (445, 0),
             "offboard": (5, 198), "learn": (115, 198), "incidents": (225, 198), "timeclock": (335, 198)}
_HR_STATE_EDGES = [((100, 94), (120, 94), False), ((210, 94), (230, 94), False), ((320, 94), (340, 94), False),
                   ((430, 94), (450, 94), True),                                   # Active ⇄ On leave
                   ((350, 110), (210, 146), False),                                # Active → Offboarding
                   ((470, 110), (210, 160), False),                                # On leave → Offboarding
                   ((120, 156), (100, 156), False)]                                # Offboarding → Former
_HR_STEP_EDGES = {"recruit": [((55, 52), (55, 78), "Candidate")],
                  "onboard": [((150, 52), (150, 78), "Hired"), ((200, 52), (255, 78), "Onboarding")],
                  "compliance": [((310, 52), (360, 78), "Active")],
                  "answer": [((400, 52), (400, 78), "Active")],
                  "timeoff": [((480, 52), (480, 78), "On leave"), ((455, 52), (420, 78), "Active")],
                  "offboard": [((90, 198), (150, 172), "Offboarding"), ((40, 198), (40, 172), "Former")],
                  "learn": [((205, 198), (270, 110), "Onboarding")],
                  "incidents": [((300, 198), (370, 110), "Active")],
                  "timeclock": [((420, 198), (410, 110), "Active")]}


def hr_flow(settings: dict, edition: str | None = None) -> dict:
    """The HR picture with the HR agent's steps (same drawing code and colours as the others)."""
    enabled = bool(settings.get("agent_hr_enabled"))
    if can_approve_timeoff(settings):
        extra = (f"It may approve simple time off itself (up to {settings.get('agent_hr_timeoff_max_days', 2)} "
                 f"day(s), {settings.get('agent_hr_timeoff_notice_days', 14)} days' notice, only when every check "
                 "passes).")
    elif settings.get("agent_hr_can_approve_timeoff"):
        extra = "\"Let the agent approve time off\" is ticked, but only works with Time off on Auto and practice off."
    else:
        extra = "A person approves all time off."
    extra += (" Reviews: " + ("the owner, HR Admin users and managers (their own team's time off)"
                              if settings.get("agent_hr_reviewers") == "hr_admin_managers"
                              else "the owner and HR Admin users")
              + ". Incident reports: " + ("it reads them" if settings.get("agent_hr_incidents_access") == "read"
                                          else "type only") + ".")
    _p, why = hr_runner(settings, edition)
    if why:
        extra += " ⚠ " + why
    extra += " People make every decision about a person; it never changes pay, time or records."
    out = _flow(settings, edition, stages=HR_STAGES, short=HR_STAGE_SHORT, help_=HR_STAGE_HELP, positions=_HR_STEPS,
                state_edges=_HR_STATE_EDGES, step_edges=_HR_STEP_EDGES, states_xy=_HR_STATES,
                prefix="agent_hr_stage_", enabled=enabled, practice=bool(settings.get("agent_hr_shadow")),
                extra_summary=extra)
    if not enabled:
        out["summary"] = "The HR agent is off — nothing runs. Your choices are kept for when you turn it on."
    return out


def hr_ui_options() -> dict:
    return {"stages": [list(s) for s in HR_STAGES], "stage_help": HR_STAGE_HELP, "practice_help": HR_PRACTICE_HELP,
            "timeoff_help": HR_TIMEOFF_HELP, "reviewers": [list(x) for x in HR_REVIEWERS],
            "reviewers_help": HR_REVIEWERS_HELP, "incidents": [list(x) for x in HR_INCIDENTS],
            "incidents_help": HR_INCIDENTS_HELP, "runner_help": HR_RUNNER_HELP}
