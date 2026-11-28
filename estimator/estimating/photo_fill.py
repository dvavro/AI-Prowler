"""Upload your drawing - let's get an estimate (2026-11-27, Jamie): the AI reads a drawing or photo and answers a quick
estimate's questions.

On the ⚡ Quick estimate page the person picks a service, then uploads a drawing, a sketch or a photo of the job (a yard
plan, a photo of the yard, the pool, the driveway ...). The picture goes to the company's AI - the AI measuring agent
(agents/roles.py "llm_takeoff") on the agent API key, the same one AI design uses - together with the service's own
questions. The AI answers only those questions, says for each what it saw, and leaves out what the picture doesn't show.

Every answer is checked like a typed one (quick._coerce): a value that isn't one of the choices or is out of range is
dropped, never guessed. Nothing is priced here - the page fills the form, marks each AI answer for a person to check, and
the person presses Price it. The budget is checked before the call, usage is recorded, and the call is in the AI Log.
"""
from __future__ import annotations

import base64
import io
import json
import re
import time

from estimator.context import RequestContext
from estimator.errors import InvalidInput, NotAvailable

ROLE = "llm_takeoff"                  # the AI measuring role (🤖 AI agents in Setup), as AI design uses
FLOW = "photo_fill"                   # its step in providers.STEP_GROUPS (read: complex)
MAX_PHOTOS = 3                        # drawings or photos with one request
PHOTO_MAX_BYTES = 8 * 1024 * 1024     # each, as sent (the page shrinks phone photos before sending)
PHOTO_MAX_PX = 1600                   # their long side when they go to the AI
NOTE_MAX = 1000

SYSTEM = ("You are an experienced estimator for small service businesses (landscaping, pressure washing, pool service, "
          "cleaning, pest control and the like). You look at a customer's drawing, sketch or photo of a job and answer an "
          "estimate's intake questions from what you can actually see. You never invent what the picture doesn't show. "
          "Reply with ONLY one JSON object, nothing else.")

SHAPE = """{
  "summary": "one or two sentences: what the picture shows",
  "answers": {"<question id>": {"value": <the answer>, "why": "what in the picture shows it, in a few words"}},
  "not_shown": ["<question id>", ...]
}"""

RULES = """How to answer:
- Answer a question only when the picture (or the note) shows it. Put every question you can't tell in "not_shown".
- yes/no questions: true or false. Number questions: a number in the question's unit, inside its range. Choice
  questions: one of the listed values exactly (the value, not the label).
- Count what you can count (trees, windows, rooms, vehicles ...). For sizes, use the measurements written on a drawing;
  on a photo with no measurements pick the size choice that fits, and only give an exact size when the drawing gives it.
- "why" is short and plain: "4 palm trees along the back wall", "drawing says 60 x 40 ft back yard"."""


def _photos(images) -> list[dict]:
    """The person's pictures (data: URLs from the page), checked to be real pictures and shrunk for the AI."""
    if not images or not isinstance(images, list):
        raise InvalidInput("upload a drawing or a photo of the job", field="images")
    if len(images) > MAX_PHOTOS:
        raise InvalidInput(f"upload up to {MAX_PHOTOS} drawings or photos at a time", field="images")
    try:
        from PIL import Image
    except ImportError:                                             # pragma: no cover - Pillow ships with AI-Prowler
        raise NotAvailable("pictures can't be read on this PC (Pillow is missing)") from None
    out = []
    for i, s in enumerate(images):
        m = re.match(r"^data:image/(png|jpe?g|webp|gif|bmp);base64,([A-Za-z0-9+/=\s]+)$", str(s or ""))
        if not m:
            raise InvalidInput(f"file {i + 1} isn't a picture (PNG, JPG or WebP)", field="images")
        try:
            raw = base64.b64decode(m.group(2), validate=False)
        except ValueError:
            raise InvalidInput(f"file {i + 1} couldn't be read", field="images") from None
        if len(raw) > PHOTO_MAX_BYTES:
            raise InvalidInput(f"file {i + 1} is over {PHOTO_MAX_BYTES // (1024 * 1024)} MB", field="images")
        try:
            with Image.open(io.BytesIO(raw)) as im:
                im.load()
                im = im.convert("RGB")
                im.thumbnail((PHOTO_MAX_PX, PHOTO_MAX_PX))
                buf = io.BytesIO()
                im.save(buf, "JPEG", quality=88)
        except Exception:  # noqa: BLE001 - not a picture Pillow can open
            raise InvalidInput(f"file {i + 1} couldn't be read as a picture", field="images") from None
        out.append({"media_type": "image/jpeg", "data": base64.b64encode(buf.getvalue()).decode("ascii")})
    return out


def _question_text(q) -> str:
    kind = {"boolean": "yes/no", "integer": "whole number", "number": "number", "choice": "choice"}[q.type]
    parts = [f'- "{q.id}": {q.label} ({kind}']
    if q.unit:
        parts.append(f", in {q.unit}")
    if q.type in ("integer", "number") and (q.min is not None or q.max is not None):
        parts.append(f", {q.min if q.min is not None else '...'} to {q.max if q.max is not None else '...'}")
    parts.append(")")
    if q.help:
        parts.append(f" - {q.help}")
    if q.type == "choice":
        parts.append("\n    values: " + "; ".join(f'"{c["value"]}" = {c["label"]}' for c in q.choices))
    return "".join(parts)


def prompt_for(mod, note: str = "") -> str:
    """The question list the AI answers, for one service."""
    qs = "\n".join(_question_text(q) for q in mod.questions)
    extra = f"\nThe person's note about the job: {note}\n" if note else ""
    return (f"Service: {mod.name} - {mod.description}\n{extra}\nThe questions (answer by id):\n{qs}\n\n{RULES}\n\n"
            f"Answer in this shape:\n{SHAPE}")


def _json_object(text: str) -> dict:
    """The one JSON object in the AI's reply (it may wrap it in a code fence or a sentence)."""
    t = (text or "").strip()
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("no JSON object")
    got = json.loads(t[a:b + 1])
    if not isinstance(got, dict):
        raise ValueError("not a JSON object")
    return got


def parse(mod, text: str) -> dict:
    """The AI's reply as checked answers: {summary, answers {id: stored value}, why {id: text}, not_shown [ids],
    dropped [{id, reason}]}. An answer that isn't valid for its question is dropped, never guessed."""
    from estimator.estimating import quick
    try:
        raw = _json_object(text)
    except (ValueError, json.JSONDecodeError):
        raise InvalidInput("the AI's answer couldn't be read - try again, or a clearer picture") from None
    by_id = {q.id: q for q in mod.questions}
    answers, why, dropped = {}, {}, []
    for qid, item in (raw.get("answers") or {}).items():
        q = by_id.get(str(qid))
        if q is None:
            continue
        value = item.get("value") if isinstance(item, dict) else item
        if value is None or value == "":
            continue
        try:
            stored, _ = quick._coerce(q, value)
        except InvalidInput as exc:
            dropped.append({"id": q.id, "reason": exc.message})
            continue
        if q.type == "integer":
            stored = int(stored)
        elif q.type == "number":
            stored = float(stored)
        answers[q.id] = stored
        if isinstance(item, dict) and item.get("why"):
            why[q.id] = str(item["why"])[:300]
    not_shown = [q.id for q in mod.questions if q.id not in answers]
    return {"summary": str(raw.get("summary") or "")[:500], "answers": answers, "why": why,
            "not_shown": not_shown, "dropped": dropped}


def _ask(conn, ctx: RequestContext, system: str, prompt: str, images: list, *, purpose: str,
         estimate_id: int | None) -> tuple[str, dict]:
    """One call on the AI measuring role's provider (then its backup), budget-checked, usage recorded, in the AI Log."""
    from estimator.agents import ai_log, providers, roles
    cfg = roles.get_role(conn, ctx.company_id, ROLE)
    if cfg["provider"] not in providers.API_PROVIDERS:
        raise NotAvailable("the AI is off - turn on AI measuring in 🤖 AI agents (Setup) with the agent API key, so "
                           "the AI can read drawings and photos")
    ok, why = roles.budget_left(conn, ctx.company_id)
    if not ok:
        raise NotAvailable(f"the AI can't read the picture: {why}")
    errors = []
    for which in [p for p in (cfg["provider"], cfg.get("fallback_provider")) if p]:
        ready, why = providers.ready(which)
        if not ready:
            errors.append(f"{which}: {why}")
            continue
        model = providers.model_for_step(which, FLOW, "read", cfg.get("model_pinned") if which == cfg["provider"] else None)
        refs = [{"kind": "photo"} for _ in images]
        started = time.monotonic()
        try:
            text, usage = providers.ask_vision(which, system, prompt, images, model)
        except providers.ProviderError as exc:
            spent = getattr(exc, "usage", None)
            roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model, usage=spent, ok=False,
                               error=str(exc))
            ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose, system_prompt=system,
                          user_prompt=prompt, images=refs, usage=spent, estimate_id=estimate_id,
                          duration_ms=int((time.monotonic() - started) * 1000), ok=False, error=str(exc))
            errors.append(f"{which}: {exc}")
            continue
        roles.record_usage(conn, ctx, task_id=None, role=ROLE, provider=which, model=model, usage=usage, ok=True)
        log_id = ai_log.record(conn, ctx, provider=which, model=model, role=ROLE, purpose=purpose,
                               system_prompt=system, user_prompt=prompt, images=refs, estimate_id=estimate_id,
                               response_text=text, usage=usage, duration_ms=int((time.monotonic() - started) * 1000))
        return text, {"provider": which, "model": model, "log_id": log_id,
                      "cost_usd": round(providers.cost_micros(model, usage) / 1e6, 4)}
    raise NotAvailable("the AI couldn't answer: " + "; ".join(errors))


def fill(conn, ctx: RequestContext, module_id: str, images, note: str = "", estimate_id: int | None = None,
         registry=None) -> dict:
    """Read the drawing(s) or photo(s) and answer the service's questions. Returns {ok, module_id, summary, answers,
    why, not_shown, dropped, provider, model, cost_usd}. Nothing is priced or saved on an estimate."""
    from estimator.agents import ai_log
    from estimator.modules import get_registry
    mod = (registry or get_registry()).get(module_id)
    # services only (2026-11-27, Jamie): trades have plans, AI design and AI Auto Measure for that
    if mod.category != "service" or mod.path not in ("quick_estimate", "both"):
        raise InvalidInput(f"'{mod.name}' is a trade - upload its plans on the Plans screen instead",
                           module_id=module_id)
    note = str(note or "").strip()[:NOTE_MAX]
    pics = _photos(images)
    prompt = prompt_for(mod, note)
    text, meta = _ask(conn, ctx, SYSTEM, prompt, pics, purpose=f"Quick estimate from a drawing: {mod.name}",
                      estimate_id=estimate_id)
    try:
        got = parse(mod, text)
    except InvalidInput as exc:
        ai_log.set_error(conn, ctx.company_id, meta["log_id"], exc.message)
        raise
    ai_log.set_parsed(conn, ctx.company_id, meta["log_id"], got)
    return {"ok": True, "module_id": mod.id, **got, "provider": meta["provider"], "model": meta["model"],
            "cost_usd": meta["cost_usd"]}
