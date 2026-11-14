"""The Estimator's AI agents, set up like the Service Desk, Jobs and HR agents (2026-11-13, David: "add ... to the
estimator tab it already has an ai agent section").

Each step has a mode (Off / From chat only / Suggest - a person approves everything the Estimator's agents make),
belongs to a group - complex step, customer message or internal step - and so uses the model the top of the Small
Business tab sets for that group, like the Jobs and Service Desk agents. One AI (and a backup) runs them all.

flow() returns the picture in the same shape desk_gui_agent.draw_flow draws for the other agents (boxes coloured by
each step's own mode, hover help), so the Estimator tab looks and reads like the rest. Kept out of the Tk code so it
can be tested without a window.
"""
from __future__ import annotations

from estimator.agents import providers

MODES = (("off", "Off"), ("chat_only", "From chat only"), ("on", "Suggest (a person approves)"))
MODE_HELP = {
    "off": "Off — this step doesn't run; a person does it.",
    "chat_only": "From chat only — it runs when you ask your AI in chat (Claude, Grok or Muse); nothing runs on its own "
                 "and the API key isn't used.",
    "on": "Suggest — it runs on the agents' AI (the API key), within the budget below. Everything it makes is a "
          "proposal or a draft: a person approves measurements, prices and bids, and sends anything that goes out.",
}
# The Estimator's steps in flow order: (role, short label, which flow state it works on, group steps for the model).
STEPS = (
    ("plan_reader", "Plan reader", "Plans"),
    ("llm_takeoff", "AI takeoff", "Takeoff"),
    ("takeoff", "Takeoff agents", "Takeoff"),
    ("reviewer", "Reviewer", "Review"),
    ("bid_writer", "Bid writer", "Bid"),
    ("follow_up", "Follow-up", "Follow-up"),
)
STEP_HELP = {
    "plan_reader": "Reads and classifies plan sheets (which sheet is the foundation plan, the floor plan ...). An "
                   "internal step: the cheaper model when one is set.",
    "llm_takeoff": "The 🤖 AI Agent button in Blueprint Review: finds the foundation sheet, calibrates the view from the "
                   "dimensions written on the plan when it has no scale (or says a person must calibrate it, and why), "
                   "reads the slab's dimensions and the footing detail, and proposes the slab, footer and form "
                   "measurements. The app does the maths. Reading plans and calibrating are complex steps: the "
                   "stronger model.",
    "takeoff": "Measures each trade from the plans for the Estimate Runner. Starts when the Plan Engine is installed. "
               "A complex step.",
    "reviewer": "Writes notes for the human reviewer on estimates waiting for review: missing items, odd quantities, "
                "unit costs that look off. It never approves or changes prices. An internal step.",
    "bid_writer": "Drafts the scope, inclusions and exclusions for an approved estimate; a person sees it in the bid "
                  "preview before anything is sent. A customer message: always the stronger model.",
    "follow_up": "Drafts a short follow-up email for quotes that are due one; a person sends it. A customer message: "
                 "always the stronger model.",
}
STATES = ("Plans", "Takeoff", "Estimate", "Review", "Bid", "Follow-up")
FLOW_W, FLOW_H = 560, 250
_SW, _SH, _AW, _AH = 80, 32, 86, 52
_STATE_X = {s: 10 + i * 92 for i, s in enumerate(STATES)}
_STATE_Y = 120
_STEP_XY = {"plan_reader": (_STATE_X["Plans"] - 3, 20), "llm_takeoff": (_STATE_X["Takeoff"] - 3, 20),
            "takeoff": (_STATE_X["Takeoff"] - 3, 192), "reviewer": (_STATE_X["Review"] - 3, 20),
            "bid_writer": (_STATE_X["Bid"] - 3, 20), "follow_up": (_STATE_X["Follow-up"] - 3, 20)}
COLORS = {"off": "#9ca3af", "chat_only": "#7c3aed", "on": "#d97706", "waiting": "#9ca3af"}
TINTS = {"#9ca3af": "#f3f4f6", "#7c3aed": "#ede9fe", "#d97706": "#fef3c7"}
WORDS = {"off": "off", "chat_only": "from chat", "on": "waits for OK", "waiting": "needs plans"}


def mode_of(provider: str | None) -> str:
    """A role's saved provider, as this screen's mode."""
    if provider in providers.API_PROVIDERS:
        return "on"
    return "chat_only" if provider == "chat_only" else "off"


GROUP_DEFAULT = "Its group's model"           # the model choice that follows the top of the Small Business tab
_FALLBACK_MODELS = {"claude_api": (("claude-haiku-5-5", "Claude Haiku 5.5"), ("claude-sonnet-5-5", "Claude Sonnet 5.5"),
                                   ("claude-opus-5-5", "Claude Opus 5.5")),
                    "grok_api": (("grok-4.3", "Grok 4.3"),)}


def model_choices(runner: str) -> list[tuple[str, str]]:
    """[(model, label)] an agent can be set to on this runner (2026-11-13, David: "select the AI Model type for each
    agent") - the same list as the models at the top of the Small Business tab, with their prices when known."""
    try:
        import desk_agent_providers as prov
        return [(m, lab.split(" — ")[0]) for m, lab in prov.AGENT_MODELS.get(runner, ())]
    except Exception:  # noqa: BLE001 - outside AI-Prowler
        return list(_FALLBACK_MODELS.get(runner, ()))


def model_line(role: str, runner: str, pinned: str | None = None) -> str:
    """'complex step → Claude Opus 5.5' for one role on one runner; '... (set for this agent)' when it was chosen."""
    group = providers.step_group(role)
    if runner not in providers.API_PROVIDERS:
        return providers.GROUP_LABELS[group]
    own = providers.fits(runner, pinned)
    return (f"{providers.GROUP_LABELS[group]} → {_nice(providers.model_for_step(runner, role, None, pinned))}"
            + (" (set for this agent)" if own else ""))


def _nice(model: str) -> str:
    names = {"claude-haiku-5-5": "Claude Haiku 5.5", "claude-sonnet-5-5": "Claude Sonnet 5.5",
             "claude-opus-5-5": "Claude Opus 5.5", "grok-4.3": "Grok 4.3"}
    return names.get(model, model or "AI-Prowler's choice")


def flow(modes: dict, works_now: dict | None = None, runner: str = "claude_api", pinned: dict | None = None) -> dict:
    """The picture: the job's states left to right, each agent step above (or below) the state it works on, coloured
    by its own mode. A state lights up when a step that works on it is on."""
    works_now = works_now or {}
    steps, edges, lit = [], [], {}
    for role, short, state in STEPS:
        mode = modes.get(role, "off")
        shown = mode if works_now.get(role, True) or mode == "off" else "waiting"
        color = COLORS[shown]
        x, y = _STEP_XY[role]
        steps.append({"id": role, "label": short, "mode": "off" if shown in ("off", "waiting") else "auto",
                      "practice": False, "color": color, "tint": TINTS[color], "word": WORDS[shown],
                      "help": STEP_HELP[role] + "\n\n" + MODE_HELP[mode] + "\n\nModel: "
                              + model_line(role, runner, (pinned or {}).get(role)),
                      "x": x, "y": y, "w": _AW, "h": _AH})
        sx = _STATE_X[state] + _SW / 2
        top = y > _STATE_Y
        edges.append({"x1": sx, "y1": y if top else y + _AH, "x2": sx, "y2": _STATE_Y + (_SH if top else 0),
                      "kind": "step", "color": color, "dash": shown in ("off", "waiting"), "both": False})
        if shown in ("on", "chat_only"):
            lit[state] = COLORS["on"] if shown == "on" or lit.get(state) == COLORS["on"] else COLORS["chat_only"]
    states = []
    for s in STATES:
        color = lit.get(s, "#94a3b8")
        states.append({"id": s, "label": s, "x": _STATE_X[s], "y": _STATE_Y, "w": _SW, "h": _SH, "lit": s in lit,
                       "color": color, "tint": TINTS.get(color, "#ffffff") if s in lit else "#ffffff"})
    # The Director runs the whole job - it isn't an AI agent (no API key, no model): rules, the pricing engine and your
    # approvals, driven by your chat AI through its est_director tools. Shown as one band under the job, not a step.
    states.append({"id": "director", "label": "🧑‍💼 Director runs every step (rules, no AI)", "x": 200, "y": 196,
                   "w": 350, "h": _SH, "lit": False, "color": "#64748b", "tint": "#f8fafc"})
    for a, b in zip(STATES, STATES[1:]):
        edges.append({"x1": _STATE_X[a] + _SW, "y1": _STATE_Y + _SH / 2, "x2": _STATE_X[b], "y2": _STATE_Y + _SH / 2,
                      "kind": "state", "color": "#94a3b8", "dash": False, "both": False})
    on = [short for role, short, _ in STEPS if modes.get(role) == "on" and works_now.get(role, True)]
    chat = [short for role, short, _ in STEPS if modes.get(role) == "chat_only"]
    parts = []
    if on:
        parts.append("Runs on the agents' AI (a person approves): " + ", ".join(on) + ".")
    if chat:
        parts.append("From chat only: " + ", ".join(chat) + ".")
    summary = " ".join(parts) or "Every step is Off — nothing runs and nothing costs money."
    summary += (" The Director runs the job and prices the estimate itself - rules and the pricing engine, no AI and no "
                "API key (your chat AI drives it; its settings are in 🧑‍💼 Director below). Agents never approve, change "
                "prices or send anything on their own.")
    return {"w": FLOW_W, "h": FLOW_H, "states": states, "steps": steps, "edges": edges, "summary": summary}
