"""Playbooks: the steps of each lane, as short YAML files.

A playbook lists stages in order. Each stage names the agent that does it, the
action the Director runs, and whether it is a checkpoint (a person decides).
Playbooks are validated at load time, like module manifests. Every playbook
that sends anything to a customer must have an approval checkpoint before it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

PLAYBOOK_DIR = Path(__file__).resolve().parent / "playbooks"
LANES = ("quick_quote", "standard_estimate", "full_takeoff")
AGENTS = ("director", "intake", "plan_reader", "estimate_runner", "takeoff", "quick_pricer", "pricer",
          "reviewer", "bid_writer", "follow_up")
ACTIONS = ("collect_answers", "collect_job", "collect_trades", "price_quick", "price", "read_plans", "run_takeoff", "review",
           "approve", "write_bid", "follow_up")
SENDS_TO_CUSTOMER = ("write_bid",)


class PlaybookError(ValueError):
    pass


@dataclass(frozen=True)
class Stage:
    id: str
    agent: str
    action: str
    label: str
    checkpoint: bool = False


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    version: str
    lane: str
    available: bool
    available_from: str
    description: str
    stages: tuple[Stage, ...]

    def stage(self, stage_id: str) -> Stage:
        for s in self.stages:
            if s.id == stage_id:
                return s
        raise KeyError(stage_id)

    def next_stage(self, stage_id: str) -> Stage | None:
        ids = [s.id for s in self.stages]
        i = ids.index(stage_id)
        return self.stages[i + 1] if i + 1 < len(self.stages) else None

    def summary(self) -> dict:
        return {"id": self.id, "name": self.name, "version": self.version, "lane": self.lane,
                "available": self.available, "available_from": self.available_from,
                "description": self.description,
                "stages": [{"id": s.id, "agent": s.agent, "label": s.label, "checkpoint": s.checkpoint}
                           for s in self.stages]}


def parse_playbook(raw: dict, where: str) -> Playbook:
    if not isinstance(raw, dict):
        raise PlaybookError(f"{where}: must be a mapping")
    for key in ("id", "lane", "stages"):
        if not raw.get(key):
            raise PlaybookError(f"{where}: missing required field '{key}'")
    if raw["lane"] not in LANES:
        raise PlaybookError(f"{where}: lane must be one of {LANES}")
    stages, seen = [], set()
    approved = False
    for i, st in enumerate(raw["stages"]):
        sw = f"{where} stage {i + 1}"
        if not isinstance(st, dict):
            raise PlaybookError(f"{sw}: must be a mapping")
        for key in ("id", "agent", "action"):
            if not st.get(key):
                raise PlaybookError(f"{sw}: missing '{key}'")
        if st["id"] in seen:
            raise PlaybookError(f"{sw}: duplicate stage id '{st['id']}'")
        seen.add(st["id"])
        if st["agent"] not in AGENTS:
            raise PlaybookError(f"{sw}: agent must be one of {AGENTS}")
        if st["action"] not in ACTIONS:
            raise PlaybookError(f"{sw}: action must be one of {ACTIONS}")
        checkpoint = bool(st.get("checkpoint", False))
        if st["action"] == "approve":
            if not checkpoint:
                raise PlaybookError(f"{sw}: the approve stage must be a checkpoint")
            approved = True
        if st["action"] in SENDS_TO_CUSTOMER and not approved:
            raise PlaybookError(f"{sw}: '{st['action']}' needs an approval checkpoint before it")
        stages.append(Stage(st["id"], st["agent"], st["action"], st.get("label", st["id"]), checkpoint))
    return Playbook(str(raw["id"]), raw.get("name", raw["id"]), str(raw.get("version", "0.0.0")), raw["lane"],
                    bool(raw.get("available", True)), str(raw.get("available_from", "")),
                    raw.get("description", ""), tuple(stages))


def load_playbooks(folder: Path = PLAYBOOK_DIR) -> dict[str, Playbook]:
    """Load every playbook. A bad playbook raises, because the Director can't run without one."""
    books = {}
    for f in sorted(Path(folder).glob("*.yaml")):
        try:
            raw = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PlaybookError(f"{f.name}: not valid YAML ({exc})") from exc
        pb = parse_playbook(raw, f.name)
        if pb.id != f.stem:
            raise PlaybookError(f"{f.name}: id '{pb.id}' must match the file name")
        books[pb.id] = pb
    lanes = {pb.lane for pb in books.values()}
    missing = [ln for ln in LANES if ln not in lanes]
    if missing:
        raise PlaybookError(f"no playbook for lanes: {missing}")
    return books


_BOOKS: dict[str, Playbook] | None = None


def get_playbooks(reload: bool = False) -> dict[str, Playbook]:
    global _BOOKS
    if _BOOKS is None or reload:
        _BOOKS = load_playbooks()
    return _BOOKS


def playbook_for_lane(lane: str) -> Playbook:
    for pb in get_playbooks().values():
        if pb.lane == lane:
            return pb
    raise PlaybookError(f"no playbook for lane '{lane}'")
