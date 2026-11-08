"""Layer groups for the Blueprint Review layers panel (spec: "Layers panel ... CAD layers map to these automatically").

Every drawing object is put in one group by its kind and, for CAD and line work, its layer name (US National CAD
Standard prefixes and the usual words: A-WALL, E-LITE, P-FIXT, A-DOOR, I-FURN ...). The viewer shows and hides, and
locks, whole groups. "Measurements" is the takeoff's own group and is always first.

Saved per-estimate layers and layers a user makes (the spec's `layers` table) come later; for now the groups are
worked out from the drawing each time and what's shown or locked is kept by the browser.
"""
from __future__ import annotations

import re

# (group id, label, colour) in the order the panel lists them.
GROUPS = (
    ("measurements", "Measurements", "#d9480f"),
    ("rooms", "Rooms", "#2b8a3e"),
    ("walls", "Walls", "#1c7ed6"),
    ("doors_windows", "Doors & windows", "#7048e8"),
    ("electrical", "Electrical", "#f08c00"),
    ("plumbing", "Plumbing", "#0c8599"),
    ("mechanical", "Mechanical", "#c2255c"),
    ("furniture", "Furniture", "#868e96"),
    ("symbols", "Other symbols", "#e8590c"),
    ("dimensions", "Dimensions", "#5c940d"),
    ("text", "Text", "#495057"),
    ("floor_plan", "Floor plan line work", "#adb5bd"),
)
GROUP_IDS = tuple(g[0] for g in GROUPS)

_BY_NAME = (
    ("walls", re.compile(r"WALL", re.I)),
    ("doors_windows", re.compile(r"DOOR|WIND|GLAZ|OPNG|OPENING", re.I)),
    ("furniture", re.compile(r"FURN|^I-|EQPM|CASE", re.I)),
    ("plumbing", re.compile(r"^P-|PLUM|FIXT|SANR|DOMW", re.I)),
    ("electrical", re.compile(r"^E-|ELEC|LITE|LIGHT|POWR|POWER|RECEP|OUTLET|SWITCH", re.I)),
    ("mechanical", re.compile(r"^M-|MECH|HVAC|DUCT|DIFF", re.I)),
    ("dimensions", re.compile(r"DIM|ANNO-DIMS", re.I)),
    ("text", re.compile(r"TEXT|ANNO|NOTE", re.I)),
)
_KIND = {"wall": "walls", "room": "rooms", "opening": "doors_windows", "dimension": "dimensions", "text": "text"}


def group_for(kind: str, layer: str | None = None, block_name: str | None = None) -> str:
    """The panel group of one drawing object."""
    if kind in _KIND:
        return _KIND[kind]
    names = " ".join(n for n in (layer, block_name) if n)
    for gid, rx in _BY_NAME:
        if names and rx.search(names):
            if kind == "symbol" and gid in ("walls", "dimensions", "text"):
                continue                            # a symbol block on an annotation layer is still a symbol
            return gid
    return "symbols" if kind == "symbol" else "floor_plan"


def panel(objects: list[dict]) -> list[dict]:
    """The groups present on a sheet, with how many objects each holds (Measurements always listed)."""
    counts: dict[str, int] = {}
    for o in objects:
        counts[o["group"]] = counts.get(o["group"], 0) + 1
    return [{"id": gid, "label": label, "color": color, "count": counts.get(gid, 0)}
            for gid, label, color in GROUPS if gid == "measurements" or counts.get(gid)]
