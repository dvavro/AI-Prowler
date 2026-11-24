"""Surface conduit for the wiring takeoff (2026-11-23, David: "Did or should the wiring calculate plastic or metal pipe and
elbows since this job is a metal shed and I want to mount the conduit on top of the steel and not drill holes through
studs ... adding power can be done after a house is built outside the walls, for a basement, garage ... include a basic
expansion coefficient of the material used for conduit so the structure will last").

The wiring run (wiring.route) already traces every circuit: a home run from the panel, then box to box along the
shortest tree, each link a drop from the box to the run level, along the walls square, and a drop to the next box. With
the wiring method set to conduit, each of those links is a conduit run between two boxes, and this module turns them into
what to order:

  * conduit by material and trade size (EMT inside, PVC outside by default), sized for the conductors in it
    (NEC Chapter 9 Annex C fill tables, THHN/THWN-2);
  * THHN wire by size: each circuit's conductors (the cable's insulated conductors plus a green ground) times its length;
  * a 90-degree elbow at every turn and at the top of every drop, a pull point (conduit body) where a run passes 360
    degrees of bends (NEC 358.26 / 352.26), couplings every 10 ft stick, two box connectors (EMT) or male adapters (PVC)
    per run, straps within 3 ft of each box and every 10 ft (EMT, NEC 358.30) or every 3 ft (1/2-1 in PVC, NEC 352.30);
  * a surface box (4 in square with a raised cover) for each device inside, a weatherproof box outside;
  * expansion fittings: each straight leg between securely mounted points (boxes, elbows) moves
        movement (in) = coefficient (in/in/F) x leg (ft) x 12 x temperature swing (F)
    PVC 3.38e-5 in/in/F (NEC Table 352.44: an expansion fitting where the movement is 1/4 in or more); steel EMT
    6.5e-6 (NEC 300.7(B): where necessary - counted against the structure it's strapped to: EMT on a steel building moves
    with it); aluminum 1.3e-5. Outdoors in the sun the swing gets 30 F more (manufacturers' guidance). Each fitting takes up
    its rated travel (PVC expansion couplings 6 in, EMT expansion fittings 4 in).

Home runs leave the panel together: up to homerun_max_circuits circuits share one conduit to where they split. Plain
geometry - no AI tokens. Every number it uses is a setting a person can change.
"""
from __future__ import annotations

import math

METHODS = ("nm", "emt", "pvc")
METHOD_LABEL = {"nm": "NM-B cable in the walls", "emt": "EMT conduit on the surface", "pvc": "PVC conduit on the surface"}
STRUCTURES = ("wood", "steel", "masonry")
# thermal expansion, in/in/F
MATERIALS = {
    "emt": {"label": "EMT (steel)", "alpha": 6.5e-6, "rule": "NEC 300.7(B)", "relative": True, "travel_in": 4.0,
            "strap_ft": {"1/2": 10, "3/4": 10, "1": 10}, "fitting": "EMT expansion fitting with bonding jumper"},
    "pvc": {"label": "PVC Schedule 40", "alpha": 3.38e-5, "rule": "NEC 352.44", "relative": False, "travel_in": 6.0,
            "strap_ft": {"1/2": 3, "3/4": 3, "1": 3}, "fitting": "PVC expansion coupling"},
}
STRUCTURE_ALPHA = {"wood": 2.5e-6, "steel": 6.5e-6, "masonry": 5.5e-6}
STRUCTURE_LABEL = {"wood": "wood framing", "steel": "a steel building", "masonry": "block or concrete"}
SIZES = ("1/2", "3/4", "1")
SIZE_KEY = {"1/2": "050", "3/4": "075", "1": "100"}
# NEC Chapter 9 Annex C: most THHN/THWN-2 conductors of one size in a conduit (Table C.1 EMT, C.10 PVC Schedule 40)
FILL = {"emt": {"1/2": {14: 12, 12: 9, 10: 5, 8: 2, 6: 1}, "3/4": {14: 22, 12: 16, 10: 10, 8: 5, 6: 4},
                "1": {14: 35, 12: 26, 10: 16, 8: 9, 6: 6}},
        "pvc": {"1/2": {14: 11, 12: 8, 10: 5, 8: 2, 6: 1}, "3/4": {14: 21, 12: 15, 10: 9, 8: 5, 6: 3},
                "1": {14: 34, 12: 25, 10: 15, 8: 8, 6: 6}}}
STRAP_TO_BOX_FT = 3.0
MAX_BENDS = 4                     # 360 degrees of bends between pull points (NEC 358.26 / 352.26)


def conductors(cable: str) -> tuple[int, int]:
    """(AWG, conductors in conduit) for a cable size: 12/2 -> (12, 3): two insulated conductors and a green ground."""
    awg, n = cable.split("/")
    return int(awg), int(n) + 1


def trade_size(material: str, wires: dict) -> tuple[str, bool]:
    """The smallest conduit that holds the conductors ({awg: count}), by fill fraction. (size, too_big): too big means
    even 1 in is over-full - the caller splits the run."""
    for size in SIZES:
        table = FILL[material][size]
        if sum(n / table.get(awg, table[min(table, key=lambda a: abs(a - awg))]) for awg, n in wires.items()) <= 1.0:
            return size, False
    return SIZES[-1], True


def movement_in(material: str, leg_ft: float, swing_f: float, structure: str) -> float:
    """How far a straight leg grows and shrinks over the temperature swing, in inches. PVC by its own coefficient (the
    code table); metal against what it's strapped to."""
    m = MATERIALS[material]
    alpha = abs(m["alpha"] - STRUCTURE_ALPHA.get(structure, 0.0)) if m["relative"] else m["alpha"]
    return alpha * leg_ft * 12 * swing_f


def expansion_fittings(movement: float, material: str, threshold_in: float) -> int:
    if movement < threshold_in:
        return 0
    return max(1, math.ceil(movement / MATERIALS[material]["travel_in"]))


def run(material: str, legs: list, bends: int, wires: dict, outdoor: bool, s: dict, what: str, bodies: int = 0) -> dict:
    """One conduit run between two boxes (or a shared home run). legs: the straight lengths (ft) between bends.
    bodies: conduit bodies it needs besides the 360-degree rule (an LB where it goes out through a wall)."""
    legs = [round(float(x), 2) for x in legs if x > 0.05]
    size, too_big = trade_size(material, wires)
    swing = s["temp_swing_outdoor_f"] + (s["sun_add_f"] if s["outdoor_in_sun"] else 0) if outdoor \
        else s["temp_swing_indoor_f"]
    strap_ft = MATERIALS[material]["strap_ft"][size]
    exp = []
    for leg in legs:
        mv = movement_in(material, leg, swing, s["structure"])
        n = expansion_fittings(mv, material, s["expansion_threshold_in"])
        if n or mv >= 0.1:
            exp.append({"run": what, "material": material, "size": size, "leg_ft": leg, "swing_f": swing,
                        "movement_in": round(mv, 2), "fittings": n, "outdoor": outdoor})
    length = sum(legs)
    return {"what": what, "material": material, "size": size, "too_big": too_big, "length_ft": round(length, 1),
            "legs": legs, "bends": bends, "pull_points": max(0, math.ceil(bends / MAX_BENDS) - 1) + bodies,
            "couplings": sum(max(0, math.ceil(x / s["stick_ft"]) - 1) for x in legs),
            "straps": 2 + sum(max(0, math.ceil(max(0.0, x - 2 * STRAP_TO_BOX_FT) / strap_ft)) for x in legs),
            "ends": 2, "wires": {str(k): v for k, v in wires.items()}, "outdoor": outdoor, "swing_f": swing,
            "expansion": exp, "expansion_fittings": sum(e["fittings"] for e in exp)}


def items(runs: list, boxes_in: int, boxes_out: int, threshold_in: float = 0.25) -> list[dict]:
    """What to order, as wiring-run measurements: [{feeds, label, qty, unit, how}]."""
    out = []

    def add(feeds, label, qty, unit, how):
        if qty > 0:
            out.append({"feeds": feeds, "label": label, "qty": round(qty, 1) if unit == "lf" else int(qty),
                        "unit": unit, "how": how})
    for mat in ("emt", "pvc"):
        mine = [r for r in runs if r["material"] == mat]
        if not mine:
            continue
        name = MATERIALS[mat]["label"]
        for size in SIZES:
            ft = sum(r["length_ft"] for r in mine if r["size"] == size)
            add(f"{mat}_{SIZE_KEY[size]}_ft", f"{size} in {name} (wiring)", ft, "lf",
                f"{ft:.1f} ft of {size} in {name} on {sum(1 for r in mine if r['size'] == size)} runs, sized by NEC "
                f"Chapter 9 fill for the THHN in each")
        bends = sum(r["bends"] for r in mine)
        add(f"{mat}_elbows", f"{name} 90-degree elbows (wiring)", bends, "ea",
            f"{bends} bends: every turn along the walls and the top of every drop to a box")
        add(f"{mat}_couplings", f"{name} couplings (wiring)", sum(r["couplings"] for r in mine), "ea",
            "one per joint between 10 ft sticks")
        add(f"{mat}_connectors", f"{name} {'box connectors' if mat == 'emt' else 'male adapters'} (wiring)",
            sum(r["ends"] for r in mine), "ea", "two per run, one at each box")
        add(f"{mat}_straps", f"{name} straps (wiring)", sum(r["straps"] for r in mine), "ea",
            ("within 3 ft of each box and every 10 ft (NEC 358.30)" if mat == "emt"
             else "within 3 ft of each box and every 3 ft for 1/2 to 1 in (NEC 352.30)"))
        fit = sum(r["expansion_fittings"] for r in mine)
        legs = [e for r in mine for e in r["expansion"] if e["fittings"]]
        add(f"{mat}_expansion", f"{MATERIALS[mat]['fitting']}s (wiring)", fit, "ea",
            f"{len(legs)} straight leg(s) move {threshold_in:g} in or more over the temperature swing "
            f"({MATERIALS[mat]['rule']}; {MATERIALS[mat]['alpha']:.3g} in/in/F; "
            f"{MATERIALS[mat]['travel_in']:g} in of travel per fitting)")
    pulls = sum(r["pull_points"] for r in runs)
    add("conduit_bodies", "Conduit bodies / pull points (wiring)", pulls, "ea",
        "an LB where a run goes out through a wall, and a pull point where a run passes 360 degrees of bends "
        "(NEC 358.26 / 352.26)")
    add("surface_boxes", "Surface boxes with raised covers (wiring)", boxes_in, "ea",
        "one 4 in square box with a raised cover per device inside")
    add("wp_boxes", "Weatherproof boxes (wiring)", boxes_out, "ea", "one weatherproof box per device outside")
    return out


def thhn_bom(thhn: dict, waste: float, spool_ft: int = 500) -> list[dict]:
    """The THHN wire to order, as Bill of Materials lines beside the cable ones (feeds thhn_<awg>_ft)."""
    out = []
    for awg in sorted(thhn, reverse=True):
        ft = thhn[awg]
        if ft <= 0:
            continue
        order = ft * (1 + waste)
        out.append({"cable": f"{awg} AWG THHN", "measured_ft": round(ft, 1), "order_ft": math.ceil(order),
                    "rolls": math.ceil(order / spool_ft), "roll_ft": spool_ft, "feeds": f"thhn_{awg}_ft",
                    "how": f"{ft:.0f} ft of {awg} AWG THHN in conduit: each circuit's conductors plus its green ground, "
                           f"times its routed length and box make-up"})
    return out


def summary(runs: list, s: dict, methods: dict) -> dict:
    """The conduit part of the wiring result."""
    exp = [e for r in runs for e in r["expansion"]]
    notes = [
        "Home runs leave the panel together, up to %d circuits in one conduit to where they split." % s["homerun_max_circuits"],
        "Each other link between two boxes is its own conduit run; a 90-degree elbow at every turn and at the top of "
        "every drop.",
        "Expansion: movement = coefficient x leg x temperature swing. PVC %.3g in/in/F (NEC Table 352.44, a fitting at "
        "%g in); EMT %.3g in/in/F counted against %s (NEC 300.7(B)). Swing %g F inside, %g F outside%s." % (
            MATERIALS["pvc"]["alpha"], s["expansion_threshold_in"], MATERIALS["emt"]["alpha"],
            STRUCTURE_LABEL.get(s["structure"], s["structure"]), s["temp_swing_indoor_f"], s["temp_swing_outdoor_f"],
            f" + {s['sun_add_f']:g} F in the sun" if s["outdoor_in_sun"] else ""),
    ]
    if any(r["too_big"] for r in runs):
        notes.append("Some runs need more than 1 in conduit - split them into two runs or upsize by hand.")
    return {"methods": methods, "runs": len(runs), "total_ft": {m: round(sum(r["length_ft"] for r in runs
                                                                            if r["material"] == m), 1)
                                                                for m in ("emt", "pvc")},
            "expansion": sorted(exp, key=lambda e: -e["movement_in"])[:40],
            "expansion_fittings": sum(r["expansion_fittings"] for r in runs), "notes": notes,
            # 2026-11-23 (David: "can't see a visual of the conduit"): each run with its path and circuits, to draw
            "run_list": [{**{k: r[k] for k in ("what", "material", "size", "length_ft", "bends", "expansion_fittings",
                                               "outdoor", "pull_points", "wires")},
                          "path": r.get("path") or [], "circuits": r.get("circuits") or [],
                          "home_run": bool(r.get("home_run"))} for r in runs][:400]}
