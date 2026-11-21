"""The wiring schematic (2026-11-20, David: "can you make a wiring schematic diagram that shows wires, and save it as a
DXF drawing").

A one-sheet schematic from a wiring run (estimator/takeoff/wiring.py): the service (utility, meter, main breaker) feeding
the panel's two hot bus bars, neutral bar and ground bar; then one row per circuit - its breaker (1- or 2-pole) and
each conductor of its cable drawn in its own colour (black and red hots, white neutral, bare/green ground) out to the
circuit's devices, in the order the run routed them. The range and dryer are 4-wire (two hots, neutral, ground -
NEC 250.140); a 240 V-only load on /2 cable has its white re-identified as a hot (NEC 200.7(C)). 3-way travelers are
noted on their circuit. Not to scale: it shows what connects to what, not where.

Layers: S-TITLE, S-PANEL, S-BREAKER, S-HOT-L1 (black), S-HOT-L2 (red), S-NEUTRAL (white), S-GROUND (green), S-DEVICE,
S-TEXT, S-FLAG - so any of them can be turned off in CAD.
"""
from __future__ import annotations

ROW = 4.2              # one circuit row
DX = 5.0               # device spacing along a run
BUS_TOP = -6.0         # where the panel starts (y, drawing units = feet on paper; not to scale)
X_NEUT, X_GND = 21.0, 22.0                     # the neutral and ground bars, inside the panel's left side
X_L1, X_L2 = 24.0, 25.0                        # the two hot bus bars
X_BRK0, X_BRK1 = 26.0, 30.0                    # the breakers
X_RUN0 = 31.0                                  # where the conductors leave the panel
X_DEV0 = 44.0                                  # the first device

COLORS = {"L1": 7, "L2": 1, "N": 8, "G": 3}    # ACI: 7 = black on a white page (white on black), 1 red, 8 grey, 3 green
LAYER = {"L1": "S-HOT-L1", "L2": "S-HOT-L2", "N": "S-NEUTRAL", "G": "S-GROUND"}
NAME = {"L1": "BLK", "L2": "RED", "N": "WHT", "G": "GRN/BARE"}

# Device codes (the legend explains them)
CODES = {
    "duplex_receptacle": ("R", "Receptacle"), "duplex_receptacle_gfci": ("GF", "GFCI receptacle"),
    "duplex_receptacle_wp": ("WP", "Weatherproof GFCI receptacle"), "duplex_receptacle_usb": ("U", "USB receptacle"),
    "quad_receptacle": ("Q", "Quad receptacle"), "floor_box": ("FB", "Floor box"),
    "switch": ("S", "Switch"), "switch_3way": ("S3", "3-way switch"), "switch_4way": ("S4", "4-way switch"),
    "switch_dimmer": ("SD", "Dimmer"), "switch_occupancy": ("OS", "Occupancy switch"),
    "light_fixture": ("L", "Ceiling light"), "light_recessed": ("RL", "Recessed light"),
    "light_wall": ("WL", "Wall light"), "light_exterior": ("XL", "Exterior light"), "light_pendant": ("PL", "Pendant"),
    "light_undercabinet": ("UC", "Under-cabinet light"), "ceiling_fan": ("F", "Ceiling fan"),
    "exhaust_fan": ("EF", "Exhaust fan"), "smoke_detector": ("SM", "Smoke detector"),
    "smoke_co_detector": ("SC", "Smoke/CO detector"), "co_detector": ("CO", "CO detector"),
    "appliance": ("AP", "Appliance / 240 V load"),
}
APPLIANCE_CODES = {"RANGE": "RNG", "DRYER": "DRY", "WTR HTR": "WH", "WATER HEATER": "WH", "AC": "AC", "EV": "EV"}


def conductors(c: dict) -> list[tuple[str, str]]:
    """The conductors in a circuit's cable, as (bus, note): L1/L2 hots, N neutral, G ground."""
    two = c.get("poles", 1) >= 2 or c["amps"] >= 30
    three = c["wire"].endswith("/3")
    if two and three:
        return [("L1", ""), ("L2", ""), ("N", ""), ("G", "")]
    if two:
        return [("L1", ""), ("L2", "WHT re-marked hot (NEC 200.7)"), ("G", "")]
    return [("L1", ""), ("N", ""), ("G", "")]


def _short(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "."


def write(result: dict, out_path: str, title: str = "") -> str:
    import ezdxf
    from ezdxf.enums import TextEntityAlignment as TA
    doc = ezdxf.new("R2010", setup=True)
    doc.header["$INSUNITS"] = 2
    msp = doc.modelspace()
    for name, color in (("S-TITLE", 7), ("S-PANEL", 7), ("S-BREAKER", 5), ("S-HOT-L1", 7), ("S-HOT-L2", 1),
                        ("S-NEUTRAL", 8), ("S-GROUND", 3), ("S-DEVICE", 5), ("S-TEXT", 7), ("S-FLAG", 1)):
        doc.layers.add(name, color=color)

    def text(s, x, y, h=0.5, layer="S-TEXT", align=None, color=None):
        att = {"layer": layer, "height": h}
        if color is not None:
            att["color"] = color
        t = msp.add_text(s, dxfattribs=att)
        t.set_placement((x, y), align=align) if align else t.set_placement((x, y))
        return t

    def box(x0, y0, x1, y1, layer):
        msp.add_lwpolyline([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], close=True, dxfattribs={"layer": layer})

    def line(a, b, bus):
        msp.add_line(a, b, dxfattribs={"layer": LAYER[bus]})

    circuits = [c for c in result["circuits"] if c.get("assigned") or c.get("devices")]
    n = len(circuits)
    bottom = BUS_TOP - 2 - n * ROW
    main = result.get("main") or {"amps": 200, "poles": 2, "wire": ""}

    # Title
    text("WIRING SCHEMATIC" + (" - " + title if title else ""), 0, 6.0, 1.2, "S-TITLE")
    text("Panel, breakers and every circuit's conductors out to its devices. Schematic, not to scale - it shows what "
         "connects to what, not where. AI-Prowler wiring takeoff: an estimate, check before installing.", 0, 4.6, 0.5,
         "S-TITLE")

    # Service: utility -> meter -> main breaker -> the bus bars
    yS = 1.0
    box(0, yS - 1.2, 5, yS + 1.2, "S-PANEL"); text("UTILITY", 2.5, yS, 0.5, align=TA.MIDDLE_CENTER)
    box(7, yS - 1.2, 12, yS + 1.2, "S-PANEL"); text("METER", 9.5, yS, 0.5, align=TA.MIDDLE_CENTER)
    box(14, yS - 1.2, 19, yS + 1.2, "S-BREAKER")
    text(f"MAIN {main['amps']}A", 16.5, yS + 0.3, 0.45, align=TA.MIDDLE_CENTER)
    text(f"{main.get('poles', 2)}-POLE", 16.5, yS - 0.5, 0.4, align=TA.MIDDLE_CENTER)
    for i, bus in enumerate(("L1", "L2", "N", "G")):
        y = yS + 0.6 - i * 0.4
        for xa, xb in ((5, 7), (12, 14) if bus in ("L1", "L2") else (12, 12.6 + 0.5 * (i - 2))):
            line((xa, y), (xb, y), bus)
    # Main to the bars: the hots through the main breaker; the neutral and ground pass under it (bonded at the
    # service), so no conductor crosses the main breaker's box or its words.
    for k, (bus, x) in enumerate((("L1", X_L1), ("L2", X_L2), ("N", X_NEUT), ("G", X_GND))):
        y0 = yS + 0.6 - k * 0.4
        if bus in ("L1", "L2"):
            line((19, y0), (x, y0), bus)
            line((x, y0), (x, BUS_TOP), bus)
        else:
            xd = 12.6 + 0.5 * (k - 2)                                # down beside the meter, under the main
            y_low = yS - 1.7 - 0.5 * (k - 2)
            line((xd, y0), (xd, y_low), bus)
            line((xd, y_low), (x, y_low), bus)
            line((x, y_low), (x, BUS_TOP), bus)
    text(f"SERVICE: {main.get('wire') or 'service entrance'} - L1 (BLK), L2 (RED), N (WHT), G (GRN/BARE)", 0, -3.2, 0.4)
    text("Neutral and ground bonded at the service only", 0, -4.0, 0.35, "S-FLAG")

    # The panel and its four bars
    box(X_NEUT - 1.2, bottom, X_BRK1 + 0.6, BUS_TOP, "S-PANEL")
    text(f"{main['amps']} A PANEL", X_NEUT - 1.4, BUS_TOP - 1.0, 0.55, align=TA.BOTTOM_RIGHT)
    for bus, x in (("L1", X_L1), ("L2", X_L2), ("N", X_NEUT), ("G", X_GND)):
        line((x, BUS_TOP), (x, bottom + 0.5), bus)
        text({"L1": "L1", "L2": "L2", "N": "N", "G": "G"}[bus], x - 0.2, bottom + 0.1, 0.35, LAYER[bus])

    for i, c in enumerate(circuits):
        y = BUS_TOP - 2 - i * ROW
        cons = conductors(c)
        two = any(b == "L2" for b, _ in cons)
        # The breaker: 1-pole on L1 (alternating L1/L2 down the panel, as breakers are), 2-pole across both
        hot = "L1" if i % 2 == 0 else "L2"
        h = 1.6 if two else 0.9
        box(X_BRK0, y - h / 2, X_BRK1, y + h / 2, "S-BREAKER")
        text(f"{c['id']}", X_BRK0 + 0.2, y + 0.05, 0.45, "S-BREAKER")
        text(f"{c['amps']}A {'2P' if two else '1P'}", X_BRK0 + 0.2, y - 0.5, 0.35, "S-BREAKER")
        # Where each conductor starts: hots on the breaker, neutral and ground on their bars
        offs = [0.9 - k * 0.6 for k in range(len(cons))]
        devs = c.get("assigned") or []
        n_dev = max(1, len(devs))
        # Each conductor runs breaker -> device 1 -> device 2 ..., landing on each device's edge (never through it)
        xs = [X_DEV0 + j * DX for j in range(len(devs))]
        half = [1.1 if (d.get("item_type") == "appliance") else 1.0 for d in devs]
        for (bus, note), dy in zip(cons, offs):
            yy = y + dy
            color_bus = bus if two or bus != "L2" else "L1"
            if bus in ("L1", "L2"):
                src_bus = bus if two else hot
                bus_x = X_L1 if src_bus == "L1" else X_L2
                line((bus_x, yy), (X_BRK0, yy), src_bus)            # bus -> breaker
            else:
                x0 = X_NEUT if bus == "N" else X_GND
                line((x0, yy), (X_BRK0 - 0.05, yy), bus)            # the bar -> under the breaker
            start = X_BRK1
            for x, hw in zip(xs, half):
                edge = hw if hw > 1.0 else (max(1.0 - dy * dy, 0.0)) ** 0.5   # a box's side, or where it meets the circle
                line((start, yy), (x - edge, yy), color_bus)
                msp.add_circle((x - edge, yy), 0.08, dxfattribs={"layer": LAYER[color_bus]})   # it lands here
                start = x + edge
            if not xs:
                line((start, yy), (X_DEV0, yy), color_bus)
            label = NAME["L1" if bus == "L1" or (bus == "L2" and not two) else bus]
            if note:
                label = "WHT (re-marked RED)"
            text(label, X_RUN0, yy + 0.08, 0.28, LAYER[bus])
        # The circuit's description, cable and length
        trav = f" + {c['travelers_ft']:.0f} ft travelers (/3, BLK-RED-WHT + G) between 3-way switches" \
            if c.get("travelers_ft") else ""
        text(f"{c['id']}  {c['amps']} A  {c['wire']} NM-B  {c.get('total_ft', 0):.0f} ft - "
             f"{_short(c.get('description', ''), 40)}{trav}", X_RUN0 + 3.2, y + 1.55, 0.42)
        # The devices, in the routed order
        for j, a in enumerate(c.get("assigned") or []):
            x = X_DEV0 + j * DX
            it = a.get("item_type") or ""
            code, _ = CODES.get(it, ("D", ""))
            if it == "appliance":
                code = APPLIANCE_CODES.get((a.get("room") or "").upper(), "AP")
                box(x - 1.1, y - 1.1, x + 1.1, y + 1.1, "S-DEVICE")
            else:
                msp.add_circle((x, y), 1.0, dxfattribs={"layer": "S-DEVICE"})
            text(code, x, y, 0.5, "S-DEVICE", align=TA.MIDDLE_CENTER)
            text(_short(a.get("room") or "", 12), x, y - 1.6, 0.3, align=TA.MIDDLE_CENTER)
        for k, f in enumerate(c.get("flags") or []):
            text("! " + _short(f, 120), X_DEV0 + max(n_dev, 1) * DX - 1, y - 0.2 - k * 0.5, 0.32, "S-FLAG")

    # Legend
    y = bottom - 3
    text("LEGEND", 0, y, 0.8, "S-TITLE")
    for k, bus in enumerate(("L1", "L2", "N", "G")):
        yy = y - 1.3 - k * 0.8
        line((0, yy + 0.15), (3, yy + 0.15), bus)
        text({"L1": "Hot - black (L1)", "L2": "Hot - red (L2; 240 V loads, 3-way travelers)",
              "N": "Neutral - white", "G": "Equipment ground - bare or green"}[bus], 3.5, yy, 0.42)
    seen = []
    for c in circuits:
        for a in c.get("assigned") or []:
            it = a.get("item_type") or ""
            key = APPLIANCE_CODES.get((a.get("room") or "").upper(), "AP") if it == "appliance" else CODES.get(it, ("D", ""))[0]
            desc = (a.get("room") or "Appliance").title() + " (240 V load)" if it == "appliance" else CODES.get(it, ("D", it))[1]
            if (key, desc) not in seen:
                seen.append((key, desc))
    for k, (code, desc) in enumerate(seen):
        col, row = divmod(k, 6)
        xx, yy = 30 + col * 16, y - 1.3 - row * 0.8
        text(code, xx, yy, 0.42, "S-DEVICE")
        text(desc, xx + 2.0, yy, 0.42)
    text("Breaker types (AFCI / GFCI) per the estimate; NEC 210.12 wants AFCI on most 15/20 A circuits in a home.",
         0, y - 1.3 - 4 * 0.8 - 0.6, 0.38)
    doc.saveas(out_path)
    return out_path
