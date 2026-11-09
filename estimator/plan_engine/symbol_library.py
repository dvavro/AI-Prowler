"""The standard symbol library shipped with AI-Prowler (spec: Symbol Recognition Engine, "three levels": standard,
company, firm). This is the bottom level: what common symbols usually mean when the plan set's own legend doesn't say.

Each entry: item type, trade, a plain description, the short codes written next to or inside the symbol (OCR aliases,
e.g. GFI, WP, $3) and words that name it in CAD block names (DUPLEX_OUTLET, REC-GFI). The plan set's legend always
wins over this list (resolution order: CAD block name -> plan-set legend -> company library -> standard library -> AI).
Bump VERSION whenever an entry changes, so each company's copy in estimator.db is refreshed.
"""
from __future__ import annotations

import re

VERSION = 2                         # Sprint 12: fuller electrical and plumbing libraries, and what each one feeds

#  item type, trade, description, OCR aliases, CAD block-name words
_ROWS = (
    ("duplex_receptacle", "electrical", "Duplex receptacle", (), ("DUPLEX", "RECEPT", "RECEP", "OUTLET", "RCPT")),
    ("duplex_receptacle_gfci", "electrical", "Duplex receptacle, GFCI", ("GFI", "GFCI"), ("GFI", "GFCI")),
    ("duplex_receptacle_wp", "electrical", "Duplex receptacle, weatherproof", ("WP",), ("WP", "WEATHER")),
    ("quad_receptacle", "electrical", "Quad receptacle", ("QUAD",), ("QUAD", "FOURPLEX")),
    ("receptacle_240v", "electrical", "240 V receptacle", ("240V",), ("240", "RANGE", "DRYER")),
    ("floor_box", "electrical", "Floor box", ("FB",), ("FLOORBOX", "FLR_BOX", "FB")),
    ("switch", "electrical", "Single-pole switch", ("$", "S"), ("SWITCH", "SW")),
    ("switch_3way", "electrical", "Three-way switch", ("$3", "S3"), ("SW3", "3WAY", "3-WAY")),
    ("switch_4way", "electrical", "Four-way switch", ("$4", "S4"), ("SW4", "4WAY", "4-WAY")),
    ("switch_dimmer", "electrical", "Dimmer switch", ("$D", "DIM"), ("DIMMER",)),
    ("light_recessed", "electrical", "Recessed light", ("R",), ("RECESSED", "CANLIGHT", "DOWNLIGHT")),
    ("light_fixture", "electrical", "Light fixture", (), ("LIGHT", "LUMINAIRE", "FIXTURE", "LTG")),
    ("exit_sign", "electrical", "Exit sign", ("EXIT",), ("EXIT",)),
    ("emergency_light", "electrical", "Emergency light", ("EM",), ("EMERG",)),
    ("smoke_detector", "electrical", "Smoke detector", ("SD", "SMK"), ("SMOKE", "SMK")),
    ("co_detector", "electrical", "Carbon monoxide detector", ("CO", "CM"), ("CO_DET", "CODET")),
    ("data_outlet", "electrical", "Data outlet", ("DATA",), ("DATA", "CAT6", "CAT5")),
    ("phone_outlet", "electrical", "Telephone outlet", ("TEL",), ("PHONE", "TEL")),
    ("tv_outlet", "electrical", "TV outlet", ("TV", "CATV"), ("CATV", "TV")),
    ("ceiling_fan", "electrical", "Ceiling fan", ("CF",), ("CEILFAN", "CEILING_FAN")),
    ("panel", "electrical", "Electrical panel", (), ("PANEL", "PNL")),
    ("junction_box", "electrical", "Junction box", ("J", "JB"), ("JBOX", "JUNCTION")),
    # Sprint 12: the rest of a house's electrical devices
    ("duplex_receptacle_usb", "electrical", "Duplex receptacle with USB", ("USB",), ("USB",)),
    ("receptacle_dedicated", "electrical", "Dedicated receptacle", ("DED",), ("DEDICATED",)),
    ("ev_charger", "electrical", "EV charger", ("EV", "EVSE"), ("EVSE", "EVCHARGER")),
    ("disconnect", "electrical", "Disconnect switch", ("DISC",), ("DISCONNECT",)),
    ("switch_occupancy", "electrical", "Occupancy sensor switch", ("$OS", "OS"), ("OCCUPANCY", "OCCSENSOR")),
    ("light_wall", "electrical", "Wall light (sconce)", ("WL",), ("SCONCE", "WALLLIGHT")),
    ("light_pendant", "electrical", "Pendant light", ("PD",), ("PENDANT",)),
    ("light_undercabinet", "electrical", "Under-cabinet light", ("UC",), ("UNDERCAB", "UNDERCABINET")),
    ("light_exterior", "electrical", "Exterior light", (), ("FLOODLIGHT", "EXTLIGHT")),
    ("smoke_co_detector", "electrical", "Smoke and CO detector", ("SD/CO", "SDCO"), ("SMOKECO",)),
    ("doorbell", "electrical", "Doorbell", ("DB",), ("DOORBELL", "CHIME")),
    ("speaker", "electrical", "Speaker", ("SPKR",), ("SPEAKER",)),
    ("thermostat", "mechanical", "Thermostat", ("T", "TSTAT"), ("TSTAT", "THERMOSTAT")),
    ("exhaust_fan", "mechanical", "Exhaust fan", ("EF",), ("EXHAUST", "EF")),
    ("supply_diffuser", "mechanical", "Supply diffuser", ("SA",), ("DIFFUSER", "SUPPLY")),
    ("return_grille", "mechanical", "Return grille", ("RA",), ("RETURN", "GRILLE")),
    ("water_closet", "plumbing", "Water closet", ("WC",), ("TOILET", "WC", "WATERCLOSET")),
    ("lavatory", "plumbing", "Lavatory", ("LAV",), ("LAV", "LAVATORY")),
    ("sink", "plumbing", "Sink", (), ("SINK",)),
    ("floor_drain", "plumbing", "Floor drain", ("FD",), ("FLOORDRAIN", "FD")),
    ("hose_bibb", "plumbing", "Hose bibb", ("HB",), ("HOSEBIB", "HB")),
    ("water_heater", "plumbing", "Water heater", ("WH",), ("WATERHEATER", "WH")),
    ("cleanout", "plumbing", "Cleanout", ("FCO", "WCO"), ("CLEANOUT",)),
    ("shower", "plumbing", "Shower", (), ("SHOWER",)),
    ("tub", "plumbing", "Tub", (), ("TUB", "BATHTUB")),
    # Sprint 12: the rest of a house's plumbing fixtures
    ("kitchen_sink", "plumbing", "Kitchen sink", ("KS",), ("KITCHENSINK", "KSINK")),
    ("bar_sink", "plumbing", "Bar sink", ("BS",), ("BARSINK",)),
    ("laundry_sink", "plumbing", "Laundry sink", ("LS", "LT"), ("LAUNDRYSINK", "UTILITYSINK", "LAUNDRYTUB")),
    ("mop_sink", "plumbing", "Mop sink", ("MS",), ("MOPSINK", "SERVICESINK")),
    ("urinal", "plumbing", "Urinal", ("UR",), ("URINAL",)),
    ("dishwasher", "plumbing", "Dishwasher", ("DW",), ("DISHWASHER",)),
    ("washer_box", "plumbing", "Washer box", ("WB",), ("WASHERBOX", "WASHINGMACHINE")),
    ("ice_maker_box", "plumbing", "Ice maker box", ("IM", "IMB"), ("ICEMAKER",)),
    ("tub_shower", "plumbing", "Tub and shower", ("T/S",), ("TUBSHOWER",)),
    ("tankless_water_heater", "plumbing", "Tankless water heater", ("TWH",), ("TANKLESS",)),
    ("gas_outlet", "plumbing", "Gas outlet", ("GAS",), ("GASVALVE", "GASCOCK")),
    ("drinking_fountain", "plumbing", "Drinking fountain", ("DF", "EWC"), ("FOUNTAIN",)),
    ("water_meter", "plumbing", "Water meter", ("MTR",), ("WATERMETER",)),
    ("sprinkler_head", "fire", "Sprinkler head", (), ("SPRINKLER", "SPK")),
    ("fire_extinguisher", "fire", "Fire extinguisher", ("FE",), ("EXTING",)),
)

# Sprint 12: which trade question each symbol counts toward (module id, question id[, choice value]). A symbol not
# here is listed but not counted by a trade (smoke detectors, panels, cleanouts: priced another way or by a person).
FEEDS = {
    "duplex_receptacle": ("electrical", "outlets"), "duplex_receptacle_usb": ("electrical", "outlets"),
    "quad_receptacle": ("electrical", "outlets"), "floor_box": ("electrical", "outlets"),
    "duplex_receptacle_gfci": ("electrical", "gfci"), "duplex_receptacle_wp": ("electrical", "gfci"),
    "switch": ("electrical", "switches"), "switch_3way": ("electrical", "switches"),
    "switch_4way": ("electrical", "switches"), "switch_dimmer": ("electrical", "switches"),
    "switch_occupancy": ("electrical", "switches"),
    "light_recessed": ("electrical", "lights"), "light_fixture": ("electrical", "lights"),
    "light_wall": ("electrical", "lights"), "light_pendant": ("electrical", "lights"),
    "light_undercabinet": ("electrical", "lights"), "light_exterior": ("electrical", "lights"),
    "exit_sign": ("electrical", "lights"), "emergency_light": ("electrical", "lights"),
    "ceiling_fan": ("electrical", "fans"),
    "receptacle_240v": ("electrical", "appliance_circuits"), "receptacle_dedicated": ("electrical", "appliance_circuits"),
    "ev_charger": ("electrical", "appliance_circuits"),
    "data_outlet": ("electrical", "low_voltage"), "phone_outlet": ("electrical", "low_voltage"),
    "tv_outlet": ("electrical", "low_voltage"), "speaker": ("electrical", "low_voltage"),
    "water_closet": ("plumbing", "toilets"), "urinal": ("plumbing", "toilets"),
    "lavatory": ("plumbing", "sinks"), "sink": ("plumbing", "sinks"),
    "kitchen_sink": ("plumbing", "kitchen_sinks"), "bar_sink": ("plumbing", "kitchen_sinks"),
    "laundry_sink": ("plumbing", "kitchen_sinks"), "mop_sink": ("plumbing", "kitchen_sinks"),
    "shower": ("plumbing", "showers"), "tub": ("plumbing", "showers"), "tub_shower": ("plumbing", "showers"),
    "dishwasher": ("plumbing", "dishwashers"), "washer_box": ("plumbing", "washers"),
    "hose_bibb": ("plumbing", "hose_bibs"),
    "water_heater": ("plumbing", "water_heater", "tank"), "tankless_water_heater": ("plumbing", "water_heater", "tankless"),
}

STANDARD = [{"item_type": it, "trade": tr, "description": d, "aliases": list(al), "block_words": list(bw)}
            for it, tr, d, al, bw in _ROWS]
BY_TYPE = {e["item_type"]: e for e in STANDARD}
ALIASES = {a: e["item_type"] for e in STANDARD for a in e["aliases"]}


def norm_code(text: str | None) -> str:
    return re.sub(r"[\s.,:;()]", "", (text or "")).upper()


def by_alias(code: str | None) -> dict | None:
    """The standard entry whose short code this is (GFI -> GFCI receptacle)."""
    it = ALIASES.get(norm_code(code))
    return BY_TYPE.get(it) if it else None


def by_block_name(name: str | None) -> dict | None:
    """The standard entry a CAD block name names (DUPLEX_OUTLET_GFI -> GFCI receptacle). A variant beats the plain
    symbol it varies (duplex_receptacle_gfci over duplex_receptacle, switch_3way over switch), then longer words win."""
    if not name:
        return None
    words = [w for w in re.split(r"[^A-Z0-9$]+", name.upper()) if w]
    joined = "".join(words)
    hits = {}
    for e in STANDARD:
        for bw in (w.replace("-", "") for w in e["block_words"]):
            if bw in words or (len(bw) >= 4 and bw in joined):
                hits[e["item_type"]] = max(hits.get(e["item_type"], 0), len(bw))
    if not hits:
        return None

    def rank(it):
        variant = any(it != other and it.startswith(other + "_") for other in hits)
        return (variant, hits[it])
    return BY_TYPE[max(hits, key=rank)]
