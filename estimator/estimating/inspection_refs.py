"""The Inspector's reference requirements: the code checklist per construction trade.

(2026-11-18, David): the Inspector started electrical-only; it now reviews every
construction trade on an estimate. The AI MATCHES the estimate against the list
for that trade — it does not invent code sections (inspection_review.py sends the
list in the prompt and demands STRICT JSON). Every code_ref below is a real
section, verified against the Florida Building Code 8th Edition (2023), the
Florida Plumbing and Mechanical Codes, ACI 318-19, or the federal rule named.
Where a requirement depends on a local amendment or ordinance, the item carries
a "note" saying so, and the AI flags it as 'verify with the AHJ' rather than
asserting it.

Trades with genuinely thin code content get short honest lists — they are not
padded. A trade with no inspection items at all has no list and is named in
NO_CHECKLIST with the reason, so the refusal names the trade instead of
pretending a checklist exists. Service trades are never reviewed: the Inspector
checks construction work against the building code, and a cleaning or detailing
job has no code to check against.
"""
from __future__ import annotations

# The reference requirements per trade: {module_id: ({id, description, code_ref}
# [, note])}. The electrical list is the original 18-item NEC 2020 list, verbatim.
# The wire-gauge limits are 240.4(D) (14/12/10 AWG) with 8 AWG from Table 310.16.
REFERENCE_REQUIREMENTS: dict[str, tuple[dict, ...]] = {
    "electrical": (
        {"id": "afci", "description": "AFCI protection on bedroom and living-area circuits",
         "code_ref": "210.12"},
        {"id": "gfci", "description": "GFCI protection in bathrooms, kitchens, garage, laundry, outdoors,"
                                     " basement/crawl — all 125–250V receptacles in those areas",
         "code_ref": "210.8"},
        {"id": "kitchen_circuits", "description": "Two 20A small-appliance circuits in the kitchen",
         "code_ref": "210.11(C)(1)"},
        {"id": "laundry_circuit", "description": "Dedicated 20A laundry circuit",
         "code_ref": "210.11(C)(2)"},
        {"id": "bathroom_circuit", "description": "Dedicated 20A bathroom circuit",
         "code_ref": "210.11(C)(3)"},
        {"id": "receptacle_spacing", "description": "A receptacle within 6 ft of any point along a wall",
         "code_ref": "210.52(A)"},
        {"id": "tamper_resistant", "description": "Tamper-resistant receptacles",
         "code_ref": "406.12"},
        {"id": "tub_clearance", "description": "No receptacle within 3 ft horizontal / 8 ft vertical of the tub rim",
         "code_ref": "406.9(C)"},
        {"id": "switched_light", "description": "Switch-controlled light in every habitable room, hallway and garage",
         "code_ref": "210.70(A)"},
        {"id": "outdoor_receptacles", "description": "Outdoor receptacle at the front and the back",
         "code_ref": "210.52(E)"},
        {"id": "service_receptacle", "description": "A receptacle within 25 ft of equipment needing service",
         "code_ref": "210.63"},
        {"id": "surge_protection", "description": "Whole-house surge protection device",
         "code_ref": "230.67"},
        {"id": "panel_clearance", "description": "Panel working clearance 30\"W x 36\"D x 6.5'H",
         "code_ref": "110.26"},
        {"id": "panel_directory", "description": "Panel directory labeled",
         "code_ref": "408.4"},
        {"id": "subpanel_grounds", "description": "Neutral and ground separated in subpanels",
         "code_ref": "250.24(A)(5)"},
        {"id": "grounding_electrode", "description": "Grounding electrode system",
         "code_ref": "250.50"},
        {"id": "wire_gauge", "description": "Wire gauge matches the breaker"
                                            " (14 AWG/15A, 12 AWG/20A, 10 AWG/30A, 8 AWG/40A)",
         "code_ref": "240.4(D), Table 310.16"},
        {"id": "smoke_co", "description": "Hardwired interconnected smoke/CO detectors",
         "code_ref": "NFPA 72"},
    ),
    "concrete": (
        {"id": "slab_thickness", "description": "Slab-on-grade at least 3.5 in thick",
         "code_ref": "R506.1"},
        {"id": "vapor_retarder", "description": "6-mil polyethylene vapor retarder under the slab,"
                                                " joints lapped 6 in",
         "code_ref": "R506.2.3"},
        {"id": "concrete_strength", "description": "Concrete strength per Table R402.2"
                                                   " (2,500 psi minimum; 3,000–3,500 psi for garage floors"
                                                   " and exterior concrete)",
         "code_ref": "Table R402.2"},
        {"id": "footing_depth", "description": "Footings bear on undisturbed soil at least 12 in below grade",
         "code_ref": "R403.1.4"},
        {"id": "footing_size", "description": "Footing width per Table R403.1, at least 6 in thick",
         "code_ref": "R403.1.1"},
        {"id": "slab_reinforcement", "description": "Slab reinforcement at least 0.0018 of the gross concrete area",
         "code_ref": "ACI 318-19 7.6.1.1"},
        {"id": "reinforcement_cover", "description": "Reinforcement cover 3 in where concrete is cast against earth",
         "code_ref": "ACI 318-19 20.5.1"},
        {"id": "drainage", "description": "Grade falls at least 6 in within the first 10 ft away from the foundation",
         "code_ref": "R401.3"},
    ),
    "demolition": (
        {"id": "permit", "description": "Demolition permit from the building department",
         "code_ref": "FBC R105.1"},
        {"id": "asbestos_survey", "description": "Asbestos survey before demolition starts",
         "code_ref": "40 CFR 61.145",
         "note": "the federal NESHAP rule covers facilities; single-family homes are federally exempt,"
                 " but many Florida jurisdictions still require a survey or affidavit with the"
                 " demolition permit — verify with the AHJ"},
        {"id": "engineering_survey", "description": "Engineering survey of the structure before work starts"
                                                    " (framing, floors, walls, collapse risk)",
         "code_ref": "OSHA 1926.850(a)"},
        {"id": "utility_disconnect", "description": "Water, electric and gas disconnected and capped before demolition",
         "code_ref": "Local ordinance",
         "note": "disconnect requirements and sign-offs vary by jurisdiction and utility —"
                 " verify with the AHJ"},
    ),
    "drywall": (
        {"id": "garage_separation", "description": "Garage separated from the dwelling by 1/2 in gypsum board"
                                                   " on the garage side; 5/8 in Type X under habitable rooms",
         "code_ref": "Table R302.6"},
        {"id": "water_resistant_backer", "description": "Water-resistant gypsum backing board behind tile"
                                                        " in tub and shower areas",
         "code_ref": "R702.3.7"},
        {"id": "tile_backer", "description": "Tile backers in tub and shower areas are cement board,"
                                             " fiber-cement or glass-mat gypsum",
         "code_ref": "R702.4.2"},
        {"id": "fastening", "description": "Fasteners per Table R702.3.5"
                                           " (screws 16 in on center on walls, 12 in on ceilings)",
         "code_ref": "Table R702.3.5"},
    ),
    "fencing": (
        {"id": "pool_barrier_height", "description": "Pool barrier fence at least 4 ft high, no opening passing"
                                                    " a 4 in sphere, bottom gap 2 in or less",
         "code_ref": "R4501.17",
         "note": "only where the fence is a pool barrier"},
        {"id": "pool_gate", "description": "Pool gates open outward, self-close and self-latch, latch release"
                                           " at least 54 in high or on the pool side",
         "code_ref": "R4501.17.1.8",
         "note": "only where the fence is a pool barrier"},
        {"id": "height_setback", "description": "Fence height and setback meet the local ordinance",
         "code_ref": "Local ordinance",
         "note": "height and setback limits vary by city and county — verify with the AHJ"},
    ),
    "flooring": (
        {"id": "subfloor", "description": "Floor sheathing per R503 (thickness and span for the joist spacing)",
         "code_ref": "R503"},
        {"id": "floor_fire_protection", "description": "Floor assemblies protected with a 1/2 in gypsum membrane"
                                                       " or equivalent where required",
         "code_ref": "R501.3",
         "note": "applies where the floor framing is exposed or changed"},
        {"id": "stair_nosings", "description": "Stair nosings project 3/4 in to 1-1/4 in",
         "code_ref": "R311.7.5.3",
         "note": "only where stairs are part of the job"},
    ),
    "framing": (
        {"id": "fastening", "description": "Fasteners per the fastening schedule (Table R602.3(1))",
         "code_ref": "Table R602.3(1)"},
        {"id": "stud_notching", "description": "Studs notched or bored within the R602.6 limits",
         "code_ref": "R602.6"},
        {"id": "headers", "description": "Headers sized per Table R602.7(1) with the required trimmers",
         "code_ref": "R602.7"},
        {"id": "wall_bracing", "description": "Braced wall panels per R602.10",
         "code_ref": "R602.10"},
        {"id": "roof_ties", "description": "Roof-to-wall uplift connections (hurricane ties)"
                                           " for the design wind speed",
         "code_ref": "R802.11"},
        {"id": "trusses", "description": "Trusses built to the engineered shop drawings, with no field alteration",
         "code_ref": "R802.10"},
        {"id": "joist_notching", "description": "Floor joists notched or bored within the R502.8 limits",
         "code_ref": "R502.8"},
    ),
    "hvac": (
        {"id": "sizing", "description": "Equipment sized from a Manual J load calculation (Manual S selection)",
         "code_ref": "FBC-R M1401.3"},
        {"id": "condensate_disposal", "description": "Condensate drains to an approved point, 3/4 in minimum,"
                                                     " sloped to drain",
         "code_ref": "FMC 307.2.1, 307.2.2"},
        {"id": "condensate_overflow", "description": "Secondary drain or overflow shutoff switch on the condensate pan",
         "code_ref": "FMC 307.2.3"},
        {"id": "duct_insulation", "description": "Supply ducts in unconditioned attics insulated to R-8,"
                                                 " R-6 elsewhere outside the envelope",
         "code_ref": "FBC-EC R403.3"},
        {"id": "duct_leakage", "description": "Duct leakage tested: 4 cfm per 100 sq ft or less"
                                              " with the air handler installed",
         "code_ref": "FBC-EC R403.3.3"},
        {"id": "ventilation", "description": "Whole-house mechanical ventilation provided",
         "code_ref": "FBC-EC R403.6"},
    ),
    "insulation": (
        {"id": "ceiling_r_value", "description": "Ceiling insulation R-38 (Climate Zone 2)",
         "code_ref": "Table R402.1.2"},
        {"id": "wall_r_value", "description": "Wood-frame wall insulation R-13 (Climate Zone 2)",
         "code_ref": "Table R402.1.2"},
        {"id": "floor_r_value", "description": "Floor insulation R-13 over unconditioned space (Climate Zone 2)",
         "code_ref": "Table R402.1.2"},
        {"id": "air_leakage", "description": "Envelope air-sealed and blower-door tested to 7 ACH50 or less",
         "code_ref": "R402.4.1.2"},
        {"id": "eave_baffle", "description": "Baffles keep attic insulation clear of soffit vents",
         "code_ref": "R402.2.3"},
    ),
    "landscaping": (
        {"id": "drainage", "description": "Grade falls at least 6 in within the first 10 ft away from the foundation",
         "code_ref": "R401.3"},
        {"id": "irrigation_backflow", "description": "Irrigation connected through an approved backflow preventer",
         "code_ref": "FPC 608.17"},
        {"id": "tree_protection", "description": "Protected trees kept or removed only with the local permit",
         "code_ref": "Local ordinance",
         "note": "tree protection rules vary by city and county — verify with the AHJ"},
    ),
    "plumbing": (
        {"id": "drain_slope", "description": "Horizontal drains sloped 1/4 in per ft (2-1/2 in and smaller)"
                                             " or 1/8 in per ft (3–6 in)",
         "code_ref": "704.1"},
        {"id": "trap_seal", "description": "Every fixture trapped with a 2–4 in water seal; no S-traps",
         "code_ref": "1002.4, 1002.3"},
        {"id": "water_pressure", "description": "Static water pressure 80 psi or less, or a pressure-reducing valve fitted",
         "code_ref": "604.8"},
        {"id": "thermal_expansion", "description": "Thermal expansion control (expansion tank) on closed systems",
         "code_ref": "607.3"},
        {"id": "tp_discharge", "description": "T&P relief valve discharge piped to a safe, visible place"
                                              " through an air gap",
         "code_ref": "504.6"},
        {"id": "heater_pan", "description": "Drain pan under a tank water heater where a leak would cause damage",
         "code_ref": "504.7"},
        {"id": "backflow", "description": "Backflow protection at cross-connections (air gaps, vacuum breakers)",
         "code_ref": "608"},
        {"id": "cleanouts", "description": "Cleanouts at the base of stacks, at direction changes over 45 degrees,"
                                           " and within 100 ft spacing",
         "code_ref": "708"},
    ),
    "roofing": (
        {"id": "underlayment", "description": "Underlayment per R905.1.1"
                                              " (self-adhering underlayment for asphalt shingles in Florida)",
         "code_ref": "R905.1.1"},
        {"id": "shingle_slope", "description": "Asphalt shingles only on slopes of 2:12 or greater",
         "code_ref": "R905.2.2"},
        {"id": "sheathing", "description": "Shingles fastened to solidly sheathed decks",
         "code_ref": "R905.2.1"},
        {"id": "wind_resistance", "description": "Shingles rated for the design wind speed (Table R905.2.6.1)",
         "code_ref": "R905.2.6.1"},
        {"id": "ventilation", "description": "Attic ventilation at least 1 sq ft of net free area per 150 sq ft of attic",
         "code_ref": "R806.2"},
        {"id": "flashing", "description": "Flashing at roof-wall intersections, valleys and penetrations",
         "code_ref": "R903.2"},
        {"id": "drip_edge", "description": "Drip edge at eaves and rakes",
         "code_ref": "R905.2.8.5"},
    ),
    "siding": (
        {"id": "wrb", "description": "Water-resistive barrier behind the siding",
         "code_ref": "R703.2"},
        {"id": "flashing", "description": "Flashing at openings, intersections and penetrations",
         "code_ref": "R703.4"},
        {"id": "fastener_penetration", "description": "Siding fasteners penetrate at least 1-1/2 in into framing",
         "code_ref": "R703.3.4"},
        {"id": "stucco", "description": "Stucco (exterior plaster) applied per R703.7,"
                                        " with a water-resistive barrier behind it",
         "code_ref": "R703.7"},
    ),
    "windows_doors": (
        {"id": "egress", "description": "Bedroom and basement escape openings: 5.7 sq ft clear, 24 in high"
                                        " by 20 in wide, sill no more than 44 in above the floor",
         "code_ref": "R310.2"},
        {"id": "safety_glazing", "description": "Safety glazing in hazardous locations"
                                                " (doors, tub/shower enclosures, low windows)",
         "code_ref": "R308.4"},
        {"id": "fall_protection", "description": "Fall protection on operable windows with sills under 24 in"
                                                 " and more than 72 in above grade",
         "code_ref": "R312.2"},
        {"id": "wind_rating", "description": "Windows and doors tested and labeled for the design wind pressure",
         "code_ref": "R609"},
        {"id": "impact", "description": "Impact-resistant glazing or shutters in wind-borne debris regions",
         "code_ref": "R609.11"},
        {"id": "flashing", "description": "Windows and doors flashed per R703.4",
         "code_ref": "R703.4"},
        {"id": "energy", "description": "Fenestration U-factor 0.40 or less and SHGC 0.25 or less (Climate Zone 2)",
         "code_ref": "FBC-EC Table R402.1.2"},
    ),
    # 2026-11-27 (Jamie): garage doors - wind rating for the door, entrapment protection for the opener
    "garage_doors": (
        {"id": "wind_rating", "description": "Garage door tested and labeled for the design wind pressure",
         "code_ref": "R609.4"},
        {"id": "entrapment", "description": "Automatic opener listed for entrapment protection, with photo eyes"
                                           " mounted no more than 6 in above the floor",
         "code_ref": "UL 325"},
        {"id": "auto_reverse", "description": "Opener reverses when the door hits an object or the photo-eye beam"
                                             " is blocked while closing",
         "code_ref": "16 CFR 1211"},
    ),
}

# Construction trades deliberately WITHOUT a reference list: the trade has no
# building-code inspection items to check an estimate against. Painting is the
# only one: the EPA lead Renovation, Repair and Painting rule governs work
# practices and certification on pre-1978 homes, not an inspection checklist.
NO_CHECKLIST = {
    "painting": ("painting has no building-code inspection requirements — the only code-adjacent rule"
                 " is the EPA lead Renovation, Repair and Painting rule (40 CFR 745) for pre-1978 homes,"
                 " which governs work practices and certification, not an inspection checklist"),
}

# The code each trade is checked against, for the Inspector's system prompt.
TRADE_CODE = {
    "concrete": "the Florida Building Code and ACI 318",
    "demolition": "the Florida Building Code and the federal asbestos NESHAP",
    "drywall": "the Florida Building Code",
    "electrical": "the National Electrical Code (NEC)",
    "fencing": "the Florida Building Code",
    "flooring": "the Florida Building Code",
    "framing": "the Florida Building Code",
    "hvac": "the Florida Mechanical Code and the Florida Energy Code",
    "insulation": "the Florida Energy Code",
    "landscaping": "the Florida Building Code and the Florida Plumbing Code",
    "plumbing": "the Florida Plumbing Code",
    "roofing": "the Florida Building Code",
    "siding": "the Florida Building Code",
    "windows_doors": "the Florida Building Code and the Florida Energy Code",
    "garage_doors": "the International Residential Code (IRC), UL 325 and the federal opener safety rule (16 CFR 1211)",
}


def reviewable_trades() -> list[str]:
    """The module_ids with a reference list, sorted."""
    return sorted(REFERENCE_REQUIREMENTS)


def has_references(module_id: str) -> bool:
    """True when the trade has a reference list to check an estimate against."""
    return module_id in REFERENCE_REQUIREMENTS
