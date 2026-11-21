"""LLM-assisted electrical takeoff: parsing, the count measurements, the run, the results.

A fake provider stands in for Claude and Grok: no real API calls, no token cost.
Every test runs against a throwaway data folder (conftest.py) with fixture plan
sheets - never the live NSB plan or the live database.
"""
import json

import pytest

from estimator.agents import providers, roles
from estimator.api import autorun_api
from estimator.context import personal_context
from estimator.estimating import service
from estimator.takeoff import llm_electrical as le
from estimator.takeoff import llm_takeoff as lt

CTX = personal_context()
NOW = "2026-11-12T10:00:00+00:00"


class FakeVisionProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of vision texts
    (or exceptions) used in order. ask() must never be called - the LLM takeoff reads
    pictures, it doesn't chat."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}
        self.replies = {"claude_api": [], "grok_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def ask(self, provider, system, user, model=""):
        raise AssertionError("the LLM takeoff must use ask_vision, not ask")

    def ask_vision(self, provider, system, user, images, model=""):
        self.calls.append({"provider": provider, "system": system, "user": user,
                           "images": images, "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else "{}"
        if isinstance(r, Exception):
            raise r
        return r, {"input": 3000, "output": 200}

    def cost(self, model, usage):           # $2 / $10 per 1M tokens, like Sonnet
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeVisionProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _png(path, w=400, h=300):
    from PIL import Image
    Image.new("RGB", (w, h), "white").save(path, "PNG")
    return str(path)


@pytest.fixture
def plans(db, tmp_path):
    """An estimate with one plan set: a single electrical sheet (E-1) with a rendered
    image. One sheet means the ranking is trivial - the run flow is what is tested."""
    est = service.create_estimate(db, CTX, "Electrical job")["id"]
    ps = db.execute("INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type,"
                    " file_size, sha256, status, uploaded_by, created_at)"
                    " VALUES ('default', ?, 'x.dwg', 'x.dwg', 'dwg', 1, 'aa', 'processed', 'owner', ?)",
                    (est, NOW)).lastrowid
    img1 = _png(tmp_path / "e1.png")
    s1 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 1, 'E-1', 'ELECTRICAL PLAN', ?)", (ps, img1)).lastrowid
    vp = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                    " VALUES ('default', ?, 'Electrical plan', '48', 0)", (s1,)).lastrowid
    return {"est": est, "ps": ps, "s1": s1, "vp": vp}


def _on(db, provider="claude_api", **extra):
    return roles.update_role(db, CTX, "llm_takeoff", {"provider": provider, **extra}, confirm=True)


def _run(db, plans, sheet=None, vp=None):
    return autorun_api.create_run(db, CTX, plans["est"], sheet or plans["s1"], vp or plans["vp"],
                                  "electrical", [])


EVIDENCE = {"outlets": "12 duplex receptacles around the rooms",
            "switches": "4 switches by the doors",
            "gfci": "2 GFCI outlets in the kitchen",
            "lights": "6 recessed cans",
            "fans": "1 ceiling fan in the living room",
            "circuits_15a": "1 dedicated 15A circuit for the microwave",
            "appliance_circuits": "1 240V receptacle for the range",
            "low_voltage": "no data or TV drops shown"}


def _reading(sheet_id, **over):
    out = {"electrical_sheet_id": sheet_id, "outlets": 12, "switches": 4, "gfci": 2, "lights": 6,
           "fans": 1, "circuits_15a": 1, "appliance_circuits": 1, "low_voltage": 0,
           "confidence": 0.9, "notes": "symbols clear on the plan", "evidence": dict(EVIDENCE)}
    out.update(over)
    return json.dumps(out)


def _parsed(sheet_id, **over):
    return le.parse_electrical_reading(_reading(sheet_id, **over), sheet_id)


# ------------------------------------------------------------------ parsing the AI's answer

def test_parse_electrical_reading_full():
    got = le.parse_electrical_reading(_reading(4), 4)
    assert got == {"electrical_sheet_id": 4,
                   "counts": {"outlets": 12, "switches": 4, "gfci": 2, "lights": 6, "fans": 1, "exhaust_fans": 0, "switches_3way": 0, "switches_4way": 0, "dimmers": 0, "occupancy_switches": 0, "usb_outlets": 0, "quad_outlets": 0, "floor_boxes": 0, "wp_outlets": 0, "recessed_lights": 0, "wall_lights": 0, "pendant_lights": 0, "undercabinet_lights": 0, "exterior_lights": 0, "exit_emergency_lights": 0, "smoke_detectors": 0, "main_panels": 0,
                              "circuits_15a": 1, "appliance_circuits": 1, "low_voltage": 0},
                   "evidence": {**EVIDENCE, "exhaust_fans": "", "switches_3way": "", "switches_4way": "", "dimmers": "", "occupancy_switches": "", "usb_outlets": "", "quad_outlets": "", "floor_boxes": "", "wp_outlets": "", "recessed_lights": "", "wall_lights": "", "pendant_lights": "", "undercabinet_lights": "", "exterior_lights": "", "exit_emergency_lights": "", "smoke_detectors": "", "main_panels": ""}, "confidence": 0.9, "notes": "symbols clear on the plan"}


def test_parse_electrical_reading_fenced_with_nulls():
    text = "```json\n" + _reading(4, confidence=None, evidence=None) + "\n```"
    got = le.parse_electrical_reading(text, 4)
    assert got["confidence"] is None and got["evidence"] == {f: "" for f in le.COUNT_IDS}
    assert got["counts"]["outlets"] == 12


def test_parse_electrical_reading_rejects_bad_answers():
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        le.parse_electrical_reading("no json here", 4)
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        le.parse_electrical_reading('[1, 2]', 4)
    with pytest.raises(lt.LlmTakeoffError, match="couldn't be read"):
        le.parse_electrical_reading('{not json}', 4)


def test_exhaust_fans_are_counted():                                                  # 2026-11-19
    """Bath exhaust fans are an Electrical count now: the AI is asked for them, and its answer carries them (an older
    answer with no exhaust_fans reads as 0 - see the test above)."""
    got = le.parse_electrical_reading(_reading(4, exhaust_fans=4), 4)
    assert got["counts"]["exhaust_fans"] == 4 and got["counts"]["fans"] == 1
    assert le.quantities_from_reading(got)["total_devices"] == 31
    prompt = _prompt()
    assert "exhaust_fans are bath (or laundry) exhaust fans" in prompt and '"exhaust_fans": 2,' in prompt
    with pytest.raises(lt.LlmTakeoffError):
        le.parse_electrical_reading(_reading(4, exhaust_fans=-1), 4)


@pytest.mark.parametrize("field,bad", [
    ("outlets", None), ("gfci", -1), ("lights", 2.5), ("switches", "3"), ("fans", True),
    ("circuits_15a", None), ("appliance_circuits", 1.0), ("low_voltage", -5),
])
def test_parse_electrical_reading_rejects_bad_counts(field, bad):
    """Every defect names the field, so the AI Log says which count was wrong."""
    with pytest.raises(lt.LlmTakeoffError, match=field):
        le.parse_electrical_reading(_reading(4, **{field: bad}), 4)


def test_parse_electrical_reading_rejects_missing_count():
    d = json.loads(_reading(4))
    del d["gfci"]
    with pytest.raises(lt.LlmTakeoffError, match="gfci"):
        le.parse_electrical_reading(json.dumps(d), 4)


def test_parse_electrical_reading_wrong_sheet_id_uses_the_shown_sheet():
    got = le.parse_electrical_reading(_reading(9), 4)
    assert got["electrical_sheet_id"] == 4
    assert "named sheet 9" in got["notes"]


def test_parse_electrical_classification():
    assert le.parse_electrical_classification('{"electrical_sheet_id": 4, "notes": "panel"}', [4, 5]) == (4, "panel")
    assert le.parse_electrical_classification('{"electrical_sheet_id": null, "notes": "none"}', [4, 5])[0] is None
    assert le.parse_electrical_classification('{"electrical_sheet_id": 99}', [4, 5])[0] is None  # never shown: no match
    with pytest.raises(lt.LlmTakeoffError, match="didn't answer with JSON"):
        le.parse_electrical_classification("nope", [4])


# ------------------------------------------------------------------ the reader prompt

def _prompt():
    return le.read_prompt({"id": 4, "sheet_no": "E-1", "page_no": 1, "title": "ELECTRICAL PLAN"})


def test_read_prompt_tells_the_symbols_apart_by_shape():
    """The first live run (estimate 9, house wiring DXF) read the symbols by
    convention and misread them: fans and smoke detectors counted as lights,
    door swings as data drops, weatherproof receptacles as 30A circuits. Each
    rule below pins one of those misreads to the shape on the drawing."""
    prompt = _prompt()
    assert "a ceiling fan is a circle with an X (or blades) - count it as fans, not lights" in prompt
    assert "a diamond inside a circle is a smoke detector - count it as smoke_detectors" in prompt
    assert "a data or TV drop is a triangle - a half-circle is a door swing, not a drop" in prompt
    assert "a GFCI is a circle inside a square - count it as gfci, not outlets" in prompt
    assert ("an exterior double-circle receptacle is a weatherproof (WP) receptacle"
            " - count it as wp_outlets, not gfci or appliance_circuits") in prompt
    # the strict JSON contract is unchanged: the eight counts in the same skeleton
    assert '"outlets": 12, "switches": 4, "gfci": 2, "lights": 6, "fans": 1,' in prompt


def test_lights_are_counted_by_type():                                                    # 2026-11-20
    """David: "for the lights we need to count separately each type of light needed for the BOM so ask AI Auto Run
    not to bundle symbols"."""
    prompt = _prompt()
    assert "never bundled together" in prompt and "each kind is a different fixture to order" in prompt
    for k in ("recessed_lights", "wall_lights", "pendant_lights", "undercabinet_lights", "exterior_lights",
              "exit_emergency_lights"):
        assert f'"{k}":' in prompt                                                     # asked for, in the JSON
    got = _parsed(4, lights=15, recessed_lights=4, wall_lights=6, exterior_lights=2)
    assert {k: got["counts"][k] for k in ("lights", "recessed_lights", "wall_lights", "pendant_lights",
                                          "exterior_lights")} == {"lights": 15, "recessed_lights": 4, "wall_lights": 6,
                                                                  "pendant_lights": 0, "exterior_lights": 2}
    assert le.LABELS["recessed_lights"] == "Recessed lights (cans)" and le._label("lights") == "Ceiling lights"


def test_read_prompt_excludes_the_legend():
    """The legend shows one of each symbol - the live run counted the legend
    row, adding one switch and one GFCI. The prompt says to use the legend to
    tell the symbols apart, never to count it."""
    prompt = _prompt()
    assert "do not count the legend row itself" in prompt
    assert "usually at the bottom of the sheet" in prompt


# ------------------------------------------------------------------ the count measurements

def test_create_measurements_proposes_one_per_nonzero_count(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    quantities = le.quantities_from_reading(reading)
    assert quantities == {"counts": {"outlets": 12, "switches": 4, "gfci": 2, "lights": 6, "fans": 1, "exhaust_fans": 0, "switches_3way": 0, "switches_4way": 0, "dimmers": 0, "occupancy_switches": 0, "usb_outlets": 0, "quad_outlets": 0, "floor_boxes": 0, "wp_outlets": 0, "recessed_lights": 0, "wall_lights": 0, "pendant_lights": 0, "undercabinet_lights": 0, "exterior_lights": 0, "exit_emergency_lights": 0, "smoke_detectors": 0, "main_panels": 0,
                                     "circuits_15a": 1, "appliance_circuits": 1, "low_voltage": 0},
                          "total_devices": 27}
    ids = le.create_measurements(db, CTX, run, reading, quantities, "claude_api", "claude-sonnet-5-5")
    assert len(ids) == 7                              # low_voltage is 0: no row for it
    rows = [dict(r) for r in db.execute("SELECT * FROM measurements WHERE estimate_id = ?"
                                        " ORDER BY id", (plans["est"],))]
    assert [r["id"] for r in rows] == ids
    by_feeds = {r["feeds"]: r for r in rows}
    assert set(by_feeds) == {"outlets", "switches", "gfci", "lights", "fans",
                             "circuits_15a", "appliance_circuits"}
    assert (by_feeds["outlets"]["qty"], by_feeds["outlets"]["unit"]) == ("12", "ea")
    assert by_feeds["outlets"]["label"] == "Outlets (AI)"
    assert by_feeds["appliance_circuits"]["label"] == "Dedicated 30A circuits (AI)"
    assert by_feeds["lights"]["label"] == "Ceiling lights (AI)"                # 2026-11-20: lights by type
    for r in rows:
        assert r["kind"] == "count" and r["module_id"] == "electrical"
        assert r["proposed_by"] == "llm-takeoff" and r["method"] == "ai"
        assert r["status"] == "proposed" and r["locked"] == 0
        assert r["sheet_id"] == plans["s1"] and r["viewport_id"] == plans["vp"]
        assert r["geometry_json"] is None and r["confidence"] == "0.9"
        calc = json.loads(r["calc_json"])
        assert calc["source"] == "llm" and calc["auto_run_id"] == rid and calc["candidate_id"] == "llm"
        assert calc["how"] == EVIDENCE[r["feeds"]] and calc["qty"] == r["qty"]
        assert calc["electrical_sheet_id"] == plans["s1"]
        assert calc["counts"]["outlets"] == 12 and calc["counts"]["low_voltage"] == 0
        assert calc["provider"] == "claude_api" and calc["model"] == "claude-sonnet-5-5"
        assert calc["notes"] == "symbols clear on the plan"


def test_keep_approved_choice_from_the_request(db, plans):                                  # 2026-11-19
    k = autorun_api._keep_approved
    assert k({}) is True and k({"keep_approved": True}) is True and k(None) is True       # on unless said otherwise
    assert k({"keep_approved": False}) is False and k({"keep_approved": "0"}) is False
    rid = autorun_api.create_run(db, CTX, plans["est"], plans["s1"], plans["vp"], "electrical", [], keep_approved=False)
    assert autorun_api._load_run(db, CTX, rid)["keep_approved"] == 0
    assert autorun_api._load_run(db, CTX, _run(db, plans))["keep_approved"] == 1


@pytest.mark.parametrize("keep", [True, False], ids=["keep-approved", "from-scratch"])
def test_a_rerun_replaces_the_earlier_run(db, plans, keep):                                   # 2026-11-19
    """David: To measure said 4 weatherproof outlets, everything else said 2 - two runs' proposals were both waiting.
    A rerun on the same sheet replaces the earlier AI measurements of the trade there, never adds to them. With
    "Keep approved items" (the default) what a person approved stays and isn't proposed again; without it the trade
    starts over from scratch. A measurement a person typed always stays."""
    from estimator.takeoff import measurements as ms
    reading = _parsed(plans["s1"], wp_outlets=2)
    quantities = le.quantities_from_reading(reading)
    first = le.create_measurements(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)), reading, quantities,
                                   "claude_api", "m")
    outlets = next(i for i in first if db.execute("SELECT feeds FROM measurements WHERE id = ?", (i,)).fetchone()[0]
                   == "outlets")
    ms.confirm_measurements(db, CTX, [outlets], confirm=True)
    typed = ms.manual(db, CTX, plans["est"], "electrical", feeds="dimmers", qty="3", unit="ea",
                      confirm=True)["measurement"]["id"]                                 # a person's own count
    rid2 = autorun_api.create_run(db, CTX, plans["est"], plans["s1"], plans["vp"], "electrical", [],
                                  keep_approved=keep)
    second = le.create_measurements(db, CTX, autorun_api._load_run(db, CTX, rid2), reading, quantities,
                                    "claude_api", "m")
    ai = {r["feeds"]: dict(r) for r in db.execute(
        "SELECT id, feeds, qty, status FROM measurements WHERE proposed_by = 'llm-takeoff'")}
    waiting = [r for r in ai.values() if r["status"] == "proposed"]
    assert sorted(r["id"] for r in waiting) == sorted(second)                            # one new set, nothing doubled
    assert ai["wp_outlets"]["qty"] == "2" and ai["wp_outlets"]["status"] == "proposed"
    if keep:
        assert ai["outlets"]["id"] == outlets and ai["outlets"]["status"] == "approved"  # kept ...
        assert len(second) == len(first) - 1                                             # ... and not proposed again
    else:
        assert ai["outlets"]["status"] == "proposed" and len(second) == len(first)      # from scratch
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE id = ?", (typed,)).fetchone()[0] == 1
    reasons = [json.loads(r[0])["reason"] for r in db.execute(
        "SELECT after_json FROM estimate_events WHERE action = 'measurement_deleted'")]
    assert reasons == [f"replaced by AI Auto Run #{rid2}"] * (len(first) - (1 if keep else 0))


def test_create_measurements_all_zero_proposes_nothing(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"], outlets=0, switches=0, gfci=0, lights=0, fans=0,
                      circuits_15a=0, appliance_circuits=0, low_voltage=0)
    quantities = le.quantities_from_reading(reading)
    assert quantities["total_devices"] == 0
    assert le.create_measurements(db, CTX, run, reading, quantities, "claude_api", "m") == []
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ------------------------------------------------------------------ the whole run

def test_run_llm_electrical_direct(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    steps = []
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid), on_step=steps.append)
    assert len(fake.calls) == 1                       # one sheet: no classify call, just the read
    assert fake.calls[0]["provider"] == "claude_api" and len(fake.calls[0]["images"]) == 1
    assert fake.calls[0]["images"][0]["media_type"] == "image/png"
    assert "count the devices" in fake.calls[0]["system"].lower()
    assert "never null" in fake.calls[0]["user"] and "evidence" in fake.calls[0]["user"]
    assert steps == ["finding the electrical sheet", "reading the plan with the AI", "counting the devices"]
    assert out["quantities"]["total_devices"] == 27
    assert out["sheet_id"] == plans["s1"] and out["provider"] == "claude_api"
    assert out["candidate"] == {"id": "llm", "source": "llm",
                                "counts": {"outlets": 12, "switches": 4, "gfci": 2, "lights": 6, "fans": 1, "exhaust_fans": 0, "switches_3way": 0, "switches_4way": 0, "dimmers": 0, "occupancy_switches": 0, "usb_outlets": 0, "quad_outlets": 0, "floor_boxes": 0, "wp_outlets": 0, "recessed_lights": 0, "wall_lights": 0, "pendant_lights": 0, "undercabinet_lights": 0, "exterior_lights": 0, "exit_emergency_lights": 0, "smoke_detectors": 0, "main_panels": 0,
                                           "circuits_15a": 1, "appliance_circuits": 1, "low_voltage": 0},
                                "evidence": {**EVIDENCE, "exhaust_fans": "", "switches_3way": "", "switches_4way": "", "dimmers": "", "occupancy_switches": "", "usb_outlets": "", "quad_outlets": "", "floor_boxes": "", "wp_outlets": "", "recessed_lights": "", "wall_lights": "", "pendant_lights": "", "undercabinet_lights": "", "exterior_lights": "", "exit_emergency_lights": "", "smoke_detectors": "", "main_panels": ""}, "confidence": 0.9,
                                "notes": "symbols clear on the plan", "sheet_id": plans["s1"],
                                "provider": "claude_api", "model": "claude-sonnet-5-5"}
    assert out["summary"] == ("counted 27 devices on sheet %d (12 outlets, 4 single-pole switches, 2 GFCI outlets, 6 ceiling lights,"
                              " 1 ceiling fans, 1 dedicated 30A circuits, 1 dedicated 15A circuits); measurements %s"
                              % (plans["s1"], out["measurement_ids"]))
    assert len(out["measurement_ids"]) == 7
    usage = [dict(r) for r in db.execute("SELECT * FROM agent_usage WHERE company_id = 'default'")]
    assert len(usage) == 1 and usage[0]["role"] == "llm_takeoff" and usage[0]["task_id"] == rid
    assert usage[0]["ok"] == 1 and usage[0]["cost_micros"] > 0
    sent = db.execute("SELECT COUNT(*) FROM ai_send_log WHERE company_id = 'default'"
                      " AND kind = 'full_sheet'").fetchone()[0]
    assert sent == 1


def test_run_llm_electrical_legend_excluded_counts(db, fake, plans):
    """A fake-provider reply shaped like the first live run's answer (estimate 9,
    house wiring DXF) - but with the legend row excluded, as the fixed prompt
    asks: the counts the drawing actually holds, carried through the parse and
    quantities path to proposed measurements."""
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], outlets=41, switches=25, gfci=14,
                                           lights=25, fans=5, circuits_15a=0,
                                           appliance_circuits=4, low_voltage=5,
                                           confidence=0.45, notes="legend row excluded",
                                           evidence={
                                               "outlets": "41 duplex receptacles on the floor plans",
                                               "switches": "25 switches by the doors",
                                               "gfci": "12 GFCI outlets + 2 weatherproof receptacles",
                                               "lights": "25 ceiling, recessed and wall lights",
                                               "fans": "5 ceiling fans (circle with an X)",
                                               "circuits_15a": "no dedicated 15A circuits labeled",
                                               "appliance_circuits": "range, dryer, water heater, AC",
                                               "low_voltage": "5 triangle data/TV drops",
                                           })]
    rid = _run(db, plans)
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["quantities"] == {"counts": {"outlets": 41, "switches": 25, "gfci": 14, "lights": 25,
                                            "fans": 5, "exhaust_fans": 0, "switches_3way": 0, "switches_4way": 0, "dimmers": 0, "occupancy_switches": 0, "usb_outlets": 0, "quad_outlets": 0, "floor_boxes": 0, "wp_outlets": 0, "recessed_lights": 0, "wall_lights": 0, "pendant_lights": 0, "undercabinet_lights": 0, "exterior_lights": 0, "exit_emergency_lights": 0, "smoke_detectors": 0, "main_panels": 0, "circuits_15a": 0, "appliance_circuits": 4,
                                            "low_voltage": 5},
                                 "total_devices": 119}
    assert len(out["measurement_ids"]) == 7   # circuits_15a is 0: no row for it
    assert out["candidate"]["confidence"] == 0.45
    assert out["candidate"]["notes"] == "legend row excluded"
    # the prompt the fake provider was shown carries the legend rule
    assert "do not count the legend row itself" in fake.calls[0]["user"]


def test_run_llm_electrical_rules_settle_on_the_electrical_sheet(db, fake, plans, tmp_path):
    _on(db)
    img2 = _png(tmp_path / "a101.png")
    db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
               " VALUES ('default', ?, 2, 'A-101', 'FLOOR PLAN', ?)", (plans["ps"], img2))
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, _run(db, plans)))
    assert len(fake.calls) == 1                       # the sheet rules settle it: no classify call
    assert out["sheet_id"] == plans["s1"]


def _tie_run(db, plans, tmp_path):
    """A second electrical sheet with the same title score, and a run started on a
    sheet with no image - so the run's sheet doesn't break the tie under any rules."""
    img2 = _png(tmp_path / "e2.png")
    s2 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, image_path)"
                    " VALUES ('default', ?, 2, 'E-2', 'ELECTRICAL PLAN', ?)", (plans["ps"], img2)).lastrowid
    s3 = db.execute("INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title)"
                    " VALUES ('default', ?, 3, 'A-101', 'FLOOR PLAN')", (plans["ps"],)).lastrowid
    vp3 = db.execute("INSERT INTO viewports (company_id, sheet_id, label, scale_ratio, is_nts)"
                     " VALUES ('default', ?, 'Floor plan', '48', 0)", (s3,)).lastrowid
    return s2, _run(db, plans, sheet=s3, vp=vp3)


def test_run_llm_electrical_classifies_when_the_rules_tie(db, fake, plans, tmp_path):
    _on(db)
    s2, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [
        json.dumps({"electrical_sheet_id": s2, "notes": "the panel is on E-2"}),
        _reading(s2),
    ]
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert len(fake.calls) == 2                       # classify, then the read
    assert len(fake.calls[0]["images"]) == 2          # thumbnails of both electrical sheets
    assert "electrical plan" in fake.calls[0]["user"].lower()
    assert out["sheet_id"] == s2
    assert db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ?",
                      (plans["est"],)).fetchone()[0] == 7


def test_run_llm_electrical_fails_when_the_ai_cannot_find_the_electrical_sheet(db, fake, plans, tmp_path):
    _on(db)
    _, rid = _tie_run(db, plans, tmp_path)
    fake.replies["claude_api"] = [json.dumps({"electrical_sheet_id": None, "notes": "no panel seen"})]
    with pytest.raises(lt.LlmTakeoffError, match="couldn't tell which sheet is the electrical plan"):
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


def test_run_llm_electrical_off_makes_no_call(db, fake, plans):
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError) as exc:
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert "AI measuring is off" in str(exc.value) and "count the devices" in str(exc.value)
    assert fake.calls == []


def test_run_llm_electrical_budget_used_up_makes_no_call(db, fake, plans):
    _on(db)
    roles.update_budget(db, CTX, {"daily_cents": 0, "monthly_cents": 0}, confirm=True)
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="budget"):
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_electrical_sheet_off_refusal(db, fake, plans):
    _on(db)
    db.execute("INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_at)"
               " VALUES ('default', ?, 'electrical', 0, ?)", (plans["s1"], NOW))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="switched off for Electrical"):
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_electrical_no_images_at_all(db, fake, plans):
    _on(db)
    db.execute("UPDATE sheets SET image_path = NULL WHERE plan_set_id = ?", (plans["ps"],))
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="has a rendered image"):
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert fake.calls == []


def test_run_llm_electrical_bad_reading_fails(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"], gfci=2.5)]
    rid = _run(db, plans)
    with pytest.raises(lt.LlmTakeoffError, match="gfci"):
        le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM agent_usage").fetchone()[0] == 1   # the call still cost


def test_run_llm_electrical_tries_the_backup_provider(db, fake, plans):
    _on(db, fallback_provider="grok_api")
    fake.replies["claude_api"] = [providers.ProviderError("Claude is down")]
    fake.replies["grok_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    assert out["provider"] == "grok_api" and out["model"] == "grok-4.3"
    assert [c["provider"] for c in fake.calls] == ["claude_api", "grok_api"]
    usage = [dict(r) for r in db.execute("SELECT provider, ok FROM agent_usage ORDER BY id")]
    assert usage == [{"provider": "claude_api", "ok": 0}, {"provider": "grok_api", "ok": 1}]


# ------------------------------------------------------------------ the results

def _finish_run(db, rid, candidate=None, measurement_ids=None):
    autorun_api.update_run(db, rid, status="done", candidates=[candidate] if candidate else [],
                           measurement_ids=measurement_ids or [])
    return autorun_api._load_run(db, CTX, rid)


def test_electrical_results_shape(db, fake, plans):
    _on(db)
    fake.replies["claude_api"] = [_reading(plans["s1"])]
    rid = _run(db, plans)
    out = le.run_llm_electrical(db, CTX, autorun_api._load_run(db, CTX, rid))
    row = _finish_run(db, rid, out["candidate"], out["measurement_ids"])
    got = le.electrical_results(db, CTX, row)
    assert len(got["lines"]) == 7
    by_feeds = {ln["feeds"]: ln for ln in got["lines"]}
    assert by_feeds["outlets"] == {"id": out["measurement_ids"][0], "label": "Outlets (AI)",
                                   "feeds": "outlets", "qty": "12", "unit": "ea", "status": "proposed",
                                   "how": EVIDENCE["outlets"]}
    counts = {c["feeds"]: c for c in got["electrical"]["counts"]}
    assert set(counts) == set(le.COUNT_IDS)           # all eight questions, zeros included
    assert counts["outlets"] == {"feeds": "outlets", "label": "Outlets (standard duplex)", "qty": 12,
                                 "evidence": EVIDENCE["outlets"]}
    assert counts["low_voltage"] == {"feeds": "low_voltage", "label": "Data or TV drops", "qty": 0,
                                     "evidence": EVIDENCE["low_voltage"]}   # zero: the candidate's evidence
    assert got["electrical"]["sheet_id"] == plans["s1"]
    assert got["electrical"]["confidence"] == 0.9
    assert got["electrical"]["notes"] == "symbols clear on the plan"


def test_electrical_results_all_zero_counts(db, plans):
    rid = _run(db, plans)
    cand = {"id": "llm", "source": "llm", "counts": {f: 0 for f in le.COUNT_IDS},
            "evidence": {**EVIDENCE, "exhaust_fans": "", "switches_3way": "", "switches_4way": "", "dimmers": "", "occupancy_switches": "", "usb_outlets": "", "quad_outlets": "", "floor_boxes": "", "wp_outlets": "", "recessed_lights": "", "wall_lights": "", "pendant_lights": "", "undercabinet_lights": "", "exterior_lights": "", "exit_emergency_lights": "", "smoke_detectors": "", "main_panels": ""}, "confidence": 0.8, "notes": "empty plan",
            "sheet_id": plans["s1"]}
    row = _finish_run(db, rid, cand, [])
    got = le.electrical_results(db, CTX, row)
    assert got["lines"] == []
    assert all(c["qty"] == 0 for c in got["electrical"]["counts"])
    assert got["electrical"]["counts"][0]["evidence"] == EVIDENCE["outlets"]
    assert got["electrical"]["sheet_id"] == plans["s1"]
    assert got["electrical"]["confidence"] == 0.8


def test_electrical_results_none_when_nothing(db, plans):
    rid = _run(db, plans)
    assert le.electrical_results(db, CTX, autorun_api._load_run(db, CTX, rid)) is None


def test_electrical_results_without_candidate_uses_measurements(db, plans):
    rid = _run(db, plans)
    run = autorun_api._load_run(db, CTX, rid)
    reading = _parsed(plans["s1"])
    ids = le.create_measurements(db, CTX, run, reading, le.quantities_from_reading(reading),
                                 "claude_api", "claude-sonnet-5-5")
    row = _finish_run(db, rid, None, ids)
    got = le.electrical_results(db, CTX, row)
    counts = {c["feeds"]: c for c in got["electrical"]["counts"]}
    assert counts["outlets"]["qty"] == 12 and counts["low_voltage"]["qty"] == 0
    assert counts["outlets"]["evidence"] == EVIDENCE["outlets"]
    assert got["electrical"]["sheet_id"] == plans["s1"]
    assert got["electrical"]["confidence"] is None and got["electrical"]["notes"] == ""
