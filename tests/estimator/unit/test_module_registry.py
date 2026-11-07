"""Sprint 2: module registry and manifest validation (S2-R01..)."""
import shutil
import textwrap

import pytest

from estimator.modules.registry import MODULES_ROOT, ManifestError, ModuleRegistry, load_module

PW = MODULES_ROOT / "services" / "pressure_washing"


def _module(tmp_path, manifest: str, prices: str | None = None, name="demo", category_dir="services"):
    folder = tmp_path / category_dir / name
    folder.mkdir(parents=True)
    (folder / "manifest.yaml").write_text(textwrap.dedent(manifest), encoding="utf-8")
    if prices is None:
        prices = "price_key,description,kind,unit,cost\nk_sqft,Sample,other,sqft,1.00\n"
    (folder / "pricing_defaults.csv").write_text(prices, encoding="utf-8")
    return folder


GOOD = """
id: demo
name: Demo
category: service
minimum_charge: "50"
questions:
  - {id: area, label: Area, type: number, unit: sqft, default: 0, min: 0}
  - id: level
    type: choice
    default: a
    choices: [{value: a, factor: "1"}, {value: b, factor: "2"}]
lines:
  - {id: wash, kind: other, unit: sqft, quantity: "area * level", price_key: k_sqft}
"""


def test_shipped_modules_load_without_errors():  # S2-R01
    reg = ModuleRegistry().load()
    assert reg.errors == {}
    assert {"pressure_washing", "house_cleaning"} <= set(reg.modules)


def test_good_manifest_loads(tmp_path):  # S2-R02
    mod = load_module(_module(tmp_path, GOOD))
    assert mod.id == "demo" and mod.minimum_charge_cents == 5000
    assert mod.question("level").choices[1]["factor"] == 2
    assert mod.sample_prices["k_sqft"].cost_cents == 100


@pytest.mark.parametrize("change, message", [
    (("id: demo", "id: other"), "must match the folder name"),
    (("category: service", "category: food"), "category must be one of"),
    (("type: number", "type: text"), "type must be one of"),
    (('"area * level"', '"area * missing"'), "unknown variables"),
    (('"area * level"', '"__import__(1)"'), "quantity"),
    (('"area * level"', '"area *"'), "syntax error"),
    (("price_key: k_sqft", "price_key: nope"), "no sample price"),
    (("kind: other, unit: sqft", "kind: snacks, unit: sqft"), "kind must be one of"),
    (("kind: other, unit: sqft", "kind: other, unit: furlongs"), "unit"),
    (("kind: other, unit: sqft", "kind: other, unit: lf"), "doesn't match price"),
    (("default: a", "default: z"), "not one of the choices"),
])
def test_bad_manifests_are_rejected_with_a_clear_message(tmp_path, change, message):  # S2-R03
    folder = _module(tmp_path, GOOD.replace(*change))
    with pytest.raises(ManifestError, match=message):
        load_module(folder)


def test_choice_needs_two_options_and_unique_values(tmp_path):  # S2-R04
    one = GOOD.replace('choices: [{value: a, factor: "1"}, {value: b, factor: "2"}]', 'choices: [{value: a, factor: "1"}]')
    with pytest.raises(ManifestError, match="at least 2"):
        load_module(_module(tmp_path, one))
    dup = GOOD.replace('{value: b, factor: "2"}', '{value: a, factor: "2"}')
    with pytest.raises(ManifestError, match="duplicate choice"):
        load_module(_module(tmp_path / "second", dup))


def test_bad_price_csv_rejected(tmp_path):  # S2-R05
    bad = "price_key,description,kind,unit,cost\nk_sqft,Sample,other,sqft,-1\n"
    with pytest.raises(ManifestError, match="negative"):
        load_module(_module(tmp_path, GOOD, bad))
    dup = "price_key,description,kind,unit,cost\nk_sqft,a,other,sqft,1\nk_sqft,b,other,sqft,2\n"
    with pytest.raises(ManifestError, match="duplicate price_key"):
        load_module(_module(tmp_path / "y", GOOD, dup))


def test_invalid_yaml_and_missing_manifest(tmp_path):  # S2-R06
    with pytest.raises(ManifestError, match="not valid YAML"):
        load_module(_module(tmp_path, "id: [unclosed"))
    empty = tmp_path / "services" / "empty"
    empty.mkdir(parents=True)
    with pytest.raises(ManifestError, match="not found"):
        load_module(empty)


def test_bad_module_is_skipped_and_others_still_load(tmp_path):  # S2-R07
    shutil.copytree(PW, tmp_path / "services" / "pressure_washing")
    _module(tmp_path, GOOD.replace("price_key: k_sqft", "price_key: nope"), name="demo")
    reg = ModuleRegistry([tmp_path]).load()
    assert "pressure_washing" in reg.modules
    assert "demo" in reg.errors and "no sample price" in reg.errors["demo"]


def test_module_in_wrong_category_folder_is_reported(tmp_path):  # S2-R08
    _module(tmp_path, GOOD, category_dir="construction")
    reg = ModuleRegistry([tmp_path]).load()
    assert "demo" not in reg.modules and "category" in reg.errors["demo"]


def test_get_unknown_module_lists_available():  # S2-R09
    from estimator.errors import NotFound
    reg = ModuleRegistry().load()
    with pytest.raises(NotFound) as exc:
        reg.get("roof_painting")
    assert "pressure_washing" in exc.value.details["available"]
