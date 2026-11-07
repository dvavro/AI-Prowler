"""Module registry.

Each trade or service is a folder:

    estimator/modules/<category>/<module_id>/
        manifest.yaml          id, name, version, category, path, questions, lines, minimum charge
        pricing_defaults.csv   sample prices: price_key, description, kind, unit, cost (dollars)
        tests/golden.yaml      golden cases: answers and the expected total (checked by the test suite)

The registry discovers folders at startup and validates every manifest before it
can be used: required fields, the folder name matching the id, question types,
formulas (compiled by the sandboxed formula engine, using only known variables),
units, line kinds, and that every price key has a sample price. A bad module is
reported and skipped; it never stops the other modules from loading.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path

import yaml

from estimator.core.formula_engine import FormulaError, compile_formula, formula_variables
from estimator.core.units.money import cents_from_decimal
from estimator.core.units.units import UnitError, normalize_unit
from estimator.pricing.stack import LINE_KINDS

MODULES_ROOT = Path(__file__).resolve().parent
CATEGORIES = ("construction", "service")
PATHS = ("quick_estimate", "plan_takeoff", "both")
QUESTION_TYPES = ("number", "integer", "boolean", "choice")
RESERVED_VARIABLES = frozenset()
# AI-Prowler job "Recurrence" values (db_write_ops._RECURRENCE_WORDS)
RECURRENCE_VALUES = ("One-time", "Weekly", "Biweekly", "Monthly", "Bimonthly", "Quarterly", "Semi-Annually", "Annually")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Question:
    id: str
    label: str
    type: str
    unit: str | None = None
    required: bool = False
    default: object = None
    min: Decimal | None = None
    max: Decimal | None = None
    choices: tuple = ()               # ({"value", "label", "factor"}, ...)
    help: str = ""

    def as_dict(self) -> dict:
        d = {"id": self.id, "label": self.label, "type": self.type, "required": self.required,
             "default": self.default, "help": self.help}
        if self.unit:
            d["unit"] = self.unit
        if self.min is not None:
            d["min"] = str(self.min)
        if self.max is not None:
            d["max"] = str(self.max)
        if self.choices:
            d["choices"] = [{"value": c["value"], "label": c["label"]} for c in self.choices]
        return d


@dataclass(frozen=True)
class LineRule:
    id: str
    description: str
    kind: str
    unit: str
    quantity: str                     # formula
    price_key: str
    when: str | None = None           # formula; line included when it evaluates non-zero
    waste: str = "0"


@dataclass(frozen=True)
class SamplePrice:
    price_key: str
    description: str
    kind: str
    unit: str
    cost_cents: int


@dataclass
class TradeModule:
    id: str
    name: str
    version: str
    category: str
    path: str
    description: str
    folder: Path
    questions: tuple[Question, ...] = ()
    lines: tuple[LineRule, ...] = ()
    minimum_charge_cents: int | None = None
    sample_prices: dict = field(default_factory=dict)
    keywords: tuple[str, ...] = ()    # words the Director's triage matches in a request
    required_any: tuple[str, ...] = ()  # the Director won't price until at least one of these is non-zero
    recurrence: dict | None = None    # {"question": id, "map": {choice value: AI-Prowler Recurrence}}
    notes: tuple[str, ...] = ()       # reminders the Reviewer shows (e.g. hot-weather pour timing)
    scenarios: tuple[dict, ...] = ()  # good/better/best: ({"id", "label", "answers"}, ...)

    def question(self, qid: str) -> Question:
        for q in self.questions:
            if q.id == qid:
                return q
        raise KeyError(qid)

    def summary(self) -> dict:
        return {
            "id": self.id, "name": self.name, "version": self.version, "category": self.category,
            "path": self.path, "description": self.description,
            "question_count": len(self.questions), "line_rules": len(self.lines),
            "minimum_charge_cents": self.minimum_charge_cents, "keywords": list(self.keywords),
        }


def _req(d: dict, key: str, where: str):
    if key not in d or d[key] in (None, ""):
        raise ManifestError(f"{where}: missing required field '{key}'")
    return d[key]


def _dec(value, where: str) -> Decimal:
    if isinstance(value, float):
        value = repr(value)
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ManifestError(f"{where}: not a number: {value!r}") from exc


def _parse_question(raw: dict, where: str) -> Question:
    qid = _req(raw, "id", where)
    if not str(qid).isidentifier() or str(qid).startswith("_"):
        raise ManifestError(f"{where}: question id '{qid}' must be a simple name (letters, digits, _)")
    qtype = _req(raw, "type", f"{where} '{qid}'")
    if qtype not in QUESTION_TYPES:
        raise ManifestError(f"{where} '{qid}': type must be one of {QUESTION_TYPES}")
    unit = raw.get("unit")
    if unit:
        try:
            unit = normalize_unit(unit)
        except UnitError as exc:
            raise ManifestError(f"{where} '{qid}': {exc}") from exc
    choices = ()
    if qtype == "choice":
        raw_choices = raw.get("choices") or []
        if len(raw_choices) < 2:
            raise ManifestError(f"{where} '{qid}': a choice question needs at least 2 choices")
        seen = set()
        built = []
        for c in raw_choices:
            v = str(_req(c, "value", f"{where} '{qid}' choice"))
            if v in seen:
                raise ManifestError(f"{where} '{qid}': duplicate choice '{v}'")
            seen.add(v)
            built.append({"value": v, "label": c.get("label", v),
                          "factor": _dec(_req(c, "factor", f"{where} '{qid}' choice '{v}'"), where)})
        choices = tuple(built)
        if raw.get("default") is not None and str(raw["default"]) not in seen:
            raise ManifestError(f"{where} '{qid}': default '{raw['default']}' is not one of the choices")
    lo = _dec(raw["min"], where) if raw.get("min") is not None else None
    hi = _dec(raw["max"], where) if raw.get("max") is not None else None
    if lo is not None and hi is not None and lo > hi:
        raise ManifestError(f"{where} '{qid}': min is greater than max")
    return Question(
        id=qid, label=raw.get("label", qid), type=qtype, unit=unit, required=bool(raw.get("required", False)),
        default=raw.get("default"), min=lo, max=hi, choices=choices, help=raw.get("help", ""),
    )


def check_answer_value(q: Question, value, where: str) -> None:
    """Check a fixed answer written in a manifest (scenarios) against its question."""
    if q.type == "choice":
        if str(value) not in {c["value"] for c in q.choices}:
            raise ManifestError(f"{where}: '{value}' is not a choice of '{q.id}'")
    elif q.type == "boolean":
        if not isinstance(value, bool):
            raise ManifestError(f"{where}: '{q.id}' needs true or false")
    else:
        d = _dec(value, where)
        if (q.min is not None and d < q.min) or (q.max is not None and d > q.max):
            raise ManifestError(f"{where}: '{q.id}' value {value} is out of range")


def parse_scenarios(raw_list, questions: tuple, where: str) -> tuple[dict, ...]:
    if raw_list in (None, []):
        return ()
    if not isinstance(raw_list, list) or not 2 <= len(raw_list) <= 4:
        raise ManifestError(f"{where}: scenarios must be a list of 2 to 4 options")
    by_id = {q.id: q for q in questions}
    seen, out = set(), []
    for i, sc in enumerate(raw_list):
        sw = f"{where} scenario {i + 1}"
        if not isinstance(sc, dict):
            raise ManifestError(f"{sw}: must be a mapping")
        sid = str(_req(sc, "id", sw))
        if not sid.isidentifier() or sid in seen:
            raise ManifestError(f"{sw}: id '{sid}' must be a simple, unique name")
        seen.add(sid)
        answers = sc.get("answers") or {}
        if not isinstance(answers, dict) or not answers:
            raise ManifestError(f"{sw}: answers must name at least one question")
        for k, v in answers.items():
            if k not in by_id:
                raise ManifestError(f"{sw}: unknown question '{k}'")
            check_answer_value(by_id[k], v, sw)
        out.append({"id": sid, "label": str(sc.get("label") or sid), "answers": dict(answers)})
    return tuple(out)


def _load_sample_prices(path: Path) -> dict:
    prices = {}
    if not path.exists():
        return prices
    with path.open(newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f), start=2):
            where = f"{path.name} line {i}"
            key = _req(row, "price_key", where)
            if key in prices:
                raise ManifestError(f"{where}: duplicate price_key '{key}'")
            kind = _req(row, "kind", where)
            if kind not in LINE_KINDS:
                raise ManifestError(f"{where}: kind must be one of {LINE_KINDS}")
            try:
                unit = normalize_unit(_req(row, "unit", where))
                cost = cents_from_decimal(_req(row, "cost", where))
            except (UnitError, ValueError, TypeError) as exc:
                raise ManifestError(f"{where}: {exc}") from exc
            if cost < 0:
                raise ManifestError(f"{where}: cost cannot be negative")
            prices[key] = SamplePrice(key, row.get("description", ""), kind, unit, cost)
    return prices


def load_module(folder: Path) -> TradeModule:
    """Load and validate one module folder. Raises ManifestError with a clear message."""
    folder = Path(folder)
    mf = folder / "manifest.yaml"
    if not mf.exists():
        raise ManifestError(f"{folder.name}: manifest.yaml not found")
    try:
        raw = yaml.safe_load(mf.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ManifestError(f"{folder.name}: manifest.yaml is not valid YAML ({exc})") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"{folder.name}: manifest.yaml must be a mapping")
    where = f"{folder.name}/manifest.yaml"
    mid = _req(raw, "id", where)
    if mid != folder.name:
        raise ManifestError(f"{where}: id '{mid}' must match the folder name '{folder.name}'")
    category = _req(raw, "category", where)
    if category not in CATEGORIES:
        raise ManifestError(f"{where}: category must be one of {CATEGORIES}")
    path = raw.get("path", "quick_estimate")
    if path not in PATHS:
        raise ManifestError(f"{where}: path must be one of {PATHS}")

    questions = tuple(_parse_question(q, f"{where} question") for q in raw.get("questions") or [])
    qids = [q.id for q in questions]
    if len(qids) != len(set(qids)):
        raise ManifestError(f"{where}: duplicate question ids")
    known_vars = set(qids)

    samples = _load_sample_prices(folder / "pricing_defaults.csv")

    lines = []
    for lr in raw.get("lines") or []:
        lw = f"{where} line '{lr.get('id', '?')}'"
        lid = _req(lr, "id", lw)
        kind = _req(lr, "kind", lw)
        if kind not in LINE_KINDS:
            raise ManifestError(f"{lw}: kind must be one of {LINE_KINDS}")
        try:
            unit = normalize_unit(_req(lr, "unit", lw))
        except UnitError as exc:
            raise ManifestError(f"{lw}: {exc}") from exc
        qty = str(_req(lr, "quantity", lw))
        when = lr.get("when")
        waste = str(lr.get("waste", "0"))
        for label, formula in (("quantity", qty), ("when", when), ("waste", waste)):
            if formula is None:
                continue
            try:
                compile_formula(str(formula))
                unknown = formula_variables(str(formula)) - known_vars
            except FormulaError as exc:
                raise ManifestError(f"{lw} {label}: {exc}") from exc
            if unknown:
                raise ManifestError(f"{lw} {label}: unknown variables {sorted(unknown)}")
        key = _req(lr, "price_key", lw)
        if key not in samples:
            raise ManifestError(f"{lw}: price_key '{key}' has no sample price in pricing_defaults.csv")
        if samples[key].unit != unit:
            raise ManifestError(f"{lw}: unit '{unit}' doesn't match price '{key}' unit '{samples[key].unit}'")
        lines.append(LineRule(lid, lr.get("description", lid), kind, unit, qty, key,
                              str(when) if when is not None else None, waste))
    lids = [ln.id for ln in lines]
    if len(lids) != len(set(lids)):
        raise ManifestError(f"{where}: duplicate line ids")
    if path in ("quick_estimate", "both") and not lines:
        raise ManifestError(f"{where}: a quick-estimate module needs at least one line rule")

    minimum = raw.get("minimum_charge")
    min_cents = None
    if minimum is not None:
        try:
            min_cents = cents_from_decimal(str(minimum))
        except (ValueError, TypeError) as exc:
            raise ManifestError(f"{where}: minimum_charge: {exc}") from exc

    raw_kw = raw.get("keywords") or []
    if not isinstance(raw_kw, list) or not all(isinstance(k, str) and k.strip() for k in raw_kw):
        raise ManifestError(f"{where}: keywords must be a list of words or phrases")
    keywords = tuple(dict.fromkeys(k.strip().lower() for k in raw_kw))
    required_any = tuple(raw.get("required_any") or [])
    bad_any = [q for q in required_any if q not in known_vars]
    if bad_any:
        raise ManifestError(f"{where}: required_any names unknown questions {bad_any}")
    recurrence = raw.get("recurrence")
    if recurrence is not None:
        if not isinstance(recurrence, dict) or "question" not in recurrence or not isinstance(recurrence.get("map"), dict):
            raise ManifestError(f"{where}: recurrence needs a question and a map")
        rq = next((q for q in questions if q.id == recurrence["question"]), None)
        if rq is None or rq.type != "choice":
            raise ManifestError(f"{where}: recurrence question must be a choice question")
        values = {c["value"] for c in rq.choices}
        bad = [k for k in recurrence["map"] if str(k) not in values]
        if bad:
            raise ManifestError(f"{where}: recurrence map names unknown choices {bad}")
        badv = [v for v in recurrence["map"].values() if v not in RECURRENCE_VALUES]
        if badv:
            raise ManifestError(f"{where}: recurrence values must be one of {RECURRENCE_VALUES}")
        recurrence = {"question": rq.id, "map": {str(k): v for k, v in recurrence["map"].items()}}
    raw_notes = raw.get("notes") or []
    if not isinstance(raw_notes, list) or not all(isinstance(n, str) and n.strip() for n in raw_notes):
        raise ManifestError(f"{where}: notes must be a list of sentences")
    scenarios = parse_scenarios(raw.get("scenarios"), questions, f"{where}")

    return TradeModule(
        id=mid, name=raw.get("name", mid), version=str(raw.get("version", "0.0.0")), category=category,
        path=path, description=raw.get("description", ""), folder=folder, questions=questions,
        lines=tuple(lines), minimum_charge_cents=min_cents, sample_prices=samples, keywords=keywords,
        required_any=required_any, recurrence=recurrence, notes=tuple(n.strip() for n in raw_notes),
        scenarios=scenarios,
    )


class ModuleRegistry:
    def __init__(self, roots: list[Path] | None = None):
        self.roots = [Path(r) for r in (roots or [MODULES_ROOT])]
        self.modules: dict[str, TradeModule] = {}
        self.errors: dict[str, str] = {}

    def load(self) -> "ModuleRegistry":
        self.modules.clear()
        self.errors.clear()
        for root in self.roots:
            for category in CATEGORIES:
                cat_dir = root / ("services" if category == "service" else category)
                if not cat_dir.is_dir():
                    continue
                for folder in sorted(p for p in cat_dir.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))):
                    try:
                        mod = load_module(folder)
                    except ManifestError as exc:
                        self.errors[folder.name] = str(exc)
                        continue
                    if mod.category != category:
                        self.errors[folder.name] = f"category '{mod.category}' but folder is under '{cat_dir.name}'"
                        continue
                    if mod.id in self.modules:
                        self.errors[folder.name] = f"duplicate module id '{mod.id}'"
                        continue
                    self.modules[mod.id] = mod
        return self

    def get(self, module_id: str) -> TradeModule:
        if module_id not in self.modules:
            from estimator.errors import NotFound
            raise NotFound(f"no module named '{module_id}'", module_id=module_id,
                           available=sorted(self.modules))
        return self.modules[module_id]

    def list(self) -> list[TradeModule]:
        return [self.modules[k] for k in sorted(self.modules)]


_REGISTRY: ModuleRegistry | None = None


def get_registry(reload: bool = False) -> ModuleRegistry:
    global _REGISTRY
    if _REGISTRY is None or reload:
        _REGISTRY = ModuleRegistry().load()
    return _REGISTRY
