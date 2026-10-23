"""
tests/mcp_tests/test_yearly_projections.py
===========================================
(2026-10-08) Yearly calendar projections — jobs/index.html
_calRecurringProjections (~2273-2309).

For each ACTIVE customer with a Frequency + Last Service Date, the calendar
generates view-only pseudo-jobs across the next 12 months:
the server sweep's own periods (R-079, 2026-10-09): Weekly +7d, Biweekly
+14d, Monthly +1mo, Bi-Monthly +2mo, Quarterly +3mo, Semi-Annually +6mo,
Annually +12mo, month-end clamped (guard: 60 iterations max). The last
test runs index.html's real JS in node and compares it with this mirror.
loadCalendar() then merges them AFTER real jobs — a projected date is
skipped when that customer already has a real scheduled job on it.

The logic lives in the PWA's JS (not importable from Python), so this file
mirrors it 1:1 as pure functions and pins the date generation, the
frequency mapping, the skip rules, and the real-job suppression merge.

Run: run_tests.bat tests\\mcp_tests\\test_yearly_projections.py -v
"""
import calendar
import re
from datetime import date, timedelta

import pytest


# ── Python mirrors of the JS ──────────────────────────────────────────────

def _dkey(d):
    """Mirror of _dkey: local-date key, always YYYY-MM-DD."""
    return d.strftime("%Y-%m-%d")


def parse_job_date(s):
    """Mirror of parseJobDate: ISO YYYY-MM-DD or legacy MM/DD/YYYY."""
    if not s:
        return None
    s = s.strip()
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})", s)
    if m:
        return date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
    return None


def _add_months_js(d, months):
    """Mirror of JS d.setMonth(d.getMonth() + n): month overflow rolls the
    surplus days into the following month (Jan 31 + 1mo -> Mar 3)."""
    m = d.month - 1 + months
    y, m = d.year + m // 12, m % 12 + 1
    day = d.day
    while True:
        dim = calendar.monthrange(y, m)[1]
        if day <= dim:
            return date(y, m, day)
        day -= dim
        m += 1
        if m > 12:
            m, y = 1, y + 1


def _add_months_clamped(d, months):
    """Mirror of the R-079 JS step = db_write_ops._add_months: month-end
    clamped (Jan 31 + 1mo -> Feb 28), chained from the previous visit."""
    m = d.month - 1 + months
    y, m = d.year + m // 12, m % 12 + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def cal_recurring_projections(customers, today=None):
    """Mirror of _calRecurringProjections (jobs/index.html ~2273-2309).

    customers: list of dicts with the sheet's column names.
    today: override for determinism (defaults to date.today()).
    """
    out = []
    today = today or date.today()
    horizon = _add_months_js(today, 12)  # JS: new Date(y, m+12, d)
    for c in customers or []:
        if not c:
            continue
        if (c.get("Status Active/Inactive") or "").strip().lower() == "inactive":
            continue
        freq_raw = (c.get("Frequency") or "").strip().lower()
        if not freq_raw:
            continue
        last_svc = parse_job_date(c.get("Last Service Date"))
        if not last_svc:
            continue
        name = (c.get("Company Name") or "").strip()
        cust_id = (c.get("CustomerID (CUST-####)") or "").strip()
        if not name:
            continue
        # R-079: the server's own words and periods (db_write_ops
        # _PERIOD_ALIASES -> _FREQ_MAP)
        import db_write_ops
        period = db_write_ops.frequency_period(freq_raw)
        step_days, step_months = {"weekly": (7, 0), "biweekly": (14, 0), "monthly": (0, 1),
                                  "bimonthly": (0, 2), "quarterly": (0, 3), "semiannual": (0, 6),
                                  "annual": (0, 12)}.get(period, (0, 0))
        if not (step_days or step_months):
            continue
        d = last_svc
        for _guard in range(60):
            d = (d + timedelta(days=step_days) if step_days
                 else _add_months_clamped(d, step_months))
            if d > horizon:
                break
            if d <= today:
                continue
            out.append({
                "projected": True,
                "id": "PROJ-" + re.sub(r"\s+", "_", cust_id or name)
                      + "-" + _dkey(d),
                "customer": name,
                "custId": cust_id,
                "date": _dkey(d),
                "frequency": c.get("Frequency"),  # raw sheet value, like JS
            })
    return out


def merge_projections(by_date, projections):
    """Mirror of the loadCalendar() merge (~2371-2377): real jobs win — a
    projected date is skipped when that customer has a real job on it."""
    for p in projections:
        day_jobs = by_date.get(p["date"], [])
        has_real = any(
            not j.get("projected") and (
                j.get("custId") == p["custId"] if p["custId"]
                else j.get("customer") == p["customer"])
            for j in day_jobs)
        if not has_real:
            by_date.setdefault(p["date"], []).append(p)
    return by_date


def _cust(**kw):
    row = {"Company Name": "Crabby's Daytona",
           "CustomerID (CUST-####)": "CUST-2026-1",
           "Status Active/Inactive": "Active",
           "Frequency": "Weekly",
           "Last Service Date": "2026-10-08"}
    row.update(kw)
    return row


TODAY = date(2026, 10, 8)  # fixed "today" so counts are deterministic


# ── Weekly: 52 dates, 7 days apart ────────────────────────────────────────

def test_weekly_generates_52_dates_7_days_apart():
    projs = cal_recurring_projections([_cust()], today=TODAY)
    assert len(projs) == 52
    dates = [parse_job_date(p["date"]) for p in projs]
    assert dates[0] == TODAY + timedelta(days=7)
    assert dates[-1] == TODAY + timedelta(days=364)
    for a, b in zip(dates, dates[1:]):
        assert (b - a).days == 7
    assert all(d > TODAY for d in dates)
    assert all(p["projected"] is True for p in projs)


# ── Biweekly variants: 26 dates, 14 days apart ────────────────────────────

@pytest.mark.parametrize("freq",
                         ["BiWeekly", "biweekly", "Biweekly",
                          "bi-weekly", "BI-WEEKLY", "every 2 weeks",
                          "Every 2 Weeks"])
def test_biweekly_variants_generate_26_dates_14_days_apart(freq):
    projs = cal_recurring_projections([_cust(Frequency=freq)], today=TODAY)
    assert len(projs) == 26, freq
    dates = [parse_job_date(p["date"]) for p in projs]
    for a, b in zip(dates, dates[1:]):
        assert (b - a).days == 14, freq
    # Frequency is echoed back with the sheet's original casing.
    assert projs[0]["frequency"] == freq


# ── Monthly: 12 dates, 1 month apart ──────────────────────────────────────

def test_monthly_generates_12_dates_one_month_apart():
    projs = cal_recurring_projections(
        [_cust(Frequency="Monthly", **{"Last Service Date": "2026-10-01"})],
        today=TODAY)
    assert len(projs) == 12
    dates = [parse_job_date(p["date"]) for p in projs]
    assert dates[0] == date(2026, 11, 1)
    assert dates[-1] == date(2027, 10, 1)  # <= horizon (2027-10-08)
    for p in projs:
        assert parse_job_date(p["date"]).day == 1


def test_monthly_day_after_today_gets_11_not_12():
    # Horizon is exactly today+12mo (2027-10-08 here): a monthly slot on
    # the 15th would land 2027-10-15, past the horizon — so it (and only
    # it) is dropped. Documents the JS `if (d > horizon) break` edge.
    projs = cal_recurring_projections(
        [_cust(Frequency="Monthly", **{"Last Service Date": "2026-10-15"})],
        today=TODAY)
    assert len(projs) == 11
    dates = [parse_job_date(p["date"]) for p in projs]
    assert dates[-1] == date(2027, 9, 15)


def test_monthly_case_insensitive():
    projs = cal_recurring_projections([_cust(Frequency="MONTHLY")],
                                      today=TODAY)
    assert len(projs) == 12


# ── R-079: every canonical Frequency projects on the sweep's period ───────

@pytest.mark.parametrize("freq,months,count", [
    ("Bi-Monthly", 2, 6), ("bimonthly", 2, 6), ("every other month", 2, 6),
    ("Quarterly", 3, 4), ("Semi-Annually", 6, 2), ("Semi-Annual", 6, 2),
    ("Annually", 12, 1), ("Yearly", 12, 1)])
def test_long_frequencies_project_like_the_sweep(freq, months, count):
    projs = cal_recurring_projections(
        [_cust(Frequency=freq, **{"Last Service Date": "2026-10-01"})], today=TODAY)
    dates = [parse_job_date(p["date"]) for p in projs]
    assert len(dates) == count, (freq, dates)
    assert dates[0] == _add_months_clamped(date(2026, 10, 1), months)


def test_bi_monthly_is_every_two_months_not_two_weeks():
    """The bug R-079 fixed: Bi-Monthly projected every 14 days while the
    server's sweep schedules the next visit 2 months out."""
    import db_write_ops
    projs = cal_recurring_projections(
        [_cust(Frequency="Bi-Monthly", **{"Last Service Date": "2026-10-01"})], today=TODAY)
    sweep_next = db_write_ops._FREQ_MAP[db_write_ops._freq_map_key("Bi-Monthly")](date(2026, 10, 1))
    assert projs[0]["date"] == _dkey(sweep_next) == "2026-12-01"


@pytest.mark.parametrize("freq", ["Weekly", "Biweekly", "Monthly", "Bi-Monthly",
                                  "Quarterly", "Semi-Annually", "Annually"])
def test_every_projection_is_a_date_the_sweep_would_create(freq):
    """Chain the server's own _FREQ_MAP from the Last Service Date: every
    projected visit must be one of the sweep's dates (month-end included)."""
    import db_write_ops
    step = db_write_ops._FREQ_MAP[db_write_ops._freq_map_key(freq)]
    last = date(2026, 1, 31)
    sweep, d = set(), last
    for _ in range(80):
        d = step(d)
        sweep.add(_dkey(d))
    projs = cal_recurring_projections(
        [_cust(Frequency=freq, **{"Last Service Date": _dkey(last)})], today=TODAY)
    assert projs, freq
    assert {p["date"] for p in projs} <= sweep, freq


# ── Skip rules ────────────────────────────────────────────────────────────

def test_inactive_customer_gets_no_projections():
    projs = cal_recurring_projections(
        [_cust(**{"Status Active/Inactive": "Inactive"})], today=TODAY)
    assert projs == []


@pytest.mark.parametrize("status", ["inactive", "INACTIVE", " Inactive "])
def test_inactive_status_case_and_whitespace_insensitive(status):
    projs = cal_recurring_projections(
        [_cust(**{"Status Active/Inactive": status})], today=TODAY)
    assert projs == []


def test_missing_frequency_gets_no_projections():
    projs = cal_recurring_projections([_cust(Frequency="")], today=TODAY)
    assert projs == []


@pytest.mark.parametrize("freq", ["Daily", "weekly-ish", "One-time", "Whenever convenient"])
def test_unknown_frequency_gets_no_projections(freq):
    projs = cal_recurring_projections([_cust(Frequency=freq)], today=TODAY)
    assert projs == []


def test_missing_last_service_date_gets_no_projections():
    projs = cal_recurring_projections(
        [_cust(**{"Last Service Date": ""})], today=TODAY)
    assert projs == []


def test_unparseable_last_service_date_gets_no_projections():
    projs = cal_recurring_projections(
        [_cust(**{"Last Service Date": "sometime soon"})], today=TODAY)
    assert projs == []


def test_missing_company_name_gets_no_projections():
    projs = cal_recurring_projections([_cust(**{"Company Name": "  "})],
                                      today=TODAY)
    assert projs == []


def test_null_customer_row_is_skipped():
    projs = cal_recurring_projections([None, _cust()], today=TODAY)
    assert len(projs) == 52


# ── Past dates are skipped; generation starts after today ─────────────────

def test_projections_start_after_today_not_after_last_service():
    # Last serviced 30 days ago: the 4 already-past weekly slots are
    # skipped, generation resumes with the first future slot.
    last = TODAY - timedelta(days=30)
    projs = cal_recurring_projections(
        [_cust(**{"Last Service Date": _dkey(last)})], today=TODAY)
    dates = [parse_job_date(p["date"]) for p in projs]
    assert all(d > TODAY for d in dates)
    assert dates[0] == last + timedelta(days=35)  # first slot after today
    # Horizon is anchored at TODAY (today+365d = last+395d): slots k=5..56.
    assert len(projs) == 52


def test_legacy_mmddyyyy_last_service_date_parses():
    projs = cal_recurring_projections(
        [_cust(**{"Last Service Date": "10/08/2026"})], today=TODAY)
    assert len(projs) == 52
    assert projs[0]["date"] == "2026-10-15"


def test_guard_caps_iterations_at_60():
    # Last serviced 300 days ago: without the guard, weekly slots k=43..95
    # would land in (today, horizon] (53 dates). The 60-iteration guard
    # stops the loop at k=60, so only k=43..60 are emitted: 18 dates.
    last = TODAY - timedelta(days=300)
    projs = cal_recurring_projections(
        [_cust(**{"Last Service Date": _dkey(last)})], today=TODAY)
    assert len(projs) == 18
    dates = [parse_job_date(p["date"]) for p in projs]
    assert dates[0] == last + timedelta(days=7 * 43)
    assert dates[-1] == last + timedelta(days=7 * 60)
    assert all(d > TODAY for d in dates)


# ── Projection identity ───────────────────────────────────────────────────

def test_projection_id_format():
    projs = cal_recurring_projections([_cust()], today=TODAY)
    assert projs[0]["id"] == "PROJ-CUST-2026-1-2026-10-15"
    assert projs[0]["customer"] == "Crabby's Daytona"
    assert projs[0]["custId"] == "CUST-2026-1"


def test_projection_id_falls_back_to_name_with_underscores():
    projs = cal_recurring_projections(
        [_cust(**{"CustomerID (CUST-####)": ""})], today=TODAY)
    assert projs[0]["id"] == "PROJ-Crabby's_Daytona-2026-10-15"


# ── Real-job suppression merge ────────────────────────────────────────────

def test_suppression_skips_date_with_real_job_for_same_customer():
    projs = cal_recurring_projections([_cust()], today=TODAY)
    target = projs[0]["date"]
    by_date = {target: [{"projected": False, "custId": "CUST-2026-1",
                         "customer": "Crabby's Daytona"}]}
    merged = merge_projections(by_date, projs)
    assert all(not j.get("projected") for j in merged[target])
    # The other 51 projections still land.
    assert sum(1 for jobs in merged.values()
               for j in jobs if j.get("projected")) == 51


def test_suppression_does_not_skip_different_customer_same_date():
    projs = cal_recurring_projections([_cust()], today=TODAY)
    target = projs[0]["date"]
    by_date = {target: [{"projected": False, "custId": "CUST-2026-9",
                         "customer": "Someone Else"}]}
    merged = merge_projections(by_date, projs)
    assert any(j.get("projected") for j in merged[target])


def test_suppression_matches_on_name_when_no_cust_id():
    projs = cal_recurring_projections(
        [_cust(**{"CustomerID (CUST-####)": ""})], today=TODAY)
    target = projs[0]["date"]
    by_date = {target: [{"projected": False, "custId": "",
                         "customer": "Crabby's Daytona"}]}
    merged = merge_projections(by_date, projs)
    assert all(not j.get("projected") for j in merged[target])


def test_merge_adds_dates_with_no_real_jobs():
    projs = cal_recurring_projections([_cust()], today=TODAY)
    merged = merge_projections({}, projs)
    assert len(merged) == 52


# ── The REAL JS agrees with this mirror (runs index.html's code in node) ──

def _PREF_DAY_HELPERS(src: str) -> list:
    """2026-10-21: _calRecurringProjections snaps each date to the customer's
    Preferred Day(s). These fixtures have no Preferred Day, so the snap is a
    no-op and the mirror below still matches 1:1."""
    return [_js_function(src, n) for n in
            ("_prefDaySet", "_snapToPreferredDay", "_custPreferredDaysText")]


def _js_function(src: str, name: str) -> str:
    start = src.index(f"function {name}(")
    i = src.index("{", start)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


@pytest.mark.parametrize("freq,last", [
    ("Weekly", "2026-10-08"), ("Biweekly", "2026-09-30"), ("Monthly", "2026-01-31"),
    ("Bi-Monthly", "2026-10-01"), ("Quarterly", "2026-08-31"), ("Semi-Annually", "2026-05-15"),
    ("Annually", "2026-02-28"), ("weird", "2026-10-01")])
def test_index_html_js_matches_the_mirror(freq, last):
    import json
    import pathlib
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "jobs" / "index.html").read_text(encoding="utf-8")
    cust = _cust(Frequency=freq, **{"Last Service Date": last})
    script = "\n".join([
        # freeze "today" at TODAY (local midnight) for the no-arg constructor
        "const _RD = Date; class FD extends _RD { constructor(...a) {"
        f" if (a.length) super(...a); else super({TODAY.year}, {TODAY.month - 1}, {TODAY.day}); }} }}"
        " FD.now = () => new FD().getTime(); globalThis.Date = FD;",
        _js_function(src, "parseJobDate"),
        _js_function(src, "_dkey"),
        *_PREF_DAY_HELPERS(src),
        _js_function(src, "_calRecurringProjections"),
        f"process.stdout.write(JSON.stringify(_calRecurringProjections([{json.dumps(cust)}])"
        ".map(p => p.date)));",
    ])
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    js_dates = json.loads(out.stdout)
    py_dates = [p["date"] for p in cal_recurring_projections([cust], today=TODAY)]
    assert js_dates == py_dates, (freq, js_dates[:5], py_dates[:5])


def test_index_html_js_knows_every_server_frequency_word():
    """Every word the server accepts for a period (R-057 _PERIOD_ALIASES,
    in a few spellings) projects in the JS exactly as the mirror says."""
    import json
    import pathlib
    import shutil
    import subprocess
    import db_write_ops
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    words = []
    for period, aliases in db_write_ops._PERIOD_ALIASES.items():
        for a in aliases:
            words += [a, a.upper()]
    words += ["Bi-Monthly", "Semi-Annually", "Every Other Week", "every 2 months", "Twice a Year"]
    custs = [_cust(Frequency=w, **{"CustomerID (CUST-####)": f"C{i}", "Last Service Date": "2026-09-30"})
             for i, w in enumerate(words)]
    src = (pathlib.Path(__file__).resolve().parents[2] / "jobs" / "index.html").read_text(encoding="utf-8")
    script = "\n".join([
        "const _RD = Date; class FD extends _RD { constructor(...a) {"
        f" if (a.length) super(...a); else super({TODAY.year}, {TODAY.month - 1}, {TODAY.day}); }} }}"
        " globalThis.Date = FD;",
        _js_function(src, "parseJobDate"), _js_function(src, "_dkey"),
        *_PREF_DAY_HELPERS(src),
        _js_function(src, "_calRecurringProjections"),
        f"process.stdout.write(JSON.stringify(_calRecurringProjections({json.dumps(custs)})"
        ".map(p => [p.custId, p.date])));",
    ])
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    js = sorted(map(tuple, json.loads(out.stdout)))
    py = sorted((p["custId"], p["date"]) for p in cal_recurring_projections(custs, today=TODAY))
    assert js == py
    # and only one-time words project nothing
    silent = {words[int(c[1:])] for c in {c["CustomerID (CUST-####)"] for c in custs} - {p[0] for p in js}}
    assert all(db_write_ops.frequency_period(w) == "onetime" for w in silent), silent
