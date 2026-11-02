"""booking_slots — the availability engine (booking-spec.md §5, test plan §13.1).

Fixed clock: Monday 2 Nov 2026, 06:00. Default rules: Mon–Fri 07:00–17:00, lunch
12:00–13:00 (the Jobs app's rule: not a stop — work across it takes that much longer),
2-hour arrival windows, 24 h lead time, 21-day horizon. Service: 60 min + 15 buffer."""
import datetime as dt
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_slots as bs  # noqa: E402

NOW = dt.datetime(2026, 11, 2, 6, 0)          # Monday
TUE, WED, SAT = dt.date(2026, 11, 3), dt.date(2026, 11, 4), dt.date(2026, 11, 7)
SVC = bs.Service("WIN", minutes=60, people=1, buffer_min=15)
R = bs.Rules()
M = bs.hhmm


def wins(svc=SVC, rules=R, day=TUE, now=NOW, **kw):
    return [(w.date, bs.fmt(w.start), bs.fmt(w.end)) for w in
            bs.open_windows(svc, rules=rules, now=now, from_date=day, to_date=day, **kw)]


def starts(**kw):
    return [s for _, s, _ in wins(**kw)]


ALL = ["07:00", "09:00", "11:00", "13:00", "15:00"]


def test_an_empty_working_day_offers_every_window():
    assert starts() == ALL
    w = bs.open_windows(SVC, rules=R, now=NOW, from_date=TUE, to_date=TUE)[0]
    assert w.key == "2026-11-03T07:00-09:00" and w.label() == "Tue 03 Nov, 7–9" and w.crew == "owner"


def test_lunch_is_not_a_wall_but_makes_work_across_it_longer():
    assert "11:00" in starts()                                   # 11:00 start, runs over lunch, ends 13:15
    long = bs.Service("BIG", minutes=300, buffer_min=15)         # 5 h 15 m
    assert starts(svc=long) == ["07:00", "09:00"]                # 9:00 + 315 + 60 lunch = 15:15 ✓; 11:00 → 17:15 ✗
    no_lunch = bs.Rules(lunch_start=None, lunch_minutes=0)
    assert starts(svc=long, rules=no_lunch) == ["07:00", "09:00", "11:00"]


def test_weekends_closed_unless_an_extra_opening_and_closed_days_remove_time():
    assert wins(day=SAT) == []
    opening = [bs.Opening(SAT, "open", M("08:00"), M("12:00"))]
    assert starts(day=SAT, openings=opening) == ["08:00", "10:00"]
    holiday = [bs.Opening(TUE, "closed")]
    assert wins(openings=holiday) == []
    afternoon_off = [bs.Opening(TUE, "closed", M("13:00"), M("17:00"))]
    # 11:00 start would run to 12:15 + lunch = 13:15, past the 13:00 close → not offered
    assert starts(openings=afternoon_off) == ["07:00", "09:00"]


def test_hard_jobs_holds_and_busy_blocks_block_their_own_time():
    hard = [bs.Booked(TUE, 120, start=M("09:00"))]               # 9–11 committed
    assert starts(booked=hard) == ["07:00", "11:00", "13:00", "15:00"]
    hold = [bs.Booked(TUE, 120, start=M("07:00"), kind="hold")]   # holds the 7–9 window fully
    assert starts(booked=hold)[0] == "09:00"
    short_hold = [bs.Booked(TUE, 75, start=M("07:00"), kind="hold")]
    assert starts(booked=short_hold)[0] == "07:00"               # two quick jobs fit one window (8:15 start)
    busy = [bs.Booked(TUE, 240, start=M("13:00"), end=M("17:00"), kind="busy")]
    assert starts(booked=busy) == ["07:00", "09:00"]             # 11:00 → 13:15 runs into the busy block


def test_soft_jobs_use_up_the_day_and_a_full_day_shows_nothing():
    # capacity 540 min (10 h minus lunch); 85 % full = 459 min used
    assert starts(booked=[bs.Booked(TUE, 420)]) == ALL           # 78 % used
    assert wins(booked=[bs.Booked(TUE, 470)]) == []              # 87 % used
    assert wins(rules=bs.Rules(full_pct=100), booked=[bs.Booked(TUE, 470)]) == []   # 70 min left < 75 needed
    assert starts(rules=bs.Rules(full_pct=100), booked=[bs.Booked(TUE, 460)]) == ALL


def test_lead_time_and_horizon():
    tue_8am = dt.datetime(2026, 11, 3, 8, 0)
    assert wins(day=TUE, now=tue_8am) == []                      # nothing within 24 h
    assert starts(day=WED, now=tue_8am) == ["09:00", "11:00", "13:00", "15:00"]   # Wed 07:00 is too soon
    assert starts(day=WED, now=tue_8am, rules=bs.Rules(lead_hours=1.5)) == ALL
    short = bs.Rules(horizon_days=2)
    out = bs.open_windows(SVC, rules=short, now=NOW)
    assert {w.date for w in out} == {TUE, WED}                   # Mon (too soon), Tue, Wed only


def test_max_online_bookings_per_day():
    one = [bs.Booked(TUE, 60, online=True)]
    assert wins(rules=bs.Rules(max_per_day=1), booked=one) == []
    assert starts(rules=bs.Rules(max_per_day=2), booked=one) == ALL
    assert starts(rules=bs.Rules(max_per_day=1), booked=[bs.Booked(TUE, 60, online=False)]) == ALL


def test_crews_fairness_and_people_needed():
    crews = [bs.Crew("ann"), bs.Crew("bob")]
    busy_ann = [bs.Booked(TUE, 600, start=M("07:00"), end=M("17:00"), crew="ann")]
    out = bs.open_windows(SVC, rules=R, now=NOW, crews=crews, booked=busy_ann, from_date=TUE, to_date=TUE)
    assert [bs.fmt(w.start) for w in out] == ALL and {w.crew for w in out} == {"bob"}
    soft_ann = [bs.Booked(TUE, 120, crew="ann")]
    out = bs.open_windows(SVC, rules=R, now=NOW, crews=crews, booked=soft_ann, from_date=TUE, to_date=TUE)
    assert {w.crew for w in out} == {"bob"}                      # the crew with the most free time
    unassigned = [bs.Booked(TUE, 400)]                           # shared across both crews (200 each)
    out = bs.open_windows(SVC, rules=R, now=NOW, crews=crews, booked=unassigned, from_date=TUE, to_date=TUE)
    assert len(out) == 5 and out[0].free_minutes == 540 - 200
    two = bs.Service("BIG2", minutes=60, people=2)
    assert wins(svc=two, crews=crews) == []
    assert starts(svc=two, crews=[bs.Crew("team", size=2)]) == ALL


def test_daylight_saving_dates_are_ordinary_days():
    fall_back = dt.date(2026, 11, 1)                             # US DST ends (a Sunday)
    opening = [bs.Opening(fall_back, "open", M("08:00"), M("12:00"))]
    out = bs.open_windows(SVC, rules=bs.Rules(lead_hours=0), now=dt.datetime(2026, 10, 31, 6, 0),
                          openings=opening, from_date=fall_back, to_date=fall_back)
    assert [bs.fmt(w.start) for w in out] == ["08:00", "10:00"]


def test_a_service_longer_than_the_day_is_never_offered():
    assert wins(svc=bs.Service("DAY", minutes=600, buffer_min=0)) == []


@pytest.mark.parametrize("text,mins", [("07:00", 420), ("7:00", 420), ("07:00:00", 420), ("7:00 AM", 420),
                                       ("7am", 420), ("12:30 PM", 750), ("12:00 AM", 0), ("17:00", 1020),
                                       ("", None), ("noon", None), ("25:00", None), ("13 PM", None)])
def test_hhmm(text, mins):
    assert bs.hhmm(text) == mins


def test_job_minutes_and_labels():
    assert bs.job_minutes(2, "hours", R) == 120 and bs.job_minutes(45, "min", R) == 45
    assert bs.job_minutes(1, "day", R) == 540 and bs.job_minutes(None, "", R) == 60
    assert bs.job_minutes(1.5, "", R) == 90 and bs.job_minutes(90, "", R) == 90
    assert bs.nice(13 * 60) == "1" and bs.nice(10 * 60 + 30) == "10:30" and bs.fmt(65) == "01:05"


def test_service_area():
    assert bs.in_service_area("32168")[0] is True                              # nothing set up
    assert bs.in_service_area("32168-1234", zips=["32168", "32169"])[0] is True
    assert bs.in_service_area("90210", zips=["32168"]) == (False, "ZIP 90210 isn't in the service area")
    origin = (29.0258, -80.9270)                                               # New Smyrna Beach
    ok, why = bs.in_service_area("", 29.2108, -81.0228, miles=20, origin=origin)   # Daytona ≈ 14 mi
    assert ok and "miles away" in why
    ok, why = bs.in_service_area("", 28.5384, -81.3789, miles=20, origin=origin)   # Orlando ≈ 45 mi
    assert not ok and "outside the 20-mile area" in why
    assert bs.in_service_area("32168", miles=20, origin=origin) == (False, "couldn't check the distance to that address")
    assert bs.in_service_area("32168", zips=["32168"], miles=5, origin=origin)[0] is True   # either rule counts
