"""
tests/gui/test_job_tracker_guide.py
====================================
v8.1.3: the Small Business tab previously undersold the Job Tracker
spreadsheet — no explanation of multi-employee scheduling, mobile crew
access, or the QuickBooks + Claude workflow. Added a dedicated explainer
popup (show_job_tracker_guide / get_job_tracker_guide_content) opened
from two buttons on that tab.

These are lightweight smoke tests — the content itself is prose, not
something to assert word-for-word — covering: the method exists and is
callable, the returned content mentions the facts it's supposed to convey,
and calling it actually opens a window.

Test IDs
--------
  JTG-01  get_job_tracker_guide_content() returns a non-trivial string
  JTG-02  content mentions all 9 real sheet names
  JTG-03  content covers multi-employee scheduling (Crew / Technician,
          server-mode auto-scoping)
  JTG-04  content covers mobile access
  JTG-05  content covers QuickBooks + Claude
  JTG-06  show_job_tracker_guide() opens a Toplevel without raising
"""
from __future__ import annotations

import os
import sys
import tkinter as tk
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def test_jtg01_content_is_non_trivial(gui):
    content = gui.app.get_job_tracker_guide_content()
    assert isinstance(content, str)
    assert len(content) > 1000, (
        f"JTG-01 FAIL: guide content suspiciously short ({len(content)} chars)"
    )


def test_jtg02_content_mentions_all_sheets(gui):
    content = gui.app.get_job_tracker_guide_content()
    expected_sheets = [
        "Customers", "Jobs_Schedule", "Route_Planner", "Quotes",
        "Invoices", "TimeLog", "QB_Daily_Export", "Services_Pricing",
        "AI-Prowler_Commands",
    ]
    missing = [s for s in expected_sheets if s not in content]
    assert not missing, f"JTG-02 FAIL: guide is missing sheet names: {missing}"


def test_jtg03_content_covers_multi_employee(gui):
    content = gui.app.get_job_tracker_guide_content()
    for phrase in ("Crew / Technician", "Server mode", "own jobs"):
        assert phrase in content, (
            f"JTG-03 FAIL: guide missing multi-employee coverage phrase: {phrase!r}"
        )


def test_jtg04_content_covers_mobile_access(gui):
    content = gui.app.get_job_tracker_guide_content()
    assert "Mobile" in content or "mobile" in content, (
        "JTG-04 FAIL: guide does not mention mobile access"
    )


def test_jtg05_content_covers_quickbooks(gui):
    content = gui.app.get_job_tracker_guide_content()
    assert "QuickBooks" in content, (
        "JTG-05 FAIL: guide does not mention QuickBooks"
    )


def test_jtg06_show_guide_opens_toplevel(gui):
    before = set(gui.app.root.winfo_children())
    try:
        gui.app.show_job_tracker_guide()
        gui.pump()
    except Exception as e:
        pytest.fail(f"JTG-06 FAIL: show_job_tracker_guide() raised: {e}")
    after = set(gui.app.root.winfo_children())
    new_windows = [w for w in (after - before) if isinstance(w, tk.Toplevel)]
    assert new_windows, "JTG-06 FAIL: show_job_tracker_guide() did not open a window"
    for w in new_windows:
        w.destroy()
