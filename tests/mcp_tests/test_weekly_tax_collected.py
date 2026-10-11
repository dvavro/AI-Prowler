"""
tests/mcp_tests/test_weekly_tax_collected.py
============================================
(2026-10-08) Weekly Tax Collected report math — jobs/index.html ~5087-5099.

The Reports loop computes, per job row with a linked invoice:

    _invTax       = (not tax_exempt and inv) ? (inv.tax || 0) : 0
    _taxCollected = _invTax * (inv.amountPaid / inv.totalDue)   # totalDue > 0
    _taxProj      = max(0, _invTax - _taxCollected)
    # totalDue <= 0  ->  _taxProj = _invTax  (no division by zero)
    # tax-exempt (No Sales Tax) or no invoice -> both stay 0

The logic lives in the PWA's JS (not importable from Python), so this file
mirrors it 1:1 as pure functions and pins the math — including the
no-sales-tax exemption gate (_noSalesTaxIsSet, index.html ~5650) and the
zero-totalDue guard.

Run: run_tests.bat tests\\mcp_tests\\test_weekly_tax_collected.py -v
"""
import re

import pytest


# ── Python mirrors of the JS ──────────────────────────────────────────────

def _no_sales_tax_is_set(v):
    """Mirror of _noSalesTaxIsSet (jobs/index.html ~5650):
    /^(1(\\.0+)?|true|yes)$/i on the trimmed value."""
    s = "" if v is None else str(v).strip()
    return bool(re.match(r"^(1(\.0+)?|true|yes)$", s, re.IGNORECASE))


def tax_split(inv_tax, amount_paid, total_due, tax_exempt):
    """Mirror of jobs/index.html lines 5091-5099.

    Returns (tax_collected, tax_projected).
    None inputs are treated as 0 (the invoice rows the report reads always
    carry numeric tax/amountPaid/totalDue; JS would produce NaN for a
    missing amountPaid, which the report never feeds it).
    """
    tax = 0 if tax_exempt else (inv_tax or 0)
    paid = amount_paid or 0
    collected, projected = 0.0, 0.0
    if tax > 0:
        if total_due and total_due > 0:
            collected = tax * (paid / total_due)
            projected = max(0.0, tax - collected)
        else:
            # Zero/empty totalDue: guard against division by zero —
            # all of the tax is still outstanding.
            projected = tax
    return collected, projected


def tax_split_for_row(inv, no_sales_tax_value):
    """One step closer to the report loop: inv is a dict with
    tax/amountPaid/totalDue, or None when the job has no invoice yet."""
    tax_exempt = _no_sales_tax_is_set(no_sales_tax_value)
    if inv is None:
        return 0.0, 0.0
    return tax_split(inv.get("tax"), inv.get("amountPaid"),
                     inv.get("totalDue"), tax_exempt)


# ── Fully paid → all collected ────────────────────────────────────────────

def test_fully_paid_invoice_collects_all_tax():
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 108.50, "totalDue": 108.50}, None)
    assert collected == pytest.approx(8.50)
    assert projected == pytest.approx(0.0)


def test_fully_paid_round_tax():
    collected, projected = tax_split_for_row(
        {"tax": 21.00, "amountPaid": 321.00, "totalDue": 321.00}, "")
    assert collected == pytest.approx(21.00)
    assert projected == pytest.approx(0.0)


# ── Unpaid → nothing collected, all projected ─────────────────────────────

def test_unpaid_invoice_collects_nothing_projects_all():
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 0.0, "totalDue": 108.50}, None)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(8.50)


# ── Partial payment → proportional split ──────────────────────────────────

def test_half_paid_splits_tax_evenly():
    collected, projected = tax_split_for_row(
        {"tax": 10.00, "amountPaid": 50.00, "totalDue": 100.00}, None)
    assert collected == pytest.approx(5.00)
    assert projected == pytest.approx(5.00)


def test_quarter_paid_collects_quarter_of_tax():
    collected, projected = tax_split_for_row(
        {"tax": 12.00, "amountPaid": 30.00, "totalDue": 120.00}, None)
    assert collected == pytest.approx(3.00)
    assert projected == pytest.approx(9.00)


def test_collected_plus_projected_equals_invoice_tax():
    # The two buckets always partition the invoice's tax line.
    for paid in (0, 17.33, 55.10, 99.99, 120.00):
        collected, projected = tax_split_for_row(
            {"tax": 7.25, "amountPaid": paid, "totalDue": 120.00}, None)
        assert collected + projected == pytest.approx(7.25)


# ── No Sales Tax exemption → $0 / $0 ──────────────────────────────────────

@pytest.mark.parametrize("flag", ["1", "1.0", "true", "TRUE", "yes", "Yes"])
def test_tax_exempt_job_reports_zero_collected_and_zero_projected(flag):
    # Even a fully-paid invoice contributes no tax when the job is exempt.
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 108.50, "totalDue": 108.50}, flag)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(0.0)


@pytest.mark.parametrize("flag", [None, "", "0", "false", "no", "  "])
def test_non_exempt_flags_still_collect(flag):
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 108.50, "totalDue": 108.50}, flag)
    assert collected == pytest.approx(8.50)
    assert projected == pytest.approx(0.0)


# ── No invoice → $0 / $0 ──────────────────────────────────────────────────

def test_job_with_no_invoice_reports_zero_zero():
    collected, projected = tax_split_for_row(None, None)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(0.0)


# ── Zero totalDue → all projected, no division by zero ────────────────────

def test_zero_total_due_projects_all_tax_without_dividing():
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 0.0, "totalDue": 0.0}, None)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(8.50)


def test_missing_total_due_projects_all_tax():
    collected, projected = tax_split_for_row(
        {"tax": 8.50, "amountPaid": 10.0, "totalDue": None}, None)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(8.50)


# ── Zero-tax invoice → $0 / $0 ────────────────────────────────────────────

def test_zero_tax_invoice_reports_zero_zero():
    collected, projected = tax_split_for_row(
        {"tax": 0.0, "amountPaid": 100.0, "totalDue": 100.0}, None)
    assert collected == pytest.approx(0.0)
    assert projected == pytest.approx(0.0)


# ── Overpayment documents the JS behavior (no cap in the report loop) ────

def test_overpaid_invoice_documents_uncapped_collected():
    # JS does NOT cap collected at the invoice tax: paid/totalDue > 1
    # yields collected > tax, and projected floors at 0 via Math.max.
    collected, projected = tax_split_for_row(
        {"tax": 10.00, "amountPaid": 150.00, "totalDue": 100.00}, None)
    assert collected == pytest.approx(15.00)
    assert projected == pytest.approx(0.0)
