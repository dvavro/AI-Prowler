"""Helpers for the Estimator browser tests (see conftest.py in this folder)."""
import os

HUMAN = os.environ.get("ESTIMATOR_BROWSER_HUMAN") == "1"


def type_in(page, selector, text):
    """Fill a field; in --human mode key by key, like a person."""
    if HUMAN:
        page.click(selector)
        page.fill(selector, "")
        page.type(selector, text, delay=60)
    else:
        page.fill(selector, text)


def answer_yes(page, prefix):
    """Click the Yes of an ask-first question (ids <prefix>-confirm or <prefix>-yes)."""
    sel = f"#{prefix}-confirm, #{prefix}-yes"
    page.wait_for_selector(sel)
    page.click(sel)
