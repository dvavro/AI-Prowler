"""Render a bid as HTML (and PDF where a browser is available).

The customer sees descriptions, quantities and line prices (markups included),
never internal costs or margins. PDF is made by printing the HTML with the
browser Windows 11 already has (Microsoft Edge), or Chrome/Chromium elsewhere,
so nothing extra has to be installed. If no browser is found, the bid is still
complete as HTML.
"""
from __future__ import annotations

import html
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from estimator.core.units.money import format_cents

BROWSER_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
)
BROWSER_NAMES = ("msedge", "chrome", "chromium", "chromium-browser", "google-chrome")


def find_browser() -> str | None:
    override = os.environ.get("ESTIMATOR_PDF_BROWSER", "").strip()
    if override:
        return override if override.lower() != "none" else None
    for p in BROWSER_CANDIDATES:
        if Path(p).exists():
            return p
    for n in BROWSER_NAMES:
        found = shutil.which(n)
        if found:
            return found
    return None


def _e(text) -> str:
    return html.escape("" if text is None else str(text))


def _paras(text: str | None) -> str:
    if not text:
        return ""
    items = [ln.strip("-• ").strip() for ln in str(text).splitlines() if ln.strip()]
    if len(items) > 1:
        return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"
    return f"<p>{_e(items[0]) if items else ''}</p>"


def _subtotal(sec: dict) -> int:
    return sec.get("subtotal_cents", sum(ln["price_cents"] for ln in sec["lines"]))


def _options_html(snap: dict) -> str:
    opts = snap.get("options") or []
    if not opts:
        return ""
    rows = "".join(f'<tr><td>{_e(o["label"])}{" <b>(quoted above)</b>" if o.get("chosen") else ""}</td>'
                   f'<td class="m">{format_cents(o["total_cents"])}</td></tr>' for o in opts)
    return ('<h2>Options</h2><p class="muted">Total job price with each option. Tell us which you prefer.</p>'
            f'<table>{rows}</table>')


def _change_word(c: dict) -> str:
    if c["change"] == "added":
        return f"added ({format_cents(c['to_cents'])})"
    if c["change"] == "removed":
        return f"removed (was {format_cents(c['from_cents'])})"
    return f"{format_cents(c['from_cents'])} → {format_cents(c['to_cents'])}"


def notice_lines(snap: dict) -> tuple[str, list[str]]:
    """What the customer is told first on an updated quote or a change order (2026-11-16, David): the headline and
    the lines under it. ("", []) for an ordinary quote."""
    rep, co = snap.get("replaces"), snap.get("change_order")
    if co:
        head = (f"Change order {co['n']} to your accepted quote {co['of_number']} ({format_cents(co['of_total_cents'])})."
                " This price is in addition to that quote")
        head += (f"; with it the job comes to {format_cents(co['job_total_cents'])}." if co.get("job_total_cents")
                 else ".")
        return head, ([co["summary"]] if co.get("summary") else [])
    if rep:
        head = (f"Updated quote: this replaces quote {rep['number']}" + (f" sent on {rep['sent_on']}" if rep.get("sent_on")
                                                                         else "")
                + f" ({format_cents(rep['total_cents'])}).")
        what = [f"{c['title']}: {c['description']} {_change_word(c)}" for c in rep.get("changes") or []]
        if rep["total_cents"] != snap["totals"]["total_cents"]:
            what.append(f"Total: {format_cents(rep['total_cents'])} → {format_cents(snap['totals']['total_cents'])}")
        return head, what
    return "", []


def _notice_html(snap: dict) -> str:
    head, what = notice_lines(snap)
    if not head:
        return ""
    items = "".join(f"<li>{_e(w)}</li>" for w in what)
    label = "What changed" if snap.get("replaces") else ""
    return (f'<div class="notice"><b>{_e(head)}</b>'
            + (f'<div class="muted">{label}</div>' if label and items else "")
            + (f"<ul>{items}</ul>" if items else "") + "</div>")


def bid_html(bid: dict, company: dict, customer: dict) -> str:
    snap = bid["snapshot"]
    rows = []
    by_trade = snap.get("price_detail") == "trade_totals"
    for sec in snap["sections"]:
        if by_trade:
            scope = "".join(f"<li>{_e(ln['description'])} ({_e(ln['quantity'])} {_e(ln['unit'])})</li>"
                            for ln in sec["lines"])
            rows.append(f'<tr><td><b>{_e(sec["title"])}</b><ul class="scope">{scope}</ul></td><td></td>'
                        f'<td class="m">{format_cents(_subtotal(sec))}</td></tr>')
            continue
        if len(snap["sections"]) > 1:
            rows.append(f'<tr class="sec"><td colspan="2">{_e(sec["title"])}</td>'
                        f'<td class="m">{format_cents(_subtotal(sec))}</td></tr>')
        for ln in sec["lines"]:
            rows.append(f'<tr><td>{_e(ln["description"])}</td><td class="q">{_e(ln["quantity"])} {_e(ln["unit"])}</td>'
                        f'<td class="m">{format_cents(ln["price_cents"])}</td></tr>')
    adj = snap["totals"].get("adjustment_cents", 0)
    if adj:
        rows.append(f'<tr><td>Minimum charge / rounding</td><td></td><td class="m">{format_cents(adj)}</td></tr>')
    tax = snap["totals"].get("tax_cents", 0)
    tax_row = f'<tr><td colspan="2">Sales tax</td><td class="m">{format_cents(tax)}</td></tr>' if tax else ""
    cust_lines = "<br>".join(_e(x) for x in (customer.get("name"), customer.get("address"), customer.get("email"),
                                              customer.get("phone")) if x)
    comp_lines = "<br>".join(_e(x) for x in (company.get("address"), company.get("phone"),
                                              f"License {company['license_no']}" if company.get("license_no") else None)
                             if x)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{_e(company.get('name') or 'Quote')} — {_e(bid['number'])}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;color:#1d2433;margin:0;background:#fff}}
 .page{{max-width:760px;margin:0 auto;padding:40px 32px}}
 header{{display:flex;justify-content:space-between;gap:24px;border-bottom:3px solid #1f5fa8;padding-bottom:16px}}
 h1{{margin:0;font-size:24px;color:#1f5fa8}} .muted{{color:#5b6475;font-size:13px;line-height:1.5}}
 h2{{font-size:15px;text-transform:uppercase;letter-spacing:.04em;color:#1f5fa8;margin:28px 0 8px}}
 table{{width:100%;border-collapse:collapse;font-size:14px}} td{{padding:8px 6px;border-bottom:1px solid #e3e7ee;vertical-align:top}}
 td.q{{white-space:nowrap;color:#5b6475;width:140px}} td.m{{text-align:right;white-space:nowrap;width:120px}}
 tr.sec td{{font-weight:600;background:#f3f6fa}} tr.total td{{font-weight:700;font-size:17px;border-top:2px solid #1d2433;border-bottom:none}}
 .meta td{{border:none;padding:2px 0;font-size:13px;white-space:nowrap}} .sign{{margin-top:36px;display:flex;gap:32px}}
 ul.scope{{margin:4px 0 0;padding-left:18px;color:#5b6475;font-size:13px}}
 .notice{{margin:20px 0 0;padding:12px 14px;border:1px solid #f0c36d;background:#fff8e6;border-radius:6px;font-size:14px}}
 .notice ul{{margin:6px 0 0;padding-left:18px}}
 .sign div{{flex:1;border-top:1px solid #1d2433;padding-top:6px;font-size:12px;color:#5b6475}}
 @media print{{.page{{padding:0}}}}
</style></head><body><div class="page">
<header><div><h1>{_e(company.get('name') or 'Quote')}</h1><div class="muted">{comp_lines}</div></div>
<div><table class="meta"><tr><td><b>{'Change order' if snap.get('change_order') else 'Quote'}</b></td><td>&nbsp;{_e(bid['number'])}</td></tr>
<tr><td><b>Date</b></td><td>&nbsp;{_e(bid['date'])}</td></tr>
<tr><td><b>Valid until</b></td><td>&nbsp;{_e(bid['valid_until'])}</td></tr></table></div></header>
{_notice_html(snap)}
<h2>Prepared for</h2><div class="muted">{cust_lines or '&nbsp;'}</div>
<h2>Scope of work</h2>{_paras(bid.get('scope_text'))}
<h2>Price</h2>
<table>{''.join(rows)}{tax_row}<tr class="total"><td colspan="2">Total</td><td class="m">{format_cents(snap['totals']['total_cents'])}</td></tr></table>
{_options_html(snap)}
{('<h2>Included</h2>' + _paras(bid.get('inclusions'))) if bid.get('inclusions') else ''}
{('<h2>Not included</h2>' + _paras(bid.get('exclusions'))) if bid.get('exclusions') else ''}
<h2>Terms</h2>{_paras(bid.get('terms'))}
<div class="sign"><div>Accepted by (customer)</div><div>Date</div></div>
</div></body></html>"""


def bid_text(bid: dict, company: dict, customer: dict) -> str:
    snap = bid["snapshot"]
    kind = "Change order" if snap.get("change_order") else "Quote"
    lines = [f"{company.get('name') or 'Quote'} — {kind} {bid['number']}", f"Valid until {bid['valid_until']}", ""]
    head, what = notice_lines(snap)
    if head:
        lines += [head] + ([("What changed:" if snap.get("replaces") else "")] if what and snap.get("replaces") else []) \
            + [f"- {w}" for w in what] + [""]
    if customer.get("name"):
        lines.append(f"Prepared for: {customer['name']}")
    lines.append("")
    by_trade = snap.get("price_detail") == "trade_totals"
    for sec in snap["sections"]:
        if by_trade or len(snap["sections"]) > 1:
            lines.append(f"{sec['title']}: {format_cents(_subtotal(sec))}")
        for ln in sec["lines"]:
            if by_trade:
                lines.append(f"  - {ln['description']} ({ln['quantity']} {ln['unit']})")
            else:
                lines.append(f"- {ln['description']}: {ln['quantity']} {ln['unit']} — {format_cents(ln['price_cents'])}")
    if snap["totals"].get("adjustment_cents"):
        lines.append(f"- Minimum charge / rounding — {format_cents(snap['totals']['adjustment_cents'])}")
    if snap["totals"].get("tax_cents"):
        lines.append(f"Sales tax: {format_cents(snap['totals']['tax_cents'])}")
    lines.append(f"TOTAL: {format_cents(snap['totals']['total_cents'])}")
    if snap.get("options"):
        lines += ["", "Options (total job price):"] + [
            f"- {o['label']}: {format_cents(o['total_cents'])}" + (" (quoted above)" if o.get("chosen") else "")
            for o in snap["options"]]
    lines += ["", bid.get("terms") or ""]
    return "\n".join(lines).strip() + "\n"


def _wait_for_pdf(pdf_path: Path, wait: float) -> bool:
    """Wait up to `wait` seconds for the PDF to appear and stop growing.

    The browser's launcher process can exit before the print lands: Edge hands the
    print to a detached process that writes the PDF ~0.5s after the waited-on process
    exits (2026-11-19: launcher 0.04s, PDF at 0.44-0.54s, profile released at ~1s),
    so checking once right after subprocess.run returns sees no file. A size that
    holds across two checks means the write finished.
    """
    deadline = time.monotonic() + wait
    last_size = -1
    while True:
        try:
            size = pdf_path.stat().st_size
        except OSError:
            size = 0
        if size > 0 and size == last_size:
            return True
        last_size = size
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def write_pdf(html_path: Path, pdf_path: Path, timeout: int = 60, settle: float = 10.0) -> str | None:
    """Print the HTML to PDF with a headless browser. Returns None on success, or a reason it couldn't.

    `settle` is how long to wait after each browser attempt for the PDF to land (see _wait_for_pdf);
    10s is ~20x the ~0.5s a detached Edge print takes, with room for a loaded machine.
    """
    browser = find_browser()
    if not browser:
        return "no browser found to make the PDF (the HTML bid is ready)"
    base = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer", "--no-first-run",
            "--disable-background-networking", "--disable-component-update", "--disable-sync"]
    target = [f"--print-to-pdf={pdf_path}", Path(html_path).resolve().as_uri()]
    try:
        subprocess.run(base + target, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"PDF step failed: {exc}"
    if _wait_for_pdf(pdf_path, settle):
        return None
    # A second try with a throwaway profile: a headless Edge can hand the job to an Edge window that's already open
    # and quit without printing (always when one runs as administrator and the other doesn't).
    # ignore_cleanup_errors: the detached print process can still hold files in the profile (Crashpad) when the
    # block exits, and a leftover dir in %TEMP% is harmless — the cleanup must never fail the bid.
    with tempfile.TemporaryDirectory(prefix="estimator_pdf_", ignore_cleanup_errors=True) as profile:
        try:
            subprocess.run(base + ["--no-default-browser-check", f"--user-data-dir={profile}"] + target,
                           capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"PDF step failed: {exc}"
        if _wait_for_pdf(pdf_path, settle):
            return None
    return "the browser didn't produce a PDF (the HTML bid is ready)"
