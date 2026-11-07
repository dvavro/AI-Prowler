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
 .sign div{{flex:1;border-top:1px solid #1d2433;padding-top:6px;font-size:12px;color:#5b6475}}
 @media print{{.page{{padding:0}}}}
</style></head><body><div class="page">
<header><div><h1>{_e(company.get('name') or 'Quote')}</h1><div class="muted">{comp_lines}</div></div>
<div><table class="meta"><tr><td><b>Quote</b></td><td>&nbsp;{_e(bid['number'])}</td></tr>
<tr><td><b>Date</b></td><td>&nbsp;{_e(bid['date'])}</td></tr>
<tr><td><b>Valid until</b></td><td>&nbsp;{_e(bid['valid_until'])}</td></tr></table></div></header>
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
    lines = [f"{company.get('name') or 'Quote'} — Quote {bid['number']}", f"Valid until {bid['valid_until']}", ""]
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


def write_pdf(html_path: Path, pdf_path: Path, timeout: int = 60) -> str | None:
    """Print the HTML to PDF with a headless browser. Returns None on success, or a reason it couldn't."""
    browser = find_browser()
    if not browser:
        return "no browser found to make the PDF (the HTML bid is ready)"
    cmd = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer", "--no-first-run",
           "--disable-background-networking", "--disable-component-update", "--disable-sync",
           f"--print-to-pdf={pdf_path}", Path(html_path).resolve().as_uri()]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"PDF step failed: {exc}"
    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        return "the browser didn't produce a PDF (the HTML bid is ready)"
    return None
