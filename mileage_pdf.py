"""
mileage_pdf.py — dependency-free PDF output for the mileage tracker.

Two documents (spec FR-17 / FR-23):
  * render_log_pdf()        — the IRS mileage log for a date range: summary
                              (deduction by rate period, parking/tolls, crew
                              reimbursement, Form 4562 per-vehicle sheet,
                              record checks) followed by one row per trip.
  * render_statement_pdf()  — a crew reimbursement statement for one pay
                              period: trips, miles, rate, total, status.

Written against the PDF 1.4 spec directly with the 14 standard fonts
(Helvetica / Helvetica-Bold, WinAnsiEncoding), so nothing new has to be
installed or bundled — no reportlab. Text is encoded cp1252, which covers
the characters the log uses (¢ – — … •); anything else becomes '?'.
"""

from __future__ import annotations

import datetime as _dt
import zlib

# Helvetica advance widths (1/1000 em) for ASCII 32..126, from the standard AFM.
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
         1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
         333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
         556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]


def text_width(s: str, size: float, bold: bool = False) -> float:
    w = 0
    for ch in s:
        o = ord(ch)
        w += _HELV[o - 32] if 32 <= o <= 126 else 556
    return w * size / 1000.0 * (1.06 if bold else 1.0)


def fit(s: str, width: float, size: float, bold: bool = False) -> str:
    """Truncate s with an ellipsis so it fits in width points."""
    s = "" if s is None else str(s)
    if text_width(s, size, bold) <= width:
        return s
    ell = "…"
    while s and text_width(s + ell, size, bold) > width:
        s = s[:-1]
    return (s.rstrip() + ell) if s else ""


def _esc(s: str) -> bytes:
    b = str(s).encode("cp1252", errors="replace")
    return b.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


class SimplePDF:
    """Minimal page-based PDF writer: text, lines, filled rectangles."""

    def __init__(self, width: float = 612, height: float = 792, title: str = ""):
        self.w, self.h = width, height
        self.title = title
        self.pages: list[list[bytes]] = []
        self.new_page()

    # ── drawing ────────────────────────────────────────────────────────
    def new_page(self):
        self.pages.append([])

    def _op(self, b: bytes):
        self.pages[-1].append(b)

    def text(self, x: float, y: float, s: str, size: float = 9, bold: bool = False,
             align: str = "left", color=(0, 0, 0)):
        """y is measured from the TOP of the page (easier layout maths)."""
        if s is None or s == "":
            return
        s = str(s)
        if align == "right":
            x -= text_width(s, size, bold)
        elif align == "center":
            x -= text_width(s, size, bold) / 2
        r, g, b = color
        self._op(b"BT %.3f %.3f %.3f rg /%s %.1f Tf %.2f %.2f Td (" % (
            r, g, b, b"F2" if bold else b"F1", size, x, self.h - y) + _esc(s) + b") Tj ET")

    def line(self, x1, y1, x2, y2, width: float = 0.5, gray: float = 0.6):
        self._op(b"%.2f G %.2f w %.2f %.2f m %.2f %.2f l S" % (
            gray, width, x1, self.h - y1, x2, self.h - y2))

    def rect(self, x, y, w, h, gray: float = 0.92):
        self._op(b"%.3f g %.2f %.2f %.2f %.2f re f 0 g" % (gray, x, self.h - y - h, w, h))

    # ── output ─────────────────────────────────────────────────────────
    def build(self) -> bytes:
        objs: list[bytes] = []

        def add(b: bytes) -> int:
            objs.append(b)
            return len(objs)

        cat_id = add(b"")            # placeholder, filled below
        pages_id = add(b"")
        f1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        f2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        n = len(self.pages)
        for i, ops in enumerate(self.pages, start=1):
            foot = (b"BT 0.45 0.45 0.45 rg /F1 7 Tf %.2f 18 Td (" % (self.w - 90)
                    + _esc(f"Page {i} of {n}") + b") Tj ET")
            raw = b"\n".join(ops + [foot])
            data = zlib.compress(raw)
            cid = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            pid = add(b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.0f %.0f] "
                      b"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>"
                      % (pages_id, self.w, self.h, f1, f2, cid))
            kids.append(pid)
        objs[pages_id - 1] = (b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k for k in kids)
                              + b"] /Count %d >>" % len(kids))
        objs[cat_id - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages_id
        stamp = _dt.datetime.now().strftime("D:%Y%m%d%H%M%S")
        info = add(b"<< /Title (" + _esc(self.title) + b") /Producer (AI-Prowler mileage tracker) "
                   b"/CreationDate (" + stamp.encode() + b") >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objs) + 1, cat_id, info, xref))
        return bytes(out)


class _Flow:
    """Top-to-bottom layout helper with automatic page breaks."""

    def __init__(self, pdf: SimplePDF, margin: float = 36, header: str = ""):
        self.pdf, self.m, self.header = pdf, margin, header
        self.y = margin
        self._draw_running_header()

    def _draw_running_header(self):
        if self.header:
            self.pdf.text(self.m, self.m - 12, self.header, 7, color=(0.45, 0.45, 0.45))

    def need(self, h: float):
        if self.y + h > self.pdf.h - 40:
            self.pdf.new_page()
            self.y = self.m
            self._draw_running_header()
            return True
        return False

    def gap(self, h: float = 6):
        self.y += h

    def heading(self, s: str, size: float = 11):
        self.need(size + 18)
        self.gap(4)
        self.pdf.text(self.m, self.y + size, s, size, bold=True)
        self.y += size + 6

    def para(self, s: str, size: float = 8.5, color=(0.15, 0.15, 0.15)):
        width = self.pdf.w - 2 * self.m
        words, line = str(s).split(), ""
        for w in words:
            cand = (line + " " + w).strip()
            if text_width(cand, size) > width and line:
                self.need(size + 3)
                self.pdf.text(self.m, self.y + size, line, size, color=color)
                self.y += size + 3
                line = w
            else:
                line = cand
        if line:
            self.need(size + 3)
            self.pdf.text(self.m, self.y + size, line, size, color=color)
            self.y += size + 3

    def table(self, cols, rows, size: float = 7.5, total_row=None):
        """cols: [(header, width_pts, 'l'|'r')]; rows: list of lists of str."""
        rh = size + 5
        x0 = self.m

        def head():
            self.pdf.rect(x0, self.y, sum(c[1] for c in cols), rh, gray=0.88)
            x = x0
            for name, w, al in cols:
                if al == "r":
                    self.pdf.text(x + w - 3, self.y + size + 1, fit(name, w - 6, size, True), size, True, "right")
                else:
                    self.pdf.text(x + 3, self.y + size + 1, fit(name, w - 6, size, True), size, True)
                x += w
            self.y += rh

        self.need(rh * 2)
        head()
        for i, row in enumerate(rows):
            if self.need(rh):
                head()
            if i % 2:
                self.pdf.rect(x0, self.y, sum(c[1] for c in cols), rh, gray=0.965)
            x = x0
            for (name, w, al), val in zip(cols, row):
                s = fit("" if val is None else str(val), w - 6, size)
                if al == "r":
                    self.pdf.text(x + w - 3, self.y + size + 1, s, size, align="right")
                else:
                    self.pdf.text(x + 3, self.y + size + 1, s, size)
                x += w
            self.y += rh
        if total_row:
            self.need(rh)
            self.pdf.line(x0, self.y, x0 + sum(c[1] for c in cols), self.y, 0.8, 0.3)
            x = x0
            for (name, w, al), val in zip(cols, total_row):
                s = fit("" if val is None else str(val), w - 6, size, True)
                if al == "r":
                    self.pdf.text(x + w - 3, self.y + size + 1, s, size, True, "right")
                else:
                    self.pdf.text(x + 3, self.y + size + 1, s, size, True)
                x += w
            self.y += rh
        self.gap(6)


def _money(v) -> str:
    try:
        return f"${float(v):,.2f}"
    except (TypeError, ValueError):
        return ""


def _mi(v) -> str:
    try:
        return f"{float(v):,.1f}"
    except (TypeError, ValueError):
        return ""


def render_log_pdf(rep: dict, rows: list, business: str = "", prepared_for: str = "") -> bytes:
    """rep = db_mileage_ops.mileage_report(); rows = export_rows() (one dict per trip)."""
    pdf = SimplePDF(792, 612, title=f"Mileage log {rep['start']} to {rep['end']}")   # landscape letter
    hdr = f"{business + ' — ' if business else ''}Business mileage log {rep['start']} to {rep['end']}"
    f = _Flow(pdf, 36, hdr)
    pdf.text(36, f.y + 16, "Business Mileage Log", 16, bold=True)
    f.y += 22
    sub = f"{business}   " if business else ""
    sub += f"Period {rep['start']} to {rep['end']}   ·   {rep['trip_count']} trips   ·   prepared " \
           f"{_dt.date.today().isoformat()}" + (f" for {prepared_for}" if prepared_for else "")
    pdf.text(36, f.y + 9, sub, 9, color=(0.3, 0.3, 0.3))
    f.y += 18

    # Summary
    bus = sum(v["business"] for v in rep["by_driver"].values())
    com = sum(v["commute"] for v in rep["by_driver"].values())
    per = sum(v["personal"] for v in rep["by_driver"].values())
    f.heading("Summary")
    ded_rows, ded_total = [], 0.0
    for k, p in sorted(rep["deduction"].items(), key=lambda kv: kv[1]["from"] or ""):
        ded_rows.append([f"{p['from']} to {p['to']}", k, _mi(p["miles"]), _money(p["amount"])])
        ded_total += p["amount"]
    ded_rows.append(["Parking and tolls", "", "", _money(rep["parking_tolls"])])
    f.table([("Business-owned vehicles — standard mileage rate", 300, "l"), ("Rate", 60, "r"),
             ("Business miles", 90, "r"), ("Amount", 90, "r")],
            ded_rows, 8, ["Total deduction", "", _mi(sum(p["miles"] for p in rep["deduction"].values())),
                          _money(ded_total + rep["parking_tolls"])])
    f.para(f"All drivers and vehicles: {bus:,.1f} business miles, {com:,.1f} commute miles (not "
           f"deductible), {per:,.1f} personal miles.")
    f.gap(4)

    if rep.get("by_vehicle"):
        f.heading("Miles by vehicle")
        f.table([("Vehicle", 320, "l"), ("Business", 90, "r"), ("Commute", 90, "r"), ("Personal", 90, "r")],
                [[k, _mi(v["business"]), _mi(v["commute"]), _mi(v["personal"])]
                 for k, v in sorted(rep["by_vehicle"].items())], 8)
    if rep.get("by_month"):
        f.heading("Miles by month")
        f.table([("Month", 120, "l"), ("Business", 90, "r"), ("Commute", 90, "r"), ("Personal", 90, "r")],
                [[k, _mi(v["business"]), _mi(v["commute"]), _mi(v["personal"])]
                 for k, v in sorted(rep["by_month"].items())], 8)
    if rep.get("vehicles_4562"):
        f.heading("Form 4562 Part V — per business vehicle")
        f.table([("Year", 40, "l"), ("Vehicle", 190, "l"), ("VIN", 130, "l"), ("In service", 70, "l"),
                 ("Business", 70, "r"), ("Commute", 70, "r"), ("Other personal", 80, "r"), ("Total", 70, "r")],
                [[v["year"], v["label"], v["vin"], v["placed_in_service"], _mi(v["business"]),
                  _mi(v["commute"]), _mi(v["personal"]) if v["personal"] is not None else "needs odometer",
                  f"{v['total']:,}" if v["total"] is not None else "needs odometer"]
                 for v in rep["vehicles_4562"]], 8)
    if rep.get("reimbursement"):
        f.heading("Crew reimbursement (crew-owned vehicles — not part of the business-vehicle deduction)")
        status = rep.get("reimbursement_status") or {}
        rr = []
        for who, perd in sorted(rep["reimbursement"].items()):
            st = status.get(who, {})
            rr.append([who, _mi(sum(p["miles"] for p in perd.values())),
                       _money(sum(p["amount"] for p in perd.values())),
                       _money(st.get("not_submitted", 0)), _money(st.get("submitted", 0)),
                       _money(st.get("approved", 0)), _money(st.get("paid", 0))])
        f.table([("Driver", 180, "l"), ("Miles", 70, "r"), ("Amount", 80, "r"), ("Not submitted", 90, "r"),
                 ("Submitted", 80, "r"), ("Approved, unpaid", 100, "r"), ("Paid", 80, "r")], rr, 8)
        f.para("Status columns include parking and tolls.", 7.5, (0.35, 0.35, 0.35))
    f.heading("IRS record checks")
    if rep.get("compliance"):
        for m in rep["compliance"]:
            f.para("•  " + m)
    else:
        f.para("Every trip has a date, destination, business purpose, miles, and vehicle.")
    f.gap(4)
    f.para("Commuting between home and a regular work location is not deductible. Trips are never deleted: "
           "removed trips are listed as void with the reason, and every change is kept in the audit trail. "
           "Not tax advice — your accountant confirms how to claim these.", 7.5, (0.35, 0.35, 0.35))

    # Trip log
    pdf.new_page()
    f.y = f.m
    f._draw_running_header()
    f.heading("Trip log", 12)
    cols = [("Date", 52, "l"), ("Driver", 62, "l"), ("Vehicle", 82, "l"), ("From", 92, "l"), ("To", 98, "l"),
            ("Purpose", 140, "l"), ("Type", 46, "l"), ("Miles", 38, "r"), ("Rate", 30, "r"),
            ("Amount", 46, "r"), ("Flags", 34, "l")]
    body, tot_mi, tot_amt = [], 0.0, 0.0
    for r in rows:
        flags = "".join(x for x, on in (("V", r.get("Status") == "void"), ("E", r.get("Edited") == "yes"),
                                        ("C", r.get("Corrected") == "yes"), ("L", r.get("Late entry") == "yes"),
                                        ("R", r.get("Reimbursable") == "yes")) if on)
        void = r.get("Status") == "void"
        body.append([r["Date"], r["Driver"], r["Vehicle"], r["From"], r["To"],
                     (("VOID: " + (r.get("Void reason") or "")) if void else r["Purpose"]),
                     r["Classification"], _mi(r["Miles"]), f"{float(r['Rate (¢/mi)'] or 0):g}¢",
                     _money(r["Amount ($)"]) if not void else "", flags])
        if not void and r["Classification"] == "business":
            tot_mi += float(r["Miles"] or 0)
            tot_amt += float(r["Amount ($)"] or 0)
    f.table(cols, body, 7, ["", "", "", "", "", "All business trips", "", _mi(tot_mi), "", _money(tot_amt), ""])
    f.para("Flags: V = void (kept in the record), E = edited after it was recorded (reason in the audit trail), "
           "C = corrected (e.g. missing clock-out filled in), L = entered more than 7 days after the trip, "
           "R = crew-owned vehicle (reimbursed, not part of the business-vehicle deduction).",
           7, (0.35, 0.35, 0.35))
    return pdf.build()


def render_statement_pdf(reim: dict, trips: list, business: str = "") -> bytes:
    """reim = a mileage_reimbursements row (dict); trips = list_trips() dicts for it."""
    pdf = SimplePDF(612, 792, title=f"Mileage reimbursement {reim.get('reimbursement_id', '')}")
    f = _Flow(pdf, 42, f"{business + ' — ' if business else ''}Mileage reimbursement statement")
    pdf.text(42, f.y + 16, "Mileage Reimbursement Statement", 16, bold=True)
    f.y += 24
    status = (reim.get("status") or "").title()
    info = [("Statement", reim.get("reimbursement_id") or "(not submitted yet)"),
            ("Business", business or ""),
            ("Driver", reim.get("crew") or reim.get("user_key") or ""),
            ("Pay period", f"{reim.get('period_start')} to {reim.get('period_end')}"),
            ("Status", status or "Not submitted")]
    if reim.get("submitted_at"):
        info.append(("Submitted", f"{str(reim['submitted_at'])[:10]} by {reim.get('submitted_by') or ''}"))
    if reim.get("approved_at"):
        info.append(("Approved", f"{str(reim['approved_at'])[:10]} by {reim.get('approved_by') or ''}"))
    if reim.get("status") == "paid":
        ref = f" · ref {reim['paid_reference']}" if reim.get("paid_reference") else ""
        info.append(("Paid", f"{reim.get('paid_date') or ''} by {reim.get('paid_method') or ''}{ref}"))
    if reim.get("status") == "returned" and reim.get("return_note"):
        info.append(("Returned", reim["return_note"]))
    for k, v in info:
        f.need(14)
        pdf.text(42, f.y + 9, k, 9, bold=True)
        pdf.text(130, f.y + 9, fit(v, 430, 9), 9)
        f.y += 14
    f.gap(8)
    cols = [("Date", 58, "l"), ("From", 100, "l"), ("To", 110, "l"), ("Purpose", 150, "l"),
            ("Miles", 40, "r"), ("Rate", 32, "r"), ("Amount", 38, "r")]
    body, tot_mi, tot_amt, extras = [], 0.0, 0.0, 0.0
    for t in trips:
        cents = float(t.get("rate_cents") or 0)
        m = float(t.get("miles") or 0)
        amt = m * cents / 100
        tot_mi += m
        tot_amt += amt
        extras += float(t.get("parking_usd") or 0) + float(t.get("tolls_usd") or 0)
        body.append([t["trip_date"], t.get("from_label") or "", t["to_label"], t["purpose"], _mi(m),
                     f"{cents:g}¢", _money(amt)])
    f.heading("Trips")
    f.table(cols, body, 7.5, ["", "", "", "Mileage total", _mi(tot_mi), "", _money(tot_amt)])
    amount = reim.get("amount_usd")
    amount = float(amount) if amount not in (None, "") else tot_amt
    pt = reim.get("parking_tolls_usd")
    pt = float(pt) if pt not in (None, "") else extras
    f.need(60)
    for k, v, b in (("Mileage at the IRS standard rate", _money(amount), False),
                    ("Parking and tolls", _money(pt), False),
                    ("Total reimbursement", _money(amount + pt), True)):
        pdf.text(330, f.y + 10, k, 10, bold=b)
        pdf.text(570, f.y + 10, v, 10, bold=b, align="right")
        f.y += 15
    f.gap(10)
    f.para("Reimbursed under an accountable plan at no more than the IRS standard mileage rate for the "
           "date of each trip. Each trip is recorded with its date, destination, business purpose and miles. "
           "Keep this statement with your records.", 7.5, (0.35, 0.35, 0.35))
    return pdf.build()
