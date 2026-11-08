"""A tiny PDF writer for plan-engine tests: text (Helvetica) and rectangles at exact spots, in inches from the top-left
corner like the drawing model. No PDF library is needed, so the tests run on any PC."""
from __future__ import annotations

from pathlib import Path


def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(path: Path, pages: list[dict]) -> Path:
    """pages: [{"w": 36, "h": 24, "texts": [(x, top, size_pt, "TEXT")], "rects": [(x0, top, x1, bottom)],
    "rotate": 0}] - inches, origin top-left."""
    objs: list[bytes | None] = [None, None, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for p in pages:
        w, h = p.get("w", 11), p.get("h", 8.5)
        ops = []
        for (x0, top, x1, bottom) in p.get("rects", []):
            ops.append(f"{x0 * 72:.2f} {(h - bottom) * 72:.2f} {(x1 - x0) * 72:.2f} {(bottom - top) * 72:.2f} re S")
        for (xa, ya, xb, yb) in p.get("lines", []):           # straight lines, inches from the top-left
            ops.append(f"{xa * 72:.3f} {(h - ya) * 72:.3f} m {xb * 72:.3f} {(h - yb) * 72:.3f} l S")
        for (x, top, size, text) in p.get("texts", []):
            base = (h - top) * 72 - size * 0.8
            ops.append(f"BT /F1 {size} Tf {x * 72:.2f} {base:.2f} Td ({_esc(text)}) Tj ET")
        stream = "\n".join(ops).encode("latin-1")
        objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        content_id = len(objs)
        rot = f" /Rotate {p['rotate']}" if p.get("rotate") else ""
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w * 72:.2f} {h * 72:.2f}] /Contents {content_id} 0 R"
                    f" /Resources << /Font << /F1 3 0 R >> >>{rot} >>".encode())
        kids.append(len(objs))
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>").encode()
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    Path(path).write_bytes(bytes(out))
    return Path(path)


def title_block(sheet_no: str, title: str, rev: str | None = "B", date: str | None = "10/01/2026",
                w: float = 36, h: float = 24, scale: str | None = None) -> list[tuple]:
    """Title-block text down the right edge of a w x h sheet."""
    x = w - 3.5
    t = [(x, h - 6.0, 9, "PROJECT: SMITH RESIDENCE"), (x, h - 4.6, 8, "SHEET TITLE"), (x, h - 4.3, 14, title),
         (x, h - 2.6, 8, "SHEET NO."), (x, h - 2.3, 28, sheet_no)]
    if rev:
        t.append((x, h - 5.2, 8, f"REV: {rev}"))
    if date:
        t.append((x + 1.6, h - 5.2, 8, f"DATE: {date}"))
    if scale:
        t.append((x, h - 3.2, 8, f"SCALE: {scale}"))
    return t
