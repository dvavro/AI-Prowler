"""Make PDFs of the Estimator Design Spec and Implementation Plan (Markdown -> HTML -> PDF with Edge).

    python tests\\estimator\\make_pdfs.py

The PDFs are saved next to the .md files.
"""
import html
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

from markdown_it import MarkdownIt

WORK = Path(__file__).resolve().parents[3]          # ...\AI-Prowler_V970_to_V1000
DOCS = ["AI-Prowler Estimator Design Spec.md", "AI-Prowler Estimator Implementation Plan.md"]
EDGE = next((p for p in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                         r"C:\Program Files\Microsoft\Edge\Application\msedge.exe") if Path(p).exists()), None)

CSS = """
@page { size: Letter; margin: 0.6in 0.55in 0.7in 0.55in; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 9.6pt; line-height: 1.42; color: #1f2328; }
.cover { border-bottom: 3px solid #2563eb; margin-bottom: 18px; padding-bottom: 8px; }
.cover .t { font-size: 22pt; font-weight: 700; color: #1e3a8a; }
.cover .s { color: #57606a; font-size: 9pt; margin-top: 2px; }
h1 { font-size: 17pt; color: #1e3a8a; border-bottom: 1.5px solid #c7d2fe; padding-bottom: 3px; margin: 22px 0 8px; }
h2 { font-size: 13.5pt; color: #1e40af; margin: 18px 0 6px; break-after: avoid; }
h3 { font-size: 11.2pt; color: #1e3a8a; margin: 14px 0 5px; break-after: avoid; }
h4 { font-size: 10pt; margin: 12px 0 4px; break-after: avoid; }
p { margin: 5px 0; }
ul, ol { margin: 4px 0 6px; padding-left: 20px; }
li { margin: 2px 0; }
code { font-family: Consolas, "Courier New", monospace; font-size: 8.6pt; background: #f3f4f6; padding: 0 3px;
       border-radius: 3px; }
pre { background: #f6f8fa; border: 1px solid #e5e7eb; border-radius: 5px; padding: 7px 9px; font-size: 8pt;
      white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8pt; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px; font-size: 8.2pt; table-layout: auto; }
th, td { border: 1px solid #d0d7de; padding: 3px 5px; vertical-align: top; text-align: left;
         overflow-wrap: anywhere; }
th { background: #eef2ff; color: #1e3a8a; }
tr { break-inside: avoid; }
tr:nth-child(even) td { background: #fafbfc; }
blockquote { border-left: 3px solid #93c5fd; margin: 6px 0; padding: 2px 10px; color: #374151; background: #f8fafc; }
hr { border: 0; border-top: 1px solid #d0d7de; margin: 14px 0; }
a { color: #1d4ed8; text-decoration: none; }
"""


def join_split_tables(text: str) -> str:
    """Table rows separated from their table by blank lines (added later in the doc) rejoin the table."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            i = len(out)
            while i > 0 and not out[i - 1].strip():
                i -= 1
            if i < len(out) and i > 0 and out[i - 1].lstrip().startswith("|"):
                del out[i:]
        out.append(line)
    return "\n".join(out) + "\n"


def build_html(md_path: Path) -> str:
    md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table").enable("strikethrough")
    body = md.render(join_split_tables(md_path.read_text(encoding="utf-8")))
    title = md_path.stem
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<style>{CSS}</style></head><body><div class='cover'><div class='t'>{html.escape(title)}</div>"
            f"<div class='s'>AI-Prowler Estimator &middot; PDF made {date.today():%B %d, %Y} from "
            f"{html.escape(md_path.name)}</div></div>{body}</body></html>")


def to_pdf(html_file: Path, pdf_file: Path, profile: Path) -> None:
    if pdf_file.exists():
        pdf_file.unlink()
    cmd = [EDGE, "--headless=new", "--disable-gpu", "--no-first-run", "--no-pdf-header-footer",
           f"--user-data-dir={profile}", f"--print-to-pdf={pdf_file}", html_file.as_uri()]
    subprocess.run(cmd, capture_output=True, timeout=120)
    for _ in range(60):                      # Edge can return before the file is fully written
        if pdf_file.exists() and pdf_file.stat().st_size > 0:
            break
        time.sleep(0.5)
    if not pdf_file.exists():
        raise SystemExit(f"Edge didn't make {pdf_file.name}")


def main() -> int:
    if EDGE is None:
        print("Microsoft Edge wasn't found, so no PDF could be made.")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name in DOCS:
            src = WORK / name
            if not src.exists():
                print(f"Not found: {src}")
                continue
            html_file = tmp / (src.stem.replace(" ", "_") + ".html")
            html_file.write_text(build_html(src), encoding="utf-8")
            pdf = src.with_suffix(".pdf")
            to_pdf(html_file, pdf, tmp / "edge_profile")
            print(f"Made {pdf}  ({pdf.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
