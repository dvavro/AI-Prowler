"""Quick check of the Estimator PDFs: pages, and how many tables and headings the source has."""
import re
from pathlib import Path

from markdown_it import MarkdownIt

WORK = Path(__file__).resolve().parents[3]
md = MarkdownIt("commonmark").enable("table")
for name in ("AI-Prowler Estimator Design Spec", "AI-Prowler Estimator Implementation Plan"):
    pdf = (WORK / f"{name}.pdf").read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page(?!s)", pdf))
    from make_pdfs import join_split_tables
    html = md.render(join_split_tables((WORK / f"{name}.md").read_text(encoding="utf-8")))
    heads = len(re.findall(r"<h[1-3]", html))
    raw = len(re.findall(r"<p>\|", html))
    print(f"{name}: {pages} pages, {len(pdf) // 1024} KB; source has {html.count('<table')} tables, "
          f"{heads} headings, {html.count('<pre')} code blocks; leftover raw table pipes: {raw}")
    for m in re.finditer(r"<p>(\|[^\n]{0,150})", html):
        print("   raw:", m.group(1))
