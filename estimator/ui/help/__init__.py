"""Step-by-step how-to guides (design spec "How-to-use guide and guided tour").

Each guide is a short Markdown file in guides/: the first line is "# Title", the
second an HTML comment naming the screen it belongs to and search words, e.g.
    <!-- screen: quick; words: price, service, quote -->
The web app's Help screen lists and searches them, and each screen's "?" opens
the guide for that screen. They are short extracts from the Estimator User Guide.
"""
from __future__ import annotations

import re
from pathlib import Path

from estimator.errors import NotFound

GUIDES_DIR = Path(__file__).resolve().parent / "guides"
_ID = re.compile(r"^[a-z0-9_]{1,64}$")
_META = re.compile(r"^<!--\s*(.*?)\s*-->$")


def _parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    title = lines[0].lstrip("#").strip() if lines and lines[0].startswith("#") else path.stem.replace("_", " ")
    meta: dict[str, str] = {}
    body_from = 1
    if len(lines) > 1:
        mm = _META.match(lines[1].strip())
        if mm:
            body_from = 2
            for part in mm.group(1).split(";"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    meta[k.strip().lower()] = v.strip()
    body = "\n".join(lines[body_from:]).strip()
    steps = sum(1 for ln in lines if re.match(r"^\d+\.\s", ln))
    words = [w.strip().lower() for w in meta.get("words", "").split(",") if w.strip()]
    return {"id": path.stem, "title": title, "screen": meta.get("screen", ""), "words": words,
            "steps": steps, "text": body}


def _all() -> list[dict]:
    return [_parse(p) for p in sorted(GUIDES_DIR.glob("*.md"))]


def _summary(g: dict) -> dict:
    return {k: g[k] for k in ("id", "title", "screen", "steps")}


def list_guides() -> list[dict]:
    """Every guide: id, title, the screen it belongs to and how many steps."""
    return [_summary(g) for g in _all()]


def get_guide(guide_id: str) -> dict:
    if not _ID.match(guide_id or "") or not (GUIDES_DIR / f"{guide_id}.md").is_file():
        raise NotFound(f"no how-to guide called {guide_id!r}", available=[g["id"] for g in _all()])
    g = _parse(GUIDES_DIR / f"{guide_id}.md")
    return {k: g[k] for k in ("id", "title", "screen", "steps", "text")}


def search(question: str) -> list[dict]:
    """Guides that match a question, best first: title words count most, then search words, then the text."""
    terms = [t for t in re.findall(r"[a-z0-9]+", (question or "").lower()) if len(t) > 2]
    if not terms:
        return list_guides()
    scored = []
    for g in _all():
        title, words, text = g["title"].lower(), " ".join(g["words"]), g["text"].lower()
        score = sum(3 * (t in title) + 2 * (t in words) + (t in text) for t in terms)
        if score:
            scored.append((-score, g["title"], g))
    return [_summary(g) for _, _, g in sorted(scored, key=lambda x: (x[0], x[1]))]
