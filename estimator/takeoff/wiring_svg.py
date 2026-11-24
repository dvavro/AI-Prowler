"""The wiring drawings as pictures for the screen (2026-11-21, David: "why does the file have to be downloaded when it
can be just displayed or downloaded or both?").

The wiring run saves two DXFs (estimator/takeoff/wiring_run.py): the wiring drawing (the floor plan with every
circuit's route) and the wiring schematic (the panel, its breakers and every circuit's conductors). This turns either
into an SVG with ezdxf's drawing add-on - the same library that reads the CAD plans - so the Measure screen can show it
without CAD software. Drawn on a white page in the drawing's own colours (black and red hots, white/grey neutral,
green ground). The SVG is kept beside the DXF and drawn again only when the DXF is newer (a new wiring run).
"""
from __future__ import annotations

from pathlib import Path


def svg_path(dxf: Path) -> Path:
    return dxf.with_suffix(".svg")


def render(dxf: Path) -> str:
    """The DXF as SVG text (no scripts - lines, circles, arcs and text as paths)."""
    import ezdxf
    from ezdxf.addons.drawing import Frontend, RenderContext, config, layout, svg

    doc = ezdxf.readfile(str(dxf))
    backend = svg.SVGBackend()
    cfg = config.Configuration(background_policy=config.BackgroundPolicy.WHITE,
                               color_policy=config.ColorPolicy.COLOR)
    Frontend(RenderContext(doc), backend, config=cfg).draw_layout(doc.modelspace())
    page = layout.Page(0, 0, layout.Units.mm, margins=layout.Margins.all(5))     # 0 x 0: sized to the drawing
    return backend.get_string(page)


def get(dxf: Path) -> str | None:
    """The SVG for this DXF, drawn now if it isn't saved yet or the DXF is newer. None when there's no DXF."""
    if not dxf.is_file():
        return None
    out = svg_path(dxf)
    try:
        if out.is_file() and out.stat().st_mtime >= dxf.stat().st_mtime:
            return out.read_text(encoding="utf-8")
    except OSError:
        pass
    text = render(dxf)
    try:
        out.write_text(text, encoding="utf-8")
    except OSError:
        pass                                   # can't keep it: drawn again next time, still shown now
    return text
