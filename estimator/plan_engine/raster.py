"""Scanned and photographed plans: straighten, clean up and find the line work (Coder 2 Sprint 16).

Spec, Blueprint processing stage 4, "Raster (scans, photos): deskew, denoise and binarize, then detect lines and
contours". This is done with numpy and scipy (already used for raster symbol matching), not OpenCV:

- Photos: when the page sits on a darker background, its four corners are found and the page is squared up
  (perspective). A photo has no true scale, so its sheets always say to calibrate.
- Blueprints (white lines on a dark sheet) are turned the right way round, so OCR and the line finder can read them.
- Binarize: Otsu's threshold, a little above it so thin lines that were shrunk don't fade out.
- Denoise: specks of ink smaller than a few pixels are dropped.
- Deskew: the angle (up to 5 degrees) at which the rows of ink line up best; the sheet is turned back by it, and the
  saved sheet image and the OCR words are the straightened ones, so every box lands on the same spot of the picture.
- Lines: long horizontal and vertical runs of ink become line segments in sheet inches, the same as a PDF's line
  work, so walls, rooms, elevations and site objects are found the same way. A filled (solid) wall gives both of its
  edges. Slanted lines, curves and dashed lines aren't traced on scans.

Everything found on a scan or photo is source "raster": it's marked to check and is never approved automatically.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

LINE_PX = 100                 # pixels per inch the line work is found at
MIN_LINE_IN = 0.4             # shorter runs are text, hatching or dashes
MAX_THICK_IN = 0.06           # thicker than this, a run is a filled wall: both edges are kept
MAX_FILL_IN = 0.5             # thicker still, it's a solid block (a logo, a stamp): left out
SPECK_PX = 3                  # ink blobs this many pixels or fewer (at LINE_PX) are noise
MAX_SKEW_DEG = 5.0
MIN_SKEW_DEG = 0.15           # smaller tilts are left alone
SKEW_PTS = 200_000            # ink pixels sampled for the skew search
PAPER_MIN, PAPER_MAX = 0.2, 0.97   # a photographed page covers this share of the photo
MAX_SEGMENTS = 120_000
CONFIDENCE = 0.5              # the most a raster object is trusted before a person checks it


@dataclass
class Prepared:
    image: object                          # PIL "L" image: squared up, the right way round and straight
    dpi: float
    angle: float = 0.0                     # degrees the sheet was turned back (counter-clockwise +)
    squared_up: bool = False
    inverted: bool = False
    segments: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.angle or self.squared_up or self.inverted)


# ---------------------------------------------------------------- binarize, denoise

def otsu(arr) -> float:
    """Otsu's threshold of a uint8 array."""
    import numpy as np
    hist = np.bincount(arr.ravel(), minlength=256).astype(np.float64)
    total = hist.sum()
    if total == 0:
        return 127.0
    levels = np.arange(256, dtype=np.float64)
    w0 = np.cumsum(hist)
    m0 = np.cumsum(hist * levels)
    w1 = total - w0
    mt = m0[-1]
    with np.errstate(divide="ignore", invalid="ignore"):
        between = (mt * w0 / total - m0) ** 2 / (w0 * w1)
    between = np.nan_to_num(between)
    return float(np.argmax(between))


def ink_of(arr):
    """Ink (True) on paper: below Otsu's threshold, lifted halfway to the paper so thin shrunk lines stay."""
    import numpy as np
    t = otsu(arr)
    paper = float(np.percentile(arr, 90))
    cut = max(t, (t + paper) / 2) if paper > t else t
    if cut >= paper:                                   # a blank page: nothing is ink
        return np.zeros(arr.shape, dtype=bool)
    return arr < cut


def denoise(ink, speck: int = SPECK_PX):
    """Drop specks of ink of `speck` pixels or fewer."""
    import numpy as np
    from scipy import ndimage
    labels, n = ndimage.label(ink, structure=np.ones((3, 3), dtype=bool))
    if n == 0:
        return ink
    sizes = np.bincount(labels.ravel())
    keep = sizes > speck
    keep[0] = False
    return keep[labels]


# ---------------------------------------------------------------- deskew

def skew_angle(ink, max_deg: float = MAX_SKEW_DEG) -> float:
    """The angle (degrees, counter-clockwise +, as PIL's rotate) the drawing is turned by: the one where the rows of ink
    line up best (the sharpest projection profile)."""
    import numpy as np
    ys, xs = np.nonzero(ink)
    if len(ys) < 50:
        return 0.0
    if len(ys) > SKEW_PTS:
        pick = np.random.default_rng(0).choice(len(ys), SKEW_PTS, replace=False)
        ys, xs = ys[pick], xs[pick]
    ys = ys.astype(np.float64)
    xs = xs.astype(np.float64)
    h = ink.shape[0]
    pad = int(ink.shape[1] * math.tan(math.radians(max_deg))) + 2

    def score(a_deg: float) -> float:
        rows = np.round(ys - xs * math.tan(math.radians(a_deg))).astype(np.int64) + pad
        hist = np.bincount(rows, minlength=h + 2 * pad)
        return float((hist.astype(np.float64) ** 2).sum())

    best = max(np.arange(-max_deg, max_deg + 1e-9, 0.25), key=score)
    fine = max(np.arange(best - 0.25, best + 0.25 + 1e-9, 0.02), key=score)
    slope = float(fine)                                # rows run down to the right by this angle (y is down)
    return round(-slope, 2)


def rotate(img, angle: float, fill: int = 255):
    """Turn a PIL image by `angle` degrees counter-clockwise about its centre, keeping its size."""
    from PIL import Image
    return img.rotate(angle, resample=Image.Resampling.BICUBIC, fillcolor=fill)


# ---------------------------------------------------------------- photos: find the page and square it up

def find_paper(arr):
    """The page's four corners (top-left, top-right, bottom-right, bottom-left, in pixels) when a photo shows a light
    page on a darker background, else None."""
    import numpy as np
    from scipy import ndimage
    t = otsu(arr)
    bright = arr > t
    share = bright.mean()
    if not PAPER_MIN <= share <= PAPER_MAX:
        return None
    labels, n = ndimage.label(bright)
    if n == 0:
        return None
    sizes = np.bincount(labels.ravel())
    sizes[0] = 0
    page = ndimage.binary_fill_holes(labels == int(np.argmax(sizes)))
    area = float(page.sum())
    if area < PAPER_MIN * arr.size:
        return None
    ys, xs = np.nonzero(page)
    s, d = xs + ys, xs - ys
    tl = (int(xs[np.argmin(s)]), int(ys[np.argmin(s)]))
    br = (int(xs[np.argmax(s)]), int(ys[np.argmax(s)]))
    tr = (int(xs[np.argmax(d)]), int(ys[np.argmax(d)]))
    bl = (int(xs[np.argmin(d)]), int(ys[np.argmin(d)]))
    quad = [tl, tr, br, bl]
    q_area = 0.5 * abs(sum(quad[i][0] * quad[(i + 1) % 4][1] - quad[(i + 1) % 4][0] * quad[i][1] for i in range(4)))
    if q_area <= 0 or not 0.9 <= area / q_area <= 1.1:     # not a four-sided page (torn, folded, cut off)
        return None
    h, w = arr.shape
    near = 0.02 * max(w, h)
    corners = [(0, 0), (w - 1, 0), (w - 1, h - 1), (0, h - 1)]
    if all(math.hypot(p[0] - c[0], p[1] - c[1]) <= near for p, c in zip(quad, corners)):
        return None                                        # the page fills the picture: nothing to square up
    return quad


def square_up(img, quad):
    """The page inside `quad` (tl, tr, br, bl) as a straight rectangle."""
    from PIL import Image
    tl, tr, br, bl = quad
    w = int(round((math.dist(tl, tr) + math.dist(bl, br)) / 2))
    h = int(round((math.dist(tl, bl) + math.dist(tr, br)) / 2))
    data = (*tl, *bl, *br, *tr)
    return img.transform((max(w, 1), max(h, 1)), Image.Transform.QUAD, data, resample=Image.Resampling.BICUBIC)


# ---------------------------------------------------------------- line work

def _run_mask(ink, min_len: int):
    """Pixels on a horizontal run of ink at least `min_len` long."""
    import numpy as np
    h, w = ink.shape
    p = np.zeros((h, w + 2), dtype=np.int8)
    p[:, 1:-1] = ink
    d = np.diff(p, axis=1)
    sr, sc = np.nonzero(d == 1)
    er, ec = np.nonzero(d == -1)
    keep = (ec - sc) >= min_len
    m = np.zeros((h, w + 1), dtype=np.int32)
    np.add.at(m, (sr[keep], sc[keep]), 1)
    np.add.at(m, (er[keep], ec[keep]), -1)
    return np.cumsum(m, axis=1)[:, :w] > 0


def _horizontal(ink, px_per_in: float) -> list:
    """Horizontal line segments (pixel coordinates) from long runs of ink."""
    import numpy as np
    from scipy import ndimage
    min_len = max(int(MIN_LINE_IN * px_per_in), 3)
    thin = max(MAX_THICK_IN * px_per_in, 2.0)
    fill = MAX_FILL_IN * px_per_in
    runs = _run_mask(ink, min_len)
    labels, n = ndimage.label(runs)
    out = []
    for i, sl in enumerate(ndimage.find_objects(labels), start=1):
        if sl is None:
            continue
        comp = labels[sl] == i
        ys, xs = np.nonzero(comp)
        y0, x0 = sl[0].start, sl[1].start
        width = int(xs.max() - xs.min() + 1)
        if width < min_len:
            continue
        thick = len(xs) / width
        if thick > fill:
            continue
        edge = max(1, width // 20)
        left = xs <= xs.min() + edge
        right = xs >= xs.max() - edge
        yl, yr = float(ys[left].mean()) + y0, float(ys[right].mean()) + y0
        xa, xb = float(xs.min()) + x0, float(xs.max()) + x0 + 1
        if thick <= thin:
            out.append(((xa, yl + 0.5), (xb, yr + 0.5)))
        else:                                          # a filled wall: its two edges, like a drawn wall's two lines
            half = thick / 2
            out.append(((xa, yl + 0.5 - half), (xb, yr + 0.5 - half)))
            out.append(((xa, yl + 0.5 + half), (xb, yr + 0.5 + half)))
    return out


def line_segments(ink, px_per_in: float) -> list:
    """Horizontal and vertical line work in inches from the top-left, as ((x0, y0), (x1, y1))."""
    k = 1.0 / px_per_in
    out = [((a[0] * k, a[1] * k), (b[0] * k, b[1] * k)) for a, b in _horizontal(ink, px_per_in)]
    out += [((a[1] * k, a[0] * k), (b[1] * k, b[0] * k)) for a, b in _horizontal(ink.T, px_per_in)]
    return out[:MAX_SEGMENTS]


# ---------------------------------------------------------------- the whole pipeline

def _array(img):
    import numpy as np
    return np.asarray(img, dtype=np.uint8)


def _work(gray, dpi: float):
    """The image at LINE_PX (never enlarged), and its pixels per inch."""
    from PIL import Image
    k = min(1.0, LINE_PX / dpi)
    if k < 1.0:
        gray = gray.resize((max(1, int(gray.size[0] * k)), max(1, int(gray.size[1] * k))), Image.Resampling.BOX)
    return gray, dpi * k


def prepare(img, dpi: float, *, photo: bool = False, find_lines: bool = True) -> Prepared:
    """A scan or photo made ready to read: squared up (photos), the right way round, straight, and its line work.
    `photo`: the picture came from a camera (it says what was or wasn't squared up)."""
    from PIL import Image, ImageOps

    gray = img.convert("L")
    out = Prepared(image=gray, dpi=float(dpi))
    # Photos: find the page on its background and square it up.
    small = gray
    longest = max(gray.size)
    if longest > 1200:
        f = 1200 / longest
        small = gray.resize((max(1, int(gray.size[0] * f)), max(1, int(gray.size[1] * f))), Image.Resampling.BOX)
    quad = find_paper(_array(small))
    if quad:
        f = gray.size[0] / small.size[0]
        gray = square_up(gray, [(x * f, y * f) for x, y in quad])
        out.squared_up = True
        out.notes.append("photo: the page's edges were found and it was squared up; calibrate the scale before measuring")
    elif photo:
        out.notes.append("photo: the page's edges weren't found, so it wasn't squared up; measure only after calibrating, "
                         "and check every quantity")
    # Blueprints: white lines on a dark sheet.
    work, ppi = _work(gray, dpi)
    arr = _array(work)
    if (arr < otsu(arr)).mean() > 0.5:
        gray, work = ImageOps.invert(gray), ImageOps.invert(work)
        arr = _array(work)
        out.inverted = True
        out.notes.append("light lines on a dark sheet (a blueprint): read inverted")
    # Deskew.
    ink = denoise(ink_of(arr))
    angle = skew_angle(ink)
    if abs(angle) >= MIN_SKEW_DEG:
        gray = rotate(gray, -angle)
        work = rotate(work, -angle)
        ink = denoise(ink_of(_array(work)))
        out.angle = angle
        out.notes.append(f"straightened by {abs(angle):.1f} degrees")
    out.image = gray
    if find_lines:
        out.segments = line_segments(ink, ppi)
    return out


def confidence(c) -> float:
    """A raster object's confidence: never above CONFIDENCE before a person checks it."""
    try:
        return round(min(float(c), CONFIDENCE), 3)
    except (TypeError, ValueError):
        return CONFIDENCE
