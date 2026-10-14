"""Jobs PWA page structure (2026-10-13).

E2E MOB-01/02 found the bottom nav OUTSIDE #app: two "/.main" closing </div>s
(one from the 2026-10-06 repair, one older) meant the second one closed #app,
so the nav sat below the 100dvh app box — off the bottom of a phone screen.
These checks parse jobs/index.html the way a browser nests <div>s and pin the
layout contract:
  * every tab screen (.screen) is inside .main
  * .main and the bottom nav are both direct children of #app
  * .main closes before the nav opens
"""
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "source", "track", "wbr"}


class _Chains(HTMLParser):
    """Records the open-element chain at every start tag."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.found = []          # (label, classes, chain-of-labels)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        label = tag + ("#" + a["id"] if a.get("id") else "")
        classes = (a.get("class") or "").split()
        if classes:
            label += "." + classes[0]
        self.found.append((label, classes, list(self.stack)))
        if tag not in VOID:
            self.stack.append(label)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].split("#")[0].split(".")[0] == tag:
                del self.stack[i:]
                return


def _parse():
    p = _Chains()
    p.feed((ROOT / "jobs" / "index.html").read_text(encoding="utf-8"))
    return p.found


def test_every_screen_is_inside_main():
    screens = [(lab, chain) for lab, cls, chain in _parse() if "screen" in cls]
    assert len(screens) >= 9, f"expected the tab screens, found {[s[0] for s in screens]}"
    for lab, chain in screens:
        assert chain and chain[-1] == "div.main", f"{lab} is not a direct child of .main: {chain[-4:]}"


def test_bottom_nav_is_a_direct_child_of_app():
    navs = [chain for lab, cls, chain in _parse() if "bottomnav" in cls]
    assert len(navs) == 1
    assert navs[0][-1] == "div#app", \
        f"the bottom nav must sit directly inside #app (after .main), found under {navs[0][-4:]}"


def test_main_is_a_direct_child_of_app():
    mains = [chain for lab, cls, chain in _parse() if lab == "div.main"]
    assert len(mains) == 1
    assert mains[0][-1] == "div#app"
