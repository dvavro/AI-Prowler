"""Dev helper: print the open-element chain (tag#id.class) at each element whose id
(or tag) matches the given names, using a tolerant stack parser.
Usage: html_parents.py <html file rel. to work copy> name1 [name2 ...]"""
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
want = set(sys.argv[2:])


class P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        label = tag + ("#" + a["id"] if a.get("id") else "") + ("." + a["class"].split()[0] if a.get("class") else "")
        if a.get("id") in want or tag in want:
            print(f"line {self.getpos()[0]}: {' > '.join(self.stack[-8:])} > [{label}]")
        if tag not in VOID:
            self.stack.append(label)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].split("#")[0].split(".")[0] == tag:
                lab = self.stack[i]
                if any(w in lab.replace("#", " ").replace(".", " ").split() for w in want if w.startswith("close:")) \
                        or ("close:" + lab.split("#")[-1].split(".")[0]) in want \
                        or ("close:" + lab.split(".")[-1]) in want:
                    print(f"line {self.getpos()[0]}: closes {lab} (parent chain {' > '.join(self.stack[max(0, i-3):i])})")
                del self.stack[i:]
                return
        print(f"line {self.getpos()[0]}: stray </{tag}>")


text = (ROOT / sys.argv[1]).read_text(encoding="utf-8", errors="replace")
# ignore <script> bodies (they contain HTML strings)
P().feed(text)
