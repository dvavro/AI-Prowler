"""R-072: Settings Database corruption status button.

Tests (no tkinter display needed):
- sqlite_quick_check_ok: corrupt -> False, valid -> True, missing -> True
- _set_corrupt_btn_state: RED/GREEN text, colors, state
- _on_corrupt_btn_click: RED -> confirm + clear + invalidate + after_cleared;
                         GREEN -> reset to checking + re-run check
"""
import ast
import os
import sqlite3
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

passed, failed = [], []

def check(name, cond):
    (passed if cond else failed).append(name)
    print(("PASS " if cond else "FAIL ") + name)

if __name__ == "__main__":
    from rag_preprocessor import sqlite_quick_check_ok

    tmpd = tempfile.mkdtemp()
    bad = os.path.join(tmpd, "bad.sqlite3")
    with open(bad, "wb") as f:
        f.write(b"not a sqlite file, just garbage" * 100)
    check("corrupt file -> False", sqlite_quick_check_ok(bad) is False)

    good = os.path.join(tmpd, "good.sqlite3")
    conn = sqlite3.connect(good)
    conn.execute("CREATE TABLE t (a TEXT)")
    conn.commit()
    conn.close()
    check("valid file -> True", sqlite_quick_check_ok(good) is True)

    check("missing file -> True",
          sqlite_quick_check_ok(os.path.join(tmpd, "nope.sqlite3")) is True)

    with open(os.path.join(REPO, "rag_gui.py"), "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())

    def get_method(name):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == name:
                        return ast.unparse(item)
        return None

    src_set = get_method("_set_corrupt_btn_state")
    check("method _set_corrupt_btn_state exists", src_set is not None)
    check("corrupt button created in Database section",
          "_corrupt_btn = tk.Button(db_frame" in ast.unparse(tree))

    class MockBtn:
        def __init__(self):
            self.kw = {}
        def configure(self, **kw):
            self.kw.update(kw)

    ns = {}
    exec(src_set, ns)
    fn = ns["_set_corrupt_btn_state"]

    class FakeSelf:
        pass

    s = FakeSelf()
    s._corrupt_btn = MockBtn()
    fn(s, True)
    check("RED text", s._corrupt_btn.kw.get("text", "").startswith("\U0001f534"))
    check("RED bg", s._corrupt_btn.kw.get("bg") == "#c0392b")
    check("RED state stored", s._corrupt_state is True)

    s2 = FakeSelf()
    s2._corrupt_btn = MockBtn()
    fn(s2, False)
    check("GREEN text", s2._corrupt_btn.kw.get("text", "").startswith("\U0001f7e2"))
    check("GREEN bg", s2._corrupt_btn.kw.get("bg") == "#27ae60")
    check("GREEN state stored", s2._corrupt_state is False)

    # RED click flow with mocks; threading.Thread runs synchronously
    src_click = get_method("_on_corrupt_btn_click")
    check("method _on_corrupt_btn_click exists", src_click is not None)

    calls = []

    class MockMsgBox:
        @staticmethod
        def askyesno(title, msg):
            calls.append(("askyesno", title))
            return True

    import threading as _th
    _real_thread = _th.Thread

    class SyncThread:
        def __init__(self, target=None, daemon=None):
            self._t = target
        def start(self):
            self._t()

    ns2 = {
        "messagebox": MockMsgBox,
        "threading": _th,
        "clear_database_only": lambda confirm: calls.append(("clear", confirm)),
        "invalidate_chroma_cache": lambda: calls.append(("invalidate",)),
        "RAG_AVAILABLE": False,
        "TRACKING_DB": None,
        "get_chroma_client": lambda: calls.append(("get_client",)),
    }
    # stub the inner import: replace 'from rag_preprocessor import get_chroma_client'
    src_click_stubbed = src_click.replace(
        "from rag_preprocessor import get_chroma_client",
        "get_chroma_client = __ns_get_client__",
    )
    ns2["__ns_get_client__"] = ns2["get_chroma_client"]
    exec(src_click_stubbed, ns2)
    click = ns2["_on_corrupt_btn_click"]
    ns2["threading"].Thread = SyncThread

    class FakeSelf2:
        def __init__(self, state):
            self._corrupt_state = state
            self._corrupt_btn = MockBtn()
            class R:
                def after(inner_self, ms, fn_):
                    fn_()
            self.root = R()
        def _after_corrupt_cleared(self):
            calls.append(("_after_cleared",))
        def _check_index_integrity_async(self):
            calls.append(("_recheck",))

    try:
        click(FakeSelf2(True))
        check("RED asks confirm", any(c[0] == "askyesno" for c in calls))
        check("RED clears db", any(c[0] == "clear" for c in calls))
        check("RED invalidates cache", any(c[0] == "invalidate" for c in calls))
        check("RED verifies fresh client", any(c[0] == "get_client" for c in calls))
        check("RED -> after_cleared", any(c[0] == "_after_cleared" for c in calls))
    except Exception as e:
        check("RED click flow (exc: %s)" % e, False)
    finally:
        _th.Thread = _real_thread

    calls.clear()
    s4 = FakeSelf2(False)
    click(s4)
    check("GREEN resets to checking", s4._corrupt_state is None)
    check("GREEN re-runs check", any(c[0] == "_recheck" for c in calls))

    print()
    print("PASSED: %d  FAILED: %d" % (len(passed), len(failed)))
    sys.exit(1 if failed else 0)
