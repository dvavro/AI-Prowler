"""Regression test for the log-rotation lock hang (v9.1.x hardening gap).

Root cause: _SafeRotatingFileHandler.doRollover() only guards against
doRollover() itself raising. If the recovery re-open (self._open()) ALSO
fails -- e.g. the rotation target is locked by a tailing viewer/AV scan AND
the original path can't be reopened either -- self.stream is left as None.
The NEXT emit() then falls through to the stock (unoverridden) emit() path,
which calls self.stream = self._open() again inside logging.FileHandler.emit,
raises, and BaseRotatingHandler.emit's except routes it to the stock
handleError(), which writes to sys.stderr. This process redirects sys.stderr
to a class that itself logs via the SAME handler -- so handleError's write
re-enters emit(), which fails the same way, calls handleError() again, writes
to stderr again... an unbounded recursive re-entry into the one handler that
is supposed to be crash-proof. In production (piped stderr into the GUI's
log display) this manifests as the whole single-threaded server freezing
with no further log output and no crash, exactly matching the observed
symptom (mcp_server.log.1/.2 missing, .3 present -- a rotation chain that
died mid-sequence and never recovered).

This test extracts the ACTUAL class source from ai_prowler_mcp.py via ast
(never a hand-copied duplicate that could drift) and drives it through that
exact failure sequence in a subprocess, so a real hang shows up as a real
subprocess timeout instead of freezing the test runner itself.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

SRC_PATH = Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\ai_prowler_mcp.py")
CLASS_NAME = "_SafeRotatingFileHandler"
TIMEOUT_SEC = 8


def _extract_class_source(path: Path, class_name: str) -> str:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            seg = ast.get_source_segment(src, node)
            if seg is None:
                raise RuntimeError(f"could not extract source for {class_name}")
            return seg
    raise RuntimeError(f"{class_name} not found in {path}")


REPRO_TEMPLATE = '''
import logging, os, sys
from logging.handlers import RotatingFileHandler as _RotatingFileHandler

{class_src}

log_path = sys.argv[1]
handler = {class_name}(log_path, mode="w", maxBytes=1, backupCount=3, encoding="utf-8")
logging.basicConfig(level=logging.DEBUG, handlers=[handler])
log = logging.getLogger("repro")

class _StderrToLog:
    def write(self, msg):
        msg = msg.rstrip()
        if msg:
            log.error("STDERR: %s", msg)
    def flush(self):
        pass
sys.stderr = _StderrToLog()

# Simulate: every rotation-target rename fails (file locked by a tailing
# viewer/AV scan) AND the recovery re-open also fails (path still locked).
def _broken_rename(a, b):
    raise PermissionError("simulated lock: cannot rename")
os.rename = _broken_rename

def _broken_open(self):
    raise PermissionError("simulated lock: cannot reopen")
{class_name}._open = _broken_open

sys.setrecursionlimit(300)  # fail fast instead of churning if it does recurse
print("ABOUT_TO_LOG", flush=True)
for i in range(5):
    log.info("message %d - padding padding padding padding", i)
print("DONE_NO_HANG", flush=True)
'''


def _run_repro() -> subprocess.CompletedProcess | None:
    class_src = _extract_class_source(SRC_PATH, CLASS_NAME)
    script = REPRO_TEMPLATE.format(class_src=class_src, class_name=CLASS_NAME)
    with tempfile.TemporaryDirectory() as td:
        script_path = Path(td) / "repro.py"
        script_path.write_text(script, encoding="utf-8")
        log_path = Path(td) / "test.log"
        try:
            return subprocess.run(
                [sys.executable, str(script_path), str(log_path)],
                capture_output=True, text=True, timeout=TIMEOUT_SEC,
            )
        except subprocess.TimeoutExpired:
            return None  # None = hung (the bug, worst case)


def test_log_rotation_survives_locked_rotation_and_locked_reopen():
    """The real _SafeRotatingFileHandler must keep logging (rc=0, all 5
    messages, no hang) even when BOTH the rotation rename AND the recovery
    re-open are locked out from under it. Before the fix this either hangs
    (subprocess timeout) or crashes with RecursionError from the
    stderr<->logger re-entry loop."""
    result = _run_repro()
    assert result is not None, (
        f"HUNG: {CLASS_NAME}.emit() did not return within {TIMEOUT_SEC}s when "
        "both rotation and recovery re-open were locked out -- this is the "
        "production freeze, reproduced."
    )
    assert result.returncode == 0, (
        f"CRASHED (rc={result.returncode}) instead of degrading gracefully.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "DONE_NO_HANG" in result.stdout, (
        f"did not complete logging all messages.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "RecursionError" not in result.stderr, (
        f"stderr<->logger recursive re-entry still reachable:\n{result.stderr}"
    )


# ── 2026-10-02 (Vicki): ".log.1/.log.2 missing, only .log.3 left" ────────────
# Root cause: several AI-Prowler server processes (the HTTP server plus the
# stdio copies Claude Desktop / background task runs start) all wrote
# mcp_server.log. Windows can't rename a file another process has open, and
# the stock rotation shifted .1→.2→.3 BEFORE failing to move the live log —
# then retried on EVERY log line, pushing .1/.2 into .3 while the live log
# grew without limit (117 MB). These tests drive the REAL handler class.
import logging as _logging
import os as _os


def _handler_class():
    from logging.handlers import RotatingFileHandler
    ns = {"logging": _logging, "os": _os, "sys": sys, "_RotatingFileHandler": RotatingFileHandler}
    exec(_extract_class_source(SRC_PATH, CLASS_NAME), ns)
    return ns[CLASS_NAME]


def _logger(path, max_bytes=200, backups=3):
    cls = _handler_class()
    h = cls(str(path), mode="a", maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    lg = _logging.getLogger(f"rot_{id(h)}")
    lg.handlers[:] = [h]
    lg.propagate = False
    lg.setLevel(_logging.INFO)
    return lg, h


def _write(lg, tag, n=10):
    for i in range(n):
        lg.info("%s line %02d %s", tag, i, "x" * 40)


def test_rotation_keeps_three_backups_and_a_small_live_log(tmp_path):
    p = tmp_path / "mcp_server.log"
    lg, h = _logger(p)
    for tag in ("A", "B", "C", "D", "E"):
        _write(lg, tag)
    h.close()
    for n in (1, 2, 3):
        assert (tmp_path / f"mcp_server.log.{n}").exists(), f".log.{n} missing"
    assert not (tmp_path / "mcp_server.log.4").exists()
    assert p.stat().st_size < 400, "the live log should stay small"
    # newest backup holds newer text than the oldest
    assert (tmp_path / "mcp_server.log.1").stat().st_mtime >= (tmp_path / "mcp_server.log.3").stat().st_mtime


def test_live_log_held_by_another_process_never_loses_a_backup(tmp_path, monkeypatch):
    """The exact bug: the live log can't be moved (another process has it open).
    Before: .1/.2 were shifted into .3 on every line. Now: backups untouched,
    no retry on every line, logging continues in the same file."""
    p = tmp_path / "mcp_server.log"
    lg, h = _logger(p)
    for tag in ("A", "B", "C", "D"):
        _write(lg, tag)                      # builds .1 .2 .3
    before = {n: (tmp_path / f"mcp_server.log.{n}").read_bytes() for n in (1, 2, 3)}

    real_replace, calls = _os.replace, []

    def _locked_live_log(src, dst):
        calls.append((src, dst))
        if _os.path.abspath(src) == _os.path.abspath(str(p)):
            raise PermissionError("another process has mcp_server.log open")
        return real_replace(src, dst)

    monkeypatch.setattr(_os, "replace", _locked_live_log)
    _write(lg, "LOCKED", n=40)               # way past maxBytes, many lines
    after = {n: (tmp_path / f"mcp_server.log.{n}").read_bytes() for n in (1, 2, 3)}
    assert after == before, "a backup changed while the live log couldn't be moved"
    assert len(calls) <= 2, f"rotation retried on every line: {len(calls)} rename attempts"
    assert b"LOCKED line 39" in p.read_bytes(), "logging must carry on in the same file"
    h.close()


def test_rotation_catches_up_once_the_live_log_is_free(tmp_path, monkeypatch):
    p = tmp_path / "mcp_server.log"
    lg, h = _logger(p)
    for tag in ("A", "B", "C", "D"):
        _write(lg, tag)
    real_replace = _os.replace
    monkeypatch.setattr(_os, "replace", lambda s, d: (_ for _ in ()).throw(PermissionError("held"))
                        if _os.path.abspath(s) == _os.path.abspath(str(p)) else real_replace(s, d))
    _write(lg, "HELD")
    monkeypatch.setattr(_os, "replace", real_replace)        # the other process let go
    h._rollover_blocked_until = 0.0                          # skip the 5-minute wait
    _write(lg, "FREE", n=1)          # one line: the oversized held log rotates once
    h.close()
    assert b"HELD line 09" in (tmp_path / "mcp_server.log.1").read_bytes(), \
        "the text written while the log was held must become .log.1"
    assert all((tmp_path / f"mcp_server.log.{n}").exists() for n in (1, 2, 3))
    assert b"HELD" not in p.read_bytes(), "the live log starts fresh after catching up"


def test_each_process_kind_gets_its_own_log_file():
    """The HTTP server keeps mcp_server.log; stdio copies (Claude Desktop,
    background task runs) and anything that just imports the module write
    mcp_stdio_<pid>.log — never the shared file."""
    src = SRC_PATH.read_text(encoding="utf-8")
    assert '_LOG_PATH = _LOG_DIR / "mcp_server.log"' in src
    assert '_LOG_PATH = _LOG_DIR / f"mcp_stdio_{os.getpid()}.log"' in src
    i = src.index("def _argv_transport_is_http()")
    ns = {"sys": sys, "__name__": "__main__"}
    exec(src[i:src.index("_IS_HTTP_SERVER = ", i)], ns)
    f = ns["_argv_transport_is_http"]
    for argv, want in ((["x", "--transport", "http"], True), (["x", "--transport=http"], True),
                       (["x", "--transport", "stdio"], False), (["x"], False)):
        sys_argv = sys.argv
        try:
            sys.argv = argv
            assert f() is want, argv
        finally:
            sys.argv = sys_argv
    ns["__name__"] = "ai_prowler_mcp"                     # merely imported
    exec(src[i:src.index("_IS_HTTP_SERVER = ", i)], ns)
    assert ns["_argv_transport_is_http"]() is False


def test_old_stdio_logs_are_pruned(tmp_path):
    import time as _t
    src = SRC_PATH.read_text(encoding="utf-8")
    i = src.index("def _prune_stdio_logs(")
    ns = {"Path": Path}
    exec(src[i:src.index("if _IS_HTTP_SERVER:", i)], ns)
    for n in range(14):
        f = tmp_path / f"mcp_stdio_{1000 + n}.log"
        f.write_text("x")
        (tmp_path / f"mcp_stdio_{1000 + n}.log.1").write_text("x")
        _os.utime(f, (_t.time() - 1000 + n, _t.time() - 1000 + n))
    (tmp_path / "mcp_server.log").write_text("keep me")
    ns["_prune_stdio_logs"](tmp_path, 9)
    left = sorted(p.name for p in tmp_path.glob("mcp_stdio_*.log"))
    assert left == [f"mcp_stdio_{1000 + n}.log" for n in range(5, 14)], left
    assert not (tmp_path / "mcp_stdio_1000.log.1").exists()
    assert (tmp_path / "mcp_server.log").exists(), "never touches the HTTP server's log"


if __name__ == "__main__":
    r = _run_repro()
    if r is None:
        print(f"HUNG after {TIMEOUT_SEC}s (timeout) -- bug reproduced")
    else:
        print(f"rc={r.returncode}")
        print("--- stdout ---")
        print(r.stdout)
        print("--- stderr ---")
        print(r.stderr[:3000])
