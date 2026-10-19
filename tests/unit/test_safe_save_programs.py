"""
tests/unit/test_safe_save_programs.py
=====================================
Safe-save across the AI-Prowler programs (2026-10-19, David) - Tier 1 + Tier 2.

THE PROBLEM
-----------
open(path, 'w') / Path.write_text() truncate the file to EMPTY first and then
fill it in. The GUI, the MCP server, the scheduler and the file watcher all
read the same settings files, so a reader could catch one empty / half-written,
and most loaders treat "unreadable" as "empty" - the next load -> change ->
save then wrote back a nearly empty file (settings + API keys, the write
allowlist, the task queue, learnings, the tracking DB...). A crash or power cut
mid-save left the file broken for good.

THE FIX
-------
safe_save.py: temp file in the same folder + fsync + os.replace() (atomic,
retried while Windows has the file locked); read_json_retry() for the read
side. Load-for-update paths now REFUSE to save over a file that exists but
can't be read, instead of saving {} + one key.

Every test here works in tmp_path - no real config / allowlist / queue file is
ever touched.

SP-01..SP-09  safe_save module itself
SP-10..SP-19  each program's save/load goes through it (behaviour)
SP-20         source guard: no in-place save of a protected file creeps back
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import safe_save as ss  # noqa: E402


def _temps(p: Path):
    return [x.name for x in p.parent.iterdir() if x.name.startswith(p.name + ".tmp")]


def _hammer(path: Path, save_a, save_b, check, rounds=300):
    """Reader thread reads `path` non-stop while the saver alternates two
    contents. Returns (reads, bad_reads)."""
    stop = threading.Event()
    bad, reads = [], [0]

    def reader():
        while not stop.is_set():
            try:
                raw = path.read_bytes()
            except (PermissionError, FileNotFoundError):
                continue                      # Windows: swap in progress - fine
            reads[0] += 1
            try:
                if not check(json.loads(raw.decode("utf-8"))):
                    bad.append(f"unexpected content {raw[:60]!r}")
            except Exception as e:            # empty / truncated / partial
                bad.append(f"{type(e).__name__}: {raw[:60]!r}")

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    deadline = time.time() + 45                   # never let a slow disk hang the suite
    try:
        for i in range(rounds):
            (save_b if i % 2 else save_a)()
            if time.time() > deadline and i % 2:
                break
    finally:
        stop.set()
        t.join(10)
    return reads[0], bad


# ══ safe_save module ═════════════════════════════════════════════════════════

def test_SP_01_json_roundtrip_no_temp_left(tmp_path):
    p = tmp_path / "a.json"
    ss.atomic_write_json(p, {"x": 1, "y": ["\u00e9"]})
    assert json.loads(p.read_text(encoding="utf-8")) == {"x": 1, "y": ["\u00e9"]}
    assert ss.read_json_retry(p) == {"x": 1, "y": ["\u00e9"]}
    assert not _temps(p)


def test_SP_02_text_newlines_match_open_w(tmp_path):
    """newline=None writes os.linesep like open(path,'w'); '' writes as-is."""
    p = tmp_path / "t.txt"
    ss.atomic_write_text(p, "a\nb")
    assert p.read_bytes() == ("a" + os.linesep + "b").encode()
    ss.atomic_write_text(p, "a\nb", newline="")
    assert p.read_bytes() == b"a\nb"


def test_SP_03_replace_refused_is_retried(tmp_path):
    p = tmp_path / "r.json"
    ss.atomic_write_json(p, {"v": "old"})
    real, calls = os.replace, [0]

    def flaky(a, b):
        calls[0] += 1
        if calls[0] <= 3:
            raise PermissionError(13, "in use")
        return real(a, b)

    with patch.object(ss.os, "replace", flaky):
        ss.atomic_write_json(p, {"v": "new"})
    assert calls[0] == 4
    assert ss.read_json_retry(p) == {"v": "new"}
    assert not _temps(p)


def test_SP_04_failed_save_keeps_old_file_and_cleans_temp(tmp_path):
    p = tmp_path / "f.json"
    ss.atomic_write_json(p, {"keep": True})

    def always(a, b):
        raise PermissionError(13, "locked forever")

    with patch.object(ss.os, "replace", always):
        with pytest.raises(PermissionError):
            ss.atomic_write_json(p, {"keep": False}, retries=3, delay=0.001)
    assert ss.read_json_retry(p) == {"keep": True}
    assert not _temps(p)


def test_SP_05_unserialisable_data_never_touches_file(tmp_path):
    p = tmp_path / "u.json"
    ss.atomic_write_json(p, [1, 2, 3])
    with pytest.raises(TypeError):
        ss.atomic_write_json(p, {"bad": object()})
    assert ss.read_json_retry(p) == [1, 2, 3]
    assert not _temps(p)


def test_SP_06_read_missing_default_or_raise(tmp_path):
    p = tmp_path / "missing.json"
    assert ss.read_json_retry(p, []) == []
    with pytest.raises(FileNotFoundError):
        ss.read_json_retry(p)


def test_SP_07_read_retries_a_mid_save_empty_file(tmp_path):
    """File is empty (an old in-place writer mid-save) and becomes valid a
    moment later - the read must wait for it, not report 'empty'."""
    p = tmp_path / "e.json"
    p.write_text("", encoding="utf-8")

    def fill():
        time.sleep(0.08)
        p.write_text('{"ok": 1}', encoding="utf-8")

    t = threading.Thread(target=fill)
    t.start()
    try:
        assert ss.read_json_retry(p, None, attempts=20, delay=0.02) == {"ok": 1}
    finally:
        t.join()


def test_SP_08_read_broken_file_default_or_raise_and_bom_cp1252(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("{ broken", encoding="utf-8")
    assert ss.read_json_retry(p, "D", attempts=2, delay=0.001) == "D"
    with pytest.raises(ValueError):
        ss.read_json_retry(p, attempts=2, delay=0.001)
    p.write_bytes(b"\xef\xbb\xbf" + b'{"bom": true}')         # UTF-8 BOM
    assert ss.read_json_retry(p) == {"bom": True}
    p.write_bytes(b'{"name": "Caf\xe9"}')                       # old cp1252 file
    assert ss.read_json_retry(p) == {"name": "Caf\u00e9"}


def test_SP_09_reader_never_sees_partial_file(tmp_path):
    p = tmp_path / "h.json"
    small, big = {"items": [1]}, {"items": list(range(500))}
    ss.atomic_write_json(p, small)
    reads, bad = _hammer(p, lambda: ss.atomic_write_json(p, small),
                         lambda: ss.atomic_write_json(p, big),
                         lambda d: len(d["items"]) in (1, 500), rounds=100)
    assert reads > 50, f"reader barely ran ({reads})"
    assert not bad, f"{len(bad)} bad reads e.g. {bad[:3]}"
    assert not _temps(p)


# ══ programs ═════════════════════════════════════════════════════════════════

# ── rag_preprocessor: main settings (~/.rag_config.json) ─────────────────────
@pytest.fixture
def rp_cfg(tmp_path):
    import rag_preprocessor as rp
    p = tmp_path / ".rag_config.json"
    with patch.object(rp, "CONFIG_FILE", p):
        yield rp, p


def test_SP_10_save_config_keeps_other_settings(rp_cfg):
    rp, p = rp_cfg
    p.write_text(json.dumps({"provider_api_keys": {"x": "KEEP"}, "model": "m1"}), encoding="utf-8")
    assert rp.save_config(ocr_debug=True) is True
    d = json.loads(p.read_text(encoding="utf-8"))
    assert d == {"provider_api_keys": {"x": "KEEP"}, "model": "m1", "ocr_debug": True}
    assert not _temps(p)


def test_SP_11_save_config_refuses_to_overwrite_unreadable_file(rp_cfg):
    """The old code read a damaged file as {} and saved back ONLY the changed
    key - wiping API keys and every other setting. Now: refuse, keep a copy."""
    rp, p = rp_cfg
    p.write_text('{"provider_api_keys": {"x": "KEEP"}, "mod', encoding="utf-8")
    before = p.read_bytes()
    assert rp.save_config(ocr_debug=True) is False
    assert p.read_bytes() == before                         # untouched
    assert list(p.parent.glob(p.name + ".unreadable-*"))     # copy kept
    assert rp.save_extension_config({".txt"}, set(), set()) is False
    assert p.read_bytes() == before


def test_SP_12_tracking_db_and_email_index_atomic(tmp_path):
    import rag_preprocessor as rp
    t, e = tmp_path / "track.json", tmp_path / "email.json"
    with patch.object(rp, "TRACKING_DB", t), patch.object(rp, "EMAIL_INDEX_DB", e):
        assert rp.save_email_index({"m1": {"a": 1}}) is True
        assert rp.load_email_index() == {"m1": {"a": 1}}
        assert rp.save_tracking_database({}) is True
        assert json.loads(t.read_text(encoding="utf-8")) == {}
        assert not _temps(t) and not _temps(e)


# ── ai_prowler_mcp: allowlists, approval queue, task queue, licence cache ────
@pytest.fixture
def mcp_files(tmp_path):
    mcp = pytest.importorskip("ai_prowler_mcp")
    names = {"_WRITABLE_DIRS_FILE": "w.json", "_ACCESS_ONLY_DIRS_FILE": "a.json",
             "_WRITE_APPROVAL_QUEUE_FILE": "q.json", "_PENDING_TASKS_FILE": "pt.json",
             "_LICENSE_CACHE_PATH": "lc.json"}
    patches = [patch.object(mcp, n, tmp_path / f) for n, f in names.items() if hasattr(mcp, n)]
    for pa in patches:
        pa.start()
    try:
        yield mcp, {n: tmp_path / f for n, f in names.items()}
    finally:
        for pa in patches:
            pa.stop()


def test_SP_13_mcp_writable_allowlist_hammer(mcp_files, tmp_path):
    mcp, f = mcp_files
    one = [str(tmp_path / "only")]
    many = [str(tmp_path / f"d{i:03d}") for i in range(80)]
    assert mcp._writable_allowlist_save(one) is True
    reads, bad = _hammer(f["_WRITABLE_DIRS_FILE"],
                         lambda: mcp._writable_allowlist_save(one),
                         lambda: mcp._writable_allowlist_save(many),
                         lambda d: len(d) in (1, 80), rounds=80)
    assert reads > 30 and not bad, (reads, bad[:3])
    assert len(mcp._writable_allowlist_load()) == 80              # last save was `many`
    assert mcp.access_allowlist_save(one) is True
    assert mcp.access_allowlist_load() == one
    assert not _temps(f["_WRITABLE_DIRS_FILE"])


def test_SP_14_mcp_pending_tasks_and_licence_cache(mcp_files):
    mcp, f = mcp_files
    tasks = [{"task_id": "ZTEST-1", "status": "pending", "note": "caf\u00e9"}]
    mcp._save_pending_tasks(tasks)
    assert mcp._load_pending_tasks() == tasks
    assert "caf\u00e9" in f["_PENDING_TASKS_FILE"].read_text(encoding="utf-8")   # ensure_ascii=False kept
    mcp._save_license_cache_for("ZTEST-KEY", {"tier": "x"})
    assert mcp._load_license_cache_for("ZTEST-KEY").get("tier") == "x"
    assert not _temps(f["_PENDING_TASKS_FILE"]) and not _temps(f["_LICENSE_CACHE_PATH"])


def test_SP_15_mcp_file_tools_write_atomically_and_fall_back(tmp_path):
    mcp = pytest.importorskip("ai_prowler_mcp")
    p = tmp_path / "doc.txt"
    mcp._ss_overwrite_user_file(p, b"one")
    assert p.read_bytes() == b"one" and not _temps(p)

    def locked(a, b):
        raise PermissionError(13, "editor has it open")

    with patch.object(ss.os, "replace", locked):          # editor holds the file
        mcp._ss_overwrite_user_file(p, b"two")            # falls back, never fails
    assert p.read_bytes() == b"two" and not _temps(p)


# ── task_queue_automation: queue config, status, keys, tokens ────────────────
def test_SP_16_task_queue_config_and_key_atomic(tmp_path):
    tqa = pytest.importorskip("task_queue_automation")
    cfg = tmp_path / "tq.json"
    with patch.object(tqa, "CONFIG_PATH", cfg), patch.object(tqa, "AI_PROWLER_HOME", tmp_path):
        c = tqa.load_config()
        c["ztest_marker"] = 1
        tqa.save_config(c)
        assert tqa.load_config().get("ztest_marker") == 1
        assert not _temps(cfg)
    # conftest points the key paths into tmp_path
    tqa.save_api_key("sk-ztest-not-a-real-key")
    assert tqa.api_key_path("anthropic").read_text(encoding="utf-8") == "sk-ztest-not-a-real-key"
    assert not _temps(tqa.api_key_path("anthropic"))


# ── custom tasks / scheduler / learnings / mobile activator ──────────────────
def test_SP_17_custom_tasks_unreadable_file_is_kept_aside(tmp_path):
    ctm = pytest.importorskip("custom_tasks_manager")
    p = tmp_path / "custom_tasks.json"
    with patch.object(ctm, "CUSTOM_TASKS_PATH", p):
        assert ctm.save_custom_tasks([{"id": "ZTEST"}]) is True
        assert ctm.load_custom_tasks() == [{"id": "ZTEST"}]
        p.write_text('[{"id": "ZT', encoding="utf-8")         # damaged
        assert ctm.load_custom_tasks() == []
        assert list(tmp_path.glob("custom_tasks.json.unreadable-*"))
        assert not _temps(p)


def test_SP_18_scheduler_and_learnings_atomic(tmp_path):
    se = pytest.importorskip("scheduler_engine")
    p = tmp_path / "sched.json"
    with patch.object(se, "CONFIG_PATH", p):
        c = se.load_config()
        c["ztest"] = True
        se.save_config(c)
        assert se.load_config().get("ztest") is True
        assert not _temps(p)

    sl = pytest.importorskip("self_learning")
    lf = tmp_path / "learnings.json"
    with patch.object(sl, "LEARNINGS_FILE", lf), patch.object(sl, "_ensure_dir", lambda: None):
        sl._save_db({"version": 1, "learnings": [{"id": "ZTEST"}]})
        assert sl._load_db()["learnings"] == [{"id": "ZTEST"}]
        lf.write_text('{"version": 1, "learn', encoding="utf-8")   # damaged
        assert sl._load_db()["learnings"] == []
        assert list(tmp_path.glob("learnings.json.unreadable-*"))   # recoverable copy
        assert not _temps(lf)


def test_SP_19_mobile_activator_never_saves_over_unreadable_config(tmp_path):
    ma = pytest.importorskip("mobile_activator")
    p = tmp_path / "config.json"
    assert ma._load_json_for_update(p) == {}                   # first save: fine
    ma._write_json(p, {"remote_token": "KEEP", "x": 1})
    assert ma._load_json_for_update(p)["remote_token"] == "KEEP"
    p.write_text('{"remote_token": "KE', encoding="utf-8")
    with pytest.raises(RuntimeError):
        ma._load_json_for_update(p)
    assert not _temps(p)


# ══ SP-20 source guard ═══════════════════════════════════════════════════════
# A protected file must never again be saved with open(...,'w') / write_text().
_PROGRAMS = ["rag_preprocessor.py", "ai_prowler_mcp.py", "rag_gui.py", "self_learning.py",
             "task_queue_automation.py", "scheduler_engine.py", "custom_tasks_manager.py",
             "subscription_client.py", "mobile_activator.py", "setup_wizard.py"]

# Variables that hold a protected file's path.
_PROTECTED_VARS = {
    "CONFIG_FILE", "TRACKING_DB", "AUTO_UPDATE_LIST", "EMAIL_INDEX_DB", "LICENSE_FILE",
    "_WRITABLE_DIRS_FILE", "_ACCESS_ONLY_DIRS_FILE", "_WRITE_APPROVAL_QUEUE_FILE",
    "_PENDING_TASKS_FILE", "_pending_file", "_LICENSE_CACHE_PATH", "CONFIG_PATH", "STATUS_PATH",
    "OAUTH_TOKEN_PATH", "OAUTH_TOKEN_PLAIN_PATH", "CUSTOM_TASKS_PATH",
    "BUILTIN_ANALYSIS_CONFIG_PATH", "_LAST_RUN_PATH", "LEARNINGS_FILE", "JOBS_SKIPS_PATH",
    "seats_path", "GENERATED_MCP_CONFIG_PATH", "now_config_path", "settings_path",
    "writable_path", "pending_path", "tasks_path", "_learnings_file", "token_file_cfg",
}
# File names that mark a short local variable (p, _p, f ...) as protected when
# they appear in the few lines above the write.
_PROTECTED_NAMES = re.compile(
    r"pending_tasks\.json|license_seats\.json|email_config\.json|users\.json|"
    r"rag_writable_dirs|rag_access_only_dirs|rag_writable_pending|learnings\.json|"
    r"['\"]config\.json['\"]|rag_file_tracking|custom_tasks\.json|oauth_token|api_key\.txt")
# Functions that ARE the safe-save (or its partial-update fallback).
_ALLOWED_FUNCS = re.compile(r"^(_ss_|_atomic_|atomic_|_save_db$)")


def _in_place_writes(src: str):
    tree = ast.parse(src)
    lines = src.splitlines()
    out = []

    def visit(node, func):
        for ch in ast.iter_child_nodes(node):
            f = ch.name if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if (isinstance(ch, ast.ExceptHandler) and ch.type is not None
                    and "ImportError" in ast.unparse(ch.type)):
                f = "_ss_import_fallback"        # plain write only if safe_save.py is missing
            if isinstance(ch, ast.Call) and not (func and _ALLOWED_FUNCS.match(func)):
                target = None
                fn = ch.func
                if isinstance(fn, ast.Attribute) and fn.attr in ("write_text", "write_bytes"):
                    target = fn.value
                elif isinstance(fn, ast.Name) and fn.id == "open" and ch.args:
                    mode = ch.args[1] if len(ch.args) > 1 else next(
                        (k.value for k in ch.keywords if k.arg == "mode"), None)
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "w" in mode.value:
                        target = ch.args[0]
                if target is not None:
                    tname = ast.unparse(target)
                    last = tname.split(".")[-1].strip("()")
                    window = "\n".join(lines[max(0, ch.lineno - 9):ch.lineno])
                    if last in _PROTECTED_VARS or (len(last) <= 3 and _PROTECTED_NAMES.search(window)):
                        out.append(f"{ch.lineno}: {lines[ch.lineno - 1].strip()[:110]}")
            visit(ch, f)

    visit(tree, None)
    return out


@pytest.mark.parametrize("fname", _PROGRAMS)
def test_SP_20_no_in_place_save_of_protected_files(fname):
    src = (_SRC / fname).read_text(encoding="utf-8")
    hits = _in_place_writes(src)
    assert not hits, f"{fname}: protected file saved in place (use safe_save):\n" + "\n".join(hits)


def test_SP_20b_guard_catches_the_old_pattern():
    """The guard itself works: it flags the exact pre-fix code."""
    old = ("def save(entries):\n"
           "    with open(_WRITABLE_DIRS_FILE, 'w', encoding='utf-8') as f:\n"
           "        json.dump(entries, f)\n"
           "def q():\n"
           "    _p = Path.home() / '.ai-prowler' / 'pending_tasks.json'\n"
           "    _p.write_text('[]', encoding='utf-8')\n")
    assert len(_in_place_writes(old)) == 2
    ok = "def _ss_write_text(path, text):\n    Path(path).write_text(text)\n"
    assert _in_place_writes(ok) == []
