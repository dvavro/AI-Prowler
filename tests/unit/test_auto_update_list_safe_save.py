"""
tests/unit/test_auto_update_list_safe_save.py
=============================================
Safe-save for the tracked-folders list (~/.rag_auto_update_dirs.json),
2026-10-19 (David).

THE BUG
-------
save_auto_update_list() rewrote the file in place: open(path, 'w') truncates
it to EMPTY, then json.dump fills it in. Anything that read it in between (the
MCP read-allowlist check, the GUI, the file watcher, another AI-Prowler
process) saw an empty / half-written file. load_auto_update_list() returns []
on a bad read, so "nothing is tracked" for a moment - and a caller that then
added a folder and saved could wipe the whole list. Found by the 2026-10-19
regression run (G-UPD-04: JSONDecodeError at char 0 while polling the file).

THE FIX
-------
_atomic_write_json(): write a temp file in the same folder, fsync, then
os.replace() it over the real file (atomic: readers see old or new, never
partial). On Windows os.replace() is refused while a reader has the file open,
so it retries briefly. load_auto_update_list() also retries a bad read a few
times before giving up.
"""
import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import rag_preprocessor as rp  # noqa: E402


@pytest.fixture
def auto_list(tmp_path):
    p = tmp_path / ".rag_auto_update_dirs.json"
    with patch.object(rp, "AUTO_UPDATE_LIST", p):
        yield p


def _leftover_temps(p: Path):
    return [x.name for x in p.parent.iterdir() if x.name.startswith(p.name + ".tmp")]


# ── SS-01 ─────────────────────────────────────────────────────────────────────
def test_SS_01_save_writes_valid_json_and_leaves_no_temp_file(auto_list, tmp_path):
    dirs = [str(tmp_path / "A"), str(tmp_path / "B")]
    assert rp.save_auto_update_list(dirs) is True
    data = json.loads(auto_list.read_text(encoding="utf-8"))
    assert data["directories"] == [rp.normalise_path(d) for d in dirs]
    assert "last_updated" in data
    assert rp.load_auto_update_list() == [rp.normalise_path(d) for d in dirs]
    assert not _leftover_temps(auto_list)


# ── SS-02 ─────────────────────────────────────────────────────────────────────
def test_SS_02_reader_never_sees_an_empty_or_partial_file(auto_list, tmp_path):
    """Hammer the file with a reader thread while the list is saved hundreds of
    times, alternating 1 and 60 entries. With the old in-place write the reader
    catches it empty / half-written; with the safe-save it never does."""
    small = [str(tmp_path / "only")]
    big = [str(tmp_path / (f"folder_{i:03d}_" + "x" * 40)) for i in range(60)]
    rp.save_auto_update_list(small)

    stop = threading.Event()
    bad, reads = [], [0]

    def reader():
        while not stop.is_set():
            try:
                txt = auto_list.read_text(encoding="utf-8")
            except PermissionError:
                continue                      # Windows: the swap is happening right now - fine
            reads[0] += 1
            try:
                n = len(json.loads(txt)["directories"])
            except Exception as e:            # empty / truncated / partial JSON
                bad.append(f"{type(e).__name__}: {txt[:60]!r}")
                continue
            if n not in (1, 60):
                bad.append(f"{n} directories")

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        for i in range(300):
            assert rp.save_auto_update_list(big if i % 2 else small) is True
    finally:
        stop.set()
        t.join(10)
    assert reads[0] > 50, f"reader barely ran ({reads[0]} reads) - test proves nothing"
    assert not bad, f"reader saw {len(bad)} bad reads, e.g. {bad[:3]}"
    assert not _leftover_temps(auto_list)


# ── SS-03 ─────────────────────────────────────────────────────────────────────
def test_SS_03_replace_refused_briefly_is_retried(auto_list, tmp_path):
    """Windows refuses os.replace() while another process is reading the file;
    the save must retry instead of failing."""
    rp.save_auto_update_list([str(tmp_path / "old")])
    real_replace, calls = os.replace, [0]

    def flaky(src, dst):
        calls[0] += 1
        if calls[0] <= 3:
            raise PermissionError(13, "The process cannot access the file")
        return real_replace(src, dst)

    with patch.object(rp.os, "replace", flaky):
        assert rp.save_auto_update_list([str(tmp_path / "new")]) is True
    assert calls[0] == 4
    assert rp.load_auto_update_list() == [rp.normalise_path(str(tmp_path / "new"))]
    assert not _leftover_temps(auto_list)


# ── SS-04 ─────────────────────────────────────────────────────────────────────
def test_SS_04_failed_save_keeps_the_old_list_intact(auto_list, tmp_path):
    """If the swap never succeeds, the save reports failure and the ORIGINAL list
    is untouched (the old in-place write would have left it truncated)."""
    rp.save_auto_update_list([str(tmp_path / "keep_me")])
    before = auto_list.read_text(encoding="utf-8")

    def always_locked(src, dst):
        raise PermissionError(13, "locked")

    with patch.object(rp.os, "replace", always_locked), patch.object(rp.time, "sleep", lambda s: None):
        assert rp.save_auto_update_list([str(tmp_path / "other")]) is False
    assert auto_list.read_text(encoding="utf-8") == before
    assert rp.load_auto_update_list() == [rp.normalise_path(str(tmp_path / "keep_me"))]
    assert not _leftover_temps(auto_list)


# ── SS-05 ─────────────────────────────────────────────────────────────────────
def test_SS_05_load_retries_a_momentarily_empty_file(auto_list, tmp_path):
    """An older AI-Prowler process may still rewrite the file in place. If load
    lands on it empty, it retries instead of returning 'nothing tracked'."""
    good = {"directories": [str(tmp_path / "Docs")], "last_updated": "x"}
    auto_list.write_text("", encoding="utf-8")            # mid-rewrite: empty

    def finish_write():
        time.sleep(0.08)
        auto_list.write_text(json.dumps(good), encoding="utf-8")

    t = threading.Thread(target=finish_write)
    t.start()
    got = rp.load_auto_update_list()
    t.join()
    assert got == [rp.normalise_path(str(tmp_path / "Docs"))]


def test_SS_05b_truly_broken_file_still_returns_empty(auto_list):
    """Unchanged behaviour for a file that is genuinely not JSON: [] (no crash)."""
    auto_list.write_text("{ not json", encoding="utf-8")
    with patch.object(rp.time, "sleep", lambda s: None):
        assert rp.load_auto_update_list() == []


def test_SS_05c_missing_file_returns_empty(auto_list):
    assert not auto_list.exists()
    assert rp.load_auto_update_list() == []


# ── SS-06 ─────────────────────────────────────────────────────────────────────
def test_SS_06_adding_folders_while_another_reader_runs_loses_nothing(auto_list, tmp_path):
    """The real-world failure: something keeps reading the list (allowlist check,
    GUI refresh) while folders are added one by one. Every folder must survive."""
    folders = []
    for i in range(25):
        d = tmp_path / "tracked" / f"proj_{i:02d}"
        d.mkdir(parents=True)
        folders.append(d)

    stop = threading.Event()

    def reader():
        while not stop.is_set():
            rp.load_auto_update_list()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        # add_to_auto_update_list() also regenerates the auto-update script on
        # disk - keep the test from writing anything real.
        with patch.object(rp, "generate_auto_update_script", lambda *a, **k: None):
            for d in folders:
                rp.add_to_auto_update_list(str(d))
    finally:
        stop.set()
        t.join(10)
    saved = rp.load_auto_update_list()
    missing = [str(d) for d in folders if not any(rp.path_equals(s, rp.normalise_path(str(d.resolve()))) for s in saved)]
    assert not missing, f"{len(missing)} added folders were lost: {missing[:3]}"
    assert not _leftover_temps(auto_list)


# ── SS-07 ─────────────────────────────────────────────────────────────────────
@pytest.mark.skipif(sys.platform != "win32", reason="case-variant self-heal is Windows-only")
def test_SS_07_self_heal_on_load_also_uses_safe_save(auto_list, tmp_path):
    """load_auto_update_list() rewrites a list with case-variant duplicates; that
    write must go through the safe-save too."""
    auto_list.write_text(json.dumps({"directories": [r"C:\Docs\A", r"c:\docs\a", r"C:\Docs\B"]}), encoding="utf-8")
    seen = []
    real = rp._atomic_write_json

    def spy(path, data, *a, **k):
        seen.append(list(data["directories"]))
        return real(path, data, *a, **k)

    with patch.object(rp, "_atomic_write_json", spy):
        got = rp.load_auto_update_list()
    assert got == [r"C:\Docs\A", r"C:\Docs\B"]
    assert seen == [[r"C:\Docs\A", r"C:\Docs\B"]]
    assert json.loads(auto_list.read_text(encoding="utf-8"))["directories"] == got


# ── SS-08 ─────────────────────────────────────────────────────────────────────
def test_SS_08_no_in_place_writes_of_the_list_remain():
    """Source guard: nothing in rag_preprocessor opens AUTO_UPDATE_LIST for
    writing directly any more - every write goes through _atomic_write_json."""
    src = (Path(rp.__file__)).read_text(encoding="utf-8")
    import re
    hits = re.findall(r"open\(\s*AUTO_UPDATE_LIST\s*,\s*['\"][wa]", src)
    assert not hits, f"in-place write(s) of AUTO_UPDATE_LIST still present: {hits}"
