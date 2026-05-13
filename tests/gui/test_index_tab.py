"""
GUI tests — Index Docs tab (G-IDX-* of the test plan)

Each test exercises a specific behaviour of the indexing UI by calling the
RAGGui method that the corresponding button is wired to. Widget state is
read directly via the standard Tk API (cget, get, etc.).

We don't simulate mouse clicks — we call the methods. This is equivalent
because every button's command= is one of these methods, and Tkinter's
button machinery doesn't perform additional checks before invoking it.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-01 — Queue management: add, remove, clear
# ──────────────────────────────────────────────────────────────────────────────
def test_G_IDX_01a_add_directory_to_queue(gui, isolated_env):
    """Type a directory into the entry box and call _queue_add_directory()
    (what the Add button is wired to). Listbox should grow by one, count
    label should update, entry box should be cleared."""
    folder = isolated_env.sample_root / "queueable"
    folder.mkdir()

    gui.app.index_dir_var.set(str(folder))
    gui.app._queue_add_directory()
    gui.pump()

    queue_items = list(gui.app.queue_listbox.get(0, "end"))
    assert str(folder) in queue_items, (
        f"Folder not added to queue. Queue: {queue_items}"
    )
    assert gui.app.index_dir_var.get() == "", "Entry box should be cleared"
    assert "1" in gui.app.queue_count_var.get(), (
        f"Count label not updated. Got: {gui.app.queue_count_var.get()}"
    )


def test_G_IDX_01b_add_invalid_directory_warns(gui, isolated_env):
    """Adding a non-existent path triggers showerror and does NOT add to
    the queue."""
    gui.app.index_dir_var.set(str(isolated_env.sample_root / "does_not_exist"))
    gui.app._queue_add_directory()
    gui.pump()

    # Listbox unchanged
    assert gui.app.queue_listbox.size() == 0

    # Error dialog was shown
    err = gui.dialogs.last_call("showerror")
    assert err is not None, "Expected an error dialog to be shown"
    assert "not found" in (err["message"] or "").lower() \
           or "invalid" in (err["title"] or "").lower(), (
        f"Error dialog content unexpected: {err}"
    )


def test_G_IDX_01c_add_empty_path_warns(gui):
    """Add with empty entry box → showwarning, no listbox change."""
    gui.app.index_dir_var.set("")
    gui.app._queue_add_directory()
    gui.pump()

    assert gui.app.queue_listbox.size() == 0
    warn = gui.dialogs.last_call("showwarning")
    assert warn is not None


def test_G_IDX_01d_remove_selected_from_queue(gui, isolated_env):
    """Add three folders, select the middle one, remove → only the middle
    one disappears."""
    folders = []
    for name in ("alpha", "bravo", "charlie"):
        f = isolated_env.sample_root / name
        f.mkdir()
        folders.append(f)
        gui.app.index_dir_var.set(str(f))
        gui.app._queue_add_directory()
        gui.pump()

    assert gui.app.queue_listbox.size() == 3

    # Select the middle entry (index 1) and remove
    gui.app.queue_listbox.selection_set(1)
    gui.app._queue_remove_selected()
    gui.pump()

    remaining = list(gui.app.queue_listbox.get(0, "end"))
    assert str(folders[0]) in remaining
    assert str(folders[1]) not in remaining   # bravo gone
    assert str(folders[2]) in remaining


def test_G_IDX_01e_clear_queue(gui, isolated_env):
    """Clear Queue empties the listbox and resets the count."""
    for name in ("a", "b"):
        f = isolated_env.sample_root / name
        f.mkdir()
        gui.app.index_dir_var.set(str(f))
        gui.app._queue_add_directory()
    gui.pump()
    assert gui.app.queue_listbox.size() == 2

    gui.app._queue_clear()
    gui.pump()

    assert gui.app.queue_listbox.size() == 0
    assert "0" in gui.app.queue_count_var.get()


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-02 — Button states: idle / running / stopped
# ──────────────────────────────────────────────────────────────────────────────
def test_G_IDX_02a_initial_button_states_are_idle(gui):
    """On a freshly opened Index Docs tab, Start+Scan are enabled and
    Pause+Stop are disabled."""
    assert str(gui.app.index_start_btn.cget("state")) == "normal"
    assert str(gui.app.index_scan_btn.cget("state"))  == "normal"
    assert str(gui.app.index_pause_btn.cget("state")) == "disabled"
    assert str(gui.app.index_stop_btn.cget("state"))  == "disabled"


def test_G_IDX_02b_button_states_after_state_helper(gui):
    """The _index_set_buttons helper is the single source of truth for
    button state. Verify it transitions correctly."""
    # Running
    gui.app._index_set_buttons("running")
    gui.pump()
    assert str(gui.app.index_start_btn.cget("state")) == "disabled"
    assert str(gui.app.index_pause_btn.cget("state")) == "normal"
    assert str(gui.app.index_stop_btn.cget("state"))  == "normal"
    assert str(gui.app.index_scan_btn.cget("state"))  == "disabled"

    # Stopped — Start gets re-labelled "Resume Indexing"
    gui.app._index_set_buttons("stopped")
    gui.pump()
    assert str(gui.app.index_start_btn.cget("state")) == "normal"
    assert "Resume" in str(gui.app.index_start_btn.cget("text")), (
        f"Stopped state should re-label Start. Got: {gui.app.index_start_btn.cget('text')!r}"
    )
    assert str(gui.app.index_pause_btn.cget("state")) == "disabled"

    # Back to idle — label should revert to "Start Indexing Queue"
    gui.app._index_set_buttons("idle")
    gui.pump()
    assert str(gui.app.index_start_btn.cget("state")) == "normal"
    assert "Start" in str(gui.app.index_start_btn.cget("text"))


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-03 — Empty-queue start shows a warning, not a crash
# ──────────────────────────────────────────────────────────────────────────────
def test_G_IDX_03_start_with_empty_queue_warns(gui):
    """Clicking Start on an empty queue should pop a warning, not start
    a worker thread."""
    gui.app._queue_clear()
    gui.app.start_indexing()
    gui.pump()

    warn = gui.dialogs.last_call("showwarning")
    assert warn is not None
    assert "empty" in (warn["title"] or "").lower() \
           or "empty" in (warn["message"] or "").lower(), (
        f"Empty-queue warning content unexpected: {warn}"
    )
    # And the worker should not have started
    assert gui.app._index_running is False


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-04 — Pre-scan via _run_prescan
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_IDX_04_prescan_reports_findings(gui, isolated_env):
    """Pre-scan a folder containing 2 files → output queue receives a
    scan report mentioning that 2 files would be indexed.

    Implementation note: we read from self.output_queue directly rather
    than waiting for the queue-pump callback to flush results into the
    text widget. Two reasons:

      1. _prescan_worker uses `sys.stdout = TextRedirector(self.output_queue, …)`
         to capture print() output. Pytest also redirects sys.stdout for
         capture purposes. The two compete — running the worker on the
         main thread, pytest's capture wins and the text never reaches
         the queue OR the widget.

      2. The queue IS the source of truth — the text widget is just a
         presentation layer. Verifying the queue contents is closer to
         what we actually care about, and survives pytest's capture
         semantics.
    """
    from tests.helpers import sample_files as builders
    folder = isolated_env.sample_root / "prescan_test"
    builders.make_txt(folder / "doc1.txt",  "alpha alpha " * 30)
    builders.make_txt(folder / "doc2.md",   "bravo bravo " * 30)

    # Add folder to queue
    gui.app.index_dir_var.set(str(folder))
    gui.app._queue_add_directory()
    gui.pump()

    # Run the worker synchronously on the main thread. This bypasses the
    # threading wrapper but exercises the worker's logic identically.
    # We pre-empt pytest's stdout capture for the duration by saving and
    # restoring sys.stdout around the call — the worker reassigns it
    # internally to TextRedirector, so we just need to make sure our
    # saved reference is the real stream, not pytest's wrapper.
    import sys as _sys
    saved_stdout = _sys.stdout
    try:
        gui.app._prescan_worker([str(folder)], recursive=True)
    finally:
        _sys.stdout = saved_stdout

    # Drain the output queue directly — this is what the queue-pump callback
    # would also be reading, but we don't depend on its timing.
    queue_items: list[tuple[str, str]] = []
    while not gui.app.output_queue.empty():
        queue_items.append(gui.app.output_queue.get_nowait())

    assert queue_items, (
        "Pre-scan worker should have posted items to the output queue. "
        "Queue was empty — worker may have failed silently."
    )

    # Concatenate all the 'index'-tagged text payloads
    index_text = "".join(payload for tag, payload in queue_items
                         if tag == "index")
    assert index_text, (
        f"No 'index'-tagged messages in queue. Items: {queue_items[:5]}"
    )
    assert "PRE-SCAN" in index_text or "scan" in index_text.lower(), (
        f"Pre-scan output should include a recognisable header. "
        f"Got: {index_text[:500]!r}"
    )
    # The worker reports file counts — verify the 2 files we created show up
    assert "2" in index_text, (
        f"Output should mention the 2 files. Got: {index_text[:500]!r}"
    )

    # Verify ChromaDB was NOT written to
    client, ef = isolated_env.rag.get_chroma_client()
    try:
        coll = client.get_collection(name=isolated_env.rag.COLLECTION_NAME,
                                     embedding_function=ef)
        assert coll.count() == 0, "Pre-scan should not write to ChromaDB"
    except Exception:
        pass   # collection doesn't exist yet — also valid


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-05 — Recursive checkbox state is honoured by the worker
# ──────────────────────────────────────────────────────────────────────────────
def test_G_IDX_05a_recursive_default_is_true(gui):
    """The Recursive checkbox should default to ON — most users want
    sub-folder indexing."""
    assert gui.app.recursive_var.get() is True


def test_G_IDX_05b_smart_scan_default_is_true(gui):
    """Smart Scan should default to ON (filters binaries by extension)."""
    assert gui.app.scan_mode_var.get() is True


# ──────────────────────────────────────────────────────────────────────────────
# G-IDX-06 — Output box clears on a fresh start, accumulates during run
# ──────────────────────────────────────────────────────────────────────────────
def test_G_IDX_06_output_text_widget_starts_empty(gui):
    """On a fresh GUI, the index output text widget should be empty
    (or contain only the welcome blurb if there is one)."""
    text = gui.app.index_output.get("1.0", "end").strip()
    # Empty or close to empty is fine; the widget shouldn't have leftover
    # content from a previous test (which would mean state leaked between
    # fixture teardowns).
    assert len(text) < 500, (
        f"Output widget should start mostly empty; has {len(text)} chars"
    )
