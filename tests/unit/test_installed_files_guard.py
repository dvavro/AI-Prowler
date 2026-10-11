"""The installed-files guard really protects ~/.ai-prowler (2026-10-09).

SAFETY: no test here ever aims a write at the REAL installed files. The
write-route tests register a stand-in file in tmp_path as protected and
attack that; the real path's protection is checked with no file I/O at all
(_refuse is called directly). So even a broken guard can't touch the install.
Tests that trigger a refusal take the recorded violation themselves so the
suite-wide check stays green.

Run: run_tests.bat tests\\unit\\test_installed_files_guard.py -v
"""
import json
import os

import pytest

import installed_files_guard as g

REAL_CONFIG = g.REAL_STATE_DIR / "config.json"


@pytest.fixture
def stand_in(tmp_path, monkeypatch):
    """A file named config.json in tmp_path that the guard treats as installed."""
    p = tmp_path / "config.json"
    p.write_text('{"edition": "home", "mode": "personal"}', encoding="utf-8")
    keys = dict(g._PROTECTED_KEYS)
    keys[g._key(p)] = p
    monkeypatch.setattr(g, "_PROTECTED_KEYS", keys)
    return p


def test_guard_is_installed_for_the_whole_run():
    assert g._installed
    assert open is g._open and os.replace is g._replace and os.unlink is g._unlink


def test_the_real_installed_files_are_on_the_protected_list():
    for name in ("config.json", "users.json", "email_config.json",
                 "remote_access.json", "license_seats.json"):
        assert g._key(g.REAL_STATE_DIR / name) in g._PROTECTED_KEYS, name
    with pytest.raises(PermissionError, match="TEST GUARD"):
        g._refuse(REAL_CONFIG, "write")            # decision only — no file is opened
    assert g.take_violations()


@pytest.mark.parametrize("how", ["open_w", "open_a", "path_write_text", "path_write_bytes",
                                 "os_open", "os_replace", "os_unlink", "path_unlink",
                                 "path_open_rplus"])
def test_every_write_route_is_refused(how, stand_in, tmp_path):
    before = stand_in.read_bytes()
    src = tmp_path / "other.json"
    src.write_text("{}", encoding="utf-8")
    actions = {
        "open_w": lambda: open(stand_in, "w"),
        "open_a": lambda: open(str(stand_in), "a"),
        "path_write_text": lambda: stand_in.write_text('{"mode": "server"}'),
        "path_write_bytes": lambda: stand_in.write_bytes(b"{}"),
        "os_open": lambda: os.open(str(stand_in), os.O_WRONLY | os.O_TRUNC),
        "os_replace": lambda: os.replace(src, stand_in),
        "os_unlink": lambda: os.unlink(stand_in),
        "path_unlink": lambda: stand_in.unlink(),
        "path_open_rplus": lambda: stand_in.open("r+"),
    }
    with pytest.raises(PermissionError, match="TEST GUARD"):
        actions[how]()
    assert g.take_violations(), "the refusal wasn't recorded"
    assert stand_in.read_bytes() == before, "the protected file changed"


def test_reading_a_protected_file_is_allowed(stand_in):
    assert json.loads(stand_in.read_text(encoding="utf-8"))["mode"] == "personal"
    assert not g.take_violations()


def test_unprotected_files_are_untouched_by_the_guard(tmp_path):
    p = tmp_path / "sub" / "config.json"       # same NAME, not protected
    p.parent.mkdir()
    p.write_text('{"a": 1}', encoding="utf-8")
    os.replace(p, tmp_path / "moved.json")
    assert not g.take_violations()


def test_redirect_sends_reads_writes_and_exists_to_the_sandbox(stand_in, tmp_path):
    sandbox = tmp_path / "sandbox_config.json"
    sandbox.write_text(json.dumps({"edition": "business", "mode": "server"}), encoding="utf-8")
    g.redirect(stand_in, sandbox)
    try:
        assert json.loads(stand_in.read_text(encoding="utf-8"))["mode"] == "server"
        stand_in.write_text(json.dumps({"edition": "home", "mode": "x"}), encoding="utf-8")
        with open(stand_in, encoding="utf-8") as f:
            assert json.load(f)["mode"] == "x"
        sandbox.unlink()
        assert not stand_in.exists() and not os.path.exists(str(stand_in))
    finally:
        g.clear_redirect(stand_in)
    assert not g.take_violations()
    assert json.loads(stand_in.read_text(encoding="utf-8"))["mode"] == "personal", \
        "a redirected write reached the protected file"


def test_a_change_made_behind_the_guard_is_put_back(stand_in, tmp_path, monkeypatch):
    """A SUBPROCESS bypasses the in-process patch; check_and_restore() must
    put the original back and keep the changed copy."""
    monkeypatch.setattr(g, "PROTECTED", (stand_in,))
    monkeypatch.setattr(g, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setitem(g._snapshot, str(stand_in), stand_in.read_bytes())
    with g._real["open"](stand_in, "w", encoding="utf-8") as f:     # behind the guard's back
        f.write('{"edition": "business", "mode": "server"}')
    problems = g.check_and_restore()
    assert problems and "put back" in problems[0]
    assert json.loads(stand_in.read_text(encoding="utf-8")) == {"edition": "home", "mode": "personal"}
    assert list((tmp_path / "backups").glob("config.json.changed_by_test.*")), "changed copy not kept"
