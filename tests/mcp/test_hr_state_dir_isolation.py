"""
tests/mcp/test_hr_state_dir_isolation.py
=========================================
Tests for the AIPROWLER_TEST_STATE_DIR path-isolation fix applied to HR's own
mutable state (2026-08-28) — the item that was explicitly deferred as
"option 4" earlier in this engagement and picked up as a follow-on task.

WHAT CHANGED IN ai_prowler_mcp.py / hr_scheduler.py
----------------------------------------------------
Before this fix, `_HR_ROOT_DIR` (= the directory containing ai_prowler_mcp.py,
i.e. the real AI-Prowler install dir) was used, unconditionally, both for:
  (a) HR's read-only shipped assets (hr_state_rules.json, hr_task_templates
      .json, hr_forms_library.json, the /hr PWA bundle) — these are never
      written to, so there was never an isolation problem here, and
  (b) HR's MUTABLE state (hr_db.json, uploaded documents under doc_root,
      and hr_scheduler.py's hr_task_tracking.json) — these ARE written to
      by normal operation, so any in-process or subprocess test that
      exercised the real code paths would have written to the operator's
      real install directory. That is exactly why every other HR test file
      in this suite uses local mirror reimplementations instead of the real
      functions.

The fix introduces `_HR_STATE_DIR` (ai_prowler_mcp.py) and
`_HR_SCHED_STATE_DIR` (hr_scheduler.py), each resolving to
`os.environ["AIPROWLER_TEST_STATE_DIR"]` when that var is set (mirroring the
existing `_state_dir()` hook used elsewhere in ai_prowler_mcp.py for
config.json/users.json). Only (b) above was repointed at `_HR_STATE_DIR` —
(a) deliberately still resolves under `_HR_ROOT_DIR`, since redirecting
read-only assets would serve no isolation purpose.

UPDATE (2026-08-29): the non-test default was ALSO changed, because it was
itself a real bug, not just a theoretical isolation gap. `_HR_STATE_DIR`
used to fall back to `_HR_ROOT_DIR` (the install dir) when
AIPROWLER_TEST_STATE_DIR was unset — on the real Windows install that's
"C:\\Program Files\\AI-Prowler", which a non-elevated process cannot write to.
This was confirmed against the real mcp_server.log: every
`POST /hr-api/setup/complete` was throwing `PermissionError` trying to
create `hr_db.json.tmp` there, which is why the Company Setup wizard could
never actually save (surfaced to the user as a misleading "check
connection" toast). The non-test default now resolves to a per-user,
always-writable folder (`~/.ai-prowler/hr`), matching how the rest of the
app already stores mutable state — AIPROWLER_TEST_STATE_DIR still overrides
it exactly as before for the test sandbox.

SAFETY (per explicit user requirement — read before editing this file)
------------------------------------------------------------------------
This file does NOT import ai_prowler_mcp.py or hr_scheduler.py, does NOT
start any background thread or live server, and does NOT touch the real
hr_db.json / hr_task_tracking.json / hr_documents on the AI-Prowler install.

  - TestStateDirResolutionLogic / TestSchedStateDirResolutionLogic reimplement
    the exact one-line resolution logic locally (the same "local mirror"
    pattern test_hr_scheduler.py and friends already use) and exercise it
    against synthetic env-var values only — no real file ever touched.
  - The Test*SourceWiring classes read the real ai_prowler_mcp.py /
    hr_scheduler.py files as plain text (read-only) and assert on their
    structure/content — same "structural regression test" style as
    tests/gui/test_pwa_asset_paths_match_jobs_route.py and
    tests/analysis/test_hr_scheduler.py's own TestJobRegistryStructure.

NOTE ON SCOPE
-------------
A genuine subprocess-level e2e test (spawn the real ai_prowler_mcp.py with
AIPROWLER_TEST_STATE_DIR set to a pytest tmp_path, hit /hr-api/employees over
real HTTP, and assert the real install's hr_db.json is untouched) is now
possible thanks to this fix, following the exact pattern already proven safe
in tests/e2e/test_server_e2e.py (its own docstring documents the same
AIPROWLER_TEST_STATE_DIR + test_mode:true sandboxing this file relies on).
That is deliberately left as a separate, larger follow-up rather than folded
into this change: it means driving the OAuth/PKCE + license-validation
machinery in _run_http (or the users.json/RBAC setup in _run_server_mode)
just to reach the HR routes, which is real infrastructure worth building and
reviewing on its own rather than rushed in alongside a path-resolution fix.

Run:
    run_tests.bat tests\\mcp\\test_hr_state_dir_isolation.py -v
"""

import os
import pytest

SRC_ROOT = os.environ.get(
    "AI_PROWLER_SRC",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
AI_PROWLER_PATH = os.path.join(SRC_ROOT, "ai_prowler_mcp.py")
HR_SCHEDULER_PATH = os.path.join(SRC_ROOT, "hr_scheduler.py")


# ── Local mirrors of the resolution logic (deliberately NOT imported) ───────

_REAL_USER_HR_STATE_DIR = os.path.join(os.path.expanduser("~"), ".ai-prowler", "hr")


def _mirror_hr_state_dir(env_value, root_dir=_REAL_USER_HR_STATE_DIR):
    """Mirrors (as of the 2026-08-29 fix): (_hros.environ.get(
    "AIPROWLER_TEST_STATE_DIR", "").strip() or
    _hros.path.join(_hros.path.expanduser("~"), ".ai-prowler", "hr"))"""
    td = (env_value or "").strip()
    return td if td else root_dir


def _mirror_hr_sched_state_dir(env_value, root_dir=_REAL_USER_HR_STATE_DIR):
    """Mirrors (as of the 2026-08-29 fix): os.environ.get(
    "AIPROWLER_TEST_STATE_DIR", "").strip() or
    os.path.join(os.path.expanduser("~"), ".ai-prowler", "hr")"""
    td = (env_value or "").strip()
    return td if td else root_dir


class TestStateDirResolutionLogic:
    """_HR_STATE_DIR (ai_prowler_mcp.py)."""

    def test_env_var_unset_falls_back_to_user_state_dir(self):
        assert _mirror_hr_state_dir(None) == _REAL_USER_HR_STATE_DIR
        assert _mirror_hr_state_dir("") == _REAL_USER_HR_STATE_DIR

    def test_env_var_whitespace_only_falls_back_to_user_state_dir(self):
        # .strip() must treat "   " the same as unset, matching _state_dir()'s
        # own existing AIPROWLER_TEST_STATE_DIR handling elsewhere in the file.
        assert _mirror_hr_state_dir("   ") == _REAL_USER_HR_STATE_DIR
        assert _mirror_hr_state_dir("\t\n") == _REAL_USER_HR_STATE_DIR

    def test_env_var_set_overrides_root_dir(self):
        assert _mirror_hr_state_dir("/tmp/sandbox_abc") == "/tmp/sandbox_abc"

    def test_env_var_set_with_surrounding_whitespace_is_stripped(self):
        assert _mirror_hr_state_dir("  /tmp/sandbox_abc  ") == "/tmp/sandbox_abc"

    def test_default_now_resolves_under_user_home_not_install_dir(self):
        """Regression guard for the 2026-08-29 fix: a real (non-test) launch
        never sets AIPROWLER_TEST_STATE_DIR, so _HR_STATE_DIR must resolve to
        the per-user ~/.ai-prowler/hr folder -- NOT the install dir (that was
        the bug: C:\\Program Files\\AI-Prowler is not writable by a
        non-elevated process, which is why /hr-api/setup/complete used to
        throw PermissionError on hr_db.json.tmp)."""
        install_dir = "C:\\Program Files\\AI-Prowler"
        result = _mirror_hr_state_dir(None)
        assert result == _REAL_USER_HR_STATE_DIR
        assert result != install_dir


class TestSchedStateDirResolutionLogic:
    """_HR_SCHED_STATE_DIR (hr_scheduler.py) — same logic, separate module."""

    def test_env_var_unset_falls_back_to_user_state_dir(self):
        assert _mirror_hr_sched_state_dir(None) == _REAL_USER_HR_STATE_DIR

    def test_env_var_whitespace_only_falls_back_to_user_state_dir(self):
        assert _mirror_hr_sched_state_dir("   ") == _REAL_USER_HR_STATE_DIR

    def test_env_var_set_overrides_root_dir(self):
        assert _mirror_hr_sched_state_dir("/tmp/sandbox_xyz") == "/tmp/sandbox_xyz"

    def test_default_now_resolves_under_user_home_not_install_dir(self):
        """Same 2026-08-29 fix as TestStateDirResolutionLogic, applied to
        hr_scheduler.py's hr_task_tracking.json."""
        install_dir = "C:\\Program Files\\AI-Prowler"
        result = _mirror_hr_sched_state_dir(None)
        assert result == _REAL_USER_HR_STATE_DIR
        assert result != install_dir


# ── Structural checks against the real source (read-only, never imported) ──

@pytest.fixture(scope="module")
def ai_prowler_source():
    with open(AI_PROWLER_PATH, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def hr_scheduler_source():
    with open(HR_SCHEDULER_PATH, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def hr_engine_block(ai_prowler_source):
    """Isolate the HR Backend Engine's path-constants section so assertions
    can't accidentally match an unrelated part of this 22k-line file."""
    start = ai_prowler_source.index("_HR_ROOT_DIR")
    end = ai_prowler_source.index("_hr_db_lock")
    return ai_prowler_source[start:end]


class TestHrStateDirSourceWiring:

    def test_hr_root_dir_still_resolves_from_file_location(self, hr_engine_block):
        # Unchanged: still the real install dir, still __file__-relative.
        assert '_HR_ROOT_DIR            = _hros.path.dirname(_hros.path.abspath(__file__))' \
            in hr_engine_block

    def test_hr_state_dir_honors_test_sandbox_env_var(self, hr_engine_block):
        assert 'AIPROWLER_TEST_STATE_DIR' in hr_engine_block
        assert '_HR_STATE_DIR' in hr_engine_block

    def test_hr_state_dir_default_is_user_home_not_root_dir(self, hr_engine_block):
        """2026-08-29 fix: the non-test default must no longer be
        _HR_ROOT_DIR (the install dir) -- it must be a per-user writable
        folder under the user's home directory."""
        assert 'or _HR_ROOT_DIR)' not in hr_engine_block
        assert '_hros.path.expanduser("~")' in hr_engine_block
        assert '.ai-prowler' in hr_engine_block
        assert '_hros.makedirs(_HR_STATE_DIR, exist_ok=True)' in hr_engine_block

    def test_hr_db_path_uses_state_dir_not_root_dir(self, hr_engine_block):
        assert '_HR_DB_PATH             = _hros.path.join(_HR_STATE_DIR, "hr_db.json")' \
            in hr_engine_block

    def test_readonly_asset_paths_still_use_root_dir(self, hr_engine_block):
        """Deliberate: templates/rules/forms/PWA are shipped, read-only
        assets. They must NOT be redirected by AIPROWLER_TEST_STATE_DIR --
        only HR's mutable state should move."""
        assert '_HR_STATE_RULES_PATH    = _hros.path.join(_HR_ROOT_DIR, "hr_state_rules.json")' \
            in hr_engine_block
        assert '_HR_TASK_TEMPLATES_PATH = _hros.path.join(_HR_ROOT_DIR, "hr_task_templates.json")' \
            in hr_engine_block
        assert '_HR_FORMS_LIBRARY_PATH  = _hros.path.join(_HR_ROOT_DIR, "hr_forms_library.json")' \
            in hr_engine_block
        assert '_HR_PWA_DIR             = _hros.path.join(_HR_ROOT_DIR, "hr")' \
            in hr_engine_block

    def test_create_document_folders_uses_state_dir(self, ai_prowler_source):
        block = ai_prowler_source.split(
            "def _hr_create_document_folders", 1)[1].split("\n\n", 1)[0]
        assert "_HR_STATE_DIR" in block
        assert "_HR_ROOT_DIR" not in block

    def test_handle_document_upload_doc_root_uses_state_dir(self, ai_prowler_source):
        block = ai_prowler_source.split(
            "def _hr_handle_document_upload", 1)[1].split("def _hr_api_route", 1)[0]
        assert 'doc_root if _hros.path.isabs(doc_root) else _hros.path.join(_HR_STATE_DIR, doc_root)' \
            in block
        # Confirm the OLD (unsandboxed) form is fully gone from this function,
        # not just that the new form is present somewhere else in it.
        assert '_hros.path.join(_HR_ROOT_DIR, doc_root)' not in block

    def test_no_stray_root_dir_usages_remain_for_mutable_state(self, ai_prowler_source):
        """Belt-and-suspenders: hr_db.json's path constant line and both
        doc-root base-resolution call sites must each reference
        _HR_STATE_DIR, and there must be exactly one definition of
        _HR_STATE_DIR itself (no accidental duplicate/shadowing)."""
        assert ai_prowler_source.count(
            '_HR_STATE_DIR           = (_hros.environ.get("AIPROWLER_TEST_STATE_DIR"'
        ) == 1
        assert ai_prowler_source.count(
            '_hros.path.join(_HR_STATE_DIR, doc_root)'
        ) == 2  # _hr_create_document_folders + _hr_handle_document_upload


class TestHrSchedulerStateDirSourceWiring:

    def test_sched_state_dir_honors_test_sandbox_env_var(self, hr_scheduler_source):
        assert 'AIPROWLER_TEST_STATE_DIR' in hr_scheduler_source
        assert '_HR_SCHED_STATE_DIR' in hr_scheduler_source

    def test_sched_state_dir_default_is_user_home_not_root_dir(self, hr_scheduler_source):
        """2026-08-29 fix: same as the ai_prowler_mcp.py fix, applied to
        hr_scheduler.py's hr_task_tracking.json."""
        assert 'or _HR_SCHED_ROOT_DIR' not in hr_scheduler_source
        assert 'os.path.expanduser("~")' in hr_scheduler_source
        assert 'os.makedirs(_HR_SCHED_STATE_DIR, exist_ok=True)' in hr_scheduler_source

    def test_sched_root_dir_still_resolves_from_file_location(self, hr_scheduler_source):
        assert '_HR_SCHED_ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))' \
            in hr_scheduler_source

    def test_tracking_path_uses_sched_state_dir_not_root_dir(self, hr_scheduler_source):
        assert '_HR_TRACKING_PATH     = os.path.join(_HR_SCHED_STATE_DIR, "hr_task_tracking.json")' \
            in hr_scheduler_source
        assert '_HR_TRACKING_PATH     = os.path.join(_HR_SCHED_ROOT_DIR, "hr_task_tracking.json")' \
            not in hr_scheduler_source
