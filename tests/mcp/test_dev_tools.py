"""
tests/mcp/test_dev_tools.py — D-DEV-NN: dev tools coverage

Exercises syntax_check, lint_check, run_script, and the async
run_script_start / run_script_status / run_script_kill triple end-to-end.
The tools run real subprocesses against real binaries (Python is always
available; non-Python binaries are skipped gracefully if not installed).

Test plan IDs follow D-DEV-NN:

    Group A — _dev_tools_enabled (gate behavior)        D-DEV-01..05
    Group B — syntax_check Python paths                 D-DEV-06..11
    Group C — syntax_check multi-language dispatch      D-DEV-12..17
    Group D — lint_check (Python pyflakes)              D-DEV-18..21
    Group E — run_script (blocking execution)           D-DEV-22..28e
    Group F — internal helpers                          D-DEV-29..32
    Group G — run_script_start/status/kill (async jobs) D-DEV-33..41

Tests that invoke heavyweight binaries are marked @pytest.mark.slow.
Helper-only tests are fast.

IMPORTANT honest notes about this test file:
  • `pyflakes` may not be installed on every dev machine — pyflakes tests
    skip gracefully via pytest.skip() if not available.
  • Non-Python compilers (gcc, node, etc.) are NOT required. Tests check
    BOTH the "binary available → real success" path AND the
    "binary unavailable → clean error message" path.
  • run_script_start async tests spin up real background processes and
    poll run_script_status. They add ~3-5s each. Marked slow.
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def mcp_mod():
    """Import ai_prowler_mcp once per session."""
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def dev_env(isolated_env, mcp_mod, monkeypatch):
    """A writable project root wired into both allowlists, dev tools enabled.

    Mirrors `reindex_env` from test_reindex_after_write.py but minimal: no
    seed corpus, just a clean tracked directory the test can write fixture
    source files into.
    """
    rag = isolated_env.rag
    root = isolated_env.sample_root / "dev_proj"
    root.mkdir()

    # Add to READ allowlist (required by _resolve_allowlisted_path)
    rag.add_to_auto_update_list(str(root))

    # Force _dev_tools_enabled to True regardless of config.json on this box.
    # We don't want test outcomes to depend on the developer's local config.
    monkeypatch.setattr(
        mcp_mod, "_dev_tools_enabled",
        lambda: (True, "test fixture forced enabled"),
    )

    class E:
        pass
    e = E()
    e.rag = rag
    e.root = root
    return e


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _write(dev_env, name: str, content: str) -> str:
    """Write a fixture file inside the dev_env root and return its path."""
    fp = dev_env.root / name
    fp.write_text(content, encoding="utf-8")
    return str(fp)


def _has(binary: str) -> bool:
    """True if `binary` is on PATH."""
    return shutil.which(binary) is not None


def _has_pyflakes() -> bool:
    """True if pyflakes is importable in this Python."""
    import subprocess as _sp
    try:
        rc = _sp.run([sys.executable, "-c", "import pyflakes"],
                     capture_output=True, timeout=10).returncode
        return rc == 0
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# GROUP A — _dev_tools_enabled gate behavior (v7.0.0: always enabled)
# ══════════════════════════════════════════════════════════════════════════════
class TestDevToolsGate:
    """The gate was redesigned in v7.0.0 to always return True. These tests
    lock that behavior in so a future refactor doesn't silently re-tighten."""

    def test_D_DEV_01_gate_returns_true_by_default(self, mcp_mod, monkeypatch):
        """Default config (home/personal) → enabled."""
        monkeypatch.setattr(mcp_mod, "_load_runtime_config", lambda: {})
        enabled, reason = mcp_mod._dev_tools_enabled()
        assert enabled is True, f"expected True, got ({enabled}, {reason})"

    def test_D_DEV_02_gate_true_for_business_server(self, mcp_mod, monkeypatch):
        """Business/server config → still enabled (v7.0.0 unlock)."""
        monkeypatch.setattr(mcp_mod, "_load_runtime_config",
                            lambda: {"edition": "business", "mode": "server"})
        enabled, reason = mcp_mod._dev_tools_enabled()
        assert enabled is True
        assert "business" in reason and "server" in reason

    def test_D_DEV_03_gate_true_for_business_personal(self, mcp_mod, monkeypatch):
        """Business edition + personal mode (child key on personal laptop)
        → enabled. This is the scenario from decision 2."""
        monkeypatch.setattr(mcp_mod, "_load_runtime_config",
                            lambda: {"edition": "business", "mode": "personal"})
        enabled, _ = mcp_mod._dev_tools_enabled()
        assert enabled is True

    def test_D_DEV_04_gate_true_for_mobile(self, mcp_mod, monkeypatch):
        """Mobile edition → enabled."""
        monkeypatch.setattr(mcp_mod, "_load_runtime_config",
                            lambda: {"edition": "mobile", "mode": "personal"})
        enabled, _ = mcp_mod._dev_tools_enabled()
        assert enabled is True

    def test_D_DEV_05_dev_tools_flag_still_recognized(self, mcp_mod, monkeypatch):
        """The legacy `dev_tools: true` flag is preserved as an escape hatch.
        Even though the gate is now always-true, the flag's specific reason
        text should still appear when set."""
        monkeypatch.setattr(mcp_mod, "_load_runtime_config",
                            lambda: {"edition": "business", "mode": "server",
                                     "dev_tools": True})
        enabled, reason = mcp_mod._dev_tools_enabled()
        assert enabled is True
        assert "dev_tools flag set" in reason


# ══════════════════════════════════════════════════════════════════════════════
# GROUP B — syntax_check on Python files
# ══════════════════════════════════════════════════════════════════════════════
class TestSyntaxCheckPython:

    @pytest.mark.slow
    def test_D_DEV_06_valid_python_passes(self, dev_env, mcp_mod):
        fp = _write(dev_env, "ok.py", "x = 1\nprint('hello')\n")
        result = mcp_mod.syntax_check(fp)
        assert "✅" in result, result
        assert "syntax OK" in result
        assert "Python" in result

    @pytest.mark.slow
    def test_D_DEV_07_syntax_error_fails(self, dev_env, mcp_mod):
        fp = _write(dev_env, "bad.py", "def foo(:\n    return 1\n")
        result = mcp_mod.syntax_check(fp)
        assert "❌" in result or "FAILED" in result, result
        # Should NOT claim success
        assert "✅" not in result or "FAILED" in result

    @pytest.mark.slow
    def test_D_DEV_08_undefined_name_passes_syntax(self, dev_env, mcp_mod):
        """syntax_check only checks SYNTAX. A reference to an undefined name
        is a runtime / load-time error and should pass syntax. (This is what
        differentiates syntax_check from lint_check.)"""
        fp = _write(dev_env, "undef.py", "y = undefined_name_xyz\n")
        result = mcp_mod.syntax_check(fp)
        assert "✅" in result, f"Expected success on syntax-valid file, got: {result}"

    @pytest.mark.slow
    def test_D_DEV_09_empty_file_passes(self, dev_env, mcp_mod):
        fp = _write(dev_env, "empty.py", "")
        result = mcp_mod.syntax_check(fp)
        assert "✅" in result, result

    @pytest.mark.slow
    def test_D_DEV_10_nonexistent_file_returns_error(self, dev_env, mcp_mod):
        result = mcp_mod.syntax_check(str(dev_env.root / "doesnotexist.py"))
        # _resolve_allowlisted_path returns an error string when the file
        # doesn't exist; tool should propagate it cleanly (not crash).
        assert "✅" not in result, result
        assert "not found" in result.lower() or "does not exist" in result.lower() \
            or "no such" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_11_output_includes_filepath(self, dev_env, mcp_mod):
        """The result should include the resolved path so the operator can
        eyeball which file was actually checked."""
        fp = _write(dev_env, "verify_path.py", "x = 1\n")
        result = mcp_mod.syntax_check(fp)
        assert "verify_path.py" in result, result


# ══════════════════════════════════════════════════════════════════════════════
# GROUP C — syntax_check multi-language dispatch
# ══════════════════════════════════════════════════════════════════════════════
class TestSyntaxCheckDispatch:

    def test_D_DEV_12_unsupported_extension(self, dev_env, mcp_mod):
        """An extension we don't have a config for → clean unsupported message,
        not a crash."""
        fp = _write(dev_env, "weird.xyz", "anything")
        result = mcp_mod.syntax_check(fp)
        assert "unsupported extension" in result.lower() \
            or "⚠️" in result, result

    def test_D_DEV_13_rust_returns_friendly_not_supported(self, dev_env, mcp_mod):
        """Rust is in _LANG_NOT_SUPPORTED with a specific cargo-check message."""
        fp = _write(dev_env, "main.rs", "fn main() {}\n")
        result = mcp_mod.syntax_check(fp)
        assert "Rust" in result, result
        assert "cargo" in result.lower(), result
        # Not a failure marker — this is informational
        assert "ℹ️" in result or "not supported" in result.lower()

    @pytest.mark.slow
    @pytest.mark.skipif(not _has("node"), reason="node not on PATH")
    def test_D_DEV_14_js_passes_if_node_present(self, dev_env, mcp_mod):
        fp = _write(dev_env, "ok.js", "const x = 1;\nconsole.log(x);\n")
        result = mcp_mod.syntax_check(fp)
        assert "✅" in result, result
        assert "JavaScript" in result

    def test_D_DEV_15_js_clean_error_if_node_missing(self, dev_env, mcp_mod, monkeypatch):
        """Even if node IS installed on the box, we monkey-patch _binary_available
        to simulate a missing binary and verify the clean error path."""
        monkeypatch.setattr(mcp_mod, "_binary_available", lambda b: False)
        fp = _write(dev_env, "missing_compiler.js", "var x = 1;")
        result = mcp_mod.syntax_check(fp)
        assert "not available" in result.lower() or "❌" in result, result
        assert "node" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_16_perl_skips_if_missing(self, dev_env, mcp_mod):
        """If perl isn't installed (common on Windows), we expect the
        'not available' message — not a crash."""
        fp = _write(dev_env, "ok.pl", "print \"hi\\n\";\n")
        result = mcp_mod.syntax_check(fp)
        # Either it succeeded (perl installed) or returned clean unavailable msg.
        # Either is acceptable; what's NOT acceptable is a Python traceback.
        assert "Traceback" not in result, result
        if not _has("perl"):
            assert "not available" in result.lower() or "❌" in result, result

    def test_D_DEV_17_extension_case_insensitive(self, dev_env, mcp_mod):
        """.PY (uppercase) should be treated the same as .py."""
        fp = _write(dev_env, "UPPERCASE.PY", "x = 1\n")
        result = mcp_mod.syntax_check(fp)
        # Should dispatch to Python, not fall into 'unsupported extension'.
        assert "unsupported extension" not in result.lower(), result


# ══════════════════════════════════════════════════════════════════════════════
# GROUP D — lint_check
# ══════════════════════════════════════════════════════════════════════════════
class TestLintCheck:

    @pytest.mark.slow
    @pytest.mark.skipif(not _has_pyflakes(), reason="pyflakes not installed")
    def test_D_DEV_18_clean_python_lints_clean(self, dev_env, mcp_mod):
        fp = _write(dev_env, "clean.py",
                    "def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n")
        result = mcp_mod.lint_check(fp)
        assert "✅" in result or "lint clean" in result.lower(), result

    @pytest.mark.slow
    @pytest.mark.skipif(not _has_pyflakes(), reason="pyflakes not installed")
    def test_D_DEV_19_undefined_name_caught_by_lint(self, dev_env, mcp_mod):
        """The exact class of bug pyflakes catches that syntax_check misses:
        an undefined name reference at module scope. This is the bug that
        bit us with _get_or_create_collection — lint would have caught it."""
        fp = _write(dev_env, "undef.py", "x = totally_undefined_thing\n")
        result = mcp_mod.lint_check(fp)
        # pyflakes returns rc=0 but emits warnings; we treat that as findings.
        assert "totally_undefined_thing" in result \
            or "undefined" in result.lower() \
            or "lint findings" in result.lower(), result

    def test_D_DEV_20_no_lint_tool_for_perl(self, dev_env, mcp_mod):
        """Perl has no standard lint in our table → friendly message."""
        fp = _write(dev_env, "x.pl", "print \"x\";\n")
        result = mcp_mod.lint_check(fp)
        assert "No standard lint tool" in result \
            or "no lint tool" in result.lower(), result
        assert "Perl" in result

    def test_D_DEV_21_unsupported_extension(self, dev_env, mcp_mod):
        fp = _write(dev_env, "x.xyz", "blah")
        result = mcp_mod.lint_check(fp)
        assert "unsupported extension" in result.lower() \
            or "⚠️" in result, result


# ══════════════════════════════════════════════════════════════════════════════
# GROUP E — run_script (blocking, short-running scripts)
# ══════════════════════════════════════════════════════════════════════════════
class TestRunScript:
    """run_script executes a script synchronously and returns combined output.
    All scripts must be under the tracked read allowlist."""

    @pytest.mark.slow
    def test_D_DEV_22_python_script_passes(self, dev_env, mcp_mod):
        """A simple Python script that exits 0 → ✅ rc=0."""
        fp = _write(dev_env, "hello.py", "print('hello from run_script')\n")
        result = mcp_mod.run_script(fp)
        assert "✅" in result, result
        assert "rc=0" in result, result
        assert "hello from run_script" in result, result

    @pytest.mark.slow
    def test_D_DEV_23_python_script_fails(self, dev_env, mcp_mod):
        """A Python script that exits non-zero → ❌ rc=N."""
        fp = _write(dev_env, "fail.py", "import sys\nsys.exit(1)\n")
        result = mcp_mod.run_script(fp)
        assert "❌" in result, result
        assert "rc=1" in result, result

    @pytest.mark.slow
    def test_D_DEV_24_python_script_with_args(self, dev_env, mcp_mod):
        """Args string is split and passed to the script."""
        fp = _write(dev_env, "echo_args.py",
                    "import sys\nprint(' '.join(sys.argv[1:]))\n")
        result = mcp_mod.run_script(fp, args="foo bar baz")
        assert "foo bar baz" in result, result

    @pytest.mark.slow
    def test_D_DEV_25_unsupported_extension_clean_error(self, dev_env, mcp_mod):
        """Unknown file type → clean ⚠️ message, not a crash."""
        fp = _write(dev_env, "script.xyz", "anything")
        result = mcp_mod.run_script(fp)
        assert "⚠️" in result, result
        assert "unsupported" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_26_output_truncation_honored(self, dev_env, mcp_mod):
        """max_output_lines caps the returned output size."""
        fp = _write(dev_env, "noisy.py",
                    "for i in range(500):\n    print(f'line {i}')\n")
        result = mcp_mod.run_script(fp, max_output_lines=20)
        assert "✅" in result, result
        # With 500 lines capped to 20, output must be well under 10KB
        assert len(result) < 10000, f"Output too large: {len(result)} chars"

    @pytest.mark.slow
    def test_D_DEV_27_script_outside_allowlist_denied(self, dev_env, mcp_mod,
                                                       tmp_path):
        """A script that is NOT under any tracked root is rejected."""
        outside = tmp_path / "outside.py"
        outside.write_text("print('should be denied')\n", encoding="utf-8")
        result = mcp_mod.run_script(str(outside))
        assert "✅" not in result, result
        # Should mention path restriction, not execute the script
        assert "not found" in result.lower() \
            or "not under" in result.lower() \
            or "allowlist" in result.lower() \
            or "⚠️" in result, result

    @pytest.mark.slow
    def test_D_DEV_28_python_stderr_captured(self, dev_env, mcp_mod):
        """stderr output is captured alongside stdout."""
        fp = _write(dev_env, "stderr_test.py",
                    "import sys\nsys.stderr.write('error output\\n')\n")
        result = mcp_mod.run_script(fp)
        assert "error output" in result, result

    @pytest.mark.slow
    def test_D_DEV_28b_preview_appears_before_output(self, dev_env, mcp_mod):
        """Script content preview is included at the top of the result,
        before the execution output. This is the transparency/audit gate —
        Claude sees what it is about to run."""
        content = "print('audit trail test')\n"
        fp = _write(dev_env, "audit.py", content)
        result = mcp_mod.run_script(fp)
        # Preview section must be present
        assert "📄 Script preview" in result, \
            f"Expected preview header in result:\n{result}"
        assert "audit trail test" in result, result
        # Preview must appear BEFORE execution output
        preview_pos = result.index("📄 Script preview")
        output_pos  = result.index("✅")
        assert preview_pos < output_pos, \
            "Preview should appear before execution result"

    @pytest.mark.slow
    def test_D_DEV_28c_preview_shows_script_content(self, dev_env, mcp_mod):
        """The preview includes the actual source lines of the script."""
        content = "# my distinctive comment\nprint('hello')\n"
        fp = _write(dev_env, "content_check.py", content)
        result = mcp_mod.run_script(fp)
        assert "# my distinctive comment" in result, \
            f"Expected script source in preview:\n{result}"

    @pytest.mark.slow
    def test_D_DEV_28d_long_script_preview_truncated_at_50_lines(self,
                                                                    dev_env, mcp_mod):
        """Scripts over 50 lines show first 50 with a truncation note."""
        lines = [f"# line {i}\n" for i in range(100)]
        content = "".join(lines)
        fp = _write(dev_env, "long_script.py", content)
        result = mcp_mod.run_script(fp)
        assert "📄 Script preview" in result, result
        assert "showing first 50" in result, \
            f"Expected truncation note for 100-line script:\n{result}"
        assert "50 more lines" in result or "50)" in result or \
               "more lines" in result, result

    @pytest.mark.slow
    def test_D_DEV_28e_short_script_no_truncation_note(self, dev_env, mcp_mod):
        """Scripts under 50 lines show full content without a truncation note."""
        content = "".join([f"# line {i}\n" for i in range(10)])
        fp = _write(dev_env, "short_script.py", content)
        result = mcp_mod.run_script(fp)
        assert "📄 Script preview" in result, result
        assert "showing first 50" not in result, \
            "Short script should not show truncation note"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP F — internal helpers (renumbered from D-DEV-27..30 → D-DEV-29..32)
# ══════════════════════════════════════════════════════════════════════════════
class TestInternalHelpers:

    def test_D_DEV_29_detect_language_known(self, mcp_mod):
        """Known extensions resolve to the right language config."""
        for ext, expected_lang in [
            (".py", "Python"), (".js", "JavaScript"), (".ts", "TypeScript"),
            (".c", "C"), (".cpp", "C++"), (".go", "Go"), (".java", "Java"),
            (".pl", "Perl"), (".rb", "Ruby"), (".php", "PHP"), (".sh", "Bash"),
        ]:
            cfg = mcp_mod._detect_language(f"file{ext}")
            assert cfg is not None, f"{ext} should be detected"
            assert cfg[0] == expected_lang, f"{ext} → expected {expected_lang}, got {cfg[0]}"

    def test_D_DEV_30_detect_language_unknown_returns_none(self, mcp_mod):
        assert mcp_mod._detect_language("file.xyz") is None
        assert mcp_mod._detect_language("README") is None
        assert mcp_mod._detect_language("file.unknown") is None

    def test_D_DEV_31_binary_available_finds_python(self, mcp_mod):
        """sys.executable is special-cased to always return True."""
        assert mcp_mod._binary_available(sys.executable) is True

    def test_D_DEV_32_binary_available_rejects_fake(self, mcp_mod):
        """A clearly-nonexistent binary returns False."""
        assert mcp_mod._binary_available(
            "definitely_not_a_real_binary_xyz_12345") is False


# ══════════════════════════════════════════════════════════════════════════════
# GROUP G — run_script_start / run_script_status / run_script_kill (async)
# ══════════════════════════════════════════════════════════════════════════════
class TestRunScriptAsync:
    """Tests for the async job manager. Each test starts a background job,
    polls status, and verifies the manifest + log. Marked slow because
    each involves real subprocess startup + file I/O."""

    def _poll(self, mcp_mod, job_id, max_polls=20, interval=0.5):
        """Poll run_script_status until done/failed/killed/timeout/error."""
        import time
        for _ in range(max_polls):
            result = mcp_mod.run_script_status(job_id)
            if any(s in result for s in
                   ["[DONE]", "[FAILED]", "[KILLED]", "[TIMEOUT]", "[ERROR]"]):
                return result
            time.sleep(interval)
        return mcp_mod.run_script_status(job_id)  # final check

    @pytest.mark.slow
    def test_D_DEV_33_start_returns_job_id(self, dev_env, mcp_mod):
        """run_script_start returns a job_id string immediately."""
        fp = _write(dev_env, "quick.py", "print('done')\n")
        result = mcp_mod.run_script_start(fp)
        assert "✅" in result, result
        assert "job_" in result, result
        # Extract job_id and verify status reachable
        job_id = [w for w in result.split() if w.startswith("job_")][0]
        assert job_id, "No job_id found in start result"

    @pytest.mark.slow
    def test_D_DEV_34_job_completes_successfully(self, dev_env, mcp_mod):
        """A passing script transitions to DONE with rc=0."""
        fp = _write(dev_env, "pass_job.py", "print('job output')\n")
        start = mcp_mod.run_script_start(fp)
        job_id = [w for w in start.split() if w.startswith("job_")][0]

        final = self._poll(mcp_mod, job_id)
        assert "[DONE]" in final, f"Expected DONE, got:\n{final}"
        assert "job output" in final, final
        assert "Exit code: 0" in final, final

    @pytest.mark.slow
    def test_D_DEV_35_job_captures_failure(self, dev_env, mcp_mod):
        """A failing script transitions to FAILED with non-zero exit code."""
        fp = _write(dev_env, "fail_job.py",
                    "import sys\nprint('before fail')\nsys.exit(42)\n")
        start = mcp_mod.run_script_start(fp)
        job_id = [w for w in start.split() if w.startswith("job_")][0]

        final = self._poll(mcp_mod, job_id)
        assert "[FAILED]" in final, f"Expected FAILED, got:\n{final}"
        assert "before fail" in final, final
        assert "42" in final, final

    @pytest.mark.slow
    def test_D_DEV_36_status_shows_log_tail(self, dev_env, mcp_mod):
        """run_script_status includes the tail of the log file."""
        fp = _write(dev_env, "log_job.py",
                    "for i in range(10):\n    print(f'line {i}')\n")
        start = mcp_mod.run_script_start(fp)
        job_id = [w for w in start.split() if w.startswith("job_")][0]

        final = self._poll(mcp_mod, job_id)
        assert "line 9" in final, f"Expected last log line, got:\n{final}"

    @pytest.mark.slow
    def test_D_DEV_37_status_unknown_job_id_returns_error(self, mcp_mod):
        """Querying a nonexistent job_id returns a clear error."""
        result = mcp_mod.run_script_status("job_nonexistent_xyz_00000000_aaaa")
        assert "⚠️" in result or "No job found" in result, result

    @pytest.mark.slow
    def test_D_DEV_38_kill_terminates_running_job(self, dev_env, mcp_mod):
        """run_script_kill stops a long-running job and marks it killed."""
        import time
        fp = _write(dev_env, "long_job.py",
                    "import time\nfor i in range(60):\n"
                    "    print(f'tick {i}')\n    time.sleep(1)\n")
        start = mcp_mod.run_script_start(fp)
        job_id = [w for w in start.split() if w.startswith("job_")][0]

        # Let it start
        time.sleep(1.5)

        # Kill it
        kill_result = mcp_mod.run_script_kill(job_id)
        assert "🛑" in kill_result or "Killed" in kill_result, kill_result

        # Status should now show killed
        status = mcp_mod.run_script_status(job_id)
        assert "[KILLED]" in status, f"Expected KILLED, got:\n{status}"

    @pytest.mark.slow
    def test_D_DEV_39_kill_already_done_job_returns_info(self, dev_env, mcp_mod):
        """Killing an already-completed job returns an info message, not an error."""
        fp = _write(dev_env, "done_kill.py", "print('done')\n")
        start = mcp_mod.run_script_start(fp)
        job_id = [w for w in start.split() if w.startswith("job_")][0]

        # Wait for completion
        self._poll(mcp_mod, job_id)

        # Try to kill completed job
        result = mcp_mod.run_script_kill(job_id)
        assert "ℹ️" in result or "already" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_40_script_outside_allowlist_denied_async(self, dev_env,
                                                              mcp_mod, tmp_path):
        """run_script_start rejects scripts outside the tracked allowlist."""
        outside = tmp_path / "outside_async.py"
        outside.write_text("print('denied')\n", encoding="utf-8")
        result = mcp_mod.run_script_start(str(outside))
        # Should return an error string, NOT a job_id
        assert "job_" not in result or "✅" not in result, result
        assert "⚠️" in result \
            or "not found" in result.lower() \
            or "not under" in result.lower() \
            or "allowlist" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_41_start_includes_preview_before_job_id(self, dev_env, mcp_mod):
        """run_script_start includes the script content preview before the
        job confirmation, giving Claude full visibility before the job runs."""
        content = "# async preview test\nprint('async job')\n"
        fp = _write(dev_env, "async_preview.py", content)
        result = mcp_mod.run_script_start(fp)
        # Preview must be present
        assert "📄 Script preview" in result, \
            f"Expected preview in run_script_start result:\n{result}"
        assert "# async preview test" in result, result
        # Preview must appear before the job confirmation
        preview_pos = result.index("📄 Script preview")
        job_pos     = result.index("✅ Job started")
        assert preview_pos < job_pos, \
            "Preview should appear before job started confirmation"
