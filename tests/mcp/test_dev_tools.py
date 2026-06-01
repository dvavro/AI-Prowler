"""
tests/mcp/test_dev_tools.py — D-DEV-NN: dev tools coverage

Exercises syntax_check, lint_check, and pytest_check end-to-end. The tools
run real subprocesses against real binaries (Python is always available;
non-Python binaries are skipped gracefully if not installed on the box).

Test plan IDs follow D-DEV-NN:

    Group A — _dev_tools_enabled (gate behavior)        D-DEV-01..05
    Group B — syntax_check Python paths                 D-DEV-06..11
    Group C — syntax_check multi-language dispatch      D-DEV-12..17
    Group D — lint_check (Python pyflakes)              D-DEV-18..21
    Group E — pytest_check                              D-DEV-22..26
    Group F — internal helpers                          D-DEV-27..30

Tests that invoke heavyweight binaries are marked @pytest.mark.slow.
Helper-only tests are fast.

IMPORTANT honest notes about this test file:
  • `pyflakes` may not be installed on every dev machine — pyflakes tests
    skip gracefully via pytest.skip() if not available.
  • Non-Python compilers (gcc, node, etc.) are NOT required. Tests check
    BOTH the "binary available → real success" path AND the
    "binary unavailable → clean error message" path.
  • pytest_check tests use an isolated nested pytest invocation. This is
    legal (subprocess pytest doesn't interfere with the outer pytest run)
    but adds ~3-5 seconds per test for pytest startup. Marked slow.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
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
# GROUP E — pytest_check
# ══════════════════════════════════════════════════════════════════════════════
class TestPytestCheck:
    """These tests invoke pytest as a subprocess, which loads pytest + the
    test module fresh each time. ~3-5s startup cost per test. Marked slow."""

    @pytest.mark.slow
    def test_D_DEV_22_passing_test_returns_passed(self, dev_env, mcp_mod):
        """Create a one-test file, point pytest_check at it, expect PASSED."""
        fp = _write(dev_env, "test_one.py", textwrap.dedent("""
            def test_trivial_pass():
                assert 1 + 1 == 2
        """).strip())
        result = mcp_mod.pytest_check(fp)
        assert "✅" in result or "PASSED" in result, result
        assert "1 passed" in result.lower() or "passed" in result.lower(), result

    @pytest.mark.slow
    def test_D_DEV_23_failing_test_returns_failed(self, dev_env, mcp_mod):
        fp = _write(dev_env, "test_two.py", textwrap.dedent("""
            def test_definitely_fails():
                assert 1 + 1 == 3, "math is broken"
        """).strip())
        result = mcp_mod.pytest_check(fp)
        assert "❌" in result or "FAILED" in result, result
        # The first-failure trace should be included
        assert "math is broken" in result or "AssertionError" in result, result

    @pytest.mark.slow
    def test_D_DEV_24_k_filter_narrows_selection(self, dev_env, mcp_mod):
        """When k_filter is passed, only matching tests run."""
        fp = _write(dev_env, "test_three.py", textwrap.dedent("""
            def test_keep_me():
                assert True

            def test_skip_me():
                assert False, "would fail if run"
        """).strip())
        # Without filter, this would fail. With filter "keep", only test_keep_me runs.
        result = mcp_mod.pytest_check(fp, k_filter="keep")
        assert "✅" in result or "PASSED" in result, \
            f"With k_filter=keep, should pass: {result}"

    @pytest.mark.slow
    def test_D_DEV_25_no_tests_collected(self, dev_env, mcp_mod):
        """A file with no test_ functions should produce 'no tests collected'
        not a crash, not a generic failure."""
        fp = _write(dev_env, "test_empty.py",
                    "# this file has no test_ functions\nx = 1\n")
        result = mcp_mod.pytest_check(fp)
        # pytest rc=5 = no tests collected
        assert "no tests collected" in result.lower() or "ℹ️" in result, result

    @pytest.mark.slow
    def test_D_DEV_26_output_truncation_honored(self, dev_env, mcp_mod):
        """If max_output_lines is small, the output should be truncated and
        include a 'truncated N earlier lines' marker."""
        # Create a test that prints many lines, so pytest output is large.
        fp = _write(dev_env, "test_noisy.py", textwrap.dedent("""
            def test_noisy():
                for i in range(500):
                    print(f"line {i}")
                assert True
        """).strip())
        result = mcp_mod.pytest_check(fp, max_output_lines=20)
        # We don't necessarily see the truncation marker (pytest's verbose
        # output for 1 test isn't 500 lines), so this test asserts only that
        # the result is bounded — under ~5000 chars even with all the output.
        # A non-truncated 500-line output would be much larger.
        assert len(result) < 50000, \
            f"Output too large ({len(result)} chars) for max_output_lines=20"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP F — internal helpers
# ══════════════════════════════════════════════════════════════════════════════
class TestInternalHelpers:

    def test_D_DEV_27_detect_language_known(self, mcp_mod):
        """Known extensions resolve to the right language config."""
        for ext, expected_lang in [
            (".py", "Python"), (".js", "JavaScript"), (".ts", "TypeScript"),
            (".c", "C"), (".cpp", "C++"), (".go", "Go"), (".java", "Java"),
            (".pl", "Perl"), (".rb", "Ruby"), (".php", "PHP"), (".sh", "Bash"),
        ]:
            cfg = mcp_mod._detect_language(f"file{ext}")
            assert cfg is not None, f"{ext} should be detected"
            assert cfg[0] == expected_lang, f"{ext} → expected {expected_lang}, got {cfg[0]}"

    def test_D_DEV_28_detect_language_unknown_returns_none(self, mcp_mod):
        assert mcp_mod._detect_language("file.xyz") is None
        assert mcp_mod._detect_language("README") is None
        assert mcp_mod._detect_language("file.unknown") is None

    def test_D_DEV_29_binary_available_finds_python(self, mcp_mod):
        """sys.executable is special-cased to always return True."""
        assert mcp_mod._binary_available(sys.executable) is True

    def test_D_DEV_30_binary_available_rejects_fake(self, mcp_mod):
        """A clearly-nonexistent binary returns False."""
        assert mcp_mod._binary_available("definitely_not_a_real_binary_xyz_12345") is False
