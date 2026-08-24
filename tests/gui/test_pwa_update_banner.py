"""
tests/gui/test_pwa_update_banner.py
======================================
Behavioral regression tests for the PWA "update available" banner —
the visible prompt (2026-08-23) that closes the one gap left by the
network-first service worker fix from earlier the same day: a tab that's
already open and just sitting in the foreground/background won't pick up
new JS in memory on its own, no matter how good the caching strategy is.
Every polished PWA closes this with a dismissible "Refresh Now" prompt
rather than a surprise reload — important here specifically because a
crew member could be mid-clock-in or mid-photo-upload when an update
lands.

WHY THESE RUN THROUGH NODE, NOT PURE PYTHON STRING CHECKS
-------------------------------------------------------------
Other PWA-source tests in this suite (test_pwa_multiday_multicrew_and_
sorting.py, etc.) check for literal substrings in the raw HTML — cheap,
and fine for "does this pattern exist", but it can't verify a state
machine's actual BEHAVIOR. The update-banner logic has real behavior
that matters and that a substring check cannot catch:
  - "Later" must NEVER force a reload (an earlier version of this
    feature did, silently, via a controllerchange listener — which made
    "Later" nearly meaningless, since the reload could still happen
    seconds later regardless of what the user chose).
  - "Later" must re-prompt on the NEXT in-app navigation, and keep doing
    so on every subsequent navigation, not just once.
  - Only the user's own "Refresh Now" tap may ever call location.reload().
  - A first-ever install must NOT show the banner (nothing to update
    FROM yet) — only a genuine update while something was already
    running should trigger it.

These tests extract the ACTUAL, LIVE function bodies straight from the
real source files at test-run time (via real brace-depth counting, not
a lazy regex) — never a hand-copied snapshot that could silently drift
out of sync with what's actually shipped — and execute them for real via
Node.js with mocked browser APIs (navigator.serviceWorker, document,
window.location), asserting on the resulting behavior. This is the same
harness approach used to manually verify the feature when it was built.

Both jobs/index.html and remote/index.html implement this identically
(same function bodies, different sw.js registration path and different
downstream navigation hook — showScreen() vs switchTab()), so both are
covered via parametrize.

Skipped automatically if Node.js isn't on PATH in this environment (kept
a soft dependency rather than a hard requirement for the whole suite).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Found 2026-08-23: this directory's own conftest.py has an autouse=True
# fixture (_silence_subprocess) that globally monkeypatches subprocess.run
# to a no-op returning a fake CompletedProcess(returncode=0, stdout="",
# stderr="") for EVERY test here — deliberately, to stop the GUI's own
# startup code (which spawns Ollama/MCP server subprocesses) from actually
# launching real processes during widget tests. That's correct for its
# purpose, but it silently intercepted this file's real Node invocation
# too: the harness "passed" because subprocess.run never actually ran
# Node at all, not because the logic was correct — confirmed by
# deliberately reintroducing the old "Later force-reloads" bug and
# watching this file's tests still pass.
#
# Capturing subprocess.run alone at import time wasn't sufficient either:
# the stdlib's run() internally does subprocess.Popen(*popenargs, **kwargs)
# as a FRESH module-attribute lookup each call, so even a saved reference
# to the original run() still ends up invoking whatever Popen currently
# is — the same fixture patches that too. Capturing the Popen CLASS
# itself at import time, and driving it directly rather than going
# through run()'s convenience wrapper, is what actually sidesteps both
# patches: _real_Popen(...) always constructs a genuine subprocess
# regardless of what subprocess.Popen currently points to.
_real_Popen = subprocess.Popen


def _run_node(script_path: Path, timeout: int = 30):
    """Minimal run-and-capture, built directly on the captured real Popen
    class so it can't be affected by this directory's autouse subprocess
    mocking (see the note on _real_Popen above)."""
    proc = _real_Popen(
        ["node", str(script_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise
    return proc.returncode, stdout, stderr


_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
JOBS_HTML = SRC_ROOT / "jobs" / "index.html"
REMOTE_HTML = SRC_ROOT / "remote" / "index.html"


@pytest.fixture(scope="module")
def node_available():
    if shutil.which("node") is None:
        pytest.skip("Node.js not on PATH — cannot execute PWA JS for behavioral verification")


def _extract_braced_block(source: str, start_marker: str) -> str:
    """Extract a `function name() { ... }` block starting at start_marker,
    using real brace-depth counting rather than a lazy regex. These
    functions contain nested arrow functions and if-blocks, so a naive
    non-greedy match (e.g. up to the first `\\n}`) would truncate at an
    inner closing brace instead of the function's own — exactly the kind
    of bug that would make this test extract broken JS and fail for the
    wrong reason.
    """
    idx = source.index(start_marker)
    brace_start = source.index("{", idx)
    depth = 0
    for i in range(brace_start, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[idx : i + 1]
    raise ValueError(f"Unbalanced braces extracting {start_marker!r} from source")


def _extract_update_banner_logic(html_path: Path) -> str:
    """Pull the live update-banner functions straight out of the real PWA
    source file. Never a hand-copied snapshot — this always tests
    whatever is actually currently shipped in that file.
    """
    source = html_path.read_text(encoding="utf-8")

    assert "let _updatePending = false;" in source, (
        f"_updatePending declaration not found in {html_path} — has the "
        "update-banner feature been removed or renamed?"
    )

    parts = ["let _updatePending = false;"]
    # Found 2026-08-24: _initUpdateBanner() now also drives an explicit
    # reg.update() (immediately, on tab-visibility regain, and on a
    # periodic interval) rather than relying solely on the browser's own
    # throttled automatic check — see that function's comments. It holds
    # the live ServiceWorkerRegistration in this module-level var so the
    # visibilitychange/interval callbacks can reach it. Included only when
    # present so this stays correct for whichever apps have picked up the
    # fix and whichever haven't yet.
    if "let _swRegistration = null;" in source:
        parts.append("let _swRegistration = null;")
    for marker in [
        "function _initUpdateBanner()",
        "function _showUpdateBanner()",
        "function _dismissUpdateBanner()",
        "function _maybeReshowUpdateBanner()",
        "function _refreshForUpdate()",
    ]:
        parts.append(_extract_braced_block(source, marker))
    return "\n\n".join(parts)


_HARNESS_TEMPLATE = """
__EXTRACTED_LOGIC__

// ── Mocked browser APIs ─────────────────────────────────────────────────
let registeredPath = null;

function setupMocks(hasController) {
  const state = {
    reloadCount: 0, bannerShown: false,
    updateCallCount: 0, intervalDelayMs: null, intervalCallback: null,
    visibilityHandler: null,
  };
  global.window = { location: { reload: () => { state.reloadCount++; } } };

  const installingObj = { state: 'installing', _listeners: {} };
  installingObj.addEventListener = function (evt, fn) { this._listeners[evt] = fn; };
  const regListeners = {};
  const registration = {
    waiting: null,
    installing: installingObj,
    addEventListener: (evt, fn) => { regListeners[evt] = fn; },
    _fireUpdateFound: () => regListeners['updatefound'](),
    // Found 2026-08-24: the whole point of the fix under test — records
    // every call so tests can assert it actually fires (immediately, on
    // visibility regain, and on the periodic interval) instead of the
    // page silently relying on the browser's own throttled auto-check.
    update: () => { state.updateCallCount++; return Promise.resolve(); },
  };

  Object.defineProperty(global, 'navigator', {
    value: {
      serviceWorker: {
        controller: hasController ? { fake: true } : null,
        register: (path) => { registeredPath = path; return Promise.resolve(registration); },
        addEventListener: () => {},
      },
    },
    configurable: true,
  });

  const bannerEl = {
    classList: {
      add: (c) => { if (c === 'show') state.bannerShown = true; },
      remove: (c) => { if (c === 'show') state.bannerShown = false; },
    },
  };
  let _visibilityState = 'visible';
  global.document = {
    getElementById: (id) => (id === 'updateBanner' ? bannerEl : null),
    addEventListener: (evt, fn) => { if (evt === 'visibilitychange') state.visibilityHandler = fn; },
    removeEventListener: () => {},
    get visibilityState() { return _visibilityState; },
    _setVisibility: (v) => { _visibilityState = v; },
  };

  // Capture rather than actually schedule — a real 30-minute timer has no
  // place in a test process. Tests fire it manually via
  // state.intervalCallback() to assert what happens when it eventually
  // does fire for real in the browser.
  global.setInterval = (fn, delay) => { state.intervalCallback = fn; state.intervalDelayMs = delay; return 1; };
  global.clearInterval = () => {};

  return { state, registration, installingObj };
}

async function triggerUpdate(registration, installingObj) {
  registration._fireUpdateFound();
  installingObj.state = 'installed';
  installingObj._listeners['statechange']();
}

const results = [];
function check(name, cond) { results.push([name, !!cond]); }

(async () => {
  // 1. Registers the correct sw.js path for this app.
  {
    setupMocks(false);
    _initUpdateBanner();
    await new Promise(r => setTimeout(r, 5));
    check('registers_correct_sw_path', registeredPath === '__EXPECTED_SW_PATH__');
  }

  // 2. A first-ever install (no prior controller) must NOT show the banner —
  //    there's nothing to update FROM yet.
  {
    _updatePending = false;
    const { state, registration, installingObj } = setupMocks(false);
    _initUpdateBanner();
    await new Promise(r => setTimeout(r, 5));
    await triggerUpdate(registration, installingObj);
    check('no_banner_on_first_install', state.bannerShown === false);
  }

  // 3. Real update -> banner shows; Later hides it WITHOUT reloading and
  //    without clearing the pending flag; it reappears on every subsequent
  //    in-app navigation until the user actually taps Refresh Now.
  {
    _updatePending = false;
    const { state, registration, installingObj } = setupMocks(true);
    _initUpdateBanner();
    await new Promise(r => setTimeout(r, 5));
    await triggerUpdate(registration, installingObj);
    check('banner_shows_on_real_update', state.bannerShown === true);

    _dismissUpdateBanner();
    check('later_hides_banner', state.bannerShown === false);
    check('later_does_not_reload', state.reloadCount === 0);
    check('later_keeps_pending_true', _updatePending === true);

    _maybeReshowUpdateBanner();
    check('banner_reappears_after_navigation', state.bannerShown === true);

    _dismissUpdateBanner();
    _maybeReshowUpdateBanner();
    check('banner_reappears_on_second_navigation', state.bannerShown === true);

    _refreshForUpdate();
    check('refresh_now_reloads_exactly_once', state.reloadCount === 1);
  }

  // 4. Navigating with nothing pending must never show the banner out of
  //    nowhere.
  {
    _updatePending = false;
    const { state } = setupMocks(true);
    _maybeReshowUpdateBanner();
    check('no_spurious_banner_when_nothing_pending', state.bannerShown === false);
  }

  // Found 2026-08-24: register() alone doesn't guarantee a live check of
  // sw.js — browsers throttle their OWN automatic update checks to
  // roughly once per 24h, so a same-day code change could sit completely
  // undetected. _initUpdateBanner() now forces its own checks via
  // reg.update(), independent of that internal browser throttle. Only
  // run against apps that have actually picked up the fix.
  if (__HAS_LIVE_RECHECK__) {
    // 5. reg.update() fires once immediately after registration resolves.
    {
      _updatePending = false;
      const { state } = setupMocks(true);
      _initUpdateBanner();
      await new Promise(r => setTimeout(r, 5));
      check('calls_update_immediately_after_register', state.updateCallCount === 1);
    }

    // 6. Tab regaining visibility (the exact scenario from the original
    //    report: config changed elsewhere while this tab sat in the
    //    background) triggers another live check.
    {
      _updatePending = false;
      const { state } = setupMocks(true);
      _initUpdateBanner();
      await new Promise(r => setTimeout(r, 5));
      check('visibility_handler_registered', typeof state.visibilityHandler === 'function');

      global.document._setVisibility('visible');
      state.visibilityHandler();
      check('visibility_regain_triggers_another_update', state.updateCallCount === 2);
    }

    // 7. A periodic interval is scheduled (not zero/immediate, not longer
    //    than an hour — otherwise a tab left open for a long shift would
    //    go most of the day without a check) and firing it checks again.
    {
      _updatePending = false;
      const { state } = setupMocks(true);
      _initUpdateBanner();
      await new Promise(r => setTimeout(r, 5));
      check('interval_scheduled', typeof state.intervalDelayMs === 'number' && state.intervalDelayMs > 0);
      check('interval_reasonably_frequent', state.intervalDelayMs <= 60 * 60 * 1000);

      state.intervalCallback();
      check('interval_fire_triggers_another_update', state.updateCallCount === 2);
    }
  }

  console.log(JSON.stringify(results));
  process.exit(results.every(r => r[1]) ? 0 : 1);
})();
"""


def _run_update_banner_harness(html_path: Path, expected_sw_path: str, tmp_path: Path, app_name: str):
    extracted = _extract_update_banner_logic(html_path)
    has_live_recheck = "let _swRegistration = null;" in extracted
    script = (
        _HARNESS_TEMPLATE
        .replace("__EXTRACTED_LOGIC__", extracted)
        .replace("__EXPECTED_SW_PATH__", expected_sw_path)
        .replace("__HAS_LIVE_RECHECK__", "true" if has_live_recheck else "false")
    )

    script_path = tmp_path / f"update_banner_{app_name}.js"
    script_path.write_text(script, encoding="utf-8")

    returncode, stdout, stderr = _run_node(script_path, timeout=30)

    if returncode != 0:
        # Try to parse the per-check results for a precise failure message;
        # fall back to raw stdout/stderr if parsing fails for any reason
        # (e.g. a real JS exception before results were ever printed).
        detail = stdout.strip() or "(no stdout)"
        try:
            checks = json.loads(stdout.strip().splitlines()[-1])
            failed = [name for name, ok in checks if not ok]
            detail = f"Failed checks: {failed}"
        except Exception:
            pass
        pytest.fail(
            f"[{app_name}] update-banner behavior test failed.\n"
            f"{detail}\nstdout: {stdout}\nstderr: {stderr}"
        )


class TestUpdateBannerBehavior:
    """Executes the real, currently-shipped update-banner logic against
    mocked browser APIs and asserts on actual behavior — most importantly
    that 'Later' never force-reloads and correctly re-prompts on the next
    in-app navigation rather than staying silent forever or nagging only
    once.
    """

    def test_jobs_app(self, node_available, tmp_path):
        assert JOBS_HTML.exists(), f"{JOBS_HTML} not found"
        _run_update_banner_harness(JOBS_HTML, "/jobs/sw.js", tmp_path, "jobs")

    def test_jobs_app_has_live_recheck_fix(self):
        """2026-08-24 regression guard: jobs/index.html specifically must
        keep the explicit reg.update() live-recheck (checks 5-7 in the
        harness above are skipped, not failed, when this declaration is
        missing — this test exists so a future edit that accidentally
        drops it fails loudly instead of silently losing coverage)."""
        source = JOBS_HTML.read_text(encoding="utf-8")
        assert "let _swRegistration = null;" in source
        assert "reg.update()" in source

    def test_remote_app(self, node_available, tmp_path):
        assert REMOTE_HTML.exists(), f"{REMOTE_HTML} not found"
        _run_update_banner_harness(REMOTE_HTML, "/remote/sw.js", tmp_path, "remote")


class TestUpdateBannerWiredIntoNavigation:
    """Structural check (cheap, no Node needed) — confirms the re-prompt
    hook is actually called from each app's real navigation function, not
    just defined and never invoked. The behavioral tests above prove
    _maybeReshowUpdateBanner() does the right thing WHEN called; this
    proves it actually gets called on every screen/tab change.
    """

    def test_jobs_showScreen_calls_reshow_hook(self):
        source = JOBS_HTML.read_text(encoding="utf-8")
        idx = source.index("function showScreen(name, btn)")
        end_idx = source.index("\n}", idx)
        body = source[idx:end_idx]
        assert "_maybeReshowUpdateBanner();" in body

    def test_remote_switchTab_calls_reshow_hook(self):
        source = REMOTE_HTML.read_text(encoding="utf-8")
        idx = source.index("function switchTab(tab)")
        end_idx = source.index("\n}", idx)
        body = source[idx:end_idx]
        assert "_maybeReshowUpdateBanner();" in body
