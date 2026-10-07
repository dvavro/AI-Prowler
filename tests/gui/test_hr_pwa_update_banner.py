"""
tests/gui/test_hr_pwa_update_banner.py
=======================================
Behavioral guard for the HR PWA's "update available" banner, per
Implementation Plan v2.1 Section 13.2.4.

DEVIATION FROM THE PLAN — DELIBERATE
-------------------------------------
The plan assumes hr/sw.js and hr/index.html reuse the exact named-function
pattern from jobs/index.html and remote/index.html (_initUpdateBanner(),
_showUpdateBanner(), _dismissUpdateBanner(), _maybeReshowUpdateBanner(),
_refreshForUpdate()) and suggests simply parametrizing
test_pwa_update_banner.py's existing fixture to add hr/sw.js as a third
path. That assumption doesn't hold: the real, shipped hr/index.html
implements the update banner differently — a single inline 'updatefound'
listener that shows #update-banner, plus a standalone applyUpdate()
function that posts SKIP_WAITING and reloads. There is no
_initUpdateBanner/_dismissUpdateBanner/_maybeReshowUpdateBanner to
extract, so parametrizing the existing harness against hr/index.html
would fail for a reason that has nothing to do with a real regression.

Per the testing philosophy in Section 13.0 ("test against real shipped
source, not mocks"), this file instead extracts and behaviorally tests the
ACTUAL code that ships in hr/index.html and hr/sw.js as its own dedicated
harness, rather than editing the Jobs/Remote-focused
test_pwa_update_banner.py to expect a pattern HR doesn't use — this also
avoids any risk of destabilizing that file's existing Jobs/Remote
coverage. Uses the same _real_Popen capture technique that file documents,
for the same reason (this directory's conftest.py autouse-no-ops
subprocess.run for widget tests).

Follow-up suggestion (not done here): if hr/index.html is ever refactored
to share the named-function pattern with jobs/index.html for consistency,
this file should be replaced by parametrizing test_pwa_update_banner.py
instead, per the plan's original intent.

Safe: reads hr/index.html and hr/sw.js as plain text only, runs extracted
JS snippets in an isolated Node subprocess with mocked globals. Never
imports ai_prowler_mcp.py, never touches hr_db.json or a live server.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_real_Popen = subprocess.Popen

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr" / "index.html"
HR_SW = SRC_ROOT / "hr" / "sw.js"


@pytest.fixture(scope="module")
def node_available():
    if shutil.which("node") is None:
        pytest.skip("Node.js not on PATH — cannot execute PWA JS for behavioral verification")


def _run_node(script_path: Path, timeout: int = 30):
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


def _extract_braced_block(source: str, start_marker: str) -> str:
    """Real brace-depth counting, matching the technique in
    test_pwa_update_banner.py — a naive regex would truncate at the first
    inner closing brace instead of the function's own."""
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
                return source[idx: i + 1]
    raise ValueError(f"Unbalanced braces extracting {start_marker!r} from source")


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def hr_sw_text():
    return HR_SW.read_text(encoding="utf-8")


class TestHrUpdateBannerStructure:
    """Cheap, no-Node structural checks against the real shipped source."""

    def test_index_registers_hr_service_worker(self, hr_index_text):
        assert "register('/hr/sw.js')" in hr_index_text

    def test_index_shows_update_banner_on_installed_state(self, hr_index_text):
        assert "update-banner" in hr_index_text
        assert "'installed'" in hr_index_text or '"installed"' in hr_index_text

    def test_apply_update_function_exists(self, hr_index_text):
        assert "function applyUpdate()" in hr_index_text

    def test_apply_update_sends_skip_waiting_and_reloads(self, hr_index_text):
        body = _extract_braced_block(hr_index_text, "function applyUpdate()")
        assert "SKIP_WAITING" in body
        assert "location.reload()" in body

    def test_sw_handles_skip_waiting_message(self, hr_sw_text):
        assert "SKIP_WAITING" in hr_sw_text
        assert "self.skipWaiting()" in hr_sw_text


_HARNESS_TEMPLATE = """
function setupMocks(hasController) {
  const state = { reloadCount: 0, skipWaitingSent: false };
  // Found running this suite: Node 21+ ships a built-in read-only global
  // `navigator` (Web API polyfill). A plain `global.navigator = {...}`
  // assignment silently no-ops against it, leaving the real Node
  // navigator (no .serviceWorker) in place instead — the exact same
  // Object.defineProperty workaround test_pwa_update_banner.py already
  // uses for this reason.
  Object.defineProperty(global, 'navigator', {
    value: {
      serviceWorker: {
        controller: hasController ? {
          postMessage: (msg) => { if (msg && msg.type === 'SKIP_WAITING') state.skipWaitingSent = true; },
        } : null,
      },
    },
    configurable: true,
  });
  global.window = { location: { reload: () => { state.reloadCount++; } } };
  return state;
}

__EXTRACTED_LOGIC__

const results = [];
function check(name, cond) { results.push([name, !!cond]); }

(() => {
  // 1. Controller present (a real update waiting) -> SKIP_WAITING posted,
  //    then exactly one reload.
  {
    const state = setupMocks(true);
    applyUpdate();
    check('sends_skip_waiting_when_controller_present', state.skipWaitingSent === true);
    check('reloads_exactly_once_with_controller', state.reloadCount === 1);
  }

  // 2. No controller yet (nothing to skip-wait for) -> must not throw, and
  //    still reloads (matches the real code's unconditional reload call).
  {
    const state = setupMocks(false);
    applyUpdate();
    check('no_skip_waiting_sent_without_controller', state.skipWaitingSent === false);
    check('still_reloads_without_controller', state.reloadCount === 1);
  }

  console.log(JSON.stringify(results));
  process.exit(results.every(r => r[1]) ? 0 : 1);
})();
"""


class TestHrUpdateBannerBehavior:
    """Executes the real applyUpdate() function straight out of
    hr/index.html against mocked browser APIs. Lighter than the
    Jobs/Remote harness because HR's real implementation is itself
    lighter (no _updatePending / re-prompt-on-navigation state machine
    exists to test yet) — this proves the two things that actually ship:
    SKIP_WAITING is posted only when a controller exists, and reload()
    fires exactly once either way.
    """

    def test_apply_update_behavior(self, node_available, hr_index_text, tmp_path):
        extracted = _extract_braced_block(hr_index_text, "function applyUpdate()")
        script = _HARNESS_TEMPLATE.replace("__EXTRACTED_LOGIC__", extracted)
        script_path = tmp_path / "hr_update_banner.js"
        script_path.write_text(script, encoding="utf-8")
        returncode, stdout, stderr = _run_node(script_path, timeout=15)
        if returncode != 0:
            detail = stdout.strip() or "(no stdout)"
            pytest.fail(f"HR update-banner behavior test failed.\n{detail}\nstderr: {stderr}")
