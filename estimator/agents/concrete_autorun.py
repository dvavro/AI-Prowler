"""Concrete agent auto-run (Phase 1): the visible, headed browser driver.

The sibling API (estimator/api/autorun_api.py) finds the slab rectangles on a
foundation plan and owns the run row; this module drives the Blueprint Review
page the way a person would, so David can watch it work:

    python -m estimator.agents.concrete_autorun --base <server base URL> --db <db path>
        --run-id <id> [--headed | --headless] [--slow-mo MS]

--base takes the server origin (http://localhost:8770, as autorun_api's
spawn_agent passes) or the Estimator page base (.../estimator/); the agent
adds /estimator/ for the page and /estimator-api/ for its own calls.

What it does, for the largest slab candidate on the run's viewport:

  1. opens #/takeoffs/<estimate>?sheet=<sheet> and clicks Fit,
  2. calibrates from a dimension line when the viewport has no scale yet
     (it never guesses a scale - no dimension, no run),
  3. draws the slab with the Rectangle tool and saves it as "Slab (agent)"
     feeding area_sqft, then draws the outline twice with the Length tool
     and saves "Footer (agent)" (footing_lf) and "Forms (agent)"
     (perimeter_lf) - all three through the page's own save form, left
     proposed for a person to approve,
  4. stamps each saved measurement through POST /measurements/<id>/mark-agent.

No LLM, no API key, no token cost: deterministic geometry plus scripted UI
driving. On any failure the run row is marked failed with the step and the
error, so a run is never left stuck in 'running'.

Run-row updates are direct sqlite on the auto_runs table (the --db path);
only the mark-agent stamp and the read-only API calls go through HTTP.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

AGENT = "concrete-agent"
MODULE_ID = "concrete"
PLAYWRIGHT_ERROR = "Playwright/Chromium is not installed — run: playwright install chromium"
NO_DIMENSION = "Could not find a dimension to calibrate on — please calibrate this sheet manually first"
NO_SLAB = "No slab outline found on this sheet — the agent could not find a rectangular slab from the drawing"

VIEWPORT = {"width": 1400, "height": 950}

# Generous waits: the sheet render and the save round-trip can be slow.
TIMEOUT_OPEN = 30_000
TIMEOUT_SAVE_FORM = 15_000
TIMEOUT_CONFIRM = 5_000
TIMEOUT_SAVED = 30_000


class AgentError(Exception):
    """A failed run: the message goes into the run row's error field."""


class ApiError(AgentError):
    def __init__(self, status: int | None, message: str):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ pure helpers
# No Playwright here, so the unit tests cover them without a browser.

def sheet_to_screen(x: float, y: float, z: float, tx: float, ty: float, rect: dict) -> tuple[float, float]:
    """Sheet (paper) units -> screen pixels: the inverse of Viewer.toSheet
    (review.js:455: [(cx - rect.left - tx)/z, (cy - rect.top - ty)/z]).

    rect carries the viewer box's left/top from getBoundingClientRect().
    """
    return (rect["left"] + tx + x * z, rect["top"] + ty + y * z)


def split_base(base: str) -> tuple[str, str]:
    """--base into (page base, API base).

    Accepts the server origin (http://localhost:8770 - what autorun_api's
    spawn_agent passes) or the Estimator page base (.../estimator/).
    """
    trimmed = base.rstrip("/")
    if trimmed.endswith("/estimator"):
        origin = trimmed[: -len("/estimator")]
        page_base = trimmed + "/"
    else:
        origin = trimmed
        page_base = trimmed + "/estimator/"
    return page_base, origin + "/estimator-api"


def pick_candidate(candidates: list[dict]) -> dict | None:
    """The largest candidate (biggest first, as slab-candidates returns them).

    Paper area orders them exactly as square feet would - the scale factor
    is the same for every candidate - so this also works on an uncalibrated
    viewport, where area_sqft is None.
    """
    if not candidates:
        return None
    return max(candidates, key=lambda c: float(c.get("area") or 0))


def find_calibration_dimension(objects: list[dict], candidate: dict) -> dict | None:
    """A dimension line as long as the candidate's width or length, with a
    real length in its label - see slab_find.find_calibration_dimension.

    Returns {points [[x, y], [x, y]], label, real_inches} or None.
    """
    from estimator.takeoff import slab_find

    return slab_find.find_calibration_dimension(objects, candidate)


# ------------------------------------------------------------------ the run row

class RunStore:
    """Direct sqlite updates on the auto_runs table (migration 20)."""

    def __init__(self, db_path: str):
        if not Path(db_path).is_file():
            raise AgentError(f"database not found: {db_path}")
        self.conn = sqlite3.connect(str(db_path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 30000")

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def read_run(self, run_id: int) -> dict:
        try:
            row = self.conn.execute("SELECT * FROM auto_runs WHERE id = ?", (int(run_id),)).fetchone()
        except sqlite3.Error as e:
            raise AgentError(f"could not read auto-run {run_id} from the database: {e}") from e
        if row is None:
            raise AgentError(f"auto-run {run_id} not found")
        return dict(row)

    def update(self, run_id: int, *, status: str | None = None, step: str | None = None,
               error: str | None = None, candidate_id: str | None = None,
               candidates: list | None = None, measurement_ids: list | None = None) -> None:
        """Only the given fields change (None leaves a field alone)."""
        sets, args = [], []
        if status is not None:
            sets.append("status = ?")
            args.append(status)
        if step is not None:
            sets.append("step = ?")
            args.append(step)
        if error is not None:
            sets.append("error = ?")
            args.append(error)
        if candidate_id is not None:
            sets.append("candidate_id = ?")
            args.append(candidate_id)
        if candidates is not None:
            sets.append("candidates_json = ?")
            args.append(json.dumps(candidates))
        if measurement_ids is not None:
            sets.append("measurement_ids_json = ?")
            args.append(json.dumps([int(m) for m in measurement_ids]))
        sets.append("updated_at = ?")
        args.append(_now())
        args.append(int(run_id))
        self.conn.execute(f"UPDATE auto_runs SET {', '.join(sets)} WHERE id = ?", args)
        self.conn.commit()


# ------------------------------------------------------------------ the Estimator API

class ApiClient:
    """Read-only calls plus mark-agent, over plain urllib.

    Same-PC requests need no sign-in (auth.py: same-PC = owner), and writes
    must carry X-Estimator-Request: 1 (the anti-CSRF header, auth.py:16).
    """

    def __init__(self, api_base: str):
        self.api_base = api_base

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body or {}).encode("utf-8") if method != "GET" else None
        req = urllib.request.Request(self.api_base + path, data=data, method=method)
        if method != "GET":
            req.add_header("X-Estimator-Request", "1")
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read().decode("utf-8"))
                message = payload.get("message") or f"HTTP {e.code}"
            except (ValueError, UnicodeDecodeError):
                message = f"HTTP {e.code} on {method} {path}"
            raise ApiError(e.code, message) from e
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise AgentError(f"could not reach the Estimator server at {self.api_base}: {e}") from e
        if isinstance(payload, dict) and payload.get("ok") is False:
            raise ApiError(None, payload.get("message") or f"the Estimator refused {method} {path}")
        return payload

    def get(self, path: str) -> dict:
        return self._call("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self._call("POST", path, body)


# ------------------------------------------------------------------ the viewer, from the page

# RV.viewer is the Viewer instance (review.js:132): z/tx/ty plus .box, the
# #bp-viewer element. RV is a top-level const in review.js, so page.evaluate
# sees it as a global lexical binding. Fallbacks: RV.view[sheetId] (the same
# numbers, written by Viewer.render, review.js:461), then the stage's CSS
# transform plus the overlay's width over its viewBox width.
_VIEWER_STATE_JS = r"""() => {
  const box = document.querySelector('#bp-viewer');
  if (!box) return null;
  const r = box.getBoundingClientRect();
  let v = null;
  try { if (typeof RV !== 'undefined' && RV.viewer) v = {z: RV.viewer.z, tx: RV.viewer.tx, ty: RV.viewer.ty}; } catch (e) {}
  if (!v) {
    try { const s = RV.view[RV.sheetId]; if (s) v = {z: s.z, tx: s.tx, ty: s.ty}; } catch (e) {}
  }
  if (!v) {
    const stage = box.querySelector('.bp-stage');
    const overlay = box.querySelector('.bp-overlay');
    if (!stage || !overlay) return null;
    const m = /translate\((-?[0-9.]+)px,\s*(-?[0-9.]+)px\)/.exec(stage.style.transform || '');
    const vb = (overlay.getAttribute('viewBox') || '').split(/\s+/).map(Number);
    const w = parseFloat(overlay.getAttribute('width'));
    if (!m || vb.length < 4 || !w || !vb[2]) return null;
    v = {z: w / vb[2], tx: parseFloat(m[1]), ty: parseFloat(m[2])};
  }
  return {z: v.z, tx: v.tx, ty: v.ty, left: r.left, top: r.top, width: r.width, height: r.height};
}"""

_REVIEW_READY_JS = "() => typeof RV !== 'undefined' && !!RV.viewer && !!RV.sheet"


# ------------------------------------------------------------------ the driver

class ConcreteAutoRun:
    def __init__(self, *, base: str, db_path: str, run_id: int, headed: bool, slow_mo: int):
        self.page_base, api_base = split_base(base)
        self.api = ApiClient(api_base)
        self.store = RunStore(db_path)
        self.run_id = run_id
        self.headed = headed
        self.slow_mo = slow_mo
        self.run_row: dict | None = None
        self.step = "starting"
        self.candidate: dict | None = None
        self.measurement_ids: list[int] = []
        self._pw = None
        self._browser = None
        self._page = None

    # -- plumbing ---------------------------------------------------

    def log(self, message: str) -> None:
        print(f"[concrete-autorun] {message}", flush=True)

    def set_step(self, step: str) -> None:
        self.step = step
        self.log(step)
        try:
            self.store.update(self.run_id, step=step)
        except sqlite3.Error as e:
            self.log(f"could not write step '{step}' to the run row: {e}")

    def _mark_failed(self, message: str) -> None:
        try:
            self.store.update(self.run_id, status="failed", step=self.step, error=message)
        except Exception as e:  # noqa: BLE001 - failing to record the failure must not hide it
            self.log(f"could not mark the run failed: {e}")

    def _close_browser(self) -> None:
        for closer in (getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:  # noqa: BLE001 - teardown must not raise
                pass
        self._browser = self._pw = self._page = None

    # -- the run ----------------------------------------------------

    def run(self) -> int:
        """Drive the run. Returns 0 on success, 1 on failure (run row marked failed)."""
        try:
            self.run_row = self.store.read_run(self.run_id)
            self.store.update(self.run_id, status="running", step="starting")
            try:
                from playwright.sync_api import sync_playwright
            except ImportError:
                raise AgentError(PLAYWRIGHT_ERROR) from None
            try:
                self._pw = sync_playwright().start()
                self._browser = self._pw.chromium.launch(headless=not self.headed, slow_mo=self.slow_mo)
            except Exception as e:  # noqa: BLE001 - no Chromium (or no display) looks like this
                raise AgentError(PLAYWRIGHT_ERROR) from e
            page = self._browser.new_context(viewport=VIEWPORT).new_page()
            page.set_default_timeout(TIMEOUT_OPEN)
            self._page = page
            self._drive(page)
            self.store.update(self.run_id, status="done", step="done",
                              candidate_id=self.candidate["id"], measurement_ids=self.measurement_ids)
            self.log(f"done: measurements {self.measurement_ids}")
            return 0
        except AgentError as e:
            self._mark_failed(str(e))
            self.log(f"FAILED at {self.step}: {e}")
            return 1
        except Exception as e:  # noqa: BLE001 - any surprise still marks the run failed
            message = f"{self.step}: {e}"
            self._mark_failed(message)
            self.log(f"FAILED: {message}")
            return 1
        finally:
            self._close_browser()
            self.store.close()

    def _drive(self, page) -> None:
        run = self.run_row
        estimate_id, sheet_id, viewport_id = run["estimate_id"], run["sheet_id"], run["viewport_id"]

        self.set_step("opening")
        page.goto(f"{self.page_base}#/takeoffs/{estimate_id}?sheet={sheet_id}")
        page.wait_for_selector("#nav a[data-screen]", timeout=TIMEOUT_OPEN)
        if page.locator("#login:visible").count():
            raise AgentError("the Estimator asked for a sign-in - run the agent on the same PC as the server")
        page.wait_for_selector("#bp-viewer", timeout=TIMEOUT_OPEN)
        page.wait_for_function(_REVIEW_READY_JS, timeout=TIMEOUT_OPEN)
        self._dismiss_tour(page)

        self.set_step("fitting")
        page.click("#bp-fit")
        page.wait_for_timeout(600)

        self.set_step("calibrating")
        found = self._slab_candidates(viewport_id)
        if not found.get("calibrated"):
            found = self._calibrate(page, found, sheet_id, viewport_id)
        candidates = found.get("candidates") or []
        if not candidates:
            raise AgentError(NO_SLAB)
        self.candidate = pick_candidate(candidates)
        # mark-agent refuses a candidate the run row doesn't hold
        # (autorun_api.py: mark_agent_measurement), so store them first.
        self.store.update(self.run_id, candidate_id=self.candidate["id"], candidates=candidates)
        self.log(f"slab {self.candidate.get('label') or self.candidate['id']}: "
                 f"{self.candidate.get('area_sqft')} sq ft, corners {self.candidate['corners']}")

        corners = self.candidate["corners"]  # TL, TR, BR, BL in sheet units
        tl, tr, br, bl = corners
        self.set_step("measuring_area")
        self._save_measurement(page, tool="rect", points=[tl, br],
                               feeds="area_sqft", label="Slab (agent)")
        self.set_step("measuring_footer")
        self._save_measurement(page, tool="length", points=[tl, tr, br, bl, tl],
                               feeds="footing_lf", label="Footer (agent)")
        self.set_step("measuring_forms")
        self._save_measurement(page, tool="length", points=[tl, tr, br, bl, tl],
                               feeds="perimeter_lf", label="Forms (agent)")

    # -- steps ------------------------------------------------------

    def _slab_candidates(self, viewport_id: int) -> dict:
        try:
            return self.api.get(f"/viewports/{viewport_id}/slab-candidates")
        except ApiError as e:
            if e.status == 404:
                raise AgentError("the slab-candidates endpoint is not available (HTTP 404) - "
                                 "the auto-run API is not deployed yet") from e
            raise

    def _calibrate(self, page, found: dict, sheet_id: int, viewport_id: int) -> dict:
        candidates = found.get("candidates") or []
        if not candidates:
            raise AgentError(NO_DIMENSION)
        sheet = self.api.get(f"/sheets/{sheet_id}").get("sheet") or {}
        if sheet.get("units") != "paper_in":
            raise AgentError("the viewport has no scale and this sheet is not a paper plan, "
                             "so it cannot be calibrated here - set the scale on the Plans screen first")
        candidate = pick_candidate(candidates)
        objects = self.api.get(f"/sheets/{sheet_id}/objects").get("objects") or []
        dim = find_calibration_dimension(objects, candidate)
        if dim is None:
            # No dimension line matches the slab: let the auto calibrator read the written dimensions (2026-11-13).
            self.log("no matching dimension line - asking the auto calibrator")
            try:
                got = self.api.post(f"/viewports/{viewport_id}/auto-calibrate", {"auto_run_id": self.run_id})
            except ApiError as e:
                raise AgentError(f"{NO_DIMENSION} ({e})") from None
            if got.get("status") in ("calibrated", "calibrated_unchecked"):
                self.log(f"auto-calibrated: 1 inch = {got.get('scale_ratio')} inches")
                page.reload()
                page.wait_for_timeout(500)
                return self._slab_candidates(viewport_id)
            raise AgentError("Manual calibration required — " + (got.get("reason") or NO_DIMENSION) + " "
                             + (got.get("how") or ""))
        self.log(f"calibrating on the {dim['label']} dimension at {dim['points']}")
        page.click('button[data-tool="calibrate"]')
        page.wait_for_timeout(200)
        (x1, y1), (x2, y2) = dim["points"]
        self._sheet_click(page, x1, y1)
        self._sheet_click(page, x2, y2)
        page.wait_for_selector("#bp-cal-box", state="visible", timeout=TIMEOUT_SAVE_FORM)
        page.fill("#bp-cal-distance", dim["label"])
        page.click("#bp-cal-set")
        self._answer_yes(page, "#bp-cal-yes")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            found = self._slab_candidates(viewport_id)
            if found.get("calibrated"):
                self.log(f"calibrated: 1 inch = {found.get('scale_ratio')} inches")
                # The page saved it as the signed-in person: stamp it as the agent's (2026-11-13).
                try:
                    self.api.post(f"/viewports/{viewport_id}/mark-agent", {"auto_run_id": self.run_id})
                except ApiError as e:
                    self.log(f"could not mark the calibration as the agent's: {e}")
                return found
            time.sleep(1)
        raise AgentError("calibration did not take - the viewport still has no scale")

    def _save_measurement(self, page, *, tool: str, points: list, feeds: str, label: str) -> int:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        before = self._measurement_ids()
        page.click(f'button[data-tool="{tool}"]')
        page.wait_for_timeout(200)
        for x, y in points:
            self._sheet_click(page, x, y)
        if tool == "length":
            # Close the loop, then Finish (Enter on the viewer is the fallback).
            try:
                page.wait_for_selector("#bp-finish", state="visible", timeout=TIMEOUT_CONFIRM)
                page.click("#bp-finish")
            except PlaywrightTimeoutError:
                page.locator("#bp-viewer").press("Enter")
        page.wait_for_selector("#bp-save-box", state="visible", timeout=TIMEOUT_SAVE_FORM)
        page.select_option("#bp-trade", MODULE_ID)
        page.wait_for_function(
            "(feeds) => [...document.querySelectorAll('#bp-feeds option')].some(o => o.value === feeds)",
            arg=feeds, timeout=TIMEOUT_CONFIRM)
        page.select_option("#bp-feeds", feeds)
        page.fill("#bp-label", label)
        approve = page.locator("#bp-approve")
        if approve.count() and approve.is_checked():
            approve.uncheck()  # proposed, never approved: a person approves
        page.click("#bp-save")
        self._answer_yes(page, "#bp-save-yes")
        page.wait_for_selector("#bp-save-box", state="detached", timeout=TIMEOUT_SAVED)
        error = page.locator("#review-message .error")
        if error.count():
            raise AgentError(f"saving '{label}' failed: {error.first.inner_text()}")
        mid = self._wait_for_new_measurement(before, feeds, label)
        self.api.post(f"/measurements/{mid}/mark-agent",
                      {"auto_run_id": self.run_id, "candidate_id": self.candidate["id"]})
        self.measurement_ids.append(mid)
        self.log(f"saved '{label}' as measurement {mid} ({feeds})")
        return mid

    # -- small pieces -----------------------------------------------

    def _dismiss_tour(self, page) -> None:
        """Close the first-open tour pop-up if it auto-started, so it cannot cover a control."""
        try:
            page.wait_for_timeout(400)
            if page.locator("#tour-pop:visible").count():
                page.click("#tour-skip")
                page.wait_for_selector("#tour-pop", state="hidden", timeout=5000)
        except Exception:  # noqa: BLE001 - best effort only
            pass

    def _answer_yes(self, page, selector: str) -> None:
        """Click the Yes of an ask-first question, if one appears."""
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            page.wait_for_selector(selector, state="visible", timeout=TIMEOUT_CONFIRM)
            page.click(selector)
        except PlaywrightTimeoutError:
            pass  # no question asked: the save already went through

    def _viewer_state(self, page) -> dict:
        state = page.evaluate(_VIEWER_STATE_JS)
        if not state:
            raise AgentError("could not read the blueprint viewer state (RV.viewer) - "
                             "the review page may not have loaded")
        return state

    def _sheet_click(self, page, x: float, y: float) -> None:
        """Click a sheet point: fresh viewer state every time, so a re-fit or
        a calibration reload can never leave a stale transform behind."""
        state = self._viewer_state(page)
        cx, cy = sheet_to_screen(x, y, state["z"], state["tx"], state["ty"], state)
        if not (state["left"] <= cx <= state["left"] + state["width"]
                and state["top"] <= cy <= state["top"] + state["height"]):
            raise AgentError(f"slab point ({x}, {y}) is outside the visible sheet - "
                             "Fit may not have run; try the run again")
        page.mouse.click(cx, cy)
        page.wait_for_timeout(120)

    def _measurement_ids(self) -> set[int]:
        data = self.api.get(f"/estimates/{self.run_row['estimate_id']}/takeoff")
        return {m["id"] for m in data.get("takeoff", {}).get("measurements", [])}

    def _wait_for_new_measurement(self, before: set[int], feeds: str, label: str,
                                  timeout: float = 15) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = self.api.get(f"/estimates/{self.run_row['estimate_id']}/takeoff")
            fresh = [m for m in data.get("takeoff", {}).get("measurements", [])
                     if m["id"] not in before and m.get("feeds") == feeds
                     and m.get("label") == label and m.get("status") == "proposed"]
            if fresh:
                return max(m["id"] for m in fresh)
            time.sleep(1)
        raise AgentError(f"'{label}' saved but the new measurement never appeared "
                         "in the estimate - it may have failed to save")


# ------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Drive the Blueprint Review page for one concrete auto-run.")
    parser.add_argument("--base", required=True,
                        help="server origin (http://localhost:8770) or Estimator page base (.../estimator/)")
    parser.add_argument("--db", required=True, help="path to estimator.db (the run row lives here)")
    parser.add_argument("--run-id", required=True, type=int, help="auto_runs id to drive")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--headed", dest="headed", action="store_true",
                       help="show the browser, so the run can be watched")
    group.add_argument("--headless", dest="headed", action="store_false",
                       help="run the browser without a window (default)")
    parser.set_defaults(headed=False)
    parser.add_argument("--slow-mo", type=int, default=None,
                        help="milliseconds between Playwright steps (default 250 headed, 0 headless)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    slow_mo = args.slow_mo if args.slow_mo is not None else (250 if args.headed else 0)
    try:
        runner = ConcreteAutoRun(base=args.base, db_path=args.db, run_id=args.run_id,
                                 headed=args.headed, slow_mo=slow_mo)
    except AgentError as e:
        print(f"[concrete-autorun] FAILED: {e}", file=sys.stderr, flush=True)
        return 1
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
