"""LLM takeoff auto-run: read the plan with the AI when geometry finds nothing.

The sibling API (estimator/api/autorun_api.py) starts this runner, detached, when a
run has no drawing candidates and the owner turned LLM takeoff on. It needs no browser
and no HTTP: it reads the plan set's sheets from the database, calls the AI through
the provider/budget system, and proposes the measurements straight into the database,
where a person still approves them. Which reader runs depends on the run's trade (concrete: estimator/takeoff/llm_takeoff.py;
every other trade: estimator/takeoff/llm_<trade>.py, run_llm_<trade> by convention).

    python -m estimator.agents.llm_takeoff_runner --db <db path> --run-id <id>

Run-row updates are direct sqlite on the auto_runs table (the --db path), the same
RunStore the Playwright driver uses. On any failure the run row is marked failed
with the step and the error, so a run is never left stuck in 'running'.
"""

from __future__ import annotations

import argparse
import importlib
import sqlite3
import sys
from datetime import datetime, timezone

from estimator.agents.concrete_autorun import AgentError, RunStore
from estimator.agents import providers
from estimator.context import RequestContext
from estimator.takeoff import llm_takeoff


def _trade_label(module_id: str) -> str:
    """The trade's display name from its manifest, else the module id as given
    (the same naming the API's refusal uses)."""
    try:
        from estimator.modules import get_registry
        return get_registry().get(module_id).name
    except Exception:  # noqa: BLE001 - no manifest, no registry: the id is the name
        return module_id


def _run_trade_reader(conn, ctx, run_row, module_id, on_step=None):
    """The trade's LLM reader, by convention: estimator/takeoff/llm_<trade>.py,
    run_llm_<trade>. A trade with no reader module isn't built yet."""
    try:
        mod = importlib.import_module(f"estimator.takeoff.llm_{module_id}")
    except ModuleNotFoundError as exc:
        if exc.name == f"estimator.takeoff.llm_{module_id}":
            raise AgentError(f"auto-run isn't built for {_trade_label(module_id)} yet") from None
        raise
    fn = getattr(mod, f"run_llm_{module_id}", None)
    if fn is None:
        raise AgentError(f"auto-run isn't built for {_trade_label(module_id)} yet")
    return fn(conn, ctx, run_row, on_step=on_step)


def run_wiring_stage(conn, ctx, estimate_id, on_step=None, keep_approved: bool = True) -> dict:
    """Electrical's second stage inside AI Auto Measure/Count: route the wiring from the panel to every device (plain geometry,
    no AI tokens) and propose the cable measurements - when the project has both CAD drawings (the electrical floor
    plan and the panel drawing). The last Wiring run's settings and device moves are kept. A missing drawing or a
    wiring problem never fails the device count; it is reported instead."""
    from estimator.takeoff import wiring_run
    try:
        src = wiring_run.sources(conn, ctx, estimate_id)
        if not src["plan"]:
            # 2026-11-21: only the floor plan is needed; with no panel drawing the circuits are laid out for it.
            return {"ran": False, "why": "wiring not routed - upload the electrical floor plan as a DXF (CAD) file on "
                                         "the Plans screen (a panel drawing with its schedule is used when there is one)"}
        if on_step:
            on_step("routing the wiring")
        last = wiring_run.latest(ctx, estimate_id) or {}
        r = wiring_run.run(conn, ctx, estimate_id, last.get("settings"), last.get("overrides"),
                           keep_approved=keep_approved, on_step=on_step)
    except Exception as e:  # noqa: BLE001 - the count stands; say why the wiring didn't
        return {"ran": False, "why": f"wiring not routed - {e}"}
    cable = ", ".join(f"{b['measured_ft']:g} ft of {b['cable'].split()[0]}" for b in r["bom"])
    laid_out = r.get("circuits_from") == "laid_out"
    return {"ran": True, "measurement_ids": r["measurement_ids"], "circuits": len(r["circuits"]),
            "unassigned": len(r["unassigned"]), "bom": r["bom"], "circuits_from": r.get("circuits_from", "schedule"),
            "summary": f"{len(r['circuits'])} circuits routed"
                       + (" (no panel schedule - circuits laid out by AI-Prowler)" if laid_out else "") + f": {cable}"}


class LlmTakeoffRun:
    def __init__(self, *, db_path: str, run_id: int):
        self.store = RunStore(db_path)
        self.db_path = db_path
        self.run_id = run_id
        self.run_row: dict | None = None
        self.step = "starting"
        self.conn = None

    # -- plumbing ---------------------------------------------------

    def log(self, message: str) -> None:
        print(f"[llm-takeoff] {message}", flush=True)

    def set_step(self, step: str) -> None:
        self.step = step
        self.log(step)
        try:
            self.store.update(self.run_id, step=step, live=None)      # a new step starts with no AI progress yet
        except sqlite3.Error as e:
            self.log(f"could not write step '{step}' to the run row: {e}")

    def set_live(self, info: dict) -> None:
        """The AI's progress while it answers (2026-11-21, David): the waiting message shows its latest sentence
        and how much has come back. Best effort - a busy database just skips one update."""
        try:
            self.store.update(self.run_id, live={**info, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        except sqlite3.Error:
            pass

    def _mark_failed(self, message: str) -> None:
        try:
            self.store.update(self.run_id, status="failed", step=self.step, error=message, live=None)
        except Exception as e:  # noqa: BLE001 - failing to record the failure must not hide it
            self.log(f"could not mark the run failed: {e}")

    def _close(self) -> None:
        for closer in (getattr(self.conn, "close", None), self.store.close):
            try:
                if closer:
                    closer()
            except Exception:  # noqa: BLE001 - teardown must not raise
                pass
        self.conn = None

    # -- the run ----------------------------------------------------

    def run(self) -> int:
        """Read the plan and propose the measurements. 0 on success, 1 on failure."""
        try:
            self.run_row = self.store.read_run(self.run_id)
            self.store.update(self.run_id, status="running", step="starting")
            providers.set_progress(self.set_live)    # every trade's AI reading shows its progress (2026-11-21)
            from estimator.database import open_database
            self.conn = open_database(self.db_path)
            ctx = RequestContext(company_id=self.run_row["company_id"],
                                 user_id=self.run_row["created_by"] or "owner",
                                 role="owner", agent="llm-takeoff")
            module_id = self.run_row["module_id"]
            if module_id == "concrete":
                result = llm_takeoff.run_llm_takeoff(self.conn, ctx, self.run_row, on_step=self.set_step)
            else:
                result = _run_trade_reader(self.conn, ctx, self.run_row, module_id,
                                         on_step=self.set_step)
            if module_id == "electrical":            # the second stage: wire sizes and lengths (2026-11-19, David)
                wired = run_wiring_stage(self.conn, ctx, self.run_row["estimate_id"], on_step=self.set_step,
                                         keep_approved=bool(self.run_row.get("keep_approved", 1)))
                result["candidate"] = {**result["candidate"], "wiring": wired}
                result["measurement_ids"] = list(result["measurement_ids"]) + wired.get("measurement_ids", [])
                self.log(f"wiring: {wired.get('summary') or wired.get('why')}")
            self.store.update(self.run_id, status="done", step="done",
                              candidate_id=llm_takeoff.CANDIDATE_ID, candidates=[result["candidate"]],
                              measurement_ids=result["measurement_ids"], live=None)
            self.log(f"done: {result['summary']}")
            return 0
        except (AgentError, llm_takeoff.LlmTakeoffError, providers.ProviderError) as e:
            self._mark_failed(str(e))
            self.log(f"FAILED at {self.step}: {e}")
            return 1
        except Exception as e:  # noqa: BLE001 - any surprise still marks the run failed
            message = f"{self.step}: {e}"
            self._mark_failed(message)
            self.log(f"FAILED: {message}")
            return 1
        finally:
            providers.set_progress(None)
            self._close()


# ------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read the plan with the AI for one auto-run (any trade with a reader).")
    parser.add_argument("--db", required=True, help="path to estimator.db (the run row lives here)")
    parser.add_argument("--run-id", required=True, type=int, help="auto_runs id to drive")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        runner = LlmTakeoffRun(db_path=args.db, run_id=args.run_id)
    except AgentError as e:
        print(f"[llm-takeoff] FAILED: {e}", file=sys.stderr, flush=True)
        return 1
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
