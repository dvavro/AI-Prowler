"""LLM takeoff auto-run: read the foundation sheet with the AI when geometry finds nothing.

The sibling API (estimator/api/autorun_api.py) starts this runner, detached, when a
run has no slab candidates and the owner turned LLM takeoff on. It needs no browser
and no HTTP: it reads the plan set's sheets from the database, calls the AI through
the provider/budget system (estimator/takeoff/llm_takeoff.py), and proposes the
concrete measurements straight into the database, where a person still approves them.

    python -m estimator.agents.llm_takeoff_runner --db <db path> --run-id <id>

Run-row updates are direct sqlite on the auto_runs table (the --db path), the same
RunStore the Playwright driver uses. On any failure the run row is marked failed
with the step and the error, so a run is never left stuck in 'running'.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys

from estimator.agents.concrete_autorun import AgentError, RunStore
from estimator.agents import providers
from estimator.context import RequestContext
from estimator.takeoff import llm_takeoff


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
            self.store.update(self.run_id, step=step)
        except sqlite3.Error as e:
            self.log(f"could not write step '{step}' to the run row: {e}")

    def _mark_failed(self, message: str) -> None:
        try:
            self.store.update(self.run_id, status="failed", step=self.step, error=message)
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
            from estimator.database import open_database
            self.conn = open_database(self.db_path)
            ctx = RequestContext(company_id=self.run_row["company_id"],
                                 user_id=self.run_row["created_by"] or "owner",
                                 role="owner", agent="llm-takeoff")
            result = llm_takeoff.run_llm_takeoff(self.conn, ctx, self.run_row, on_step=self.set_step)
            self.store.update(self.run_id, status="done", step="done",
                              candidate_id=llm_takeoff.CANDIDATE_ID, candidates=[result["candidate"]],
                              measurement_ids=result["measurement_ids"])
            self.log(f"done: read {result['reading']['slab_width_ft']} x "
                     f"{result['reading']['slab_length_ft']} on sheet "
                     f"{result['foundation_sheet_id']}; measurements {result['measurement_ids']}")
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
            self._close()


# ------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read the foundation sheet with the AI for one concrete auto-run.")
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
