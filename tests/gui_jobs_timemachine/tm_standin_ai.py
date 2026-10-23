"""A stand-in for Claude / Grok in the time-machine task-queue tests.

David 2026-10-22: "I don't think we should have real Claude or Grok runs
because that depends on having credits, but do everything else you can in the
Time Machine." So every AI step here is scripted: it does exactly what the
queue-runner prompt (task_queue_automation.QUEUE_RUNNER_PROMPT) tells the AI to
do, with fixed steps, against the time machine's throwaway AI-Prowler — no AI
service, no credits. Everything around the AI (the connection to the running
AI-Prowler, the MCP calls, the queue, the due dates, the outputs) is the real
code.

Used by test_tm_task_queue.py and by the fake `claude` it runs in the
scheduled-run test (tm_fake_claude.py).
"""
from __future__ import annotations

import json


def due_tasks(call) -> tuple[list, str]:
    """Step 1 of the queue-runner prompt: get_pending_analysis_tasks."""
    raw = call("get_pending_analysis_tasks", {})
    text = (raw or "").strip()
    if not text.startswith("{"):
        return [], raw            # "No tasks are due right now…" / "No pending analysis tasks…"
    return json.loads(text).get("tasks", []), raw


def plan_for(task: dict, when: str) -> list[tuple[str, dict]]:
    """Step 2: the tool calls asked for, for one task — its outputs, then
    complete_analysis_task. Learnings only when the task's own prompt asks
    (the queue-runner prompt's rule); a report / email when the prompt asks or
    the task's output flag says so (get_pending_analysis_tasks' instruction)."""
    label, prompt = task.get("label", ""), task.get("prompt", "")
    steps: list[tuple[str, dict]] = []
    if "record_learning()" in prompt:
        steps.append(("record_learning", {
            "title": f"{label} — stand-in run {when}",
            "content": f"Time-machine stand-in AI ran '{label}' at {when}.",
            "category": "business_insight", "tags": "ZTEST,time-machine"}))
    if "save_analysis_report()" in prompt or task.get("output_report"):
        steps.append(("save_analysis_report", {
            "task_id": task["task_id"], "title": f"{label} {when}",
            "content": f"## Summary\n- Stand-in run of {label} at {when}"}))
    if "send_email()" in prompt or task.get("output_email"):
        steps.append(("send_email", {
            "to": "", "subject": f"{label} — {when}",
            "body": f"Stand-in run of {label} at {when}."}))
    steps.append(("complete_analysis_task", {
        "task_id": task["task_id"], "summary": f"stand-in run {when}"}))
    return steps


def work_the_queue(call, when: str) -> dict:
    """The whole scheduled run, the way the prompt describes it. Returns
    {"done": [labels], "raw": first reply, "calls": [(tool, reply)]}."""
    tasks, raw = due_tasks(call)
    done, calls = [], []
    for t in tasks:
        for tool, args in plan_for(t, when):
            calls.append((tool, call(tool, args)))
        done.append(t.get("label", ""))
    return {"done": done, "raw": raw, "calls": calls}


class ScriptedGrok:
    """Plays the xAI chat API for task_queue_automation._run_grok_headless:
    turn 1 asks for get_pending_analysis_tasks; turn 2 makes every call
    plan_for() lists for the due tasks; turn 3 writes the final summary."""

    def __init__(self, when: str):
        self.when = when
        self.turn = 0
        self.offered: list[str] = []
        self.done: list[str] = []

    @staticmethod
    def _tc(i, name, args):
        return {"id": f"call_{i}", "function": {"name": name, "arguments": json.dumps(args)}}

    def __call__(self, api_key, messages, tools, model=None):
        self.offered = [t["function"]["name"] for t in tools]
        self.turn += 1
        if self.turn == 1:
            return {"tool_calls": [self._tc(0, "get_pending_analysis_tasks", {})]}
        if self.turn == 2:
            text = str(messages[-1].get("content", "")).strip()
            tasks = json.loads(text).get("tasks", []) if text.startswith("{") else []
            if not tasks:
                return {"content": "Nothing is due right now."}
            calls, n = [], 1
            for t in tasks:
                for tool, args in plan_for(t, self.when):
                    calls.append(self._tc(n, tool, args))
                    n += 1
                self.done.append(t.get("label", ""))
            return {"tool_calls": calls}
        return {"content": f"Ran {len(self.done)} task(s): {', '.join(self.done)}."}
