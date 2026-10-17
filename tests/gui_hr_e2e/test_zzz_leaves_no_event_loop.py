"""
Runs LAST in this folder (name order): after the browser tests, nothing may be
left running in this thread - the rest of run_tests.bat calls asyncio.run()
(2026-10-17: a session-wide Playwright broke 49 later tests that way).
"""
import asyncio


def test_no_event_loop_left_running():
    async def ping():
        return 42
    assert asyncio.run(ping()) == 42
