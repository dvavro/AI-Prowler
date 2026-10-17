"""
Runs LAST in this folder (name order): after the browser tests, nothing may be
left running in this thread - the rest of run_tests.bat calls asyncio.run().
(Unique file name: pytest needs one per test module across folders.)
"""
import asyncio


def test_no_event_loop_left_running_after_the_time_machine():
    async def ping():
        return 42
    assert asyncio.run(ping()) == 42
