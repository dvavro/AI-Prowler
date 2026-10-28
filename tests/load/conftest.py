"""tests/load holds stand-alone load scripts, run by hand, e.g.
    python tests\\load\\desk_load_test.py 60 10 5000   (seconds, users, tickets)
They do their work at import time, so pytest must never collect them — its
name ends in _test.py, which pytest would otherwise pick up in a full run
(found by the 2026-10-28 regression: collection crashed on pytest's own args)."""
collect_ignore_glob = ["*.py"]
