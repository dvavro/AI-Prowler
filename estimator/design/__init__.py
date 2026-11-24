"""AI design (2026-11-21, David: "the user has a shed drawing or house drawing and wants AI to do the addition of the
electrical work ... design me the lighting and receptacles ... then review"): on the Measure screen a person types what
they want added to their drawings; the AI reads the building, places every symbol from the request, the specs and the
code rules, and the app draws it as a new CAD drawing (plan + panel schedule), checks it, and keeps it PROPOSED. The
person changes it in plain words and approves it; only then does it become plan sets that are measured and priced.

Electrical first (design/electrical.py); the other trades follow on the same frame (design/runs.py: TRADES).

    building.py   the building the design goes on: from a CAD drawing's walls, or read by the AI from a PDF / photo
    electrical.py the electrical designer: the AI's prompt and answer, and the app's code checks
    draw_electrical.py  the design drawn as DXF (plan + panel schedule), read back by the plan engine and the wiring run
    runs.py       the design jobs: proposed -> revised -> approved (plan sets) / discarded, kept in the data folder
"""
