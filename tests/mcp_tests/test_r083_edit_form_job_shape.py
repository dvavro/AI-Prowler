"""R-083 (2026-10-09, found by E2E SRV-FR-01/03): the Edit Job form
(openEditJobModal) reads its job from window._allSheetJobs, which two
mappers fill — the Database tab's (loadSheetScreen) and the board's
(_boardRowToJobShape). Neither mapped 'Preferred Day(s)', so every edited
job opened with no days ticked and Save wiped the stored days.

This guards the whole class: every j.<field> the edit form reads must be
produced by BOTH mappers (pure source check of jobs/index.html).

Run: run_tests.bat tests\\mcp_tests\\test_r083_edit_form_job_shape.py -v
"""
import pathlib
import re

SRC = (pathlib.Path(__file__).resolve().parents[2] / "jobs" / "index.html").read_text(encoding="utf-8")


def _body(start_marker: str) -> str:
    start = SRC.index(start_marker)
    i = SRC.index("{", start)
    depth = 0
    for j in range(i, len(SRC)):
        depth += {"{": 1, "}": -1}.get(SRC[j], 0)
        if depth == 0:
            return SRC[start:j + 1]
    raise AssertionError(start_marker)


def _keys(obj_src: str) -> set:
    return set(re.findall(r"^\s*(\w+)\s*:", obj_src, re.M))


def _form_reads() -> set:
    body = _body("function openEditJobModal(jobId)")
    return set(re.findall(r"\bj\.(\w+)", body)) - {"id"}


def _sheet_mapper() -> str:
    # the Database-tab mapper: the object literal that ends "}; }) : [];"
    end = SRC.index("}; }) : [];")
    start = SRC.rindex("id:", 0, end)
    return SRC[start:end]


def test_edit_form_reads_preferred_days():
    assert "preferredDays" in _form_reads()


def test_board_mapper_has_every_field_the_edit_form_reads():
    missing = _form_reads() - _keys(_body("function _boardRowToJobShape(r)")) - {"custId", "customer"}
    assert not missing, f"_boardRowToJobShape doesn't map: {sorted(missing)}"


def test_sheet_mapper_has_every_field_the_edit_form_reads():
    keys = _keys(_sheet_mapper()) | {"id"}
    missing = _form_reads() - keys - {"custId", "customer"}
    assert not missing, f"the Database-tab job mapper doesn't map: {sorted(missing)}"


def test_customer_type_is_not_defaulted_to_residential():
    """R-081: a job's Customer Type is its customer's; blank stays blank."""
    for src in (_body("function _boardRowToJobShape(r)"), _sheet_mapper()):
        line = next(l for l in src.splitlines() if "customerType:" in l)
        assert "Residential" not in line, line
