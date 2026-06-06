"""
Unit tests for scope_resolver -- the shared folder->scope logic used by BOTH
the MCP engine (ai_prowler_mcp) and the GUI (rag_gui Update Index tab).

Pure and headless: no Tk, no MCP-server import, no deps. Fast to run:
    pytest tests/test_scope_resolver.py -v
"""
import scope_resolver as sr


# ── normalize_path_for_match ──────────────────────────────────────────────
def test_normalize_lowercases_and_forward_slashes():
    assert sr.normalize_path_for_match(r"C:\CompanyDocs\Sales") == "c:/companydocs/sales"


def test_normalize_strips_trailing_slash():
    assert sr.normalize_path_for_match("C:/Docs/") == "c:/docs"
    assert sr.normalize_path_for_match("C:/Docs\\") == "c:/docs"


def test_normalize_none_and_empty():
    assert sr.normalize_path_for_match("") == ""
    assert sr.normalize_path_for_match(None) == ""


def test_normalize_backslash_forward_equivalence():
    assert sr.normalize_path_for_match(r"C:\a\b") == sr.normalize_path_for_match("C:/a/b")


# ── resolve_collection_for_path ───────────────────────────────────────────
SALES = {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}
OFFICE = {"prefix": "C:/CompanyDocs/Office", "collection": "role:office"}


def test_longest_prefix_wins():
    mapping = {"rules": [
        {"prefix": "C:/Co", "collection": "role:all"},
        {"prefix": "C:/Co/Sales", "collection": "role:sales"},
    ]}
    assert sr.resolve_collection_for_path("C:/Co/Sales/q3.pdf", mapping) == "role:sales"


def test_segment_boundary_no_false_match():
    # 'Sales' must NOT match 'SalesArchive'; with no default -> terminal fallback.
    mapping = {"rules": [SALES]}
    assert sr.resolve_collection_for_path(
        "C:/CompanyDocs/SalesArchive/x.pdf", mapping) == "documents"


def test_exact_prefix_match():
    assert sr.resolve_collection_for_path("C:/CompanyDocs/Sales", {"rules": [SALES]}) == "role:sales"


def test_case_insensitive():
    assert sr.resolve_collection_for_path(
        r"c:\companydocs\sales\deal.docx", {"rules": [SALES]}) == "role:sales"


def test_backslash_path_matches_forward_slash_rule():
    assert sr.resolve_collection_for_path(
        r"C:\CompanyDocs\Sales\deal.docx", {"rules": [SALES]}) == "role:sales"


def test_no_rule_falls_back_to_default():
    mapping = {"rules": [SALES], "default_collection": "shared"}
    assert sr.resolve_collection_for_path("C:/Other/file.txt", mapping) == "shared"


def test_no_rule_no_default_uses_indexer_private():
    # This is the bug the GUI display had: it must NOT be 'shared'.
    assert sr.resolve_collection_for_path(
        "C:/Other/x", {"rules": []}, {"id": "alice01"}) == "user:alice01"


def test_no_rule_no_default_no_user_is_documents():
    assert sr.resolve_collection_for_path("C:/Other/x", {"rules": []}) == "documents"


def test_empty_mapping_is_documents():
    assert sr.resolve_collection_for_path("C:/x", None) == "documents"
    assert sr.resolve_collection_for_path("C:/x", {}) == "documents"


def test_malformed_rules_are_skipped():
    mapping = {"rules": [None, "garbage", {"prefix": "", "collection": "x"},
                         {"prefix": "C:/Co", "collection": ""}, SALES]}
    assert sr.resolve_collection_for_path("C:/CompanyDocs/Sales/x", mapping) == "role:sales"


# ── upsert_scope_rule ─────────────────────────────────────────────────────
def test_upsert_adds_new_rule():
    out = sr.upsert_scope_rule([dict(SALES)], "C:/CompanyDocs/Office", "role:office")
    assert {"prefix": "C:/CompanyDocs/Office", "collection": "role:office"} in out
    assert len(out) == 2


def test_upsert_updates_existing_rule_collection():
    out = sr.upsert_scope_rule([dict(SALES)], "C:/CompanyDocs/Sales", "role:exec")
    assert len(out) == 1
    assert out[0]["collection"] == "role:exec"


def test_upsert_matches_regardless_of_slash_or_case():
    # prefix stored forward-slash; folder passed backslash/lowercase -> SAME rule.
    out = sr.upsert_scope_rule([dict(SALES)], r"c:\companydocs\sales", "role:exec")
    assert len(out) == 1
    assert out[0]["collection"] == "role:exec"


def test_upsert_does_not_mutate_input():
    rules = [dict(SALES)]
    sr.upsert_scope_rule(rules, "C:/CompanyDocs/Sales", "role:exec")
    assert rules[0]["collection"] == "role:sales"


def test_upsert_does_not_clobber_sibling():
    out = sr.upsert_scope_rule([dict(SALES), dict(OFFICE)],
                               "C:/CompanyDocs/Sales", "role:exec")
    assert sum(1 for r in out if r["collection"] == "role:office") == 1
    assert sum(1 for r in out if r["collection"] == "role:exec") == 1
