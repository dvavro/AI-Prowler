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


# ── known_user_ids ─────────────────────────────────────────────────────────
# Added 2026-07-13 after the Christina incident: the watchdog and scheduled
# task both need to know which user:<id> collections currently correspond
# to a REAL, live user, so a rule pointing at a deleted account is never
# silently treated as safe.

def test_known_user_ids_dict_shape_keyed_by_token():
    # users.json's "users" key is keyed by bearer TOKEN, not id — id is a
    # field INSIDE each entry. This is the actual real-world shape.
    users_data = {"users": {
        "sometoken123": {"id": "christina01", "role": "staff"},
        "othertoken456": {"id": "david-owner", "role": "owner"},
    }}
    assert sr.known_user_ids(users_data) == {"christina01", "david-owner"}


def test_known_user_ids_list_shape_tolerated():
    users_data = {"users": [
        {"id": "alice01"}, {"id": "bob02"},
    ]}
    assert sr.known_user_ids(users_data) == {"alice01", "bob02"}


def test_known_user_ids_missing_key_returns_empty_set():
    assert sr.known_user_ids({}) == set()
    assert sr.known_user_ids(None) == set()


def test_known_user_ids_malformed_entries_skipped():
    users_data = {"users": {
        "t1": {"id": "good01"},
        "t2": "garbage",
        "t3": {"no_id_field": True},
        "t4": None,
    }}
    assert sr.known_user_ids(users_data) == {"good01"}


def test_known_user_ids_never_raises_on_garbage_input():
    # Must degrade to empty set, never throw — a caller with a corrupt
    # users.json should skip everything (safe), not crash the watchdog.
    assert sr.known_user_ids("not a dict at all") == set()
    assert sr.known_user_ids({"users": "not a dict or list"}) == set()


# ── resolve_collection_for_unattended_path ──────────────────────────────────
# Added 2026-07-13 (the Christina incident): the file watchdog and scheduled
# task have NO acting user/session, unlike resolve_collection_for_path (live
# MCP calls, which always has a real user to fall back to). This function's
# contract is deliberately different: no default_collection fallback, no
# indexer-identity fallback — a match must come from an actual rule, and if
# that rule points at a user:<id>, that id must be verified as a real
# CURRENT user. Anything else returns None, meaning "skip and log", never
# a guessed destination.

CHRISTINA_RULE = {"prefix": "C:/CompanyDocs/Personal/Christina",
                  "collection": "user:christina01"}
SALES_RULE = {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}


def test_unattended_matches_rule_like_the_normal_resolver():
    mapping = {"rules": [SALES_RULE]}
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/Sales/q3.pdf", mapping) == "role:sales"


def test_unattended_longest_prefix_still_wins():
    mapping = {"rules": [
        {"prefix": "C:/Co", "collection": "role:all"},
        {"prefix": "C:/Co/Sales", "collection": "role:sales"},
    ]}
    assert sr.resolve_collection_for_unattended_path(
        "C:/Co/Sales/q3.pdf", mapping) == "role:sales"


def test_unattended_no_rule_matched_returns_none_not_a_guess():
    # This is THE core behavior difference from resolve_collection_for_path:
    # no rule -> None, never "documents", never the caller's own space
    # (there is no caller), never "shared".
    assert sr.resolve_collection_for_unattended_path(
        "C:/SomeRandomFolder/x.pdf", {"rules": [SALES_RULE]}) is None


def test_unattended_ignores_default_collection_entirely():
    # Deliberately different from resolve_collection_for_path: even if an
    # admin configured a default_collection, the unattended resolver must
    # NOT use it — see the function's own docstring for the full rationale
    # (skip + log is the only safe unattended fallback).
    mapping = {"rules": [SALES_RULE], "default_collection": "shared"}
    assert sr.resolve_collection_for_unattended_path(
        "C:/Unmatched/x.pdf", mapping) is None


def test_unattended_personal_collection_matches_when_user_is_known():
    mapping = {"rules": [CHRISTINA_RULE]}
    known = {"christina01", "david-owner"}
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/Personal/Christina/notes.docx",
        mapping, known_ids=known) == "user:christina01"


def test_unattended_personal_collection_REJECTED_when_user_deleted():
    # The core safety check this whole function exists for: a rule that
    # still technically matches, but names a user who no longer exists,
    # must be treated exactly like no match at all — never write into an
    # orphaned private collection.
    mapping = {"rules": [CHRISTINA_RULE]}
    known = {"david-owner"}  # christina01 is NOT in this set — she's gone
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/Personal/Christina/notes.docx",
        mapping, known_ids=known) is None


def test_unattended_known_ids_none_skips_existence_check():
    # Explicitly passing known_ids=None means "trust the id as-is" — the
    # caller's own choice, documented as not recommended but supported for
    # callers that already validated some other way.
    mapping = {"rules": [CHRISTINA_RULE]}
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/Personal/Christina/notes.docx",
        mapping, known_ids=None) == "user:christina01"


def test_unattended_non_user_collection_unaffected_by_known_ids():
    # The existence check only applies to "user:<id>" targets — a
    # role/scope collection match is unaffected by known_ids entirely.
    mapping = {"rules": [SALES_RULE]}
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/Sales/deal.docx", mapping,
        known_ids=set()) == "role:sales"


def test_unattended_empty_mapping_returns_none():
    assert sr.resolve_collection_for_unattended_path("C:/x", None) is None
    assert sr.resolve_collection_for_unattended_path("C:/x", {}) is None


def test_unattended_segment_boundary_matching_matches_normal_resolver():
    # Same boundary-safety as resolve_collection_for_path — 'Sales' must
    # not spuriously match 'SalesArchive'.
    mapping = {"rules": [SALES_RULE]}
    assert sr.resolve_collection_for_unattended_path(
        "C:/CompanyDocs/SalesArchive/x.pdf", mapping) is None
