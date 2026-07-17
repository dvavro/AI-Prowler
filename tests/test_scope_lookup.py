"""
Unit tests for scope_lookup -- the single-collection scope-tagging logic
that replaces scope_resolver.py's multi-collection routing (see
SCOPE_SIMPLIFICATION_SPEC.md at the repo root for the full design).

Pure and headless: no Tk, no MCP-server import, no deps. Fast to run:
    pytest tests/test_scope_lookup.py -v
"""
import scope_lookup as sl


# ── normalize_path_for_match ────────────────────────────────────────────
def test_normalize_lowercases_and_forward_slashes():
    assert sl.normalize_path_for_match(r"C:\CompanyDocs\Sales") == "c:/companydocs/sales"


def test_normalize_strips_trailing_slash():
    assert sl.normalize_path_for_match("C:/Docs/") == "c:/docs"
    assert sl.normalize_path_for_match("C:/Docs\\") == "c:/docs"


def test_normalize_none_and_empty():
    assert sl.normalize_path_for_match("") == ""
    assert sl.normalize_path_for_match(None) == ""


def test_normalize_backslash_forward_equivalence():
    assert sl.normalize_path_for_match(r"C:\a\b") == sl.normalize_path_for_match("C:/a/b")


# ── canon_scope_name ─────────────────────────────────────────────────────
def test_canon_strips_legacy_scope_prefix():
    assert sl.canon_scope_name("scope:office") == "office"


def test_canon_strips_legacy_role_prefix():
    assert sl.canon_scope_name("role:sales") == "sales"


def test_canon_plain_name_unchanged():
    assert sl.canon_scope_name("office") == "office"


def test_canon_shared_unchanged():
    assert sl.canon_scope_name("shared") == "shared"


def test_canon_private_prefix_preserved():
    # The id after 'private:' is load-bearing -- must NOT be stripped
    # the way 'scope:'/'role:' are.
    assert sl.canon_scope_name("private:david-vavro") == "private:david-vavro"


def test_canon_case_insensitive():
    assert sl.canon_scope_name("Scope:Office") == "office"


def test_canon_none_and_empty():
    assert sl.canon_scope_name("") == ""
    assert sl.canon_scope_name(None) == ""


# ── resolve_scope_for_path: business scope_map matching ─────────────────
SCOPE_MAP = {
    "C:/CompanyDocs/Sales": "sales",
    "C:/CompanyDocs/Office": "office",
}


def test_longest_prefix_wins():
    scope_map = {
        "C:/Co": "shared",
        "C:/Co/Sales": "sales",
    }
    assert sl.resolve_scope_for_path("C:/Co/Sales/q3.pdf", scope_map) == "sales"


def test_segment_boundary_no_false_match():
    # 'Sales' must NOT match 'SalesArchive'; falls through to default.
    assert sl.resolve_scope_for_path(
        "C:/CompanyDocs/SalesArchive/x.pdf", SCOPE_MAP) == "shared"


def test_exact_prefix_match():
    assert sl.resolve_scope_for_path("C:/CompanyDocs/Sales", SCOPE_MAP) == "sales"


def test_case_insensitive():
    assert sl.resolve_scope_for_path(
        r"c:\companydocs\sales\deal.docx", SCOPE_MAP) == "sales"


def test_backslash_path_matches_forward_slash_rule():
    assert sl.resolve_scope_for_path(
        r"C:\CompanyDocs\Sales\deal.docx", SCOPE_MAP) == "sales"


# ── resolve_scope_for_path: default-to-shared (the new behavior) ────────
def test_no_matching_rule_defaults_to_shared():
    """Direct product decision: unscoped tracked path -> 'shared',
    never blocked/quarantined/skipped."""
    assert sl.resolve_scope_for_path("C:/SomeNewFolder/x.pdf", {}) == "shared"
    assert sl.resolve_scope_for_path(
        "C:/SomeNewFolder/x.pdf", SCOPE_MAP) == "shared"


def test_new_subfolder_under_tracked_root_inherits_parent_scope():
    """A subfolder that appears later under an already-tracked, scoped
    root -- with no override rule of its own -- INHERITS that root's
    scope via the normal longest-prefix match. This is the core
    mechanism (recursive inheritance from the tracked root, spec section
    3.3), not the thing that was removed. What's actually gone is
    PER-SUBFOLDER OVERRIDE rules (a subfolder claiming a *different*
    scope than its parent) -- see the private-folder-under-privates-root
    tests below for the one remaining exception to plain inheritance."""
    assert sl.resolve_scope_for_path(
        "C:/CompanyDocs/Sales/NewSubfolder/misfiled.pdf", SCOPE_MAP) == "sales"


def test_sibling_of_tracked_root_defaults_to_shared():
    """The 'default to shared' behavior applies to paths that don't fall
    under ANY tracked/scoped root at all -- a sibling folder next to
    Sales, not a subfolder inside it."""
    assert sl.resolve_scope_for_path(
        "C:/CompanyDocs/BrandNewFolder/x.pdf", SCOPE_MAP) == "shared"


def test_empty_scope_map_defaults_to_shared():
    assert sl.resolve_scope_for_path("C:/anything.pdf", None) == "shared"


# ── resolve_scope_for_path: private-folder convention ────────────────────
PRIVATES_ROOT = "C:/Users/AI-Prowler-Server/Documents/AI-Prowler-Server-privates"


def test_private_folder_resolves_by_convention():
    path = PRIVATES_ROOT + "/david-vavro-private/notes.txt"
    assert sl.resolve_scope_for_path(
        path, {}, privates_root=PRIVATES_ROOT) == "private:david-vavro"


def test_private_folder_ignores_scope_map_entirely():
    """Even if scope_map somehow had a conflicting rule for this exact
    path, the private-folder convention wins -- private scope is derived,
    never configured, so there's nothing to drift out of sync."""
    scope_map = {PRIVATES_ROOT + "/david-vavro-private": "shared"}
    path = PRIVATES_ROOT + "/david-vavro-private/notes.txt"
    assert sl.resolve_scope_for_path(
        path, scope_map, privates_root=PRIVATES_ROOT) == "private:david-vavro"


def test_private_folder_nested_subpath():
    path = PRIVATES_ROOT + "/vicki-vavro-private/2026/reports/q3.pdf"
    assert sl.resolve_scope_for_path(
        path, {}, privates_root=PRIVATES_ROOT) == "private:vicki-vavro"


def test_privates_root_itself_is_not_a_private_scope():
    """The root folder itself (no <slug>-private child segment) has
    nothing to derive a slug from -- falls through to default."""
    assert sl.resolve_scope_for_path(
        PRIVATES_ROOT, {}, privates_root=PRIVATES_ROOT) == "shared"


def test_sibling_folder_under_privates_root_without_suffix_not_private():
    """A folder under the privates root that doesn't end in '-private'
    (e.g. a stray misnamed folder) is not treated as anyone's private
    scope -- falls through to normal scope_map / default resolution."""
    path = PRIVATES_ROOT + "/some-other-folder/x.txt"
    assert sl.resolve_scope_for_path(
        path, {}, privates_root=PRIVATES_ROOT) == "shared"


def test_privates_root_none_skips_private_detection():
    """When privates_root is not supplied, a path that LOOKS like a
    private folder is just matched normally (no special-casing) --
    lets callers that already know a path isn't under the privates tree
    skip the check entirely."""
    path = PRIVATES_ROOT + "/david-vavro-private/notes.txt"
    assert sl.resolve_scope_for_path(path, {}, privates_root=None) == "shared"


def test_private_folder_case_insensitive():
    path = PRIVATES_ROOT.upper() + "/DAVID-VAVRO-PRIVATE/notes.txt"
    assert sl.resolve_scope_for_path(
        path, {}, privates_root=PRIVATES_ROOT) == "private:david-vavro"


# ── allowed_scopes_for_user ────────────────────────────────────────────
def test_none_user_gets_no_scopes():
    assert sl.allowed_scopes_for_user(None) == set()


def test_every_user_always_gets_shared():
    user = {"id": "staff-1", "role": "staff", "scopes": []}
    assert "shared" in sl.allowed_scopes_for_user(user)


def test_user_with_no_scopes_key_still_gets_shared():
    user = {"id": "staff-1", "role": "staff"}
    assert sl.allowed_scopes_for_user(user) == {"shared"}


def test_user_scopes_are_added_and_canonicalized():
    user = {"id": "vicki-vavro", "role": "manager",
            "scopes": ["scope:sales", "scope:office"]}
    assert sl.allowed_scopes_for_user(user) == {"shared", "sales", "office"}


def test_private_scope_added_only_when_enabled():
    user = {"id": "david-vavro", "role": "owner", "scopes": [],
            "private_collection_enabled": True}
    assert sl.allowed_scopes_for_user(user) == {"shared", "private:david-vavro"}


def test_private_scope_absent_when_not_enabled():
    user = {"id": "david-vavro", "role": "owner", "scopes": [],
            "private_collection_enabled": False}
    assert sl.allowed_scopes_for_user(user) == {"shared"}


def test_owner_does_not_automatically_get_other_users_private_scope():
    """CRITICAL: private stays private from everyone but its own user,
    including the owner -- by direct product decision. Owner's
    allowed_scopes must contain ONLY their own private:<id>, never
    another user's, regardless of role."""
    owner = {"id": "david-vavro", "role": "owner",
             "scopes": ["office", "sales", "ops", "field"],
             "private_collection_enabled": True}
    result = sl.allowed_scopes_for_user(owner)
    assert result == {"shared", "office", "sales", "ops", "field",
                       "private:david-vavro"}
    assert "private:vicki-vavro" not in result
    assert "private:samantha-vavro" not in result


def test_manager_scopes_do_not_leak_into_other_users():
    vicki = {"id": "vicki-vavro", "role": "manager",
             "scopes": ["scope:sales", "scope:office"],
             "private_collection_enabled": True}
    result = sl.allowed_scopes_for_user(vicki)
    assert result == {"shared", "sales", "office", "private:vicki-vavro"}


def test_field_crew_limited_to_assigned_scope():
    jake = {"id": "jake-crew", "role": "field_crew", "scopes": ["scope:field"]}
    assert sl.allowed_scopes_for_user(jake) == {"shared", "field"}


def test_private_missing_id_does_not_crash():
    """Defensive: a malformed user record with private_collection_enabled
    but no id must not add a broken 'private:None' scope."""
    user = {"role": "staff", "scopes": [], "private_collection_enabled": True}
    result = sl.allowed_scopes_for_user(user)
    assert "private:None" not in result
    assert result == {"shared"}


# ── get_scope_map ─────────────────────────────────────────────────────
def test_get_scope_map_returns_the_map():
    users_data = {"scope_map": {"C:/Sales": "sales"}}
    assert sl.get_scope_map(users_data) == {"C:/Sales": "sales"}


def test_get_scope_map_missing_key_returns_empty_dict():
    assert sl.get_scope_map({}) == {}
    assert sl.get_scope_map(None) == {}


def test_get_scope_map_malformed_value_returns_empty_dict():
    """A corrupt users.json (scope_map is a list, string, etc.) degrades
    to empty rather than crashing -- same fail-safe posture as
    known_user_ids() in the old scope_resolver.py."""
    assert sl.get_scope_map({"scope_map": ["not", "a", "dict"]}) == {}
    assert sl.get_scope_map({"scope_map": "garbage"}) == {}


def test_get_scope_map_is_a_copy_not_a_reference():
    """Mutating the returned dict must not corrupt the caller's
    users_data -- read-only contract."""
    users_data = {"scope_map": {"C:/Sales": "sales"}}
    result = sl.get_scope_map(users_data)
    result["C:/Sales"] = "tampered"
    assert users_data["scope_map"]["C:/Sales"] == "sales"


# ── set_scope_for_path ───────────────────────────────────────────────
def test_set_scope_adds_new_entry():
    result = sl.set_scope_for_path({}, "C:/CompanyDocs/Sales", "sales")
    assert result == {"c:/companydocs/sales": "sales"}


def test_set_scope_updates_existing_entry():
    existing = {"c:/companydocs/sales": "office"}  # e.g. mis-assigned
    result = sl.set_scope_for_path(existing, "C:/CompanyDocs/Sales", "sales")
    assert result == {"c:/companydocs/sales": "sales"}


def test_set_scope_normalizes_slashes_and_case_to_the_same_key():
    """Typing the same folder two different ways must overwrite the SAME
    entry, never accumulate a duplicate."""
    m1 = sl.set_scope_for_path({}, r"C:\CompanyDocs\Sales", "sales")
    m2 = sl.set_scope_for_path(m1, "c:/companydocs/sales/", "office")
    assert len(m2) == 1
    assert m2["c:/companydocs/sales"] == "office"


def test_set_scope_does_not_mutate_input():
    original = {"c:/a": "office"}
    result = sl.set_scope_for_path(original, "C:/B", "sales")
    assert original == {"c:/a": "office"}
    assert result == {"c:/a": "office", "c:/b": "sales"}


def test_set_scope_does_not_clobber_sibling_entries():
    existing = {"c:/companydocs/sales": "sales"}
    result = sl.set_scope_for_path(existing, "C:/CompanyDocs/Office", "office")
    assert result == {
        "c:/companydocs/sales": "sales",
        "c:/companydocs/office": "office",
    }


def test_set_scope_blank_path_is_a_noop():
    assert sl.set_scope_for_path({"c:/a": "office"}, "", "sales") == {"c:/a": "office"}
    assert sl.set_scope_for_path({"c:/a": "office"}, None, "sales") == {"c:/a": "office"}


def test_set_scope_blank_scope_is_a_noop():
    assert sl.set_scope_for_path({"c:/a": "office"}, "C:/B", "") == {"c:/a": "office"}
    assert sl.set_scope_for_path({"c:/a": "office"}, "C:/B", None) == {"c:/a": "office"}


def test_set_scope_none_map_treated_as_empty():
    result = sl.set_scope_for_path(None, "C:/Sales", "sales")
    assert result == {"c:/sales": "sales"}


# ── remove_scope_for_path ─────────────────────────────────────────────
def test_remove_scope_removes_existing_entry():
    existing = {"c:/companydocs/sales": "sales", "c:/companydocs/office": "office"}
    result = sl.remove_scope_for_path(existing, "C:/CompanyDocs/Sales")
    assert result == {"c:/companydocs/office": "office"}


def test_remove_scope_normalizes_before_matching():
    existing = {"c:/companydocs/sales": "sales"}
    result = sl.remove_scope_for_path(existing, r"C:\CompanyDocs\Sales" + "\\")
    assert result == {}


def test_remove_scope_missing_path_is_a_noop():
    existing = {"c:/companydocs/sales": "sales"}
    result = sl.remove_scope_for_path(existing, "C:/DoesNotExist")
    assert result == existing


def test_remove_scope_does_not_mutate_input():
    original = {"c:/a": "office"}
    result = sl.remove_scope_for_path(original, "C:/A")
    assert original == {"c:/a": "office"}
    assert result == {}


def test_remove_scope_none_map_treated_as_empty():
    assert sl.remove_scope_for_path(None, "C:/Sales") == {}


# ── round-trip: set then resolve then remove ─────────────────────────
def test_set_then_resolve_then_remove_round_trip():
    """End-to-end sanity check tying the whole module together: assign a
    scope via the Index Docs tab's would-be write path, confirm
    resolve_scope_for_path sees it, remove it, confirm it falls back to
    default again."""
    scope_map = {}
    scope_map = sl.set_scope_for_path(scope_map, "C:/CompanyDocs/Sales", "sales")
    assert sl.resolve_scope_for_path(
        "C:/CompanyDocs/Sales/deal.pdf", scope_map) == "sales"

    scope_map = sl.remove_scope_for_path(scope_map, "C:/CompanyDocs/Sales")
    assert sl.resolve_scope_for_path(
        "C:/CompanyDocs/Sales/deal.pdf", scope_map) == "shared"


# ── get_scope_catalog ─────────────────────────────────────────────────
def test_get_scope_catalog_returns_the_list():
    users_data = {"scope_catalog": ["office", "sales"]}
    assert sl.get_scope_catalog(users_data) == ["office", "sales"]


def test_get_scope_catalog_missing_key_returns_empty_list():
    assert sl.get_scope_catalog({}) == []
    assert sl.get_scope_catalog(None) == []


def test_get_scope_catalog_malformed_value_returns_empty_list():
    assert sl.get_scope_catalog({"scope_catalog": "not-a-list"}) == []
    assert sl.get_scope_catalog({"scope_catalog": {"a": 1}}) == []


def test_get_scope_catalog_strips_blank_entries():
    users_data = {"scope_catalog": ["office", "", "  ", "sales"]}
    assert sl.get_scope_catalog(users_data) == ["office", "sales"]


# ── add_scope_to_catalog ─────────────────────────────────────────────
def test_add_scope_to_empty_catalog():
    catalog, ok, reason = sl.add_scope_to_catalog([], "office")
    assert ok is True
    assert catalog == ["office"]


def test_add_scope_canonicalizes_legacy_prefix():
    catalog, ok, reason = sl.add_scope_to_catalog([], "scope:office")
    assert ok is True
    assert catalog == ["office"]


def test_add_scope_rejects_blank():
    catalog, ok, reason = sl.add_scope_to_catalog(["office"], "")
    assert ok is False
    assert catalog == ["office"]


def test_add_scope_rejects_shared():
    """'shared' is implicit and always available -- it must never become
    a catalog entry (would imply it could also be removed)."""
    catalog, ok, reason = sl.add_scope_to_catalog(["office"], "shared")
    assert ok is False
    assert catalog == ["office"]
    assert "shared" in reason.lower()


def test_add_scope_rejects_private_prefix():
    catalog, ok, reason = sl.add_scope_to_catalog(["office"], "private:david-vavro")
    assert ok is False
    assert catalog == ["office"]


def test_add_scope_rejects_case_insensitive_duplicate():
    catalog, ok, reason = sl.add_scope_to_catalog(["office"], "Office")
    assert ok is False
    assert catalog == ["office"]


def test_add_scope_rejects_legacy_prefix_duplicate():
    """'office' and 'scope:office' must be treated as the same entry."""
    catalog, ok, reason = sl.add_scope_to_catalog(["office"], "scope:office")
    assert ok is False
    assert catalog == ["office"]


def test_add_scope_does_not_mutate_input():
    original = ["office"]
    sl.add_scope_to_catalog(original, "sales")
    assert original == ["office"]


def test_add_scope_enforces_max_cap():
    full_catalog = [f"scope{i}" for i in range(sl.MAX_CATALOG_SCOPES)]
    catalog, ok, reason = sl.add_scope_to_catalog(full_catalog, "one-too-many")
    assert ok is False
    assert catalog == full_catalog
    assert len(catalog) == sl.MAX_CATALOG_SCOPES


def test_add_scope_succeeds_at_exactly_one_below_cap():
    almost_full = [f"scope{i}" for i in range(sl.MAX_CATALOG_SCOPES - 1)]
    catalog, ok, reason = sl.add_scope_to_catalog(almost_full, "last-one")
    assert ok is True
    assert len(catalog) == sl.MAX_CATALOG_SCOPES


# ── remove_scope_from_catalog ────────────────────────────────────────
def test_remove_scope_from_catalog_removes_entry():
    result = sl.remove_scope_from_catalog(["office", "sales"], "office")
    assert result == ["sales"]


def test_remove_scope_from_catalog_case_insensitive():
    result = sl.remove_scope_from_catalog(["office", "sales"], "OFFICE")
    assert result == ["sales"]


def test_remove_scope_from_catalog_missing_entry_is_noop():
    result = sl.remove_scope_from_catalog(["office"], "sales")
    assert result == ["office"]


def test_remove_scope_from_catalog_does_not_mutate_input():
    original = ["office", "sales"]
    sl.remove_scope_from_catalog(original, "office")
    assert original == ["office", "sales"]


def test_remove_scope_from_catalog_does_not_touch_scope_map_or_users():
    """Documents the deliberate scoping of this function: it only affects
    the catalog list itself, nothing else. (There's nothing to assert
    against scope_map/users here since the function doesn't take them as
    arguments at all -- this test exists to make that boundary explicit
    and catch a future signature change that tries to add side effects.)"""
    import inspect
    sig = inspect.signature(sl.remove_scope_from_catalog)
    assert list(sig.parameters) == ["catalog", "name"]


# ── catalog round-trip ────────────────────────────────────────────────
def test_catalog_add_then_remove_round_trip():
    catalog = []
    catalog, ok, _ = sl.add_scope_to_catalog(catalog, "office")
    assert ok
    catalog, ok, _ = sl.add_scope_to_catalog(catalog, "sales")
    assert ok
    assert catalog == ["office", "sales"]

    catalog = sl.remove_scope_from_catalog(catalog, "office")
    assert catalog == ["sales"]

    users_data = {"scope_catalog": catalog}
    assert sl.get_scope_catalog(users_data) == ["sales"]


# ── scope_picker_options / scope_picker_selected ─────────────────────────
def test_picker_options_is_just_catalog_when_no_extras():
    assert sl.scope_picker_options(["office", "sales"], []) == ["office", "sales"]


def test_picker_options_appends_stray_existing_scope():
    """A scope the user/file already has that's since fallen out of the
    catalog must still appear, appended after catalog entries -- not
    silently dropped from the widget (which would silently unassign it
    on next save)."""
    result = sl.scope_picker_options(["office", "sales"], ["legacy"])
    assert result == ["office", "sales", "legacy"]


def test_picker_options_does_not_duplicate_scope_already_in_catalog():
    result = sl.scope_picker_options(["office", "sales"], ["office"])
    assert result == ["office", "sales"]


def test_picker_options_dedupes_via_canon_not_exact_string():
    """'scope:office' (legacy stored form) must be recognized as already
    covered by catalog's 'office', not appended as a stray duplicate."""
    result = sl.scope_picker_options(["office"], ["scope:office"])
    assert result == ["office"]


def test_picker_options_handles_empty_catalog_and_empty_existing():
    assert sl.scope_picker_options([], []) == []
    assert sl.scope_picker_options(None, None) == []


def test_picker_options_empty_catalog_with_existing_shows_only_existing():
    assert sl.scope_picker_options([], ["office", "sales"]) == ["office", "sales"]


def test_picker_options_multiple_stray_extras_all_appended():
    result = sl.scope_picker_options(["office"], ["legacy1", "legacy2"])
    assert result == ["office", "legacy1", "legacy2"]


def test_picker_selected_canonicalizes():
    assert sl.scope_picker_selected(["scope:office", "sales"]) == {"office", "sales"}


def test_picker_selected_empty_and_none():
    assert sl.scope_picker_selected([]) == set()
    assert sl.scope_picker_selected(None) == set()


def test_picker_selected_ignores_blank_entries():
    assert sl.scope_picker_selected(["office", "", "  "]) == {"office"}


def test_picker_options_and_selected_work_together_for_widget_prefill():
    """The intended usage pattern: options gives the display list,
    selected gives the canon set to check membership against (via
    canon_scope_name on each option) when deciding which rows to
    pre-select."""
    catalog = ["office", "sales", "ops"]
    existing = ["scope:office", "legacy"]
    options = sl.scope_picker_options(catalog, existing)
    selected = sl.scope_picker_selected(existing)
    assert options == ["office", "sales", "ops", "legacy"]
    assert selected == {"office", "legacy"}
    # Simulate the widget's per-row pre-select check:
    pre_selected_rows = [o for o in options if sl.canon_scope_name(o) in selected]
    assert pre_selected_rows == ["office", "legacy"]


# ── format_scope_display ─────────────────────────────────────────────
def test_format_scope_display_no_pending_shows_resolved_label():
    assert sl.format_scope_display("office", None) == "office"
    assert sl.format_scope_display("office", "") == "office"


def test_format_scope_display_pending_takes_precedence():
    assert sl.format_scope_display("office", "sales") == "\u2192sales (pending)"


def test_format_scope_display_pending_whitespace_stripped():
    assert sl.format_scope_display("office", "  sales  ") == "\u2192sales (pending)"


def test_format_scope_display_whitespace_only_pending_treated_as_none():
    assert sl.format_scope_display("office", "   ") == "office"
