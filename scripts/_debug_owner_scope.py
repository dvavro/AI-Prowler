import sys
sys.path.insert(0, r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")
import scope_lookup as sl

owner_user = {
    "name": "Olive Owner",
    "role": "owner",
    "scopes": [],
    "private_collection_enabled": True,
    "can_manage_users": True,
    "status": "active",
}

try:
    result = sl.allowed_scopes_for_user(owner_user)
    print("SUCCESS:", result)
except Exception as e:
    import traceback
    print("EXCEPTION:", type(e).__name__, str(e))
    traceback.print_exc()

# Also test with an 'id' key present, as _resolve_user would likely add
owner_user2 = dict(owner_user)
owner_user2["id"] = "olive-owner"
try:
    result2 = sl.allowed_scopes_for_user(owner_user2)
    print("SUCCESS with id:", result2)
except Exception as e:
    print("EXCEPTION with id:", type(e).__name__, str(e))
