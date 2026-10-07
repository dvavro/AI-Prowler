import json, hashlib, secrets, datetime, pathlib

DB_PATH = pathlib.Path.home() / ".ai-prowler" / "hr" / "hr_db.json"

def pin_hash(pin: str, employee_id: str) -> str:
    return hashlib.sha256(f"{employee_id}:{pin}".encode()).hexdigest()

db = json.loads(DB_PATH.read_text(encoding="utf-8-sig"))

target_email = "jamievavroaiprowler@gmail.com"
emp = None
for e in db["employees"]:
    emails = {(e.get("personal_email") or "").lower(), (e.get("work_email") or "").lower()}
    if target_email in emails:
        emp = e
        break

if not emp:
    print("ERROR: employee not found for", target_email)
else:
    new_token = secrets.token_urlsafe(24)
    emp["portal_token_hash"] = pin_hash(new_token, emp["id"])
    emp["portal_token_set"] = True
    emp["portal_token_set_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    db.setdefault("audit_log", []).append({
        "at": emp["portal_token_set_at"],
        "action": "portal_token_regenerated_by_admin_script",
        "employee_id": emp["id"],
    })
    # Atomic-ish write
    tmp = DB_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(db, indent=2), encoding="utf-8")
    tmp.replace(DB_PATH)
    print(f"Employee: {emp['id']} ({emp.get('first_name')} {emp.get('last_name')})")
    print(f"Email:    {target_email}")
    print(f"NEW BEARER TOKEN (save this now — shown only once): {new_token}")
