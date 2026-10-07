import json, pathlib

db_path = pathlib.Path.home() / ".ai-prowler" / "hr" / "hr_db.json"
db = json.loads(db_path.read_text(encoding='utf-8'))
print("Top-level keys:", list(db.keys()))

# Check documents structure
docs = db.get('documents', [])
print(f"\nDocuments count: {len(docs)}")
if docs:
    print("First doc:", json.dumps(docs[0], indent=2)[:500])

# Check employees
emps = db.get('employees', [])
print(f"\nEmployees: {len(emps)}")
if emps:
    print("First emp keys:", list(emps[0].keys()))
    # Check if employee has docs
    if 'documents' in emps[0]:
        print("Emp docs:", emps[0]['documents'])
