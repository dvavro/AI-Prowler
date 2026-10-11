import json, pathlib

db_path = pathlib.Path.home() / ".ai-prowler" / "hr" / "hr_db.json"
db = json.loads(db_path.read_text(encoding='utf-8'))

messages = db.get("messages", [])
incidents = [m for m in messages if m.get("message_type") == "incident_report"]
print(f"Total messages: {len(messages)}")
print(f"Incident reports: {len(incidents)}")
for inc in incidents:
    print(f"  sender_name: '{inc.get('sender_name')}' | subject: '{inc.get('subject','')[:50]}' | sent: {inc.get('sent_at','')}")
