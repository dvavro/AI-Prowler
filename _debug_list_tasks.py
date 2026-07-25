import sys
sys.path.insert(0, r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")
import custom_tasks_manager as ctm

tasks = ctm.load_custom_tasks()
print(f"Total tasks currently on disk: {len(tasks)}")
for t in tasks:
    print(f"  - {t['task_id']}: {t['label']!r} (schedule={t.get('schedule')}, created_at={t.get('created_at')})")
