import sys
sys.path.insert(0, r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")
import task_queue_automation as tqa
import json

cfg = tqa.load_config()
print("=== task_automation_config.json ===")
print(json.dumps(cfg, indent=2))

print()
print("=== Real Windows Scheduled Task check ===")
print("scheduled_task_exists():", tqa.scheduled_task_exists())

print()
print("=== last_run status file ===")
print(tqa.load_last_run())

print()
print("=== raw schtasks query ===")
import subprocess
r = subprocess.run(["schtasks", "/query", "/tn", tqa.SCHEDULED_TASK_NAME, "/v", "/fo", "list"],
                    capture_output=True, text=True)
print("rc=", r.returncode)
print(r.stdout[:2000])
print(r.stderr[:500])
