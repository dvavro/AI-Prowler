"""Sprint 1 manual checks S1-X02 and S1-X03 (run on Windows).

    python tests\\estimator\\manual_checks_sprint1.py

S1-X02: with no overrides set, the default data folder is %USERPROFILE%\\AI-Prowler\\Estimator (nothing is created).
S1-X03: a backup succeeds while another connection holds estimator.db open in WAL mode with an open write
        transaction (uses a temporary folder; the real data folder is not touched).
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

ok = True

# S1-X02
saved = {k: os.environ.pop(k, None) for k in ("ESTIMATOR_DATA_DIR", "AIPROWLER_TEST_STATE_DIR")}
from estimator import config  # noqa: E402

expected = Path(os.environ["USERPROFILE"]) / "AI-Prowler" / "Estimator"
got = config.data_dir()
print(f"S1-X02 default data folder: {got}")
if got == expected:
    print("S1-X02 PASS")
else:
    print(f"S1-X02 FAIL (expected {expected})")
    ok = False
for k, v in saved.items():
    if v is not None:
        os.environ[k] = v

# S1-X03
from estimator.database import backup_database, connect, integrity_ok, migrate  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    db_file = Path(tmp) / "estimator.db"
    writer = connect(db_file)
    migrate(writer)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        "INSERT INTO estimates (company_id, title, created_at, updated_at) VALUES ('co1', 'open txn', 'x', 'x')")
    try:
        b = backup_database(db_file, Path(tmp) / "backups")
        good = integrity_ok(b)
        print(f"S1-X03 backup while database open: {b.name} integrity={'ok' if good else 'BAD'}")
        print("S1-X03 PASS" if good else "S1-X03 FAIL")
        ok = ok and good
    except Exception as exc:  # noqa: BLE001
        print(f"S1-X03 FAIL: {exc}")
        ok = False
    finally:
        writer.execute("ROLLBACK")
        writer.close()

sys.exit(0 if ok else 1)
