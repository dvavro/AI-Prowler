import pathlib, shutil

pairs = [
    (r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_admin\index.html",
     r"C:\Program Files\AI-Prowler\hr_admin\index.html"),
    (r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html",
     r"C:\Program Files\AI-Prowler\hr_portal\index.html"),
    (r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\ai_prowler_mcp.py",
     r"C:\Program Files\AI-Prowler\ai_prowler_mcp.py"),
]

for src, dst in pairs:
    s = pathlib.Path(src)
    d = pathlib.Path(dst)
    try:
        shutil.copy2(str(s), str(d))
        print(f"OK   {d}  ({d.stat().st_size:,} bytes)")
    except Exception as e:
        print(f"FAIL {d}  -- {type(e).__name__}: {e}")
