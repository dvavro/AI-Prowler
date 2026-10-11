import pathlib, shutil, os, tempfile

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
        # Write to a temp file in the SAME directory as the target, then
        # atomically replace via os.replace — this only needs rename
        # permission on the target, not an open-for-write handle, so it
        # can succeed even if another process has the file open for
        # reading.
        fd, tmp_path = tempfile.mkstemp(dir=str(d.parent), prefix=d.stem + "_new_", suffix=d.suffix)
        os.close(fd)
        shutil.copyfile(str(s), tmp_path)
        os.replace(tmp_path, str(d))
        print(f"OK   {d}  ({d.stat().st_size:,} bytes)")
    except Exception as e:
        print(f"FAIL {d}  -- {type(e).__name__}: {e}")
        try:
            if 'tmp_path' in dir() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
