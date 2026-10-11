import pathlib, shutil

src = pathlib.Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html")
dst = pathlib.Path(r"C:\Program Files\AI-Prowler\hr_portal\index.html")

print(f"DEV  size: {src.stat().st_size:,} bytes")
print(f"LIVE size: {dst.stat().st_size:,} bytes")
print(f"DEV  has openITModal: {'openITModal' in src.read_text(encoding='utf-8-sig', errors='replace')}")
print(f"LIVE has openITModal: {'openITModal' in dst.read_text(encoding='utf-8-sig', errors='replace')}")

# Force copy
shutil.copy2(str(src), str(dst))
print(f"\nCopied! New LIVE size: {dst.stat().st_size:,} bytes")
print(f"LIVE has openITModal: {'openITModal' in dst.read_text(encoding='utf-8-sig', errors='replace')}")
