import pathlib, shutil, subprocess

src = pathlib.Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html")
dst = pathlib.Path(r"C:\Program Files\AI-Prowler\hr_portal\index.html")

# Read both files and check
src_txt = src.read_text(encoding='utf-8-sig', errors='replace')
dst_txt = dst.read_text(encoding='utf-8-sig', errors='replace')

print(f"DEV  size: {len(src_txt):,} chars")
print(f"LIVE size: {len(dst_txt):,} chars")
print(f"DEV  openITModal count: {src_txt.count('openITModal')}")
print(f"LIVE openITModal count: {dst_txt.count('openITModal')}")
print(f"Files identical: {src_txt == dst_txt}")

if src_txt != dst_txt:
    # Find first difference
    for i, (a, b) in enumerate(zip(src_txt, dst_txt)):
        if a != b:
            print(f"First diff at char {i}: DEV={repr(src_txt[i-20:i+20])} LIVE={repr(dst_txt[i-20:i+20])}")
            break
