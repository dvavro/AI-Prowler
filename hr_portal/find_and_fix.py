import shutil, os

src = r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html"
dst = r"C:\Program Files\AI-Prowler\hr_portal\index.html"

src_size = os.path.getsize(src)
dst_size = os.path.getsize(dst)
print(f"Source:  {src_size} bytes  {src}")
print(f"Target:  {dst_size} bytes  {dst}")

# Quick check that source has our new content
with open(src, 'r', encoding='utf-8') as f:
    content = f.read()

if 'cal-hdr' in content:
    print("Source has new calendar code (cal-hdr found) ✓")
else:
    print("ERROR: Source does NOT have new calendar code!")

shutil.copy2(src, dst)
print(f"Copied! New target size: {os.path.getsize(dst)} bytes")

# Verify
with open(dst, 'r', encoding='utf-8') as f:
    check = f.read()
if 'cal-hdr' in check:
    print("TARGET now has new calendar code ✓ DONE!")
else:
    print("ERROR: Copy failed or wrong content")
