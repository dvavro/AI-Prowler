"""Dev helper (2026-10-03): print a file as base64 in 1000-char lines, so a
screenshot on this PC can be rebuilt and viewed elsewhere.
  python tests\\dev\\b64dump.py <file>"""
import base64
import sys

data = base64.b64encode(open(sys.argv[1], "rb").read()).decode()
print(f"BYTES={len(data)}")
for i in range(0, len(data), 1000):
    print(data[i:i + 1000])
print("END")
