"""Find the main GUI entry point and early startup sequence in rag_gui.py."""
from pathlib import Path

gui = Path(r'C:\Users\david\AI-Prowler_V812_to_V900_work\AI-Prowler\rag_gui.py')
lines = gui.read_text(encoding='utf-8', errors='replace').splitlines()

# Find if __name__ == '__main__' and the main() function
hits = [(i+1, l) for i, l in enumerate(lines)
        if any(k in l for k in ["if __name__", "def main(", "RAGApplication",
                                  "def __init__", "Tk()", "mainloop()"])]
for lineno, line in hits[:20]:
    print(f"  {lineno:6}: {line[:120]}")
