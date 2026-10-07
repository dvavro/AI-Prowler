import pathlib
src = pathlib.Path('ai_prowler_mcp.py').read_text(encoding='utf-8')
# Find all lines mentioning attendance
for i, line in enumerate(src.split('\n'), 1):
    if 'attendance' in line.lower() and ('path' in line.lower() or 'route' in line.lower() or 'elif' in line.lower()):
        print(f'{i:5}: {line}')
