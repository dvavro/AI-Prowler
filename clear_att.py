import pathlib, json, shutil, datetime
DB = pathlib.Path(r'C:\Users\jamie\.ai-prowler\hr\hr_db.json')
data = json.loads(DB.read_text(encoding='utf-8'))
shutil.copy2(DB, str(DB) + '.bak')
count = len(data.get('attendance', []))
data['attendance'] = []
DB.write_text(json.dumps(data, indent=2), encoding='utf-8')
print('Deleted', count, 'records')
