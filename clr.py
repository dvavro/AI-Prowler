import pathlib,json; p=pathlib.Path(r'C:\Users\jamie\.ai-prowler\hr\hr_db.json'); d=json.loads(p.read_text()); d['attendance']=[]; p.write_text(json.dumps(d,indent=2))
