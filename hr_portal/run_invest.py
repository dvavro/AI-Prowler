import subprocess, sys
r = subprocess.run([sys.executable, r'C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\invest_portal.py'], capture_output=True, text=True)
open(r'C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\invest_portal_out.txt', 'w', encoding='utf-8').write('RC=%d\nSTDOUT:\n'%r.returncode + r.stdout + '\nSTDERR:\n' + r.stderr)
print('wrote', len(r.stdout), 'chars stdout,', len(r.stderr), 'chars stderr, rc', r.returncode)
