"""
cloudflared_service_helper.py
=============================
Standalone elevated helper for cloudflared service management.
Called by mobile_activator._install_cloudflared_service() via
ShellExecute runas — this runs as Administrator while the main
AI-Prowler process stays non-elevated.

Usage (internal — do not call directly):
    python cloudflared_service_helper.py <token> <log_file>
"""
import sys
import os
import subprocess
import time
from pathlib import Path


def log(log_file, msg):
    import datetime
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"{ts}  {msg}\n"
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass
    print(line, end='')


def service_exists(name):
    r = subprocess.run(['sc', 'query', name],
                       capture_output=True, text=True)
    return r.returncode == 0


def get_service_state(name):
    r = subprocess.run(['sc', 'query', name],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if 'STATE' in line and ':' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                words = parts[1].strip().split()
                if len(words) >= 2:
                    return words[1]
    return 'UNKNOWN'


def main():
    if len(sys.argv) < 3:
        print("Usage: cloudflared_service_helper.py <token_file> <log_file> [cf_exe]")
        sys.exit(1)

    token_file_path = sys.argv[1]
    log_file = sys.argv[2]

    # Read token from file (avoids command-line length limits)
    try:
        tunnel_token = Path(token_file_path).read_text(encoding='utf-8').strip()
    except Exception as e:
        print(f"Cannot read token file {token_file_path}: {e}")
        sys.exit(1)

    # cloudflared.exe path — passed explicitly by mobile_activator so we
    # don't have to guess. Falls back to the standard install location.
    if len(sys.argv) >= 4:
        cf_exe = Path(sys.argv[3])
    else:
        cf_exe = Path(os.environ.get('PROGRAMFILES', r'C:\Program Files')) / 'AI-Prowler' / 'cloudflared.exe'
    svc = 'cloudflared'
    eventlog_key = (
        r'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Cloudflared'
    )

    log(log_file, '=== cloudflared_service_helper start ===')
    log(log_file, f'cf_exe: {cf_exe}')
    log(log_file, f'cf_exe exists: {cf_exe.exists()}')

    # 1. Stop existing service and wait for STOPPED
    exists = service_exists(svc)
    log(log_file, f'Service exists before cleanup: {exists}')
    if exists:
        state = get_service_state(svc)
        log(log_file, f'State: {state}')
        if state == 'RUNNING':
            subprocess.run(['sc', 'stop', svc], capture_output=True)
            for i in range(15):
                time.sleep(1)
                state = get_service_state(svc)
                if state not in ('RUNNING', 'STOP_PENDING'):
                    log(log_file, f'After stop ({i+1}s): {state}')
                    break

        # 2. cloudflared service uninstall (clears internal marker)
        r = subprocess.run([str(cf_exe), 'service', 'uninstall'],
                           capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().replace('\n', ' ')
        log(log_file, f'cloudflared uninstall: {out}')

        # 3. sc delete
        r = subprocess.run(['sc', 'delete', svc], capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip().replace('\n', ' ')
        log(log_file, f'sc delete: {out}')

        # 4. Wait for SCM to release
        for i in range(10):
            time.sleep(1)
            if not service_exists(svc):
                log(log_file, f'Service gone after {i+1}s')
                break

    # 5. Clear stale EventLog registry key
    r = subprocess.run(['reg', 'query', eventlog_key], capture_output=True)
    key_exists = r.returncode == 0
    log(log_file, f'EventLog key exists: {key_exists}')
    if key_exists:
        subprocess.run(['reg', 'delete', eventlog_key, '/f'], capture_output=True)
        log(log_file, 'EventLog key removed')

    # 6. Install with new token
    r = subprocess.run([str(cf_exe), 'service', 'install', tunnel_token],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip().replace('\n', ' ')
    log(log_file, f'cloudflared install (rc={r.returncode}): {out}')

    # 7. Verify in SCM
    time.sleep(2)
    exists_after = service_exists(svc)
    log(log_file, f'In SCM after install: {exists_after}')

    if exists_after:
        state = get_service_state(svc)
        log(log_file, f'State after install: {state}')
        if state != 'RUNNING':
            subprocess.run(['sc', 'start', svc], capture_output=True)
            time.sleep(2)
            state = get_service_state(svc)
            log(log_file, f'State after start: {state}')
        if state == 'RUNNING':
            log(log_file, 'SUCCESS: service running')
            log(log_file, '=== cloudflared_service_helper end ===')
            sys.exit(0)
        else:
            log(log_file, f'FAIL: service not running (state={state})')
    else:
        log(log_file, 'FAIL: service not in SCM after install')

    log(log_file, '=== cloudflared_service_helper end ===')
    sys.exit(1)


if __name__ == '__main__':
    main()
