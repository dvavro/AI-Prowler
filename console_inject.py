"""
console_inject.py — type text (plus Enter) into ANOTHER process's console.

Used by the phone sign-in relay: `claude setup-token` runs in a hidden console
and waits at "Paste code here if prompted >". The server has the code the user
pasted into the Jobs app but no way to type it into that hidden console — this
does, via AttachConsole + WriteConsoleInput (Windows only).

Runs as its OWN short-lived process, because a process can be attached to only
one console at a time and the AI-Prowler server must keep whatever it has.
The text is read from STDIN, never argv, so a pasted code never shows up in a
process listing.

    python console_inject.py <pid_of_a_process_in_the_target_console>  < text
Exit code 0 = keystrokes delivered; nonzero = failure (message on stderr).
"""
import ctypes
import sys
from ctypes import wintypes

KEY_EVENT = 0x0001
GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_SHARE_READ, FILE_SHARE_WRITE = 0x1, 0x2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", wintypes.BOOL), ("wRepeatCount", wintypes.WORD),
                ("wVirtualKeyCode", wintypes.WORD), ("wVirtualScanCode", wintypes.WORD),
                ("uChar", ctypes.c_wchar), ("dwControlKeyState", wintypes.DWORD)]


class _EVENT(ctypes.Union):
    _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]


class INPUT_RECORD(ctypes.Structure):
    _fields_ = [("EventType", wintypes.WORD), ("Event", _EVENT)]


def _records(text: str):
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    recs = []
    for ch in text + "\r":
        vk = 0x0D if ch == "\r" else (user32.VkKeyScanW(ch) & 0xFF)
        for down in (1, 0):
            r = INPUT_RECORD()
            r.EventType = KEY_EVENT
            k = r.Event.KeyEvent
            k.bKeyDown, k.wRepeatCount = down, 1
            k.wVirtualKeyCode = vk
            k.wVirtualScanCode = user32.MapVirtualKeyW(vk, 0) & 0xFF
            k.uChar, k.dwControlKeyState = ch, 0
            recs.append(r)
    return recs


def inject(pid: int, text: str) -> None:
    """Raises OSError on any failure."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.FreeConsole()
    if not k32.AttachConsole(pid):
        raise OSError(f"AttachConsole({pid}) failed: winerror {ctypes.get_last_error()}")
    try:
        h = k32.CreateFileW("CONIN$", GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        if h in (None, INVALID_HANDLE_VALUE):
            raise OSError(f"CONIN$ open failed: winerror {ctypes.get_last_error()}")
        recs = _records(text)
        arr = (INPUT_RECORD * len(recs))(*recs)
        written = wintypes.DWORD(0)
        if not k32.WriteConsoleInputW(h, arr, len(recs), ctypes.byref(written)):
            raise OSError(f"WriteConsoleInput failed: winerror {ctypes.get_last_error()}")
        if written.value != len(recs):
            raise OSError(f"only {written.value}/{len(recs)} key events written")
        k32.CloseHandle(h)
    finally:
        k32.FreeConsole()


if __name__ == "__main__":
    try:
        inject(int(sys.argv[1]), sys.stdin.read().strip("\r\n"))
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        sys.exit(1)
