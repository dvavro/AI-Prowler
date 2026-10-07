"""Read-only probe: which packages the time machine can use on this PC."""
import importlib.metadata as md

for pkg in ("freezegun", "time-machine", "playwright", "pytest-playwright", "uvicorn", "starlette"):
    try:
        print(f"{pkg}: {md.version(pkg)}")
    except md.PackageNotFoundError:
        print(f"{pkg}: NOT INSTALLED")

try:
    import playwright.sync_api as s
    print("playwright Clock API:", hasattr(s, "Clock"))
except Exception as exc:
    print("playwright import error:", exc)
