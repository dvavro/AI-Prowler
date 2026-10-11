"""Dev helper: pip install the given packages into THIS Python (the one the
test runners use). Usage: pip_install.py time-machine"""
import subprocess
import sys

sys.exit(subprocess.call([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *sys.argv[1:]]))
