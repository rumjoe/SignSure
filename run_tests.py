#!/usr/bin/env python3
"""Run the combined test file and print a concise pass/fail summary.

Usage:
    python run_tests.py
    # or with venv active
    ./run_tests.py
"""

import subprocess
import sys


def main():
    cmd = [sys.executable, "-m", "pytest", "-v", "tests/test.py"]
    rc = subprocess.call(cmd)
    if rc == 0:
        print("\nALL TESTS PASSED")
    else:
        print(f"\nSOME TESTS FAILED (exit code {rc})")
    sys.exit(rc)


if __name__ == "__main__":
    main()
