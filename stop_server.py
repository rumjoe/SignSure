#!/usr/bin/env python3
"""Stop background SignSure server processes started by `run.py`.

Usage:
    python3 stop_server.py

The script looks for processes whose command line contains `run.py --_child`
and sends SIGTERM, waiting a short grace period, then SIGKILL if necessary.
"""

import subprocess
import os
import signal
import time
import sys


def find_pids():
    # First try pgrep -f for an exact match
    try:
        out = subprocess.check_output(["pgrep", "-f", "run.py --_child"])  # may raise
        return [int(x) for x in out.decode().split()]
    except Exception:
        pass

    # Fallback: parse `ps -eo pid,args`
    pids = []
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,args"])
        for line in out.decode().splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) < 2:
                continue
            pid_s, args = parts
            if "run.py --_child" in args or "--_child" in args:
                try:
                    pids.append(int(pid_s))
                except ValueError:
                    continue
    except Exception:
        pass

    return pids


def stop_pids(pids, timeout=3.0):
    if not pids:
        print("No background SignSure server processes found.")
        return 0

    killed = 0
    for pid in pids:
        try:
            print(f"Stopping PID {pid} (SIGTERM)")
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            print(f"PID {pid} does not exist")
            continue
        except PermissionError:
            print(f"Permission denied when killing PID {pid}")
            continue

    # Wait for processes to exit
    deadline = time.time() + timeout
    while time.time() < deadline and any(os.path.exists(f"/proc/{p}") for p in pids):
        time.sleep(0.1)

    # Force kill remaining
    for pid in pids:
        if os.path.exists(f"/proc/{pid}"):
            try:
                print(f"PID {pid} still alive — sending SIGKILL")
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except Exception as e:
                print(f"Failed to SIGKILL {pid}: {e}")
        else:
            killed += 1

    print(f"Stopped servers: {killed}/{len(pids)}")
    return killed


def main():
    pids = find_pids()
    if not pids:
        print("No SignSure child processes found (run.py --_child)")
        return
    stop_pids(pids)


if __name__ == '__main__':
    main()
