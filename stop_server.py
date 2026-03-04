import subprocess
import sys

def find_pids_on_port(port):
    result = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True, text=True
    )
    pids = set()
    for line in result.stdout.splitlines():
        if f":{port}" in line and "LISTENING" in line:
            parts = line.strip().split()
            if parts:
                pids.add(parts[-1])
    return pids

def kill_pid(pid):
    result = subprocess.run(
        ["taskkill", "/PID", pid, "/F"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"[OK] Killed PID {pid}")
    else:
        print(f"[FAIL] Could not kill PID {pid}: {result.stderr.strip()}")

if __name__ == "__main__":
    port = 5000
    print(f"Looking for processes on port {port}...")
    pids = find_pids_on_port(port)

    if not pids:
        print("No processes found. Server may already be stopped.")
        sys.exit(0)

    for pid in pids:
        kill_pid(pid)

    print("Done.")
