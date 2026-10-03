"""Start the local stack: gateway :8700, simulated upstream :8702, demo MCP server :8703, feed server :8704.

Ctrl-C stops all of them. The judge (:8701) runs separately with `make judge` because it loads a
large model once and should not restart with the rest.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES = [  # name, command, port, file that must exist
    ("gateway", [sys.executable, "-m", "bouncer.gateway.app"], 8700, "bouncer/gateway/app.py"),
    ("mock", [sys.executable, "-m", "demo.mock_upstream"], 8702, "demo/mock_upstream.py"),
    ("mcp", [sys.executable, "-m", "demo.mcp_server"], 8703, "demo/mcp_server.py"),
    ("feed", [sys.executable, "scripts/feed_server.py"], 8704, "scripts/feed_server.py"),
]


def pump(name: str, proc: subprocess.Popen) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(f"[{name}] {line}")
        sys.stdout.flush()


def main() -> int:
    os.chdir(ROOT)
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONPATH": str(ROOT)}
    procs: list[tuple[str, subprocess.Popen]] = []
    for name, cmd, port, required in SERVICES:
        if not (ROOT / required).exists():
            print(f"[dev] skipping {name}: {required} not found")
            continue
        p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append((name, p))
        threading.Thread(target=pump, args=(name, p), daemon=True).start()
        print(f"[dev] {name} on :{port} (pid {p.pid})")
    print("[dev] dashboard: http://localhost:8700/ui/   Ctrl-C stops everything")

    def stop(*_: object) -> None:
        for _, p in procs:
            if p.poll() is None:
                p.terminate()
        deadline = time.time() + 5
        for _, p in procs:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while True:
        for name, p in procs:
            if p.poll() is not None:
                print(f"[dev] {name} exited with code {p.returncode}; stopping the stack")
                stop()
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
