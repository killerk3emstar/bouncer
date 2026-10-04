"""Start the local stack: gateway :8700, simulated upstream :8702, demo MCP server :8703, feed server :8704,
demo A2A agent :8707.

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
    ("a2a", [sys.executable, "-m", "demo.a2a_agent"], 8707, "demo/a2a_agent.py"),
]


def pump(name: str, proc: subprocess.Popen) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(f"[{name}] {line}")
        sys.stdout.flush()


def judge_is_up(url: str = "http://localhost:8701/health") -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=1.5) as r:  # noqa: S310 (local health check)
            return r.status == 200
    except OSError:
        return False


def judge_is_starting() -> bool:
    """`make judge` was started but the model is still loading (the port opens only when it is ready)."""
    try:
        out = subprocess.run(["pgrep", "-f", "--", "-m judge.server"], capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and bool(out.stdout.strip())


def wait_for_judge(seconds: int = 90) -> bool:
    if judge_is_up():
        return True
    if not judge_is_starting():
        return False
    print(f"[dev] T2 judge is loading its model; waiting up to {seconds} s for :8701 ...")
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(1)
        if judge_is_up():
            print("[dev] T2 judge is ready.")
            return True
    return False


def main() -> int:
    os.chdir(ROOT)
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env", override=False)
    except ImportError:
        pass
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONPATH": str(ROOT)}
    if not env.get("BOUNCER_ADMIN_TOKEN"):
        import secrets

        env["BOUNCER_ADMIN_TOKEN"] = "adm_" + secrets.token_urlsafe(18)
    if "BOUNCER_JUDGE" not in env and not wait_for_judge():
        # Without a judge every escalation would fail closed (blocked). For a first run we use the
        # deterministic stand-in and say so; `make judge` starts the real one.
        env["BOUNCER_JUDGE"] = "fake"
        print("[dev] T2 judge not reachable on :8701: using the deterministic stand-in (BOUNCER_JUDGE=fake).")
        print("[dev] For the real judge run `make judge` in another terminal, then restart `make dev`.")
    procs: list[tuple[str, subprocess.Popen]] = []
    for name, cmd, port, required in SERVICES:
        if not (ROOT / required).exists():
            print(f"[dev] skipping {name}: {required} not found")
            continue
        p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append((name, p))
        threading.Thread(target=pump, args=(name, p), daemon=True).start()
        print(f"[dev] {name} on :{port} (pid {p.pid})")
    token = env.get("BOUNCER_ADMIN_TOKEN", "")
    link = "http://localhost:8700/ui/" + ("" if token.lower() == "off" else f"?token={token}")
    print(f"[dev] dashboard (admin token included, the page stores it): {link}")
    print("[dev] Ctrl-C stops everything")

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

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)
    while True:
        for name, p in procs:
            if p.poll() is not None:
                print(f"[dev] {name} exited with code {p.returncode}; stopping the stack")
                stop()
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
