"""Container entrypoint for the Bouncer gateway.

policy/bouncer.yaml names its upstreams and the judge by localhost URLs, which is right for
`make dev` on one machine but not inside a container, where the mock upstream is the `mock`
service and Ollama runs on the Docker host. This entrypoint:

1. writes a container copy of the policy with those URLs rewritten. The rewrite is plain text
   replacement, so comments, line numbers and validation errors stay the same as in the source;
2. keeps the copy in sync: when policy/bouncer.yaml changes (it is bind-mounted from the host),
   the copy is rewritten and the gateway's own hot reload picks it up. An invalid source file is
   copied as is, so the gateway rejects it with the usual line-numbered error and keeps the last
   good version;
3. starts the gateway (bouncer.gateway.app) on the copy.

Environment:
  BOUNCER_POLICY_SOURCE  policy file to read            (default policy/bouncer.yaml)
  BOUNCER_POLICY         where the rewritten copy goes  (default /tmp/bouncer-policy/bouncer.yaml)
  BOUNCER_POLICY_POLL_S  how often the source is compared with the copy (default 0.5 s)
  BOUNCER_URL_REWRITES   comma-separated FROM=TO pairs, applied in order, e.g.
                         http://localhost:8702=http://mock:8702,http://localhost:11434=http://host.docker.internal:11434
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
log = logging.getLogger("bouncer.docker")


def parse_rewrites(spec: str) -> list[tuple[str, str]]:
    pairs = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise SystemExit(f"BOUNCER_URL_REWRITES: '{item}' is not FROM=TO")
        src, dst = item.split("=", 1)
        if src.strip() and dst.strip():
            pairs.append((src.strip(), dst.strip()))
    return pairs


def render(source: Path, target: Path, rewrites: list[tuple[str, str]]) -> bool:
    """Write the rewritten copy atomically. Returns True when the copy changed."""
    text = source.read_text(encoding="utf-8")
    for src, dst in rewrites:
        text = text.replace(src, dst)
    if target.exists() and target.read_text(encoding="utf-8") == text:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    return True


def follow(source: Path, target: Path, rewrites: list[tuple[str, str]], interval_s: float) -> None:
    """Re-render the copy whenever the source text changes (runs in a daemon thread).

    Compares file contents instead of relying on file events: events from host bind mounts do not
    always reach a container, and mtime polling misses two same-size edits within one second
    (measured with watchfiles' polling mode). Reading a ~12 KB file twice a second is cheap.
    The gateway then picks up the rewritten copy with its own watcher (container-local directory).
    """
    last = None
    while True:
        try:
            text = source.read_text(encoding="utf-8") if source.exists() else None
            if text is not None and text != last:
                if last is not None and render(source, target, rewrites):
                    log.info("policy source changed; container copy updated (%s)", target)
                last = text
        except Exception:
            log.exception("could not update the container policy copy")
        time.sleep(interval_s)


def main() -> None:
    logging.basicConfig(level=os.environ.get("BOUNCER_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    source = Path(os.environ.get("BOUNCER_POLICY_SOURCE", "policy/bouncer.yaml"))
    target = Path(os.environ.get("BOUNCER_POLICY", "/tmp/bouncer-policy/bouncer.yaml"))
    if not source.is_absolute():
        source = ROOT / source
    if source.resolve() == target.resolve():
        raise SystemExit("BOUNCER_POLICY must differ from BOUNCER_POLICY_SOURCE (the copy would overwrite the source)")
    rewrites = parse_rewrites(os.environ.get("BOUNCER_URL_REWRITES", ""))
    render(source, target, rewrites)
    os.environ["BOUNCER_POLICY"] = str(target)
    for src, dst in rewrites:
        log.info("policy URL rewrite: %s -> %s", src, dst)
    log.info("policy source %s, container copy %s", source, target)
    if os.environ.get("BOUNCER_WATCH", "1") != "0":
        interval = float(os.environ.get("BOUNCER_POLICY_POLL_S", "0.5"))
        threading.Thread(target=follow, args=(source, target, rewrites, interval), daemon=True, name="policy-follow").start()

    from bouncer.gateway.app import main as gateway_main

    gateway_main()


if __name__ == "__main__":
    main()
