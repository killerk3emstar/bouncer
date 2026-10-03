"""Prometheus metrics and in-process latency statistics for the dashboard."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

LAYERS = ("t0", "t1", "t2", "upstream", "gateway_overhead", "total")
BUCKETS = (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16)


class Telemetry:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "bouncer_requests_total", "Decisions by route and action", ["route", "action"], registry=self.registry
        )
        self.findings = Counter(
            "bouncer_findings_total", "Findings by control and action", ["control", "action"], registry=self.registry
        )
        self.latency = Histogram(
            "bouncer_layer_latency_seconds", "Latency per layer", ["layer"], buckets=BUCKETS, registry=self.registry
        )
        self.judge_calls = Counter(
            "bouncer_judge_calls_total", "T2 judge invocations", ["reason", "cached", "error"], registry=self.registry
        )
        self.spend = Counter("bouncer_spend_usd_total", "Spend in USD", ["team", "model"], registry=self.registry)
        self.tokens = Counter("bouncer_tokens_total", "Tokens", ["team", "kind"], registry=self.registry)
        self.policy_reloads = Counter(
            "bouncer_policy_reloads_total", "Policy reloads", ["status"], registry=self.registry
        )
        self.policy_info = Gauge(
            "bouncer_policy_loaded_timestamp", "When the active policy was loaded", ["version"], registry=self.registry
        )
        self._lock = threading.Lock()
        self.samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))  # layer -> (ts, ms)
        self.request_times: deque = deque(maxlen=20000)
        self.escalations = 0
        self.t1_runs = 0
        self.decisions = 0

    def observe(self, layer: str, ms: float) -> None:
        self.latency.labels(layer).observe(ms / 1000.0)
        with self._lock:
            self.samples[layer].append((time.time(), ms))

    def record_request(self, route: str, action: str, latency: dict[str, float], escalated: bool, t1_ran: bool) -> None:
        self.requests.labels(route, action).inc()
        with self._lock:
            self.request_times.append(time.time())
            self.decisions += 1
            if escalated:
                self.escalations += 1
            if t1_ran:
                self.t1_runs += 1
        for layer, ms in latency.items():
            if layer in LAYERS and ms is not None and (ms > 0 or layer in ("t0", "gateway_overhead", "total")):
                self.observe(layer, ms)

    @staticmethod
    def _percentile(values: list[float], p: float) -> float | None:
        if not values:
            return None
        values = sorted(values)
        k = (len(values) - 1) * p
        lo = int(k)
        hi = min(lo + 1, len(values) - 1)
        return round(values[lo] + (values[hi] - values[lo]) * (k - lo), 3)

    def layer_stats(self, since: float | None = None) -> dict[str, dict[str, Any]]:
        out = {}
        with self._lock:
            snapshot = {k: list(v) for k, v in self.samples.items()}
        for layer in LAYERS:
            vals = [ms for ts, ms in snapshot.get(layer, []) if since is None or ts >= since]
            out[layer] = {
                "count": len(vals),
                "p50": self._percentile(vals, 0.50),
                "p95": self._percentile(vals, 0.95),
                "p99": self._percentile(vals, 0.99),
                "max": round(max(vals), 3) if vals else None,
                "histogram": self._histogram(vals),
            }
        return out

    @staticmethod
    def _histogram(vals: list[float]) -> list[dict[str, Any]]:
        edges = [0.25, 0.5, 1, 2, 5, 10, 20, 50, 100, 250, 500, 1000, 2000, 4000, 8000]
        counts = [0] * (len(edges) + 1)
        for v in vals:
            for i, e in enumerate(edges):
                if v <= e:
                    counts[i] += 1
                    break
            else:
                counts[-1] += 1
        out = []
        prev = 0.0
        for i, e in enumerate(edges):
            out.append({"le_ms": e, "gt_ms": prev, "count": counts[i]})
            prev = e
        out.append({"le_ms": None, "gt_ms": edges[-1], "count": counts[-1]})
        return out

    def throughput(self, seconds: float = 60) -> float:
        cutoff = time.time() - seconds
        with self._lock:
            n = sum(1 for t in self.request_times if t >= cutoff)
        return round(n / seconds, 3)
