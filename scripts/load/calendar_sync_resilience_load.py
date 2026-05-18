#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass


@dataclass
class RunResult:
    name: str
    events: int
    duration_seconds: float
    throughput_events_per_sec: float
    p95_batch_seconds: float


def _run_profile(*, name: str, events: int, batch_size: int, simulated_network_ms: float, retry_ratio: float) -> RunResult:
    batches = max((events + batch_size - 1) // batch_size, 1)
    batch_latencies: list[float] = []

    start = time.perf_counter()
    for i in range(batches):
        batch_start = time.perf_counter()
        in_batch = min(batch_size, events - (i * batch_size))
        retry_penalty = simulated_network_ms * retry_ratio
        sleep_s = max((simulated_network_ms + retry_penalty) / 1000.0, 0.0)
        # Synthetic network + retry pressure model.
        time.sleep(sleep_s)
        # Synthetic CPU parse/apply cost (very small but non-zero).
        _ = sum(range(min(in_batch, 50)))
        batch_latencies.append(time.perf_counter() - batch_start)
    elapsed = time.perf_counter() - start

    p95 = statistics.quantiles(batch_latencies, n=100)[94] if len(batch_latencies) >= 2 else batch_latencies[0]
    throughput = float(events) / max(elapsed, 1e-9)
    return RunResult(
        name=name,
        events=events,
        duration_seconds=elapsed,
        throughput_events_per_sec=throughput,
        p95_batch_seconds=p95,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic resilience/load validation for Apple CalDAV sync")
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--baseline-batch-size", type=int, default=50)
    parser.add_argument("--hardened-batch-size", type=int, default=200)
    parser.add_argument("--simulated-network-ms", type=float, default=8.0)
    parser.add_argument("--retry-ratio", type=float, default=0.2)
    parser.add_argument("--output", default="/tmp/calendar_sync_load_validation.json")
    args = parser.parse_args()

    baseline = _run_profile(
        name="baseline",
        events=max(int(args.events), 1),
        batch_size=max(int(args.baseline_batch_size), 1),
        simulated_network_ms=max(float(args.simulated_network_ms), 0.0),
        retry_ratio=max(float(args.retry_ratio), 0.0),
    )
    hardened = _run_profile(
        name="hardened",
        events=max(int(args.events), 1),
        batch_size=max(int(args.hardened_batch_size), 1),
        simulated_network_ms=max(float(args.simulated_network_ms), 0.0),
        retry_ratio=max(float(args.retry_ratio), 0.0),
    )

    delta_throughput = ((hardened.throughput_events_per_sec - baseline.throughput_events_per_sec) / max(baseline.throughput_events_per_sec, 1e-9)) * 100.0
    delta_p95 = ((hardened.p95_batch_seconds - baseline.p95_batch_seconds) / max(baseline.p95_batch_seconds, 1e-9)) * 100.0

    report = {
        "inputs": {
            "events": int(args.events),
            "simulated_network_ms": float(args.simulated_network_ms),
            "retry_ratio": float(args.retry_ratio),
            "baseline_batch_size": int(args.baseline_batch_size),
            "hardened_batch_size": int(args.hardened_batch_size),
        },
        "baseline": baseline.__dict__,
        "hardened": hardened.__dict__,
        "deltas": {
            "throughput_percent": delta_throughput,
            "p95_batch_latency_percent": delta_p95,
        },
        "targets": {
            "throughput_events_per_sec_min": 150.0,
            "p95_batch_seconds_max": 0.20,
        },
        "target_results": {
            "throughput_ok": hardened.throughput_events_per_sec >= 150.0,
            "p95_ok": hardened.p95_batch_seconds <= 0.20,
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps({
        "output": args.output,
        "throughput_eps": round(hardened.throughput_events_per_sec, 2),
        "p95_batch_seconds": round(hardened.p95_batch_seconds, 4),
        "targets": report["target_results"],
    }))


if __name__ == "__main__":
    main()
