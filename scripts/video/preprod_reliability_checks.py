#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Thresholds:
    input_failover_recovery_ms: int = 15_000
    input_failover_max_rebuffer_ms: int = 4_000
    input_failover_max_dropped_segments: int = 3

    key_outage_recovery_ms: int = 20_000
    key_outage_max_license_5xx_rate: float = 0.05
    key_outage_max_stale_key_seconds: int = 120

    cdn_recovery_ms: int = 30_000
    cdn_max_origin_5xx_rate: float = 0.02
    cdn_min_edge_hit_ratio: float = 0.85
    cdn_max_manifest_stale_seconds: int = 30


class ReliabilityFailure(RuntimeError):
    pass


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ReliabilityFailure(f"report not found: {path}")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReliabilityFailure(f"invalid json report: {path}") from exc
    if not isinstance(parsed, dict):
        raise ReliabilityFailure("report root must be a JSON object")
    return parsed


def _require(report: dict[str, Any], key: str) -> dict[str, Any]:
    section = report.get(key)
    if not isinstance(section, dict):
        raise ReliabilityFailure(f"missing scenario section: {key}")
    return section


def _number(section: dict[str, Any], key: str) -> float:
    value = section.get(key)
    if not isinstance(value, (int, float)):
        raise ReliabilityFailure(f"missing numeric field '{key}' in scenario section")
    return float(value)


def evaluate(report: dict[str, Any], thresholds: Thresholds) -> list[str]:
    failures: list[str] = []

    failover = _require(report, "input_failover")
    failover_recovery_ms = _number(failover, "recover_ms")
    failover_rebuffer_ms = _number(failover, "max_rebuffer_ms")
    failover_dropped = _number(failover, "dropped_segments")

    if failover_recovery_ms > thresholds.input_failover_recovery_ms:
        failures.append(
            f"input_failover recovery exceeded threshold: {failover_recovery_ms:.0f}ms > {thresholds.input_failover_recovery_ms}ms"
        )
    if failover_rebuffer_ms > thresholds.input_failover_max_rebuffer_ms:
        failures.append(
            f"input_failover rebuffer exceeded threshold: {failover_rebuffer_ms:.0f}ms > {thresholds.input_failover_max_rebuffer_ms}ms"
        )
    if failover_dropped > thresholds.input_failover_max_dropped_segments:
        failures.append(
            f"input_failover dropped segments exceeded threshold: {failover_dropped:.0f} > {thresholds.input_failover_max_dropped_segments}"
        )

    key_outage = _require(report, "key_outage")
    key_recovery_ms = _number(key_outage, "recover_ms")
    key_5xx_rate = _number(key_outage, "license_5xx_rate")
    key_stale_seconds = _number(key_outage, "stale_key_serve_seconds")

    if key_recovery_ms > thresholds.key_outage_recovery_ms:
        failures.append(
            f"key_outage recovery exceeded threshold: {key_recovery_ms:.0f}ms > {thresholds.key_outage_recovery_ms}ms"
        )
    if key_5xx_rate > thresholds.key_outage_max_license_5xx_rate:
        failures.append(
            f"key_outage license 5xx exceeded threshold: {key_5xx_rate:.4f} > {thresholds.key_outage_max_license_5xx_rate:.4f}"
        )
    if key_stale_seconds > thresholds.key_outage_max_stale_key_seconds:
        failures.append(
            f"key_outage stale key serving exceeded threshold: {key_stale_seconds:.0f}s > {thresholds.key_outage_max_stale_key_seconds}s"
        )

    cdn = _require(report, "cdn_behavior")
    cdn_recovery_ms = _number(cdn, "recover_ms")
    cdn_origin_5xx_rate = _number(cdn, "origin_5xx_rate")
    cdn_edge_hit_ratio = _number(cdn, "edge_hit_ratio")
    cdn_manifest_stale = _number(cdn, "manifest_stale_seconds")

    if cdn_recovery_ms > thresholds.cdn_recovery_ms:
        failures.append(
            f"cdn_behavior recovery exceeded threshold: {cdn_recovery_ms:.0f}ms > {thresholds.cdn_recovery_ms}ms"
        )
    if cdn_origin_5xx_rate > thresholds.cdn_max_origin_5xx_rate:
        failures.append(
            f"cdn_behavior origin 5xx exceeded threshold: {cdn_origin_5xx_rate:.4f} > {thresholds.cdn_max_origin_5xx_rate:.4f}"
        )
    if cdn_edge_hit_ratio < thresholds.cdn_min_edge_hit_ratio:
        failures.append(
            f"cdn_behavior edge hit ratio below threshold: {cdn_edge_hit_ratio:.4f} < {thresholds.cdn_min_edge_hit_ratio:.4f}"
        )
    if cdn_manifest_stale > thresholds.cdn_max_manifest_stale_seconds:
        failures.append(
            f"cdn_behavior stale manifest exceeded threshold: {cdn_manifest_stale:.0f}s > {thresholds.cdn_max_manifest_stale_seconds}s"
        )

    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Pre-production reliability gate for video playback scenarios.")
    parser.add_argument("--report", required=True, help="JSON report generated by preprod reliability run")
    args = parser.parse_args(argv)

    report = _load_report(Path(args.report))
    failures = evaluate(report, Thresholds())

    if failures:
        print("reliability checks failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("reliability checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ReliabilityFailure as exc:
        print(f"reliability check input error: {exc}", file=sys.stderr)
        raise SystemExit(2)
