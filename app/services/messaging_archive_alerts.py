from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ArchiveHealthSignals:
    write_failures: float
    write_total: float
    integrity_errors: float
    export_failures: float
    export_total: float
    consecutive_write_failure_windows: int = 0


@dataclass(frozen=True)
class ArchiveHealthAlertDecision:
    sustained_write_failure: bool
    integrity_chain_mismatch: bool
    export_failure_spike: bool


def evaluate_archive_health_alerts(signals: ArchiveHealthSignals) -> ArchiveHealthAlertDecision:
    write_total = max(0.0, float(signals.write_total))
    write_failure_rate = 0.0 if write_total <= 0 else float(signals.write_failures) / write_total

    export_total = max(0.0, float(signals.export_total))
    export_failure_rate = 0.0 if export_total <= 0 else float(signals.export_failures) / export_total

    sustained_write_failure = write_failure_rate >= 0.05 and int(signals.consecutive_write_failure_windows) >= 3
    integrity_chain_mismatch = float(signals.integrity_errors) > 0.0
    export_failure_spike = export_failure_rate >= 0.10

    return ArchiveHealthAlertDecision(
        sustained_write_failure=sustained_write_failure,
        integrity_chain_mismatch=integrity_chain_mismatch,
        export_failure_spike=export_failure_spike,
    )
