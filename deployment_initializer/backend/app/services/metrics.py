from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock


@dataclass
class AlertState:
    code: str
    severity: str
    message: str
    runbook: str
    triggered_at: datetime


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = Lock()
        self._validation_failures_total = 0
        self._deploy_success_total = 0
        self._deploy_failure_total = 0
        self._deploy_durations_seconds: list[float] = []
        self._deploy_failures_timestamps: deque[datetime] = deque(maxlen=500)
        self._active_alerts: dict[str, AlertState] = {}

    def record_validation(self, blocking_issue_count: int) -> None:
        with self._lock:
            if blocking_issue_count > 0:
                self._validation_failures_total += 1

    def record_deploy_result(self, success: bool, duration_seconds: float) -> None:
        with self._lock:
            self._deploy_durations_seconds.append(duration_seconds)
            if success:
                self._deploy_success_total += 1
            else:
                self._deploy_failure_total += 1
                self._deploy_failures_timestamps.append(datetime.now(tz=timezone.utc))
            self._evaluate_failure_alerts_locked()

    def _evaluate_failure_alerts_locked(self) -> None:
        threshold = int(os.getenv('DEPLOY_FAILURE_ALERT_THRESHOLD', '3'))
        window_minutes = int(os.getenv('DEPLOY_FAILURE_ALERT_WINDOW_MINUTES', '15'))
        now = datetime.now(tz=timezone.utc)
        window_start = now - timedelta(minutes=window_minutes)

        while self._deploy_failures_timestamps and self._deploy_failures_timestamps[0] < window_start:
            self._deploy_failures_timestamps.popleft()

        if len(self._deploy_failures_timestamps) >= threshold:
            self._active_alerts['repeated_deploy_failures'] = AlertState(
                code='repeated_deploy_failures',
                severity='critical',
                message=f'Deploy failures exceeded threshold ({threshold}) in last {window_minutes}m.',
                runbook='https://runbooks.internal/deployment-initializer/deploy-failure-response',
                triggered_at=now,
            )

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            total = self._deploy_success_total + self._deploy_failure_total
            success_rate = (self._deploy_success_total / total) if total > 0 else 1.0
            avg_duration = (
                sum(self._deploy_durations_seconds) / len(self._deploy_durations_seconds)
                if self._deploy_durations_seconds
                else 0.0
            )
            return {
                'validation_failures_total': self._validation_failures_total,
                'deploy_success_total': self._deploy_success_total,
                'deploy_failure_total': self._deploy_failure_total,
                'deploy_success_rate': round(success_rate, 4),
                'deploy_duration_avg_seconds': round(avg_duration, 4),
                'active_alerts': [
                    {
                        'code': alert.code,
                        'severity': alert.severity,
                        'message': alert.message,
                        'runbook': alert.runbook,
                        'triggered_at': alert.triggered_at.isoformat(),
                    }
                    for alert in self._active_alerts.values()
                ],
            }

    def dashboard_template(self) -> dict[str, object]:
        return {
            'title': 'Deployment Initializer SLO Dashboard',
            'panels': [
                {'metric': 'validation_failures_total', 'type': 'timeseries', 'description': 'Validation blocking failures'},
                {'metric': 'deploy_success_rate', 'type': 'stat', 'description': 'Deploy success ratio'},
                {'metric': 'deploy_duration_avg_seconds', 'type': 'timeseries', 'description': 'Average deploy duration'},
            ],
            'alerts': [
                {
                    'code': 'repeated_deploy_failures',
                    'condition': 'deploy_failure_total increases by threshold in alert window',
                    'runbook': 'https://runbooks.internal/deployment-initializer/deploy-failure-response',
                }
            ],
        }


COLLECTOR = MetricsCollector()
