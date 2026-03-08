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

        self._admin_sso_login_success_total = 0
        self._admin_sso_login_failure_total = 0
        self._admin_sso_login_denied_total = 0
        self._admin_sso_callback_durations_seconds: list[float] = []
        self._admin_sso_config_validation_failures_total = 0
        self._admin_sso_denial_timestamps: deque[datetime] = deque(maxlen=500)
        self._admin_sso_callback_error_timestamps: deque[datetime] = deque(maxlen=500)

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

    def record_admin_sso_callback(self, outcome: str, duration_seconds: float, failure_reason: str | None = None) -> None:
        with self._lock:
            now = datetime.now(tz=timezone.utc)
            self._admin_sso_callback_durations_seconds.append(duration_seconds)
            if outcome == 'success':
                self._admin_sso_login_success_total += 1
            else:
                self._admin_sso_login_failure_total += 1
                self._admin_sso_callback_error_timestamps.append(now)
                if outcome == 'denied':
                    self._admin_sso_login_denied_total += 1
                    self._admin_sso_denial_timestamps.append(now)
            self._evaluate_admin_sso_alerts_locked(failure_reason=failure_reason)

    def record_admin_sso_config_validation_failure(self, reason_code: str | None = None) -> None:
        with self._lock:
            self._admin_sso_config_validation_failures_total += 1
            self._evaluate_admin_sso_alerts_locked(failure_reason=reason_code)

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

    def _evaluate_admin_sso_alerts_locked(self, failure_reason: str | None = None) -> None:
        now = datetime.now(tz=timezone.utc)

        denial_threshold = int(os.getenv('ADMIN_SSO_DENIAL_ALERT_THRESHOLD', '5'))
        denial_window_minutes = int(os.getenv('ADMIN_SSO_DENIAL_ALERT_WINDOW_MINUTES', '10'))
        denial_window_start = now - timedelta(minutes=denial_window_minutes)
        while self._admin_sso_denial_timestamps and self._admin_sso_denial_timestamps[0] < denial_window_start:
            self._admin_sso_denial_timestamps.popleft()

        if len(self._admin_sso_denial_timestamps) >= denial_threshold:
            self._active_alerts['admin_sso_denial_spike'] = AlertState(
                code='admin_sso_denial_spike',
                severity='high',
                message=f'Admin SSO denied logins exceeded threshold ({denial_threshold}) in last {denial_window_minutes}m.',
                runbook='https://runbooks.internal/deployment-initializer/admin-sso-denials',
                triggered_at=now,
            )

        callback_error_threshold = int(os.getenv('ADMIN_SSO_CALLBACK_ERROR_ALERT_THRESHOLD', '5'))
        callback_error_window_minutes = int(os.getenv('ADMIN_SSO_CALLBACK_ERROR_ALERT_WINDOW_MINUTES', '10'))
        callback_window_start = now - timedelta(minutes=callback_error_window_minutes)
        while self._admin_sso_callback_error_timestamps and self._admin_sso_callback_error_timestamps[0] < callback_window_start:
            self._admin_sso_callback_error_timestamps.popleft()

        if len(self._admin_sso_callback_error_timestamps) >= callback_error_threshold:
            reason_context = f' Last reason={failure_reason}.' if failure_reason else ''
            self._active_alerts['admin_sso_callback_errors'] = AlertState(
                code='admin_sso_callback_errors',
                severity='critical',
                message=(
                    f'Admin SSO callback errors exceeded threshold ({callback_error_threshold}) '
                    f'in last {callback_error_window_minutes}m.{reason_context}'
                ),
                runbook='https://runbooks.internal/deployment-initializer/admin-sso-callback-errors',
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

            admin_sso_total = self._admin_sso_login_success_total + self._admin_sso_login_failure_total
            admin_sso_success_rate = (self._admin_sso_login_success_total / admin_sso_total) if admin_sso_total > 0 else 1.0
            admin_sso_callback_latency_avg = (
                sum(self._admin_sso_callback_durations_seconds) / len(self._admin_sso_callback_durations_seconds)
                if self._admin_sso_callback_durations_seconds
                else 0.0
            )

            return {
                'validation_failures_total': self._validation_failures_total,
                'deploy_success_total': self._deploy_success_total,
                'deploy_failure_total': self._deploy_failure_total,
                'deploy_success_rate': round(success_rate, 4),
                'deploy_duration_avg_seconds': round(avg_duration, 4),
                'admin_sso_login_success_total': self._admin_sso_login_success_total,
                'admin_sso_login_failure_total': self._admin_sso_login_failure_total,
                'admin_sso_login_denied_total': self._admin_sso_login_denied_total,
                'admin_sso_login_success_rate': round(admin_sso_success_rate, 4),
                'admin_sso_callback_latency_avg_seconds': round(admin_sso_callback_latency_avg, 4),
                'admin_sso_config_validation_failures_total': self._admin_sso_config_validation_failures_total,
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
                {'metric': 'admin_sso_login_success_rate', 'type': 'stat', 'description': 'Admin SSO login success ratio'},
                {'metric': 'admin_sso_login_denied_total', 'type': 'timeseries', 'description': 'Admin SSO denied login count'},
                {'metric': 'admin_sso_callback_latency_avg_seconds', 'type': 'timeseries', 'description': 'Admin SSO callback average latency'},
                {'metric': 'admin_sso_config_validation_failures_total', 'type': 'timeseries', 'description': 'Admin SSO config validation failures'},
            ],
            'alerts': [
                {
                    'code': 'repeated_deploy_failures',
                    'condition': 'deploy_failure_total increases by threshold in alert window',
                    'runbook': 'https://runbooks.internal/deployment-initializer/deploy-failure-response',
                },
                {
                    'code': 'admin_sso_denial_spike',
                    'condition': 'admin_sso_login_denied_total exceeds denial threshold in alert window',
                    'runbook': 'https://runbooks.internal/deployment-initializer/admin-sso-denials',
                },
                {
                    'code': 'admin_sso_callback_errors',
                    'condition': 'admin_sso_login_failure_total exceeds callback error threshold in alert window',
                    'runbook': 'https://runbooks.internal/deployment-initializer/admin-sso-callback-errors',
                },
            ],
        }


COLLECTOR = MetricsCollector()
