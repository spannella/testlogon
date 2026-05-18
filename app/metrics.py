from __future__ import annotations

import os
import time
from typing import Callable, Optional

try:
    from fastapi import Request, Response
except Exception:  # pragma: no cover - tests that import metrics without fastapi installed
    Request = object  # type: ignore[assignment,misc]
    Response = object  # type: ignore[assignment,misc]

_APP_ENV = os.environ.get("APP_ENV", "development").lower()
_PROD_ENVS = {"prod", "production"}
_METRICS_ENABLED = _APP_ENV in _PROD_ENVS
METRICS_ENABLED = _METRICS_ENABLED

if _METRICS_ENABLED:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, Info, generate_latest
    except ImportError as exc:  # pragma: no cover - hard failure in prod misconfig
        raise RuntimeError("prometheus_client must be installed in production mode") from exc
else:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _NoopMetric:
        def labels(self, **_kwargs: str) -> "_NoopMetric":
            return self

        def inc(self, _value: float = 1.0) -> None:
            return None

        def observe(self, _value: float) -> None:
            return None

        def set(self, _value: float) -> None:
            return None

        def info(self, _value: dict[str, str]) -> None:
            return None

    def Counter(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Gauge(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Histogram(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def Info(*_args: object, **_kwargs: object) -> _NoopMetric:
        return _NoopMetric()

    def generate_latest() -> bytes:
        return b""

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
LOGIN_SUCCESSES = Counter(
    "login_success_total",
    "Total successful logins",
)
LOGIN_FAILURES = Counter(
    "login_failure_total",
    "Total failed logins",
)
MFA_SUCCESSES = Counter(
    "mfa_success_total",
    "Total successful MFA checks",
)
MFA_FAILURES = Counter(
    "mfa_failure_total",
    "Total failed MFA checks",
)
NEW_USERS = Counter(
    "new_users_total",
    "Total new users observed",
)
ACTIVE_SESSIONS = Gauge(
    "active_sessions",
    "Active sessions in this process",
)
ACTIVE_USERS = Gauge(
    "active_users",
    "Active users with at least one session in this process",
)
REQUEST_ERRORS = Counter(
    "http_request_errors_total",
    "Total HTTP requests resulting in server errors",
    ["method", "path", "status"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
REQUEST_SIZE = Histogram(
    "http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "path"],
    buckets=(0, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000),
)
RESPONSE_SIZE = Histogram(
    "http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "path", "status"],
    buckets=(0, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000),
)
IN_PROGRESS = Gauge(
    "http_requests_in_progress",
    "In-progress HTTP requests",
    ["method", "path"],
)
UPTIME_SECONDS = Gauge(
    "app_uptime_seconds",
    "Application uptime in seconds",
)
APP_INFO = Info(
    "app",
    "Application metadata",
)
FILEMGR_PURGE_RESULTS = Counter(
    "filemgr_purge_results_total",
    "File manager purge outcomes",
    ["scope", "outcome", "mode"],
)
FILEMGR_OPERATION_LATENCY = Histogram(
    "filemgr_operation_duration_seconds",
    "File manager operation latency in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_PROVIDER_OPERATION_TOTAL = Counter(
    "filemgr_provider_operation_total",
    "File manager operation counts segmented by provider/mount context",
    ["operation", "provider", "mount_id", "mounted", "outcome", "error_class"],
)
FILEMGR_PROVIDER_OPERATION_LATENCY = Histogram(
    "filemgr_provider_operation_latency_seconds",
    "File manager operation latency segmented by provider/mount context",
    ["operation", "provider", "mount_id", "mounted", "error_class"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_PROVIDER_ERRORS_TOTAL = Counter(
    "filemgr_provider_errors_total",
    "File manager provider errors segmented by provider/mount/error class",
    ["operation", "provider", "mount_id", "error_class"],
)
FILEMGR_MOUNT_SECRET_ACCESS = Counter(
    "filemgr_mount_secret_access_total",
    "File manager mount credential secret access events",
    ["action", "outcome"],
)
FILEMGR_ICLOUD_READ_CACHE = Counter(
    "filemgr_icloud_read_cache_total",
    "iCloud provider read cache outcomes",
    ["result", "reason"],
)

FILEMGR_PROVIDER_AUTH_FAILURES = Counter(
    "filemgr_provider_auth_failures_total",
    "File manager provider authentication failures by provider/mount/reason",
    ["provider", "mount_id", "reason"],
)
FILEMGR_MOUNT_ROLLOUT_DECISIONS = Counter(
    "filemgr_mount_rollout_decisions_total",
    "File manager iCloud mount rollout decisions",
    ["provider", "environment", "mode", "cohort", "reason"],
)
FILEMGR_MOUNT_RECONCILE_RUNS = Counter(
    "filemgr_mount_reconcile_runs_total",
    "File manager mount metadata reconcile batch runs",
    ["outcome", "dry_run"],
)
FILEMGR_MOUNT_RECONCILE_DRIFT_ITEMS = Counter(
    "filemgr_mount_reconcile_drift_items_total",
    "File manager mount metadata reconcile drift items by type",
    ["kind", "dry_run"],
)
FILEMGR_MOUNT_RECONCILE_DURATION = Histogram(
    "filemgr_mount_reconcile_duration_seconds",
    "File manager mount metadata reconcile batch latency in seconds",
    ["outcome", "dry_run"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
FILEMGR_BYTES = Counter(
    "filemgr_transfer_bytes_total",
    "File manager bytes transferred",
    ["direction", "operation"],
)
FILEMGR_SEARCH_PATH = Counter(
    "filemgr_search_path_total",
    "File manager search execution path",
    ["operation", "path"],
)
FILEMGR_PURGE_DURATION = Histogram(
    "filemgr_purge_duration_seconds",
    "File manager purge run duration in seconds",
    ["scope", "mode"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
FILEMGR_PURGE_THROUGHPUT = Counter(
    "filemgr_purge_items_total",
    "File manager purge processed items",
    ["scope", "mode", "outcome"],
)
FILEMGR_ENCRYPTION_EVENTS = Counter(
    "filemgr_encryption_events_total",
    "File manager encryption-related events",
    ["event", "encrypted", "reason"],
)
FILEMGR_SHARED_ENCRYPTED_DOWNLOADS = Counter(
    "filemgr_shared_encrypted_downloads_total",
    "File manager shared download attempts split by encryption/outcome",
    ["encrypted", "outcome"],
)
FILEMGR_PREVIEW_ATTEMPTS = Counter(
    "filemgr_preview_attempts_total",
    "File manager preview attempts by kind/outcome",
    ["kind", "outcome", "reason"],
)
FILEMGR_PREVIEW_LATENCY = Histogram(
    "filemgr_preview_latency_seconds",
    "File manager preview latency by kind",
    ["kind"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_PREVIEW_BYTES = Counter(
    "filemgr_preview_bytes_total",
    "File manager preview bytes streamed by kind",
    ["kind"],
)
FILEMGR_PREVIEW_FALLBACK = Counter(
    "filemgr_preview_fallback_total",
    "File manager preview fallback outcomes by kind/reason",
    ["kind", "reason"],
)

FILEMGR_PREVIEW_JOBS = Counter(
    "filemgr_preview_jobs_total",
    "File manager preview job outcomes by media/artifact/outcome/reason",
    ["media_type", "artifact", "outcome", "reason"],
)
FILEMGR_PREVIEW_JOB_DURATION = Histogram(
    "filemgr_preview_job_duration_seconds",
    "File manager preview artifact generation/upload duration in seconds",
    ["artifact"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
FILEMGR_PREVIEW_ARTIFACT_BYTES = Counter(
    "filemgr_preview_artifact_bytes",
    "File manager preview artifact bytes produced",
    ["artifact"],
)

FILEMGR_MOUNT_OPERATION_LATENCY = Histogram(
    "filemgr_mount_operation_duration_seconds",
    "Mounted file manager operation latency in seconds",
    ["provider", "mode", "operation", "mount_id_hash"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_MOUNT_BYTES = Counter(
    "filemgr_mount_transfer_bytes_total",
    "Mounted file manager bytes transferred",
    ["provider", "mode", "operation", "direction", "mount_id_hash"],
)
FILEMGR_MOUNT_ERRORS = Counter(
    "filemgr_mount_errors_total",
    "Mounted file manager errors by provider operation and aws code",
    ["provider", "mode", "operation", "aws_error_code", "mount_id_hash"],
)
FILEMGR_PREVIEW_HOVER_PLAY_STARTS = Counter(
    "filemgr_preview_hover_play_starts_total",
    "Client hover/tap preview play starts",
)
FILEMGR_PREVIEW_HOVER_PLAY_FAILURES = Counter(
    "filemgr_preview_hover_play_failures_total",
    "Client hover/tap preview play failures",
    ["reason"],
)

FILEMGR_MOUNT_UPLOAD_METHOD = Counter(
    "filemgr_mount_upload_method_total",
    "Mounted provider upload method usage and outcome",
    ["provider", "method", "outcome"],
)
FILEMGR_MOUNT_OPERATION_LATENCY = Histogram(
    "filemgr_mount_operation_duration_seconds",
    "Mounted file-manager operation latency in seconds",
    ["provider", "operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
FILEMGR_MOUNT_BYTES = Counter(
    "filemgr_mount_transfer_bytes_total",
    "Mounted file-manager transfer bytes",
    ["provider", "direction", "operation"],
)
FILEMGR_MOUNT_API_ERRORS = Counter(
    "filemgr_mount_api_errors_total",
    "Mounted provider API errors",
    ["provider", "operation", "status_code", "reason"],
)
FILEMGR_MOUNT_REFRESH_ATTEMPTS = Counter(
    "filemgr_mount_refresh_attempts_total",
    "Mounted provider OAuth refresh attempts",
    ["provider", "outcome", "reason"],
)
FILEMGR_PREVIEW_QUEUE_DEPTH = Gauge(
    "filemgr_preview_queue_depth",
    "Approximate in-flight preview jobs in this worker process",
)
SIGNATURE_PACKET_RENDER_JOBS = Counter(
    "signature_packet_render_jobs_total",
    "Signature packet final-PDF render job outcomes",
    ["outcome", "reason"],
)
SIGNATURE_PACKET_RENDER_LATENCY = Histogram(
    "signature_packet_render_duration_seconds",
    "Signature packet final-PDF render duration",
    ["outcome"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)
SIGNATURE_PACKET_EVENTS = Counter(
    "signature_packet_events_total",
    "Signature packet append-only lifecycle events",
    ["event_type"],
)
SIGNATURE_PACKET_REMINDER_EMAILS = Counter(
    "signature_packet_reminder_emails_total",
    "Signature packet reminder email outcomes",
    ["outcome", "reason"],
)

MESSAGING_GALLERY_REQUESTS = Counter(
    "messaging_gallery_requests_total",
    "Messaging gallery request outcomes by type/outcome",
    ["type", "outcome"],
)
MESSAGING_GALLERY_LATENCY = Histogram(
    "messaging_gallery_latency_seconds",
    "Messaging gallery request latency by type",
    ["type"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
MESSAGING_GALLERY_CURSOR_PAGE_DEPTH = Histogram(
    "messaging_gallery_cursor_page_depth",
    "Messaging gallery cursor page depth by type",
    ["type"],
    buckets=(0, 1, 2, 3, 5, 8, 13, 21, 34),
)
NEWSFEED_FEED_REQUESTS = Counter(
    "newsfeed_feed_requests_total",
    "Newsfeed list request outcomes by mode",
    ["mode", "outcome"],
)
NEWSFEED_FEED_LATENCY = Histogram(
    "newsfeed_feed_latency_seconds",
    "Newsfeed list request latency by mode/outcome",
    ["mode", "outcome"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
NEWSFEED_FEED_FILTER_USAGE = Counter(
    "newsfeed_feed_filter_usage_total",
    "Newsfeed filter usage by mode/filter name",
    ["mode", "filter_name"],
)
NEWSFEED_FEED_PAGE_DEPTH = Histogram(
    "newsfeed_feed_page_depth",
    "Newsfeed pagination depth (# scanned query pages) by mode",
    ["mode"],
    buckets=(0, 1, 2, 3, 5, 8, 13, 21, 34),
)
NEWSFEED_FEED_ERRORS = Counter(
    "newsfeed_feed_errors_total",
    "Newsfeed list error outcomes by mode/error class",
    ["mode", "error_type"],
)
NEWSFEED_FEED_BUDGET_HITS = Counter(
    "newsfeed_feed_budget_hits_total",
    "Newsfeed feed query budget guardrail hits by mode/reason",
    ["mode", "reason"],
)
CURSOR_DECODE_RESULTS = Counter(
    "cursor_decode_results_total",
    "Cursor decode outcomes by format and key source",
    ["format", "outcome", "key_source"],
)
MESSAGING_MESSAGE_CONTROL_ACTIONS = Counter(
    "messaging_message_control_actions_total",
    "Messaging message-control actions by action/result",
    ["action", "result"],
)
MESSAGING_REPORT_VALIDATION_ERRORS = Counter(
    "messaging_report_validation_errors_total",
    "Messaging report validation errors by reason",
    ["reason"],
)
MESSAGING_ARCHIVE_WRITE_EVENTS = Counter(
    "messaging_archive_write_events_total",
    "Messaging compliance archive write outcomes by result/event type",
    ["result", "event_type"],
)
MESSAGING_ARCHIVE_WRITE_LATENCY = Histogram(
    "messaging_archive_write_latency_seconds",
    "Messaging compliance archive write latency",
    ["result"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
MESSAGING_ARCHIVE_INTEGRITY_ERRORS = Counter(
    "messaging_archive_integrity_errors_total",
    "Messaging compliance archive integrity verification failures",
    ["reason"],
)
MESSAGING_ARCHIVE_EXPORT_OUTCOMES = Counter(
    "messaging_archive_export_outcomes_total",
    "Messaging compliance archive export outcomes",
    ["outcome"],
)
MESSAGING_THREAD_PROMOTION_EVENTS = Counter(
    "messaging_thread_promotion_events_total",
    "Messaging thread promotion outcomes by stage/outcome",
    ["stage", "outcome"],
)
MESSAGING_THREAD_PROMOTION_RETRIES = Counter(
    "messaging_thread_promotion_retries_total",
    "Messaging thread promotion retry attempts by reason",
    ["reason"],
)
MESSAGING_THREAD_QUERY_LATENCY = Histogram(
    "messaging_thread_query_latency_seconds",
    "Messaging thread query latency by endpoint/outcome",
    ["endpoint", "outcome"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
MESSAGING_THREAD_INVALID_CURSORS = Counter(
    "messaging_thread_invalid_cursors_total",
    "Messaging thread invalid cursor rejections by endpoint and reason category",
    ["endpoint", "reason_category"],
)
MESSAGING_THREAD_RECONCILIATION_ANOMALIES = Counter(
    "messaging_thread_reconciliation_anomalies_total",
    "Messaging thread reconciliation anomalies by reason",
    ["reason"],
)
MESSAGING_DRAFT_OPERATIONS = Counter(
    "messaging_draft_operations_total",
    "Messaging draft operation outcomes by operation/source/result",
    ["operation", "source", "result"],
)
MESSAGING_DRAFT_LATENCY = Histogram(
    "messaging_draft_operation_duration_seconds",
    "Messaging draft operation latency by operation/source",
    ["operation", "source"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
MESSAGING_DRAFT_FALLBACKS = Counter(
    "messaging_draft_fallback_total",
    "Messaging draft fallback usage by reason",
    ["reason"],
)
MASS_MESSAGE_CAMPAIGN_EVENTS = Counter(
    "messaging_mass_campaign_events_total",
    "Mass messaging campaign lifecycle events",
    ["event", "mode", "outcome"],
)
MASS_MESSAGE_DESTINATION_OUTCOMES = Counter(
    "messaging_mass_destination_outcomes_total",
    "Mass messaging destination outcomes by mode and canonical error code",
    ["mode", "outcome", "error_code"],
)
MASS_MESSAGE_DESTINATION_RETRIES = Counter(
    "messaging_mass_destination_retries_total",
    "Mass messaging destination retry attempts by mode and canonical error code",
    ["mode", "error_code"],
)
MASS_MESSAGE_WORKER_LATENCY = Histogram(
    "messaging_mass_worker_latency_seconds",
    "Mass messaging worker run latency by mode and outcome",
    ["mode", "outcome"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)
MASS_MESSAGE_LIMIT_EVENTS = Counter(
    "messaging_mass_limit_events_total",
    "Mass messaging abuse/rate-limit evaluations",
    ["scope", "limit_name", "outcome"],
)
NEWSFEED_SCHEDULE_OPERATIONS = Counter(
    "newsfeed_schedule_operations_total",
    "Newsfeed scheduled-post lifecycle operations by step and outcome",
    ["operation", "outcome"],
)
NEWSFEED_SCHEDULE_PUBLISH_LAG = Histogram(
    "newsfeed_schedule_publish_lag_seconds",
    "Lag between scheduled publish_at and actual scheduler publish",
    buckets=(0, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)
NEWSFEED_SCHEDULE_BACKLOG = Gauge(
    "newsfeed_schedule_backlog_due",
    "Count of scheduled posts currently due for publish",
)
NEWSFEED_SCHEDULE_OLDEST_DUE_AGE = Gauge(
    "newsfeed_schedule_oldest_due_age_seconds",
    "Age in seconds of the oldest currently due scheduled post",
)
NEWSFEED_SCHEDULE_ALERTS = Counter(
    "newsfeed_schedule_alerts_total",
    "Count of scheduler lag/error threshold alert breaches",
    ["alert_type"],
)
NEWSFEED_SCHEDULE_RUNS = Counter(
    "newsfeed_schedule_runs_total",
    "Newsfeed scheduler run outcomes",
    ["outcome"],
)
NEWSFEED_SCHEDULE_RUN_DURATION = Histogram(
    "newsfeed_schedule_run_duration_seconds",
    "Newsfeed scheduler run duration in seconds",
    buckets=(0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
NEWSFEED_SCHEDULE_LAST_RUN_UNIX = Gauge(
    "newsfeed_schedule_last_run_unix",
    "Unix timestamp of the most recent scheduler run heartbeat",
)
MESSAGING_LOTTERY_SENDS = Counter(
    "messaging_lottery_sends_total",
    "Lottery DM send outcomes by environment/client version",
    ["environment", "client_version", "outcome"],
)
MESSAGING_LOTTERY_UNLOCK_ATTEMPTS = Counter(
    "messaging_lottery_unlock_attempts_total",
    "Lottery DM unlock attempts by environment/client version",
    ["environment", "client_version"],
)
MESSAGING_LOTTERY_UNLOCK_RESULTS = Counter(
    "messaging_lottery_unlock_results_total",
    "Lottery DM unlock outcomes by environment/client version",
    ["environment", "client_version", "outcome"],
)
MESSAGING_LOTTERY_UNLOCK_LATENCY = Histogram(
    "messaging_lottery_unlock_latency_seconds",
    "Lottery DM unlock API latency by outcome/environment/client version",
    ["environment", "client_version", "outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
MESSAGING_LOTTERY_REVEAL_LATENCY = Histogram(
    "messaging_lottery_reveal_latency_seconds",
    "Lottery DM reveal latency (client reported or server fallback) by outcome/environment/client version",
    ["environment", "client_version", "outcome"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
USAGE_METERING_EVENTS = Counter(
    "usage_metering_events_total",
    "Usage metering event outcomes",
    ["event_type", "source", "outcome"],
)
USAGE_METERING_BYTES = Counter(
    "usage_metering_bytes_total",
    "Usage bytes observed by metering pipeline",
    ["event_type", "source"],
)
USAGE_METERING_EVENTS_BY_PERIOD = Counter(
    "usage_metering_events_by_period_total",
    "Usage metering event outcomes split by source and billing period",
    ["event_type", "source", "outcome", "period_id"],
)
USAGE_METERING_BYTES_BY_PERIOD = Counter(
    "usage_metering_bytes_by_period_total",
    "Usage bytes observed by metering pipeline split by source and billing period",
    ["event_type", "source", "period_id"],
)
USAGE_SURFACE_UNITS = Counter(
    "usage_surface_units_total",
    "Usage unit counters by source family, dimension and billing period",
    ["source_family", "dimension", "period_id"],
)
USAGE_SURFACE_TRANSFER_BYTES = Counter(
    "usage_surface_transfer_bytes_total",
    "Usage transfer bytes by source family, direction and billing period",
    ["source_family", "direction", "period_id"],
)
USAGE_METERING_PIPELINE_ERRORS = Counter(
    "usage_metering_pipeline_errors_total",
    "Usage metering pipeline errors",
    ["stage"],
)

API_USAGE_INGEST_EVENTS = Counter(
    "api_usage_ingest_events_total",
    "API usage metering ingest outcomes",
    ["outcome"],
)
API_USAGE_INGEST_LAG = Histogram(
    "api_usage_ingest_lag_seconds",
    "Lag from API event timestamp to persistence time",
    buckets=(0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)
API_USAGE_LIMIT_DENY = Counter(
    "api_usage_limit_deny_total",
    "API usage quota/limit denials",
    ["scope", "limit_type"],
)
API_USAGE_SNAPSHOT_FINALIZE = Counter(
    "api_usage_snapshot_finalize_total",
    "API usage snapshot finalize outcomes",
    ["outcome"],
)
API_USAGE_RECONCILIATION_DRIFT = Gauge(
    "api_usage_reconciliation_drift_rows",
    "API usage reconciliation drift rows by area",
    ["area"],
)
API_KEY_POLICY_DECISIONS = Counter(
    "api_key_policy_decisions_total",
    "API key policy decisions by mode/product/outcome/reason",
    ["mode", "product", "outcome", "reason"],
)
API_KEY_REGISTRY_DRIFT = Gauge(
    "api_key_registry_drift_routes",
    "Count of API-key route-scope registry entries not present in mounted routes",
)
API_KEY_REGISTRY_UNREGISTERED_LIVE = Gauge(
    "api_key_registry_unregistered_live_routes",
    "Count of live API routes on rollout surfaces without registry/exemption coverage",
)
USAGE_METERING_PIPELINE_LATENCY = Histogram(
    "usage_metering_pipeline_duration_seconds",
    "Usage metering pipeline latency in seconds",
    ["stage"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
)
HELPDESK_ALERTS_SENT = Counter(
    "helpdesk_alerts_sent_total",
    "Helpdesk alerted-agent fanout outcomes",
    ["outcome"],
)
HELPDESK_CLAIMS_TOTAL = Counter(
    "helpdesk_claims_total",
    "Helpdesk claim outcomes",
    ["outcome"],
)

HELPDESK_CLAIM_SUCCESS_TOTAL = Counter(
    "helpdesk_claim_success_total",
    "Helpdesk claim successes",
)
HELPDESK_CLAIM_CONFLICT_TOTAL = Counter(
    "helpdesk_claim_conflict_total",
    "Helpdesk claim conflicts",
)
HELPDESK_FAILOVER_TOTAL = Counter(
    "helpdesk_failover_total",
    "Helpdesk assignment failovers triggered by assignee disconnect/unavailable",
    ["reason"],
)
HELPDESK_NO_AGENTS_NOTICE_TOTAL = Counter(
    "helpdesk_no_agents_notice_total",
    "Helpdesk no-agents-online notice outcomes",
    ["outcome"],
)
HELPDESK_TIME_TO_FIRST_CLAIM_MS = Histogram(
    "helpdesk_time_to_first_claim_ms",
    "Milliseconds from conversation creation to first successful helpdesk claim",
    buckets=(100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000, 300000),
)

ADMIN_SCOPE_DENIED = Counter(
    "admin_scope_denied_total",
    "Denied admin scope authorization checks by route, required scope, and profile type",
    ["route", "required_scope", "admin_profile_type"],
)
PROFILE_LOOKUP_EVENTS = Counter(
    "profile_lookup_events_total",
    "Profile lookup outcomes by audience/result/suppression reason",
    ["audience", "result", "suppression_reason"],
)
PROFILE_LOOKUP_LATENCY = Histogram(
    "profile_lookup_latency_seconds",
    "Profile lookup request latency by audience/result",
    ["audience", "result"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
PROFILE_LOOKUP_IDENTIFIER_RESOLUTION = Counter(
    "profile_lookup_identifier_resolution_total",
    "Profile identifier resolution outcomes by resolution source and outcome",
    ["source", "outcome"],
)
ONCE_MEDIA_SEND_EVENTS = Counter(
    "messaging_once_media_send_total",
    "Once-media send events by media kind/policy and rollout cohort",
    ["media_kind", "consumption_policy", "cohort"],
)
ONCE_MEDIA_GRANT_EVENTS = Counter(
    "messaging_once_media_grant_total",
    "Once-media grant endpoint outcomes by media kind/reason/cohort",
    ["media_kind", "outcome", "reason", "cohort"],
)
ONCE_MEDIA_GRANT_LATENCY = Histogram(
    "messaging_once_media_grant_latency_seconds",
    "Once-media attachment grant issuance latency",
    ["media_kind", "outcome", "cohort"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
ONCE_MEDIA_CONSUME_EVENTS = Counter(
    "messaging_once_media_consume_total",
    "Once-media consume outcomes by media kind/reason/cohort",
    ["media_kind", "outcome", "reason", "cohort"],
)
ONCE_MEDIA_CONFLICT_EVENTS = Counter(
    "messaging_once_media_conflicts_total",
    "Once-media consume conflict/race outcomes by media kind/cohort",
    ["media_kind", "cohort"],
)
TURN_CREDENTIAL_ISSUE_EVENTS = Counter(
    "messaging_turn_credential_issue_total",
    "TURN credential issuance outcomes by status and reason",
    ["outcome", "reason"],
)
TURN_CREDENTIAL_ISSUE_LATENCY = Histogram(
    "messaging_turn_credential_issue_latency_seconds",
    "TURN credential issuance latency by status and reason",
    ["outcome", "reason"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
WEBRTC_CALL_SETUP_EVENTS = Counter(
    "messaging_webrtc_call_setup_total",
    "WebRTC call setup outcomes segmented by reason/platform/browser",
    ["outcome", "reason", "platform", "browser"],
)
WEBRTC_CALL_SETUP_LATENCY = Histogram(
    "messaging_webrtc_call_setup_latency_seconds",
    "WebRTC call setup latency segmented by outcome/platform/browser",
    ["outcome", "platform", "browser"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60),
)
WEBRTC_CALL_DURATION = Histogram(
    "messaging_webrtc_call_duration_seconds",
    "WebRTC connected-call duration segmented by end reason/network path",
    ["end_reason", "network_path"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200),
)
WEBRTC_CALL_FAILURE_EVENTS = Counter(
    "messaging_webrtc_call_failures_total",
    "WebRTC call failure taxonomy by reason and stage",
    ["reason", "stage", "platform", "browser"],
)
WEBRTC_CALL_NETWORK_PATH_EVENTS = Counter(
    "messaging_webrtc_call_network_path_total",
    "WebRTC connected call network path usage for TURN relay ratio",
    ["network_path"],
)
WEBRTC_SIGNALING_EVENTS = Counter(
    "messaging_webrtc_signaling_events_total",
    "WebRTC signaling routing outcomes by result/reason/event type",
    ["outcome", "reason", "event_type"],
)
WEBRTC_SIGNALING_LATENCY = Histogram(
    "messaging_webrtc_signaling_latency_seconds",
    "WebRTC signaling routing latency by result/reason/event type",
    ["outcome", "reason", "event_type"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
PROJECT_COUNT = Gauge(
    "project_count",
    "Estimated project count in this process",
)
TRACKED_FILE_COUNT = Gauge(
    "tracked_file_count",
    "Estimated tracked file count in this process",
)
RECONCILE_FAILURES = Counter(
    "reconcile_failures_total",
    "Tracked file reconciliation failures",
    ["provider", "reason"],
)
PROVIDER_LATENCY = Histogram(
    "provider_latency_seconds",
    "Provider operation latency in seconds",
    ["provider", "operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
PROVIDER_FAILURE_STREAK = Gauge(
    "provider_failure_streak",
    "Current consecutive provider failures",
    ["provider"],
)
PROVIDER_FAILURE_ALERTS = Counter(
    "provider_failure_alerts_total",
    "Provider repeated-failure alert triggers",
    ["provider"],
)
PAYMENT_INCIDENT_EVENTS = Counter(
    "payment_incident_events_total",
    "Payment incident lifecycle events by provider/type/status/outcome",
    ["provider", "incident_type", "event", "status", "outcome"],
)
PAYMENT_INCIDENT_RESPONSE_LATENCY = Histogram(
    "payment_incident_response_latency_seconds",
    "Latency from incident creation to dispute response submission",
    ["provider", "incident_type"],
    buckets=(60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800),
)
PAYMENT_INCIDENT_RESPONSE_SLA_BREACHES = Counter(
    "payment_incident_response_sla_breaches_total",
    "Dispute response submissions that breached response_due_at SLA",
    ["provider", "incident_type"],
)
PAYMENT_INCIDENT_RECOVERY_LATENCY = Histogram(
    "payment_incident_recovery_latency_seconds",
    "Latency from payment failure incident creation to retry_succeeded",
    ["provider"],
    buckets=(60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800),
)
PAYMENT_INCIDENT_RETRY_ATTEMPTS = Counter(
    "payment_incident_retry_attempts_total",
    "Payment incident retry attempts by provider/action/outcome/code",
    ["provider", "action", "outcome", "code"],
)
PAYMENT_INCIDENT_TICKET_LATENCY = Histogram(
    "payment_incident_ticket_latency_seconds",
    "Ticket lifecycle latency for payment incidents",
    ["provider", "metric"],
    buckets=(60, 300, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800),
)
PAYMENT_INCIDENT_WEBHOOK_OUTCOMES = Counter(
    "payment_incident_webhook_outcomes_total",
    "Payment incident webhook verification/processing outcomes",
    ["provider", "outcome", "reason"],
)
PAYMENT_INCIDENT_WEBHOOK_REPLAY_EVENTS = Counter(
    "payment_incident_webhook_replay_events_total",
    "Replay cache check/mark/reject events for payment incident webhooks",
    ["provider", "event"],
)
PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE_ENTRIES = Gauge(
    "payment_incident_webhook_replay_cache_entries",
    "Current in-process payment incident webhook replay cache entries",
)
GOOGLE_CALENDAR_SYNC_JOBS = Counter(
    "google_calendar_sync_jobs_total",
    "Google Calendar sync job outcomes by flow/state",
    ["flow", "state"],
)
GOOGLE_CALENDAR_SYNC_LATENCY = Histogram(
    "google_calendar_sync_latency_seconds",
    "Google Calendar sync latency by flow",
    ["flow"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)
GOOGLE_CALENDAR_SYNC_CONFLICTS = Counter(
    "google_calendar_sync_conflicts_total",
    "Google Calendar sync conflicts by reason",
    ["reason"],
)
GOOGLE_CALENDAR_TOKEN_REFRESH_FAILURES = Counter(
    "google_calendar_token_refresh_failures_total",
    "Google Calendar token refresh failures by reason",
    ["reason"],
)
GOOGLE_CALENDAR_OUTBOX_BACKLOG = Gauge(
    "google_calendar_outbox_backlog",
    "Google Calendar outbox backlog by status",
    ["status"],
)
GOOGLE_CALENDAR_API_RETRIES = Counter(
    "google_calendar_api_retries_total",
    "Google Calendar API retry attempts by reason and provider status code",
    ["reason", "provider_status_code"],
)
GOOGLE_CALENDAR_OAUTH_CALLBACK_REJECTIONS = Counter(
    "google_calendar_oauth_callback_rejections_total",
    "Google Calendar OAuth callback rejections by reason",
    ["reason"],
)
GOOGLE_CALENDAR_OAUTH_CALLBACK_OUTCOMES = Counter(
    "google_calendar_oauth_callback_outcomes_total",
    "Google Calendar OAuth callback outcomes by outcome/reason",
    ["outcome", "reason"],
)
CALENDAR_SYNC_RUNS = Counter(
    "calendar_sync_runs_total",
    "Calendar sync run outcomes by provider/mode/outcome",
    ["provider", "mode", "outcome"],
)
CALENDAR_SYNC_LATENCY = Histogram(
    "calendar_sync_latency_seconds",
    "Calendar sync operation latency in seconds",
    ["provider", "operation", "outcome"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)
CALENDAR_SYNC_CONFLICTS = Counter(
    "calendar_sync_conflicts_total",
    "Calendar sync conflicts by provider/reason/operation",
    ["provider", "reason", "operation"],
)
CALENDAR_SYNC_QUEUE_BACKLOG = Gauge(
    "calendar_sync_queue_backlog",
    "Calendar sync queue backlog depth",
    ["provider", "queue"],
)
CALENDAR_SYNC_AUTH_FAILURES = Counter(
    "calendar_sync_auth_failures_total",
    "Calendar integration authentication failures",
    ["provider"],
)
BROADCAST_PROVISION_LATENCY = Histogram(
    "broadcast_provision_latency_seconds",
    "Broadcast provisioning latency in seconds",
    ["provider", "result"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)
BROADCAST_SESSION_ACTIONS = Counter(
    "broadcast_session_actions_total",
    "Broadcast start/stop outcomes by provider/action/result",
    ["provider", "action", "result"],
)
BROADCAST_INPUT_LOSS_EVENTS = Counter(
    "broadcast_input_loss_total",
    "Broadcast input loss detections by provider/reason",
    ["provider", "reason"],
)
BROADCAST_OUTPUT_ERRORS = Counter(
    "broadcast_output_errors_total",
    "Broadcast output error detections by provider/reason",
    ["provider", "reason"],
)
BROADCAST_DRIFT_INCIDENTS = Counter(
    "broadcast_drift_incidents_total",
    "Broadcast drift and stale incidents by provider/type",
    ["provider", "incident_type"],
)

ENTITLEMENT_CHECKS = Counter(
    "entitlement_checks_total",
    "Entitlement check outcomes by product family",
    ["product_family", "outcome", "reason"],
)
BROWSER_SSH_CONNECT_THROTTLED = Counter(
    "browser_ssh_connect_throttled_total",
    "Browser SSH connect attempts throttled by per-user rate limit",
    ["reason"],
)
BROWSER_SSH_CONNECT_DENIED = Counter(
    "browser_ssh_connect_denied_total",
    "Browser SSH connect attempts denied by policy/auth/quota",
    ["reason"],
)
BROWSER_SSH_ACTIVE_SESSIONS = Gauge(
    "browser_ssh_active_sessions",
    "Active Browser SSH sessions by user in this process",
    ["user_sub"],
)
BROWSER_SSH_SESSION_LIFECYCLE = Counter(
    "browser_ssh_session_lifecycle_total",
    "Browser SSH session lifecycle events",
    ["event", "outcome"],
)
BROWSER_SSH_SESSION_DURATION = Histogram(
    "browser_ssh_session_duration_seconds",
    "Browser SSH connected session duration",
    ["outcome"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 900, 1800, 3600),
)

ENTITLEMENT_CHECK_LATENCY = Histogram(
    "entitlement_check_latency_seconds",
    "Entitlement check latency by product family",
    ["product_family"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
)
PLAYBACK_ENTITLEMENT_EVENTS = Counter(
    "playback_entitlement_events_total",
    "Playback entitlement operation outcomes",
    ["operation", "outcome", "reason"],
)
PLAYBACK_ENTITLEMENT_LATENCY = Histogram(
    "playback_entitlement_latency_seconds",
    "Playback entitlement operation latency",
    ["operation"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
)


VNC_SESSION_EVENTS = Counter(
    "vnc_session_events_total",
    "VNC session lifecycle events by action/outcome/target/error code",
    ["action", "outcome", "target_id", "error_code"],
)
VNC_SESSION_DURATION = Histogram(
    "vnc_session_duration_seconds",
    "VNC session duration in seconds by target/outcome",
    ["target_id", "outcome"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200),
)
VNC_BRIDGE_FAILURES = Counter(
    "vnc_bridge_failures_total",
    "VNC bridge failures by target and error code",
    ["target_id", "error_code"],
)

_START_TIME = time.monotonic()
_ACTIVE_SESSIONS_BY_USER: dict[str, int] = {}
_ACTIVE_SESSIONS_COUNT = 0
_PROJECT_COUNT_ESTIMATE = 0
_TRACKED_FILE_COUNT_ESTIMATE = 0


def _route_path(request: Request) -> str:
    route = request.scope.get("route")
    if route and getattr(route, "path", None):
        return route.path
    return request.url.path


def _get_content_length(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def record_auth_event(alert_type: str) -> None:
    if alert_type == "login_success":
        LOGIN_SUCCESSES.inc()
    elif alert_type == "login_failure":
        LOGIN_FAILURES.inc()
    elif alert_type == "mfa_success":
        MFA_SUCCESSES.inc()
    elif alert_type == "mfa_failure":
        MFA_FAILURES.inc()


def record_session_created(user_sub: str, is_new_user: bool) -> None:
    global _ACTIVE_SESSIONS_COUNT
    _ACTIVE_SESSIONS_COUNT += 1
    ACTIVE_SESSIONS.set(_ACTIVE_SESSIONS_COUNT)
    if is_new_user:
        NEW_USERS.inc()
    current = _ACTIVE_SESSIONS_BY_USER.get(user_sub, 0) + 1
    _ACTIVE_SESSIONS_BY_USER[user_sub] = current
    ACTIVE_USERS.set(len(_ACTIVE_SESSIONS_BY_USER))


def record_session_revoked(user_sub: str) -> None:
    global _ACTIVE_SESSIONS_COUNT
    if _ACTIVE_SESSIONS_COUNT > 0:
        _ACTIVE_SESSIONS_COUNT -= 1
    ACTIVE_SESSIONS.set(_ACTIVE_SESSIONS_COUNT)
    current = _ACTIVE_SESSIONS_BY_USER.get(user_sub, 0) - 1
    if current <= 0:
        _ACTIVE_SESSIONS_BY_USER.pop(user_sub, None)
    else:
        _ACTIVE_SESSIONS_BY_USER[user_sub] = current
    ACTIVE_USERS.set(len(_ACTIVE_SESSIONS_BY_USER))


async def metrics_middleware(request: Request, call_next: Callable[[Request], Response]) -> Response:
    path = _route_path(request)
    method = request.method
    request_size = _get_content_length(request.headers.get("content-length"))
    start = time.perf_counter()
    IN_PROGRESS.labels(method=method, path=path).inc()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        IN_PROGRESS.labels(method=method, path=path).dec()
        elapsed = time.perf_counter() - start
        REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)
        REQUEST_COUNT.labels(method=method, path=path, status=str(status_code)).inc()
        if request_size is not None:
            REQUEST_SIZE.labels(method=method, path=path).observe(request_size)
        response_size = _get_content_length(response.headers.get("content-length") if "response" in locals() else None)
        if response_size is not None:
            RESPONSE_SIZE.labels(method=method, path=path, status=str(status_code)).observe(response_size)
        if status_code >= 500:
            REQUEST_ERRORS.labels(method=method, path=path, status=str(status_code)).inc()



def record_usage_metering_event(event_type: str, source: str, outcome: str, *, period_id: Optional[str] = None) -> None:
    USAGE_METERING_EVENTS.labels(event_type=event_type, source=source, outcome=outcome).inc()
    if period_id:
        USAGE_METERING_EVENTS_BY_PERIOD.labels(
            event_type=event_type,
            source=source,
            outcome=outcome,
            period_id=period_id,
        ).inc()


def record_usage_metering_bytes(event_type: str, source: str, nbytes: int, *, period_id: Optional[str] = None) -> None:
    if nbytes == 0:
        return
    value = float(abs(int(nbytes)))
    USAGE_METERING_BYTES.labels(event_type=event_type, source=source).inc(value)
    if period_id:
        USAGE_METERING_BYTES_BY_PERIOD.labels(event_type=event_type, source=source, period_id=period_id).inc(value)


def record_usage_surface_units(source_family: str, dimension: str, count: int, *, period_id: Optional[str] = None) -> None:
    if count <= 0 or not period_id:
        return
    USAGE_SURFACE_UNITS.labels(source_family=source_family, dimension=dimension, period_id=period_id).inc(float(count))


def record_usage_surface_transfer_bytes(source_family: str, direction: str, nbytes: int, *, period_id: Optional[str] = None) -> None:
    if nbytes <= 0 or not period_id:
        return
    USAGE_SURFACE_TRANSFER_BYTES.labels(source_family=source_family, direction=direction, period_id=period_id).inc(float(nbytes))


def record_usage_metering_pipeline_error(stage: str) -> None:
    USAGE_METERING_PIPELINE_ERRORS.labels(stage=stage).inc()


def record_usage_metering_pipeline_latency(stage: str, elapsed_seconds: float) -> None:
    USAGE_METERING_PIPELINE_LATENCY.labels(stage=stage).observe(max(0.0, float(elapsed_seconds)))


def record_api_usage_ingest_event(outcome: str) -> None:
    API_USAGE_INGEST_EVENTS.labels(outcome=(outcome or "unknown").lower()).inc()


def record_api_usage_ingest_lag(elapsed_seconds: float) -> None:
    API_USAGE_INGEST_LAG.observe(max(0.0, float(elapsed_seconds)))


def record_api_usage_limit_deny(scope: str, limit_type: str) -> None:
    API_USAGE_LIMIT_DENY.labels(
        scope=(scope or "unknown").lower(),
        limit_type=(limit_type or "unknown").lower(),
    ).inc()


def record_api_usage_snapshot_finalize(outcome: str) -> None:
    API_USAGE_SNAPSHOT_FINALIZE.labels(outcome=(outcome or "unknown").lower()).inc()


def record_api_usage_reconciliation_drift(*, area: str, rows: int) -> None:
    API_USAGE_RECONCILIATION_DRIFT.labels(area=(area or "unknown").lower()).set(float(max(0, int(rows))))


def record_api_key_policy_decision(*, mode: str, product: str, outcome: str, reason: str) -> None:
    API_KEY_POLICY_DECISIONS.labels(
        mode=(mode or "unknown").lower(),
        product=(product or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_api_key_registry_drift(*, stale_route_count: int, unregistered_live_route_count: int = 0) -> None:
    API_KEY_REGISTRY_DRIFT.set(float(max(0, int(stale_route_count))))
    API_KEY_REGISTRY_UNREGISTERED_LIVE.set(float(max(0, int(unregistered_live_route_count))))


def record_helpdesk_alert_sent(outcome: str) -> None:
    HELPDESK_ALERTS_SENT.labels(outcome=(outcome or "unknown").lower()).inc()


def record_helpdesk_claim(outcome: str) -> None:
    HELPDESK_CLAIMS_TOTAL.labels(outcome=(outcome or "unknown").lower()).inc()




def record_helpdesk_claim_success() -> None:
    HELPDESK_CLAIM_SUCCESS_TOTAL.inc()


def record_helpdesk_claim_conflict() -> None:
    HELPDESK_CLAIM_CONFLICT_TOTAL.inc()


def record_helpdesk_failover(reason: str) -> None:
    HELPDESK_FAILOVER_TOTAL.labels(reason=(reason or "unknown").lower()).inc()


def record_helpdesk_no_agents_notice(outcome: str) -> None:
    HELPDESK_NO_AGENTS_NOTICE_TOTAL.labels(outcome=(outcome or "unknown").lower()).inc()


def record_helpdesk_time_to_first_claim_ms(elapsed_ms: float) -> None:
    HELPDESK_TIME_TO_FIRST_CLAIM_MS.observe(max(0.0, float(elapsed_ms)))


def record_profile_lookup(*, audience: str, result: str, suppression_reason: str, elapsed_seconds: float) -> None:
    normalized_audience = (audience or "unknown").lower()
    normalized_result = (result or "unknown").lower()
    normalized_reason = (suppression_reason or "none").lower()
    PROFILE_LOOKUP_EVENTS.labels(
        audience=normalized_audience,
        result=normalized_result,
        suppression_reason=normalized_reason,
    ).inc()
    PROFILE_LOOKUP_LATENCY.labels(
        audience=normalized_audience,
        result=normalized_result,
    ).observe(max(0.0, float(elapsed_seconds)))


def record_profile_lookup_identifier_resolution(*, source: str, outcome: str) -> None:
    normalized_source = (source or "unknown").lower()
    normalized_outcome = (outcome or "unknown").lower()
    PROFILE_LOOKUP_IDENTIFIER_RESOLUTION.labels(
        source=normalized_source,
        outcome=normalized_outcome,
    ).inc()


def record_entitlement_check(*, product_family: str, outcome: str, reason: str = "") -> None:
    ENTITLEMENT_CHECKS.labels(
        product_family=(product_family or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_entitlement_check_latency(*, product_family: str, elapsed_seconds: float) -> None:
    ENTITLEMENT_CHECK_LATENCY.labels(
        product_family=(product_family or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_playback_entitlement_event(*, operation: str, outcome: str, reason: str = "") -> None:
    PLAYBACK_ENTITLEMENT_EVENTS.labels(
        operation=(operation or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_playback_entitlement_latency(*, operation: str, elapsed_seconds: float) -> None:
    PLAYBACK_ENTITLEMENT_LATENCY.labels(
        operation=(operation or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_browser_ssh_connect_throttled(*, reason: str) -> None:
    BROWSER_SSH_CONNECT_THROTTLED.labels(reason=(reason or "unknown").lower()).inc()


def record_browser_ssh_connect_denied(*, reason: str) -> None:
    BROWSER_SSH_CONNECT_DENIED.labels(reason=(reason or "unknown").lower()).inc()


def set_browser_ssh_active_sessions(*, user_sub: str, count: int) -> None:
    BROWSER_SSH_ACTIVE_SESSIONS.labels(user_sub=(user_sub or "unknown")).set(max(0, int(count)))


def record_browser_ssh_session_lifecycle(*, event: str, outcome: str) -> None:
    BROWSER_SSH_SESSION_LIFECYCLE.labels(
        event=(event or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_browser_ssh_session_duration(*, outcome: str, elapsed_seconds: float) -> None:
    BROWSER_SSH_SESSION_DURATION.labels(
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_admin_scope_denied(*, route: str, required_scope: str, admin_profile_type: str) -> None:
    ADMIN_SCOPE_DENIED.labels(
        route=route or "unknown",
        required_scope=required_scope or "unknown",
        admin_profile_type=admin_profile_type or "unknown",
    ).inc()


def _normalize_once_media_kind(media_kind: str) -> str:
    kind = (media_kind or "unknown").strip().lower()
    return kind if kind in {"image", "video", "audio"} else "unknown"


def _normalize_once_media_policy(consumption_policy: str) -> str:
    policy = (consumption_policy or "unknown").strip().lower()
    return policy if policy in {"view_once", "listen_once"} else "unknown"


def _normalize_once_media_outcome(outcome: str) -> str:
    value = (outcome or "error").strip().lower()
    return value if value in {"success", "error"} else "error"


def _normalize_cohort(cohort: str) -> str:
    value = (cohort or "default").strip().lower()
    if not value:
        return "default"
    return value[:32]


def _normalize_reason(reason: str) -> str:
    value = (reason or "none").strip().lower()
    if not value:
        return "none"
    return value[:48]


def _normalize_client_dim(value: str, *, fallback: str = "unknown", max_len: int = 32) -> str:
    val = (value or fallback).strip().lower()
    if not val:
        return fallback
    return val[:max_len]


def record_once_media_send(*, media_kind: str, consumption_policy: str, cohort: str = "default") -> None:
    ONCE_MEDIA_SEND_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        consumption_policy=_normalize_once_media_policy(consumption_policy),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_grant(*, media_kind: str, outcome: str, reason: str = "none", cohort: str = "default") -> None:
    ONCE_MEDIA_GRANT_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        reason=_normalize_reason(reason),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_grant_latency(*, media_kind: str, outcome: str, elapsed_seconds: float, cohort: str = "default") -> None:
    ONCE_MEDIA_GRANT_LATENCY.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        cohort=_normalize_cohort(cohort),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_once_media_consume(*, media_kind: str, outcome: str, reason: str = "none", cohort: str = "default") -> None:
    ONCE_MEDIA_CONSUME_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        outcome=_normalize_once_media_outcome(outcome),
        reason=_normalize_reason(reason),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_once_media_conflict(*, media_kind: str, cohort: str = "default") -> None:
    ONCE_MEDIA_CONFLICT_EVENTS.labels(
        media_kind=_normalize_once_media_kind(media_kind),
        cohort=_normalize_cohort(cohort),
    ).inc()


def record_turn_credential_issue(*, outcome: str, reason: str = "none") -> None:
    TURN_CREDENTIAL_ISSUE_EVENTS.labels(
        outcome=(outcome or "error").strip().lower(),
        reason=_normalize_reason(reason),
    ).inc()


def record_turn_credential_issue_latency(*, outcome: str, reason: str = "none", elapsed_seconds: float) -> None:
    TURN_CREDENTIAL_ISSUE_LATENCY.labels(
        outcome=(outcome or "error").strip().lower(),
        reason=_normalize_reason(reason),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_webrtc_call_setup(
    *,
    outcome: str,
    reason: str = "none",
    platform: str = "unknown",
    browser: str = "unknown",
    latency_seconds: Optional[float] = None,
) -> None:
    normalized_outcome = _normalize_client_dim(outcome, fallback="unknown", max_len=16)
    normalized_platform = _normalize_client_dim(platform)
    normalized_browser = _normalize_client_dim(browser)
    WEBRTC_CALL_SETUP_EVENTS.labels(
        outcome=normalized_outcome,
        reason=_normalize_reason(reason),
        platform=normalized_platform,
        browser=normalized_browser,
    ).inc()
    if latency_seconds is not None:
        WEBRTC_CALL_SETUP_LATENCY.labels(
            outcome=normalized_outcome,
            platform=normalized_platform,
            browser=normalized_browser,
        ).observe(max(0.0, float(latency_seconds)))


def record_webrtc_call_failure(
    *,
    reason: str,
    stage: str,
    platform: str = "unknown",
    browser: str = "unknown",
) -> None:
    WEBRTC_CALL_FAILURE_EVENTS.labels(
        reason=_normalize_reason(reason),
        stage=_normalize_client_dim(stage, fallback="unknown", max_len=24),
        platform=_normalize_client_dim(platform),
        browser=_normalize_client_dim(browser),
    ).inc()


def record_webrtc_call_connected(*, network_path: str = "unknown") -> None:
    WEBRTC_CALL_NETWORK_PATH_EVENTS.labels(
        network_path=_normalize_client_dim(network_path, fallback="unknown", max_len=12),
    ).inc()


def record_webrtc_call_duration(*, duration_seconds: float, end_reason: str = "ended", network_path: str = "unknown") -> None:
    WEBRTC_CALL_DURATION.labels(
        end_reason=_normalize_reason(end_reason),
        network_path=_normalize_client_dim(network_path, fallback="unknown", max_len=12),
    ).observe(max(0.0, float(duration_seconds)))


def record_webrtc_signaling_event(*, outcome: str, reason: str = "none", event_type: str = "unknown") -> None:
    WEBRTC_SIGNALING_EVENTS.labels(
        outcome=_normalize_client_dim(outcome, fallback="unknown", max_len=16),
        reason=_normalize_reason(reason),
        event_type=_normalize_client_dim(event_type, fallback="unknown", max_len=32),
    ).inc()


def record_webrtc_signaling_latency(*, outcome: str, reason: str = "none", event_type: str = "unknown", elapsed_seconds: float) -> None:
    WEBRTC_SIGNALING_LATENCY.labels(
        outcome=_normalize_client_dim(outcome, fallback="unknown", max_len=16),
        reason=_normalize_reason(reason),
        event_type=_normalize_client_dim(event_type, fallback="unknown", max_len=32),
    ).observe(max(0.0, float(elapsed_seconds)))


def set_app_info(name: str, version: str) -> None:
    APP_INFO.info({"name": name, "version": version})



def record_filemgr_operation_latency(operation: str, elapsed_seconds: float) -> None:
    FILEMGR_OPERATION_LATENCY.labels(operation=operation).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_mount_secret_access(*, action: str, outcome: str) -> None:
    FILEMGR_MOUNT_SECRET_ACCESS.labels(action=(action or "unknown").lower(), outcome=(outcome or "unknown").lower()).inc()


def record_filemgr_provider_operation(
    *,
    operation: str,
    provider: str,
    mounted: bool,
    elapsed_seconds: float,
    outcome: str,
    mount_id: str | None = None,
    error_class: str = "none",
) -> None:
    op = (operation or "unknown").lower()
    prov = (provider or "unknown").lower()
    out = (outcome or "unknown").lower()
    m = "true" if mounted else "false"
    mid = (mount_id or "none").lower()
    err = (error_class or "none").lower()
    FILEMGR_PROVIDER_OPERATION_TOTAL.labels(operation=op, provider=prov, mount_id=mid, mounted=m, outcome=out, error_class=err).inc()
    FILEMGR_PROVIDER_OPERATION_LATENCY.labels(operation=op, provider=prov, mount_id=mid, mounted=m, error_class=err).observe(max(0.0, float(elapsed_seconds)))
    if out != "success" and err != "none":
        FILEMGR_PROVIDER_ERRORS_TOTAL.labels(
            operation=op,
            provider=prov,
            mount_id=mid,
            error_class=err,
        ).inc()


def record_filemgr_provider_auth_failure(*, provider: str, mount_id: str | None = None, reason: str = "auth_failed") -> None:
    FILEMGR_PROVIDER_AUTH_FAILURES.labels(
        provider=(provider or "unknown").lower(),
        mount_id=(mount_id or "none").lower(),
        reason=(reason or "auth_failed").lower(),
    ).inc()


def record_filemgr_mount_rollout_decision(
    *,
    provider: str = "icloud",
    environment: str = "unknown",
    mode: str = "unknown",
    cohort: str = "unknown",
    reason: str = "unknown",
) -> None:
    FILEMGR_MOUNT_ROLLOUT_DECISIONS.labels(
        provider=(provider or "unknown").lower(),
        environment=(environment or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        cohort=(cohort or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_filemgr_mount_reconcile_batch(
    *,
    dry_run: bool,
    elapsed_seconds: float,
    outcome: str,
) -> None:
    out = (outcome or "unknown").lower()
    run = "true" if dry_run else "false"
    FILEMGR_MOUNT_RECONCILE_RUNS.labels(outcome=out, dry_run=run).inc()
    FILEMGR_MOUNT_RECONCILE_DURATION.labels(outcome=out, dry_run=run).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_mount_reconcile_drift(
    *,
    dry_run: bool,
    missing_local: int = 0,
    stale_local: int = 0,
    mismatched: int = 0,
) -> None:
    run = "true" if dry_run else "false"
    if missing_local > 0:
        FILEMGR_MOUNT_RECONCILE_DRIFT_ITEMS.labels(kind="missing_local", dry_run=run).inc(float(missing_local))
    if stale_local > 0:
        FILEMGR_MOUNT_RECONCILE_DRIFT_ITEMS.labels(kind="stale_local", dry_run=run).inc(float(stale_local))
    if mismatched > 0:
        FILEMGR_MOUNT_RECONCILE_DRIFT_ITEMS.labels(kind="mismatched", dry_run=run).inc(float(mismatched))


def record_filemgr_icloud_read_cache(*, result: str, reason: str = "none") -> None:
    FILEMGR_ICLOUD_READ_CACHE.labels(result=(result or "unknown").lower(), reason=(reason or "none").lower()).inc()


def record_filemgr_bytes(direction: str, operation: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_BYTES.labels(direction=direction, operation=operation).inc(float(nbytes))




def record_filemgr_mount_operation_latency(*, provider: str, mode: str, operation: str, mount_id_hash: str, elapsed_seconds: float) -> None:
    FILEMGR_MOUNT_OPERATION_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        operation=(operation or "unknown").lower(),
        mount_id_hash=mount_id_hash or "unknown",
    ).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_mount_bytes(*, provider: str, mode: str, operation: str, direction: str, mount_id_hash: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_MOUNT_BYTES.labels(
        provider=(provider or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        operation=(operation or "unknown").lower(),
        direction=(direction or "unknown").lower(),
        mount_id_hash=mount_id_hash or "unknown",
    ).inc(float(nbytes))


def record_filemgr_mount_error(*, provider: str, mode: str, operation: str, aws_error_code: str, mount_id_hash: str) -> None:
    FILEMGR_MOUNT_ERRORS.labels(
        provider=(provider or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        operation=(operation or "unknown").lower(),
        aws_error_code=(aws_error_code or "unknown"),
        mount_id_hash=mount_id_hash or "unknown",
    ).inc()

def record_filemgr_search_path(operation: str, path: str) -> None:
    FILEMGR_SEARCH_PATH.labels(operation=operation, path=path).inc()


def record_filemgr_purge_run(
    scope: str,
    mode: str,
    *,
    purged: int,
    skipped: int,
    errors: int,
    elapsed_seconds: float,
) -> None:
    FILEMGR_PURGE_DURATION.labels(scope=scope, mode=mode).observe(max(0.0, float(elapsed_seconds)))
    if purged:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="purged").inc(float(purged))
    if skipped:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="skipped").inc(float(skipped))
    if errors:
        FILEMGR_PURGE_THROUGHPUT.labels(scope=scope, mode=mode, outcome="error").inc(float(errors))


def record_filemgr_encryption_event(event: str, *, encrypted: bool, reason: str = "") -> None:
    FILEMGR_ENCRYPTION_EVENTS.labels(
        event=event,
        encrypted="true" if encrypted else "false",
        reason=reason or "none",
    ).inc()


def record_filemgr_shared_download(*, encrypted: bool, outcome: str = "attempt") -> None:
    FILEMGR_SHARED_ENCRYPTED_DOWNLOADS.labels(
        encrypted="true" if encrypted else "false",
        outcome=outcome or "attempt",
    ).inc()


def record_filemgr_preview_attempt(*, kind: str, outcome: str, reason: str = "none") -> None:
    FILEMGR_PREVIEW_ATTEMPTS.labels(
        kind=(kind or "none").lower(),
        outcome=(outcome or "error").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_filemgr_preview_latency(*, kind: str, elapsed_seconds: float) -> None:
    FILEMGR_PREVIEW_LATENCY.labels(kind=(kind or "none").lower()).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_preview_bytes(*, kind: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_PREVIEW_BYTES.labels(kind=(kind or "none").lower()).inc(float(nbytes))


def record_filemgr_preview_fallback(*, kind: str, reason: str) -> None:
    FILEMGR_PREVIEW_FALLBACK.labels(
        kind=(kind or "none").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()



def record_filemgr_preview_job(*, media_type: str, artifact: str, outcome: str, reason: str = "none") -> None:
    FILEMGR_PREVIEW_JOBS.labels(
        media_type=(media_type or "unknown").lower(),
        artifact=(artifact or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_filemgr_preview_job_duration(*, artifact: str, elapsed_seconds: float) -> None:
    FILEMGR_PREVIEW_JOB_DURATION.labels(artifact=(artifact or "unknown").lower()).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_preview_artifact_bytes(*, artifact: str, nbytes: int) -> None:
    if nbytes <= 0:
        return
    FILEMGR_PREVIEW_ARTIFACT_BYTES.labels(artifact=(artifact or "unknown").lower()).inc(float(nbytes))


def record_filemgr_preview_hover_play_start() -> None:
    FILEMGR_PREVIEW_HOVER_PLAY_STARTS.inc()


def record_filemgr_preview_hover_play_failure(*, reason: str) -> None:
    FILEMGR_PREVIEW_HOVER_PLAY_FAILURES.labels(reason=(reason or "unknown").lower()).inc()


def record_filemgr_preview_queue_depth_delta(delta: int) -> None:
    if delta == 0:
        return
    FILEMGR_PREVIEW_QUEUE_DEPTH.inc(float(delta))


def record_signature_packet_render_job(*, outcome: str, reason: str = "none") -> None:
    SIGNATURE_PACKET_RENDER_JOBS.labels(
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_signature_packet_render_latency(*, outcome: str, elapsed_seconds: float) -> None:
    SIGNATURE_PACKET_RENDER_LATENCY.labels(outcome=(outcome or "unknown").lower()).observe(max(0.0, float(elapsed_seconds)))


def record_signature_packet_event(*, event_type: str) -> None:
    SIGNATURE_PACKET_EVENTS.labels(event_type=(event_type or "unknown").lower()).inc()


def record_signature_packet_reminder_email(*, outcome: str, reason: str = "none") -> None:
    SIGNATURE_PACKET_REMINDER_EMAILS.labels(
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()



def record_messaging_gallery_request(*, gallery_type: str, outcome: str) -> None:
    MESSAGING_GALLERY_REQUESTS.labels(
        type=(gallery_type or "unknown").lower(),
        outcome=(outcome or "error").lower(),
    ).inc()


def record_messaging_gallery_latency(*, gallery_type: str, elapsed_seconds: float) -> None:
    MESSAGING_GALLERY_LATENCY.labels(type=(gallery_type or "unknown").lower()).observe(
        max(0.0, float(elapsed_seconds))
    )


def record_messaging_gallery_cursor_page_depth(*, gallery_type: str, depth: int) -> None:
    MESSAGING_GALLERY_CURSOR_PAGE_DEPTH.labels(type=(gallery_type or "unknown").lower()).observe(
        max(0.0, float(depth))
    )


def record_newsfeed_feed_request(*, mode: str, outcome: str) -> None:
    normalized_mode = (mode or "unknown").lower()
    normalized_outcome = (outcome or "unknown").lower()
    NEWSFEED_FEED_REQUESTS.labels(mode=normalized_mode, outcome=normalized_outcome).inc()


def record_newsfeed_feed_latency(*, mode: str, outcome: str, elapsed_seconds: float) -> None:
    NEWSFEED_FEED_LATENCY.labels(
        mode=(mode or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_newsfeed_feed_filter_usage(*, mode: str, filter_name: str) -> None:
    NEWSFEED_FEED_FILTER_USAGE.labels(
        mode=(mode or "unknown").lower(),
        filter_name=(filter_name or "unknown").lower(),
    ).inc()


def record_newsfeed_feed_page_depth(*, mode: str, depth: int) -> None:
    NEWSFEED_FEED_PAGE_DEPTH.labels(mode=(mode or "unknown").lower()).observe(max(0.0, float(depth)))


def record_newsfeed_feed_error(*, mode: str, error_type: str) -> None:
    NEWSFEED_FEED_ERRORS.labels(
        mode=(mode or "unknown").lower(),
        error_type=(error_type or "unknown").lower(),
    ).inc()


def record_newsfeed_feed_budget_hit(*, mode: str, reason: str) -> None:
    NEWSFEED_FEED_BUDGET_HITS.labels(
        mode=(mode or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_cursor_decode_result(*, format_name: str, outcome: str, key_source: str = "none") -> None:
    CURSOR_DECODE_RESULTS.labels(
        format=(format_name or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        key_source=(key_source or "none").lower(),
    ).inc()


def record_messaging_message_control_action(*, action: str, result: str) -> None:
    MESSAGING_MESSAGE_CONTROL_ACTIONS.labels(
        action=(action or "unknown").lower(),
        result=(result or "unknown").lower(),
    ).inc()


def record_messaging_report_validation_error(*, reason: str) -> None:
    MESSAGING_REPORT_VALIDATION_ERRORS.labels(reason=(reason or "unknown").lower()).inc()


def record_messaging_archive_write(*, result: str, event_type: str, elapsed_seconds: float) -> None:
    MESSAGING_ARCHIVE_WRITE_EVENTS.labels(
        result=(result or "unknown").lower(),
        event_type=(event_type or "unknown").lower(),
    ).inc()
    MESSAGING_ARCHIVE_WRITE_LATENCY.labels(
        result=(result or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_messaging_archive_integrity_error(*, reason: str) -> None:
    MESSAGING_ARCHIVE_INTEGRITY_ERRORS.labels(reason=(reason or "unknown").lower()).inc()


def record_messaging_archive_export_outcome(*, outcome: str) -> None:
    MESSAGING_ARCHIVE_EXPORT_OUTCOMES.labels(outcome=(outcome or "unknown").lower()).inc()


def record_messaging_thread_promotion_event(*, stage: str, outcome: str) -> None:
    MESSAGING_THREAD_PROMOTION_EVENTS.labels(
        stage=(stage or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def _metrics_env_label(environment: str | None) -> str:
    env = (environment or _APP_ENV or "unknown").strip().lower()
    return env or "unknown"


def _metrics_client_version_label(client_version: str | None) -> str:
    raw = (client_version or "unknown").strip().lower()
    if not raw:
        return "unknown"
    # Keep cardinality under control while still retaining version usefulness.
    return raw[:48]


def record_messaging_lottery_send(*, outcome: str, client_version: str | None = None, environment: str | None = None) -> None:
    MESSAGING_LOTTERY_SENDS.labels(
        environment=_metrics_env_label(environment),
        client_version=_metrics_client_version_label(client_version),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_mass_message_campaign_event(*, event: str, mode: str, outcome: str) -> None:
    MASS_MESSAGE_CAMPAIGN_EVENTS.labels(
        event=(event or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_messaging_lottery_unlock_attempt(*, client_version: str | None = None, environment: str | None = None) -> None:
    MESSAGING_LOTTERY_UNLOCK_ATTEMPTS.labels(
        environment=_metrics_env_label(environment),
        client_version=_metrics_client_version_label(client_version),
    ).inc()


def record_messaging_lottery_unlock_result(*, outcome: str, client_version: str | None = None, environment: str | None = None) -> None:
    MESSAGING_LOTTERY_UNLOCK_RESULTS.labels(
        environment=_metrics_env_label(environment),
        client_version=_metrics_client_version_label(client_version),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_messaging_thread_promotion_retry(*, reason: str) -> None:
    MESSAGING_THREAD_PROMOTION_RETRIES.labels(reason=(reason or "unknown").lower()).inc()


def record_messaging_thread_query_latency(*, endpoint: str, outcome: str, elapsed_seconds: float) -> None:
    MESSAGING_THREAD_QUERY_LATENCY.labels(
        endpoint=(endpoint or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_messaging_lottery_unlock_latency(
    *,
    outcome: str,
    elapsed_seconds: float,
    client_version: str | None = None,
    environment: str | None = None,
) -> None:
    MESSAGING_LOTTERY_UNLOCK_LATENCY.labels(
        environment=_metrics_env_label(environment),
        client_version=_metrics_client_version_label(client_version),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_mass_message_destination_outcome(*, mode: str, outcome: str, error_code: str = "none") -> None:
    MASS_MESSAGE_DESTINATION_OUTCOMES.labels(
        mode=(mode or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        error_code=(error_code or "none").lower(),
    ).inc()


def record_mass_message_destination_retry(*, mode: str, error_code: str) -> None:
    MASS_MESSAGE_DESTINATION_RETRIES.labels(
        mode=(mode or "unknown").lower(),
        error_code=(error_code or "unknown").lower(),
    ).inc()


def record_mass_message_worker_latency(*, mode: str, outcome: str, elapsed_seconds: float) -> None:
    MASS_MESSAGE_WORKER_LATENCY.labels(
        mode=(mode or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_messaging_lottery_reveal_latency(
    *,
    outcome: str,
    elapsed_seconds: float,
    client_version: str | None = None,
    environment: str | None = None,
) -> None:
    MESSAGING_LOTTERY_REVEAL_LATENCY.labels(
        environment=_metrics_env_label(environment),
        client_version=_metrics_client_version_label(client_version),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_messaging_thread_invalid_cursor(*, endpoint: str, reason_category: str) -> None:
    MESSAGING_THREAD_INVALID_CURSORS.labels(
        endpoint=(endpoint or "unknown").lower(),
        reason_category=(reason_category or "other").lower(),
    ).inc()


def record_messaging_thread_reconciliation_anomaly(*, reason: str) -> None:
    MESSAGING_THREAD_RECONCILIATION_ANOMALIES.labels(reason=(reason or "unknown").lower()).inc()


def record_messaging_draft_operation(*, operation: str, source: str, result: str) -> None:
    MESSAGING_DRAFT_OPERATIONS.labels(
        operation=(operation or "unknown").lower(),
        source=(source or "unknown").lower(),
        result=(result or "unknown").lower(),
    ).inc()


def record_messaging_draft_latency(*, operation: str, source: str, elapsed_seconds: float) -> None:
    MESSAGING_DRAFT_LATENCY.labels(
        operation=(operation or "unknown").lower(),
        source=(source or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_messaging_draft_fallback(*, reason: str) -> None:
    MESSAGING_DRAFT_FALLBACKS.labels(reason=(reason or "unknown").lower()).inc()


def record_mass_message_limit_event(*, scope: str, limit_name: str, outcome: str) -> None:
    MASS_MESSAGE_LIMIT_EVENTS.labels(
        scope=(scope or "unknown").lower(),
        limit_name=(limit_name or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_newsfeed_schedule_operation(*, operation: str, outcome: str) -> None:
    NEWSFEED_SCHEDULE_OPERATIONS.labels(
        operation=(operation or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_newsfeed_schedule_publish_lag(*, elapsed_seconds: float) -> None:
    NEWSFEED_SCHEDULE_PUBLISH_LAG.observe(max(0.0, float(elapsed_seconds)))


def set_newsfeed_schedule_backlog(*, due_count: int) -> None:
    NEWSFEED_SCHEDULE_BACKLOG.set(max(0, int(due_count)))


def set_newsfeed_schedule_oldest_due_age(*, elapsed_seconds: float) -> None:
    NEWSFEED_SCHEDULE_OLDEST_DUE_AGE.set(max(0.0, float(elapsed_seconds)))


def record_newsfeed_schedule_alert(*, alert_type: str) -> None:
    NEWSFEED_SCHEDULE_ALERTS.labels(alert_type=(alert_type or "unknown").lower()).inc()


def record_newsfeed_schedule_run(*, outcome: str) -> None:
    NEWSFEED_SCHEDULE_RUNS.labels(outcome=(outcome or "unknown").lower()).inc()


def record_newsfeed_schedule_run_duration(*, elapsed_seconds: float) -> None:
    NEWSFEED_SCHEDULE_RUN_DURATION.observe(max(0.0, float(elapsed_seconds)))


def set_newsfeed_schedule_last_run(*, unix_seconds: float) -> None:
    NEWSFEED_SCHEDULE_LAST_RUN_UNIX.set(max(0.0, float(unix_seconds)))
def record_project_count_delta(delta: int) -> None:
    global _PROJECT_COUNT_ESTIMATE
    _PROJECT_COUNT_ESTIMATE = max(0, _PROJECT_COUNT_ESTIMATE + int(delta))
    PROJECT_COUNT.set(float(_PROJECT_COUNT_ESTIMATE))


def record_tracked_file_count_delta(delta: int) -> None:
    global _TRACKED_FILE_COUNT_ESTIMATE
    _TRACKED_FILE_COUNT_ESTIMATE = max(0, _TRACKED_FILE_COUNT_ESTIMATE + int(delta))
    TRACKED_FILE_COUNT.set(float(_TRACKED_FILE_COUNT_ESTIMATE))


def record_reconcile_failure(provider: str, reason: str) -> None:
    RECONCILE_FAILURES.labels(
        provider=(provider or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_provider_latency(provider: str, operation: str, elapsed_seconds: float) -> None:
    PROVIDER_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        operation=(operation or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_provider_failure_streak(provider: str, streak: int) -> None:
    PROVIDER_FAILURE_STREAK.labels(provider=(provider or "unknown").lower()).set(float(max(0, int(streak))))


def record_provider_failure_alert(provider: str) -> None:
    PROVIDER_FAILURE_ALERTS.labels(provider=(provider or "unknown").lower()).inc()


def record_payment_incident_event(*, provider: str, incident_type: str, event: str, status: str, outcome: str = "ok") -> None:
    PAYMENT_INCIDENT_EVENTS.labels(
        provider=(provider or "unknown").lower(),
        incident_type=(incident_type or "unknown").lower(),
        event=(event or "unknown").lower(),
        status=(status or "unknown").lower(),
        outcome=(outcome or "ok").lower(),
    ).inc()


def record_payment_incident_response_latency(*, provider: str, incident_type: str, elapsed_seconds: float) -> None:
    if elapsed_seconds < 0:
        return
    PAYMENT_INCIDENT_RESPONSE_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        incident_type=(incident_type or "unknown").lower(),
    ).observe(elapsed_seconds)


def record_payment_incident_response_sla_breach(*, provider: str, incident_type: str) -> None:
    PAYMENT_INCIDENT_RESPONSE_SLA_BREACHES.labels(
        provider=(provider or "unknown").lower(),
        incident_type=(incident_type or "unknown").lower(),
    ).inc()


def record_payment_incident_recovery_latency(*, provider: str, elapsed_seconds: float) -> None:
    if elapsed_seconds < 0:
        return
    PAYMENT_INCIDENT_RECOVERY_LATENCY.labels(provider=(provider or "unknown").lower()).observe(elapsed_seconds)


def record_payment_incident_retry_attempt(*, provider: str, action: str, outcome: str, code: str = "none") -> None:
    PAYMENT_INCIDENT_RETRY_ATTEMPTS.labels(
        provider=(provider or "unknown").lower(),
        action=(action or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        code=(code or "none").lower(),
    ).inc()


def record_payment_incident_ticket_latency(*, provider: str, metric: str, elapsed_seconds: float) -> None:
    if elapsed_seconds < 0:
        return
    PAYMENT_INCIDENT_TICKET_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        metric=(metric or "unknown").lower(),
    ).observe(elapsed_seconds)


def record_payment_incident_webhook_outcome(*, provider: str, outcome: str, reason: str = "none") -> None:
    PAYMENT_INCIDENT_WEBHOOK_OUTCOMES.labels(
        provider=(provider or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower(),
    ).inc()


def record_payment_incident_webhook_replay_event(*, provider: str, event: str) -> None:
    PAYMENT_INCIDENT_WEBHOOK_REPLAY_EVENTS.labels(
        provider=(provider or "unknown").lower(),
        event=(event or "unknown").lower(),
    ).inc()


def set_payment_incident_webhook_replay_cache_entries(*, entries: int) -> None:
    PAYMENT_INCIDENT_WEBHOOK_REPLAY_CACHE_ENTRIES.set(max(0, int(entries)))


def record_google_calendar_sync_job(*, flow: str, state: str, count: int = 1) -> None:
    GOOGLE_CALENDAR_SYNC_JOBS.labels(
        flow=(flow or "unknown").lower(),
        state=(state or "unknown").lower(),
    ).inc(max(0, int(count)))


def record_google_calendar_sync_latency(*, flow: str, elapsed_seconds: float) -> None:
    GOOGLE_CALENDAR_SYNC_LATENCY.labels(
        flow=(flow or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_google_calendar_sync_conflict(*, reason: str) -> None:
    GOOGLE_CALENDAR_SYNC_CONFLICTS.labels(reason=(reason or "unknown").lower()).inc()


def record_google_calendar_token_refresh_failure(*, reason: str) -> None:
    GOOGLE_CALENDAR_TOKEN_REFRESH_FAILURES.labels(reason=(reason or "unknown").lower()).inc()


def set_google_calendar_outbox_backlog(*, status: str, count: int) -> None:
    GOOGLE_CALENDAR_OUTBOX_BACKLOG.labels(status=(status or "unknown").lower()).set(float(max(0, int(count))))


def record_google_calendar_api_retry(*, reason: str, provider_status_code: int | None = None) -> None:
    GOOGLE_CALENDAR_API_RETRIES.labels(
        reason=(reason or "unknown").lower(),
        provider_status_code=str(provider_status_code if provider_status_code is not None else "none"),
    ).inc()


def record_google_calendar_oauth_callback_rejection(*, reason: str) -> None:
    GOOGLE_CALENDAR_OAUTH_CALLBACK_REJECTIONS.labels(reason=(reason or "unknown").lower()).inc()


def record_google_calendar_oauth_callback_outcome(*, outcome: str, reason: str) -> None:
    GOOGLE_CALENDAR_OAUTH_CALLBACK_OUTCOMES.labels(
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_calendar_sync_run(*, provider: str, mode: str, outcome: str) -> None:
    CALENDAR_SYNC_RUNS.labels(
        provider=(provider or "unknown").lower(),
        mode=(mode or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).inc()


def record_calendar_sync_latency(*, provider: str, operation: str, outcome: str, elapsed_seconds: float) -> None:
    CALENDAR_SYNC_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        operation=(operation or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_calendar_sync_conflict(*, provider: str, reason: str, operation: str) -> None:
    CALENDAR_SYNC_CONFLICTS.labels(
        provider=(provider or "unknown").lower(),
        reason=(reason or "unknown").lower(),
        operation=(operation or "unknown").lower(),
    ).inc()


def record_calendar_sync_queue_backlog(*, provider: str, queue: str, depth: int) -> None:
    CALENDAR_SYNC_QUEUE_BACKLOG.labels(
        provider=(provider or "unknown").lower(),
        queue=(queue or "unknown").lower(),
    ).set(float(max(0, int(depth))))


def record_calendar_sync_auth_failure(*, provider: str) -> None:
    CALENDAR_SYNC_AUTH_FAILURES.labels(provider=(provider or "unknown").lower()).inc()


def record_vnc_session_event(*, action: str, outcome: str, target_id: str = "unknown", error_code: str = "none") -> None:
    VNC_SESSION_EVENTS.labels(
        action=(action or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        target_id=(target_id or "unknown").lower(),
        error_code=(error_code or "none").lower(),
    ).inc()


def record_vnc_session_duration(*, target_id: str, outcome: str, elapsed_seconds: float) -> None:
    VNC_SESSION_DURATION.labels(
        target_id=(target_id or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_vnc_bridge_failure(*, target_id: str, error_code: str) -> None:
    VNC_BRIDGE_FAILURES.labels(
        target_id=(target_id or "unknown").lower(),
        error_code=(error_code or "unknown").lower(),
    ).inc()


def record_broadcast_provision_latency(*, provider: str, result: str, elapsed_seconds: float) -> None:
    BROADCAST_PROVISION_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        result=(result or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_broadcast_session_action(*, provider: str, action: str, result: str) -> None:
    BROADCAST_SESSION_ACTIONS.labels(
        provider=(provider or "unknown").lower(),
        action=(action or "unknown").lower(),
        result=(result or "unknown").lower(),
    ).inc()


def record_broadcast_input_loss(*, provider: str, reason: str) -> None:
    BROADCAST_INPUT_LOSS_EVENTS.labels(
        provider=(provider or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_broadcast_output_error(*, provider: str, reason: str) -> None:
    BROADCAST_OUTPUT_ERRORS.labels(
        provider=(provider or "unknown").lower(),
        reason=(reason or "unknown").lower(),
    ).inc()


def record_broadcast_drift_incident(*, provider: str, incident_type: str) -> None:
    BROADCAST_DRIFT_INCIDENTS.labels(
        provider=(provider or "unknown").lower(),
        incident_type=(incident_type or "unknown").lower(),
    ).inc()

def metrics_endpoint() -> Response:
    UPTIME_SECONDS.set(time.monotonic() - _START_TIME)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def record_filemgr_mount_upload_method(provider: str, method: str, outcome: str) -> None:
    FILEMGR_MOUNT_UPLOAD_METHOD.labels(provider=provider, method=method, outcome=outcome).inc()


def record_filemgr_mount_operation_latency(provider: str, operation: str, elapsed_seconds: float) -> None:
    FILEMGR_MOUNT_OPERATION_LATENCY.labels(
        provider=(provider or "unknown").lower(),
        operation=(operation or "unknown").lower(),
    ).observe(max(0.0, float(elapsed_seconds)))


def record_filemgr_mount_bytes(provider: str, direction: str, operation: str, nbytes: int) -> None:
    if int(nbytes or 0) <= 0:
        return
    FILEMGR_MOUNT_BYTES.labels(
        provider=(provider or "unknown").lower(),
        direction=(direction or "unknown").lower(),
        operation=(operation or "unknown").lower(),
    ).inc(float(nbytes))


def record_filemgr_mount_api_error(provider: str, operation: str, status_code: int | str, reason: str) -> None:
    FILEMGR_MOUNT_API_ERRORS.labels(
        provider=(provider or "unknown").lower(),
        operation=(operation or "unknown").lower(),
        status_code=str(status_code or "unknown"),
        reason=(reason or "unknown").lower()[:64],
    ).inc()


def record_filemgr_mount_refresh_attempt(provider: str, outcome: str, reason: str = "none") -> None:
    FILEMGR_MOUNT_REFRESH_ATTEMPTS.labels(
        provider=(provider or "unknown").lower(),
        outcome=(outcome or "unknown").lower(),
        reason=(reason or "none").lower()[:64],
    ).inc()
