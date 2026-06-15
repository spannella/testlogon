from __future__ import annotations

import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    # AWS
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")
    aws_endpoint_url: str = os.environ.get("AWS_ENDPOINT_URL", "")
    ddb_endpoint_url: str = os.environ.get("DDB_ENDPOINT_URL", "")
    s3_endpoint_url: str = os.environ.get("S3_ENDPOINT_URL", "")
    cognito_endpoint_url: str = os.environ.get("COGNITO_ENDPOINT_URL", "")
    kms_endpoint_url: str = os.environ.get("KMS_ENDPOINT_URL", "")
    secretsmanager_endpoint_url: str = os.environ.get("SECRETSMANAGER_ENDPOINT_URL", "")
    sqs_endpoint_url: str = os.environ.get("SQS_ENDPOINT_URL", "")
    s3_use_path_style: bool = os.environ.get("S3_USE_PATH_STYLE", "0") not in ("0", "false", "False")

    # Cognito (optional wiring; auth is pluggable)
    cognito_user_pool_id: str = os.environ.get("COGNITO_USER_POOL_ID", "")
    cognito_region: str = os.environ.get("COGNITO_REGION", "")
    cognito_app_client_id: str = os.environ.get("COGNITO_APP_CLIENT_ID", "")
    cognito_issuer_url: str = os.environ.get("COGNITO_ISSUER_URL", "")
    cognito_jwks_url: str = os.environ.get("COGNITO_JWKS_URL", "")
    cognito_expected_token_use: str = os.environ.get("COGNITO_EXPECTED_TOKEN_USE", "access")
    cognito_jwks_ttl_seconds: int = int(os.environ.get("COGNITO_JWKS_TTL_SECONDS", "3600"))

    # Root identity
    root_user_sub: str = os.environ.get("ROOT_USER_SUB", "root")
    root_login_allowed_ips: str = os.environ.get("ROOT_LOGIN_ALLOWED_IPS", "")
    root_login_local_only: bool = os.environ.get("ROOT_LOGIN_LOCAL_ONLY", "false").lower() in ("1", "true", "yes", "on")
    trusted_proxy_cidrs: str = os.environ.get("TRUSTED_PROXY_CIDRS", "")
    # Break-glass secret for rootctl mutating CLI commands (prod: from Secrets Manager
    # injected into env; dev: well-known value in .env.local). Same code path either way.
    rootctl_break_glass_secret: str = os.environ.get("ROOTCTL_BREAK_GLASS_SECRET", "")

    # DynamoDB tables
    ddb_sessions_table: str = os.environ.get("DDB_SESSIONS_TABLE", "")
    ddb_totp_table: str = os.environ.get("DDB_TOTP_TABLE", "")
    ddb_sms_table: str = os.environ.get("DDB_SMS_TABLE", "")
    ddb_recovery_table: str = os.environ.get("DDB_RECOVERY_TABLE", "")
    ddb_email_table: str = os.environ.get("DDB_EMAIL_TABLE", "")

    api_keys_table_name: str = os.environ.get("API_KEYS_TABLE_NAME", "api_keys")
    users_table_name: str = os.environ.get("USERS_TABLE_NAME", "users")
    role_audit_table_name: str = os.environ.get("ROLE_AUDIT_TABLE_NAME", "role_audit")
    api_keys_user_index: str = os.environ.get("API_KEYS_USER_INDEX", "user_sub-index")
    api_key_pepper: str = os.environ.get("API_KEY_PEPPER", "")
    api_key_ttl_days: int = int(os.environ.get("API_KEY_TTL_DAYS", "365"))
    # API key phased rollout flags (AKI-052)
    api_key_filemanager: bool = os.environ.get("API_KEY_FILEMANAGER", "1") not in ("0", "false", "False")
    api_key_filemanager_phase: str = os.environ.get("API_KEY_FILEMANAGER_PHASE", "ga")
    api_key_filemanager_canary_percent: int = int(os.environ.get("API_KEY_FILEMANAGER_CANARY_PERCENT", "0"))
    api_key_filemanager_canary_subjects: str = os.environ.get("API_KEY_FILEMANAGER_CANARY_SUBJECTS", "")

    api_key_newsfeed: bool = os.environ.get("API_KEY_NEWSFEED", "1") not in ("0", "false", "False")
    api_key_newsfeed_phase: str = os.environ.get("API_KEY_NEWSFEED_PHASE", "ga")
    api_key_newsfeed_canary_percent: int = int(os.environ.get("API_KEY_NEWSFEED_CANARY_PERCENT", "0"))
    api_key_newsfeed_canary_subjects: str = os.environ.get("API_KEY_NEWSFEED_CANARY_SUBJECTS", "")

    api_key_tickets: bool = os.environ.get("API_KEY_TICKETS", "1") not in ("0", "false", "False")
    api_key_tickets_phase: str = os.environ.get("API_KEY_TICKETS_PHASE", "ga")
    api_key_tickets_canary_percent: int = int(os.environ.get("API_KEY_TICKETS_CANARY_PERCENT", "0"))
    api_key_tickets_canary_subjects: str = os.environ.get("API_KEY_TICKETS_CANARY_SUBJECTS", "")

    api_key_shopping: bool = os.environ.get("API_KEY_SHOPPING", "1") not in ("0", "false", "False")
    api_key_shopping_phase: str = os.environ.get("API_KEY_SHOPPING_PHASE", "ga")
    api_key_shopping_canary_percent: int = int(os.environ.get("API_KEY_SHOPPING_CANARY_PERCENT", "0"))
    api_key_shopping_canary_subjects: str = os.environ.get("API_KEY_SHOPPING_CANARY_SUBJECTS", "")

    api_key_messager: bool = os.environ.get("API_KEY_MESSAGER", "1") not in ("0", "false", "False")
    api_key_messager_phase: str = os.environ.get("API_KEY_MESSAGER_PHASE", "ga")
    api_key_messager_canary_percent: int = int(os.environ.get("API_KEY_MESSAGER_CANARY_PERCENT", "0"))
    api_key_messager_canary_subjects: str = os.environ.get("API_KEY_MESSAGER_CANARY_SUBJECTS", "")
    api_key_dual_credential_mode: str = os.environ.get("API_KEY_DUAL_CREDENTIAL_MODE", "prefer_api_key")
    api_key_registry_drift_warn_threshold: int = int(os.environ.get("API_KEY_REGISTRY_DRIFT_WARN_THRESHOLD", "0"))
    api_key_rollout_state_allow_subjects: bool = os.environ.get("API_KEY_ROLLOUT_STATE_ALLOW_SUBJECTS", "0") not in ("0", "false", "False")

    alerts_table_name: str = os.environ.get("ALERTS_TABLE_NAME", "alerts")
    alert_prefs_table_name: str = os.environ.get("ALERT_PREFS_TABLE_NAME", "alert_prefs")
    alerts_enabled: bool = os.environ.get("ALERTS_ENABLED", "1") not in ("0", "false", "False")
    alerts_ttl_days: int = int(os.environ.get("ALERTS_TTL_DAYS", "90"))

    # TTL
    ddb_ttl_attr: str = os.environ.get("DDB_TTL_ATTR", "ttl_epoch")
    registration_pending_ttl_days: int = int(os.environ.get("REGISTRATION_PENDING_TTL_DAYS", "7"))
    # When True, POST /ui/register/start re-issues a verification challenge for a
    # pending_verification account instead of silently returning a fake success
    # (GAP-0108). Default on — the no-resume behaviour is the bug, not desired.
    registration_allow_resume_unverified: bool = os.environ.get(
        "REGISTRATION_ALLOW_RESUME_UNVERIFIED", "1"
    ) not in ("0", "false", "False")

    # Sessions
    ui_session_ttl_seconds: int = int(os.environ.get("UI_SESSION_TTL_SECONDS", str(30 * 24 * 3600)))
    ui_inactivity_seconds: int = int(os.environ.get("UI_INACTIVITY_SECONDS", str(2 * 3600)))
    session_challenge_ttl_seconds: int = int(os.environ.get("SESSION_CHALLENGE_TTL_SECONDS", "300"))
    ui_stepup_max_age_seconds: int = int(os.environ.get("UI_STEPUP_MAX_AGE_SECONDS", "300"))
    ui_session_cookie_name: str = os.environ.get("UI_SESSION_COOKIE_NAME", "ui_session")
    ui_csrf_cookie_name: str = os.environ.get("UI_CSRF_COOKIE_NAME", "ui_csrf")
    ui_csrf_header_name: str = os.environ.get("UI_CSRF_HEADER_NAME", "x-csrf-token")
    ui_cookie_secure: bool = os.environ.get("UI_COOKIE_SECURE", "0") not in ("0", "false", "False")
    ui_cookie_samesite: str = os.environ.get("UI_COOKIE_SAMESITE", "lax")
    ui_device_cookie_name: str = os.environ.get("UI_DEVICE_COOKIE_NAME", "ui_device")
    ui_device_cookie_ttl_seconds: int = int(os.environ.get("UI_DEVICE_COOKIE_TTL_SECONDS", str(90 * 24 * 3600)))
    ui_access_token_cookie_name: str = os.environ.get("UI_ACCESS_TOKEN_COOKIE_NAME", "ui_access_token")
    ui_access_token_ttl_seconds: int = int(os.environ.get("UI_ACCESS_TOKEN_TTL_SECONDS", "900"))
    ui_access_token_secret: str = os.environ.get("UI_ACCESS_TOKEN_SECRET", "")
    ui_refresh_token_cookie_name: str = os.environ.get("UI_REFRESH_TOKEN_COOKIE_NAME", "ui_refresh_token")
    ui_refresh_token_ttl_seconds: int = int(os.environ.get("UI_REFRESH_TOKEN_TTL_SECONDS", str(30 * 24 * 3600)))
    root_session_ttl_seconds: int = int(os.environ.get("ROOT_SESSION_TTL_SECONDS", "3600"))
    root_access_token_ttl_seconds: int = int(os.environ.get("ROOT_ACCESS_TOKEN_TTL_SECONDS", "300"))
    root_refresh_token_ttl_seconds: int = int(os.environ.get("ROOT_REFRESH_TOKEN_TTL_SECONDS", "1800"))
    impersonation_ttl_seconds: int = int(os.environ.get("IMPERSONATION_TTL_SECONDS", "1800"))
    impersonation_max_ttl_seconds: int = int(os.environ.get("IMPERSONATION_MAX_TTL_SECONDS", "3600"))
    impersonation_allow_privileged_targets: bool = os.environ.get("IMPERSONATION_ALLOW_PRIVILEGED_TARGETS", "false").lower() in ("1", "true", "yes", "on")

    # Admin scope enforcement feature flags (AP-016)
    admin_scope_enforce_auth_support: bool = os.environ.get("ADMIN_SCOPE_ENFORCE_AUTH_SUPPORT", "1") not in ("0", "false", "False")
    admin_scope_enforce_billing_support: bool = os.environ.get("ADMIN_SCOPE_ENFORCE_BILLING_SUPPORT", "1") not in ("0", "false", "False")
    admin_scope_enforce_content_moderation: bool = os.environ.get("ADMIN_SCOPE_ENFORCE_CONTENT_MODERATION", "1") not in ("0", "false", "False")

    # Browser SSH terminal feature flag
    browser_ssh_terminal_enabled: bool = os.environ.get("BROWSER_SSH_TERMINAL_ENABLED", "0") not in ("0", "false", "False")
    browser_ssh_allowed_hosts: str = os.environ.get("BROWSER_SSH_ALLOWED_HOSTS", "")
    browser_ssh_denied_hosts: str = os.environ.get("BROWSER_SSH_DENIED_HOSTS", "")
    browser_ssh_allowed_ports: str = os.environ.get("BROWSER_SSH_ALLOWED_PORTS", "")
    browser_ssh_denied_ports: str = os.environ.get("BROWSER_SSH_DENIED_PORTS", "")
    browser_ssh_terminal_allowed_roles: str = os.environ.get("BROWSER_SSH_TERMINAL_ALLOWED_ROLES", "admin,root")
    browser_ssh_idle_timeout_seconds: int = int(os.environ.get("BROWSER_SSH_IDLE_TIMEOUT_SECONDS", "900"))
    browser_ssh_max_session_duration_seconds: int = int(os.environ.get("BROWSER_SSH_MAX_SESSION_DURATION_SECONDS", "3600"))
    browser_ssh_max_sessions_per_user: int = int(os.environ.get("BROWSER_SSH_MAX_SESSIONS_PER_USER", "2"))
    browser_ssh_connect_rate_limit_count: int = int(os.environ.get("BROWSER_SSH_CONNECT_RATE_LIMIT_COUNT", "10"))
    browser_ssh_connect_rate_limit_window_seconds: int = int(os.environ.get("BROWSER_SSH_CONNECT_RATE_LIMIT_WINDOW_SECONDS", "60"))

    # Calendar integrations
    calendar_integrations_enabled: bool = os.environ.get("CALENDAR_INTEGRATIONS_ENABLED", "1") not in ("0", "false", "False")
    # MSG-006: Emoji messages — shortcode replacement feature flag (frontend reads via /ui/config).
    emoji_shortcodes_enabled: bool = os.environ.get("EMOJI_SHORTCODES_ENABLED", "1") not in ("0", "false", "False")
    apple_caldav_enabled: bool = os.environ.get("APPLE_CALDAV_ENABLED", "0") not in ("0", "false", "False")
    apple_caldav_base_url: str = os.environ.get("APPLE_CALDAV_BASE_URL", "https://caldav.icloud.com").rstrip("/")
    apple_caldav_mock_enabled: bool = os.environ.get("APPLE_CALDAV_MOCK_ENABLED", "0") not in ("0", "false", "False")
    apple_caldav_connect_timeout_seconds: float = float(os.environ.get("APPLE_CALDAV_CONNECT_TIMEOUT_SECONDS", "5"))
    apple_caldav_read_timeout_seconds: float = float(os.environ.get("APPLE_CALDAV_READ_TIMEOUT_SECONDS", "10"))
    apple_caldav_retry_max_attempts: int = int(os.environ.get("APPLE_CALDAV_RETRY_MAX_ATTEMPTS", "3"))
    apple_caldav_poll_interval_seconds: int = int(os.environ.get("APPLE_CALDAV_POLL_INTERVAL_SECONDS", "300"))
    apple_caldav_poll_jitter_seconds: int = int(os.environ.get("APPLE_CALDAV_POLL_JITTER_SECONDS", "30"))
    apple_caldav_poll_batch_size: int = int(os.environ.get("APPLE_CALDAV_POLL_BATCH_SIZE", "50"))
    apple_caldav_outbox_process_limit: int = int(os.environ.get("APPLE_CALDAV_OUTBOX_PROCESS_LIMIT", "200"))
    apple_caldav_initial_import_lookback_days: int = int(os.environ.get("APPLE_CALDAV_INITIAL_IMPORT_LOOKBACK_DAYS", "365"))
    apple_caldav_initial_import_lookahead_days: int = int(os.environ.get("APPLE_CALDAV_INITIAL_IMPORT_LOOKAHEAD_DAYS", "30"))
    calendar_connections_table_name: str = os.environ.get("CALENDAR_CONNECTIONS_TABLE_NAME", "calendar_connections")
    calendar_connection_secrets_table_name: str = os.environ.get("CALENDAR_CONNECTION_SECRETS_TABLE_NAME", "calendar_connection_secrets")
    external_calendars_table_name: str = os.environ.get("EXTERNAL_CALENDARS_TABLE_NAME", "external_calendars")
    external_event_links_table_name: str = os.environ.get("EXTERNAL_EVENT_LINKS_TABLE_NAME", "external_event_links")
    calendar_sync_runs_table_name: str = os.environ.get("CALENDAR_SYNC_RUNS_TABLE_NAME", "calendar_sync_runs")

    # MFA rate limiting
    mfa_send_min_interval_seconds: int = int(os.environ.get("MFA_SEND_MIN_INTERVAL_SECONDS", "30"))
    mfa_send_max_per_hour: int = int(os.environ.get("MFA_SEND_MAX_PER_HOUR", "20"))

    # MFA attempt budgets
    email_code_max_attempts: int = int(os.environ.get("EMAIL_CODE_MAX_ATTEMPTS", "5"))
    email_code_attempt_window_seconds: int = int(os.environ.get("EMAIL_CODE_ATTEMPT_WINDOW_SECONDS", "600"))
    sms_code_max_attempts: int = int(os.environ.get("SMS_CODE_MAX_ATTEMPTS", "8"))
    sms_code_attempt_window_seconds: int = int(os.environ.get("SMS_CODE_ATTEMPT_WINDOW_SECONDS", "600"))
    login_attempt_max_per_window: int = int(os.environ.get("LOGIN_ATTEMPT_MAX_PER_WINDOW", "10"))
    login_attempt_window_seconds: int = int(os.environ.get("LOGIN_ATTEMPT_WINDOW_SECONDS", "900"))
    admin_action_max_per_window: int = int(os.environ.get("ADMIN_ACTION_MAX_PER_WINDOW", "120"))
    admin_action_window_seconds: int = int(os.environ.get("ADMIN_ACTION_WINDOW_SECONDS", "900"))
    login_anomaly_window_seconds: int = int(os.environ.get("LOGIN_ANOMALY_WINDOW_SECONDS", "900"))
    login_anomaly_ip_prefix_threshold: int = int(os.environ.get("LOGIN_ANOMALY_IP_PREFIX_THRESHOLD", "5"))
    login_anomaly_user_threshold: int = int(os.environ.get("LOGIN_ANOMALY_USER_THRESHOLD", "10"))
    login_anomaly_risk_score_threshold: int = int(os.environ.get("LOGIN_ANOMALY_RISK_SCORE_THRESHOLD", "1"))
    login_high_risk_refresh_ttl_seconds: int = int(os.environ.get("LOGIN_HIGH_RISK_REFRESH_TTL_SECONDS", "3600"))
    mfa_verify_max_per_window: int = int(os.environ.get("MFA_VERIFY_MAX_PER_WINDOW", "10"))
    mfa_verify_window_seconds: int = int(os.environ.get("MFA_VERIFY_WINDOW_SECONDS", "600"))
    lockout_max_attempts: int = int(os.environ.get("LOCKOUT_MAX_ATTEMPTS", "5"))
    lockout_window_seconds: int = int(os.environ.get("LOCKOUT_WINDOW_SECONDS", "900"))
    lockout_base_seconds: int = int(os.environ.get("LOCKOUT_BASE_SECONDS", "300"))
    lockout_max_seconds: int = int(os.environ.get("LOCKOUT_MAX_SECONDS", "3600"))

    # Device limits
    sms_device_limit: int = int(os.environ.get("SMS_DEVICE_LIMIT", "3"))
    email_device_limit: int = int(os.environ.get("EMAIL_DEVICE_LIMIT", "5"))

    # KMS
    kms_key_id: str = os.environ.get("KMS_KEY_ID", "")

    # SES / Twilio
    ses_from_email: str = os.environ.get("SES_FROM_EMAIL", "")
    twilio_account_sid: str = os.environ.get("TWILIO_ACCOUNT_SID", "")
    twilio_auth_token: str = os.environ.get("TWILIO_AUTH_TOKEN", "")
    twilio_verify_service_sid: str = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")

    # Alert fanout channels
    alerts_from_email: str = os.environ.get("ALERTS_FROM_EMAIL", "")
    alerts_email_enabled: bool = os.environ.get("ALERTS_EMAIL_ENABLED", "0") not in ("0","false","False")
    alerts_email_max_per_window: int = int(os.environ.get("ALERTS_EMAIL_MAX_PER_WINDOW", "20"))
    alerts_email_window_seconds: int = int(os.environ.get("ALERTS_EMAIL_WINDOW_SECONDS", "3600"))

    alerts_sms_enabled: bool = os.environ.get("ALERTS_SMS_ENABLED", "0") not in ("0","false","False")
    alerts_sms_max_per_window: int = int(os.environ.get("ALERTS_SMS_MAX_PER_WINDOW", "10"))
    alerts_sms_window_seconds: int = int(os.environ.get("ALERTS_SMS_WINDOW_SECONDS", "3600"))

    # SMS Delivery Tracking (PLATFORM-007)
    sms_delivery_table_name: str = os.environ.get("SMS_DELIVERY_TABLE_NAME", "sms_delivery")
    sms_message_type: str = os.environ.get("SMS_MESSAGE_TYPE", "Transactional")
    sms_sender_id: str = os.environ.get("SMS_SENDER_ID", "")
    sms_origination_number: str = os.environ.get("SMS_ORIGINATION_NUMBER", "")
    sms_daily_limit_per_number: int = int(os.environ.get("SMS_DAILY_LIMIT_PER_NUMBER", "10"))
    sms_suppression_enabled: bool = os.environ.get("SMS_SUPPRESSION_ENABLED", "1") not in ("0", "false", "False")
    sms_cost_per_segment_usd: float = float(os.environ.get("SMS_COST_PER_SEGMENT_USD", "0.00645"))
    # Global platform-wide daily SMS spend cap in USD (SEC-014 / GAP-0326).
    # 0 = disabled (default; backward compatible — no behaviour change). When set
    # to a positive value, send_sms() returns status="rate_limited" for all
    # outbound SMS once the estimated cumulative daily segment cost reaches it.
    sms_daily_cost_cap_usd: float = float(os.environ.get("SMS_DAILY_COST_CAP_USD", "0"))

    alerts_webhook_url: str = os.environ.get("ALERTS_WEBHOOK_URL", "")
    alerts_webhook_secret: str = os.environ.get("ALERTS_WEBHOOK_SECRET", "")
    alerts_webhook_timeout_seconds: int = int(os.environ.get("ALERTS_WEBHOOK_TIMEOUT_SECONDS", "5"))
    alerts_webhook_event_types: str = os.environ.get("ALERTS_WEBHOOK_EVENT_TYPES", "")
    alerts_webhook_enabled: bool = os.environ.get("ALERTS_WEBHOOK_ENABLED", "0") not in ("0","false","False")
    alerts_webhook_max_per_window: int = int(os.environ.get("ALERTS_WEBHOOK_MAX_PER_WINDOW", "30"))
    alerts_webhook_window_seconds: int = int(os.environ.get("ALERTS_WEBHOOK_WINDOW_SECONDS", "3600"))

    # Email Delivery Tracking (PLATFORM-006)
    email_delivery_table_name: str = os.environ.get("EMAIL_DELIVERY_TABLE_NAME", "email_delivery")
    email_suppression_enabled: bool = os.environ.get("EMAIL_SUPPRESSION_ENABLED", "1") not in ("0", "false", "False")
    # SES/SNS notification signature verification (PLATFORM-002 / GAP-0319).
    # Default ON (secure). Same verification code runs in dev and prod; the flag
    # exists only so tests/dev can opt out deterministically.
    ses_sns_signature_verification_enabled: bool = os.environ.get(
        "SES_SNS_SIGNATURE_VERIFICATION_ENABLED", "1"
    ) not in ("0", "false", "False")

    # Admin Email/SMS Dashboards (ADMIN-002)
    admin_messaging_templates_table_name: str = os.environ.get(
        "ADMIN_MESSAGING_TEMPLATES_TABLE_NAME", "admin_messaging_templates"
    )
    admin_messaging_dashboard_enabled: bool = os.environ.get(
        "ADMIN_MESSAGING_DASHBOARD_ENABLED", "1"
    ) not in ("0", "false", "False")
    admin_messaging_dashboard_template_edit_enabled: bool = os.environ.get(
        "ADMIN_MESSAGING_DASHBOARD_TEMPLATE_EDIT_ENABLED", "1"
    ) not in ("0", "false", "False")
    admin_messaging_dashboard_test_send_enabled: bool = os.environ.get(
        "ADMIN_MESSAGING_DASHBOARD_TEST_SEND_ENABLED", "1"
    ) not in ("0", "false", "False")
    admin_messaging_dashboard_test_send_limit_per_hour: int = int(
        os.environ.get("ADMIN_MESSAGING_DASHBOARD_TEST_SEND_LIMIT_PER_HOUR", "10")
    )

    siem_webhook_enabled: bool = os.environ.get("SIEM_WEBHOOK_ENABLED", "0") not in ("0", "false", "False")
    siem_webhook_url: str = os.environ.get("SIEM_WEBHOOK_URL", "")
    siem_webhook_secret: str = os.environ.get("SIEM_WEBHOOK_SECRET", "")
    siem_webhook_timeout_seconds: int = int(os.environ.get("SIEM_WEBHOOK_TIMEOUT_SECONDS", "5"))
    siem_root_admin_events_only: bool = os.environ.get("SIEM_ROOT_ADMIN_EVENTS_ONLY", "1") not in ("0", "false", "False")

    verify_email_max_per_window: int = int(os.environ.get("VERIFY_EMAIL_MAX_PER_WINDOW", "5"))
    verify_email_window_seconds: int = int(os.environ.get("VERIFY_EMAIL_WINDOW_SECONDS", "3600"))
    verify_sms_max_per_window: int = int(os.environ.get("VERIFY_SMS_MAX_PER_WINDOW", "5"))
    verify_sms_window_seconds: int = int(os.environ.get("VERIFY_SMS_WINDOW_SECONDS", "3600"))

    # Websocket/SSE token (HMAC)
    ws_token_secret: str = os.environ.get("WS_TOKEN_SECRET", "")

    # Credential stuffing protection
    hibp_enabled: bool = os.environ.get("HIBP_ENABLED", "0") not in ("0", "false", "False")
    hibp_api_key: str = os.environ.get("HIBP_API_KEY", "")

    # Passwordless (magic links)
    magic_link_enabled: bool = os.environ.get("MAGIC_LINK_ENABLED", "0") not in ("0", "false", "False")
    magic_link_ttl_seconds: int = int(os.environ.get("MAGIC_LINK_TTL_SECONDS", "900"))
    webauthn_rp_id: str = os.environ.get("WEBAUTHN_RP_ID", "")
    webauthn_rp_name: str = os.environ.get("WEBAUTHN_RP_NAME", "YourApp")
    webauthn_origin: str = os.environ.get("WEBAUTHN_ORIGIN", "")
    totp_issuer: str = os.environ.get("TOTP_ISSUER", os.environ.get("WEBAUTHN_RP_NAME", "YourApp"))

    # Push / FCM
    push_devices_table_name: str = os.environ.get("PUSH_DEVICES_TABLE_NAME", "push_devices")
    push_enabled: bool = os.environ.get("PUSH_ENABLED", "0") not in ("0","false","False")
    fcm_enabled: bool = os.environ.get("FCM_ENABLED", "0") not in ("0","false","False")
    fcm_project_id: str = os.environ.get("FCM_PROJECT_ID", "")
    fcm_client_email: str = os.environ.get("FCM_CLIENT_EMAIL", "")
    fcm_private_key: str = os.environ.get("FCM_PRIVATE_KEY", "")  # keep \n escaped

    audit_log_enabled: bool = os.environ.get("AUDIT_LOG_ENABLED", "1") not in ("0","false","False")
    security_csp_header: str = os.environ.get(
        "SECURITY_CSP_HEADER",
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'self' blob:; frame-src 'self' blob:; media-src 'self' blob:; font-src 'self' data:",
    )
    dev_mode: bool = os.environ.get("DEV_MODE", "1") not in ("0", "false", "False")
    dev_test_user: str = os.environ.get("DEV_TEST_USER", "")
    dev_test_password: str = os.environ.get("DEV_TEST_PASSWORD", "")
    dev_registration_email: str = os.environ.get("DEV_REGISTRATION_EMAIL", "")
    dev_registration_password: str = os.environ.get("DEV_REGISTRATION_PASSWORD", "")
    dev_registration_code: str = os.environ.get("DEV_REGISTRATION_CODE", "")
    dev_registration_phone: str = os.environ.get("DEV_REGISTRATION_PHONE", "")
    dev_email_log: str = os.environ.get("DEV_EMAIL_LOG", ".logs/dev/emails.log")
    dev_sms_log: str = os.environ.get("DEV_SMS_LOG", ".logs/dev/sms.log")
    # Internal Dev Log UI discovery defaults (DLU-001).
    devtools_email_log_path: str = os.environ.get("DEVTOOLS_EMAIL_LOG_PATH", os.environ.get("DEV_EMAIL_LOG", ".logs/dev/emails.log"))
    devtools_sms_log_path: str = os.environ.get("DEVTOOLS_SMS_LOG_PATH", os.environ.get("DEV_SMS_LOG", ".logs/dev/sms.log"))
    # Stripe mock writes provider logs under .local/logs in host-mode startup.
    devtools_billing_stripe_log_path: str = os.environ.get("DEVTOOLS_BILLING_STRIPE_LOG_PATH", ".local/logs/stripe-mock.log")
    # CCBill/PayPal mock calls are served in-process and observable from backend logs.
    devtools_billing_backend_log_path: str = os.environ.get("DEVTOOLS_BILLING_BACKEND_LOG_PATH", ".logs/dev/backend.log")

    # Billing / CCBill
    ccbill_base_url: str = os.environ.get("CCBILL_BASE_URL", "https://api.ccbill.com").rstrip("/")
    ccbill_accept: str = os.environ.get(
        "CCBILL_ACCEPT",
        "application/vnd.mcn.transaction-service.api.v.2+json",
    )
    ccbill_frontend_client_id: str = os.environ.get("CCBILL_FRONTEND_CLIENT_ID", "")
    ccbill_frontend_client_secret: str = os.environ.get("CCBILL_FRONTEND_CLIENT_SECRET", "")
    ccbill_backend_client_id: str = os.environ.get("CCBILL_BACKEND_CLIENT_ID", "")
    ccbill_backend_client_secret: str = os.environ.get("CCBILL_BACKEND_CLIENT_SECRET", "")
    ccbill_client_accnum: int = int(os.environ.get("CCBILL_CLIENT_ACCNUM", "0"))
    ccbill_client_subacc: int = int(os.environ.get("CCBILL_CLIENT_SUBACC", "0"))
    default_monthly_price_cents: int = int(os.environ.get("DEFAULT_MONTHLY_PRICE_CENTS", "999"))
    default_currency_code: int = int(os.environ.get("DEFAULT_CURRENCY_CODE", "840"))
    default_currency: str = os.environ.get("DEFAULT_CURRENCY", "usd")
    property_dashboard_enabled: bool = os.environ.get("PROPERTY_DASHBOARD_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    rent_policy_table_name: str = os.environ.get("RENT_POLICY_TABLE_NAME", "rent_policy")
    rent_policy_cache_ttl_seconds: int = int(os.environ.get("RENT_POLICY_CACHE_TTL_SECONDS", "60"))
    property_documents_table_name: str = os.environ.get("PROPERTY_DOCUMENTS_TABLE_NAME", "property_documents")
    portfolio_kpi_max_ledger_scan_pages: int = int(os.environ.get("PORTFOLIO_KPI_MAX_LEDGER_SCAN_PAGES", "50"))
    portfolio_priority_items_default_limit: int = int(os.environ.get("PORTFOLIO_PRIORITY_ITEMS_DEFAULT_LIMIT", "20"))
    ccbill_webhook_ip_enforce: bool = os.environ.get("CCBILL_WEBHOOK_IP_ENFORCE", "false").lower() in ("1", "true", "yes", "on")
    ccbill_webhook_ip_ranges: str = os.environ.get("CCBILL_WEBHOOK_IP_RANGES", "")
    ccbill_webhook_verify_mode: str = os.environ.get("CCBILL_WEBHOOK_VERIFY_MODE", "")
    ccbill_webhook_signature_secret: str = os.environ.get("CCBILL_WEBHOOK_SIGNATURE_SECRET", "")
    ccbill_webhook_signature_header: str = os.environ.get("CCBILL_WEBHOOK_SIGNATURE_HEADER", "x-ccbill-signature")
    ccbill_mock_enabled: bool = os.environ.get("CCBILL_MOCK_ENABLED", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")

    # UPS
    ups_base_url: str = os.environ.get("UPS_BASE_URL", "").rstrip("/")
    ups_auth_url: str = os.environ.get("UPS_AUTH_URL", "").rstrip("/")
    ups_client_id: str = os.environ.get("UPS_CLIENT_ID", "")
    ups_client_secret: str = os.environ.get("UPS_CLIENT_SECRET", "")
    ups_webhook_secret: str = os.environ.get("UPS_WEBHOOK_SECRET", "")
    # UPS webhook replay protection (GAP-0350): timestamp tolerance window (seconds)
    ups_webhook_timestamp_tolerance_seconds: int = int(
        os.environ.get("UPS_WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", "300")
    )
    # Carrier tracking (SHOP-004)
    carrier_tracking_poll_enabled: bool = os.environ.get("CARRIER_TRACKING_POLL_ENABLED", "false").lower() not in ("0", "false", "")
    carrier_tracking_poll_interval_minutes: int = int(os.environ.get("CARRIER_TRACKING_POLL_INTERVAL_MINUTES", "30"))
    carrier_tracking_poll_batch_size: int = int(os.environ.get("CARRIER_TRACKING_POLL_BATCH_SIZE", "50"))
    # Billing / PayPal
    billing_table_name: str = os.environ.get("BILLING_TABLE_NAME", os.environ.get("DDB_TABLE", "billing"))
    public_base_url: str = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

    paypal_env: str = os.environ.get("PAYPAL_ENV", "sandbox").lower()
    paypal_client_id: str = os.environ.get("PAYPAL_CLIENT_ID", "")
    paypal_client_secret: str = os.environ.get("PAYPAL_CLIENT_SECRET", "")
    paypal_webhook_id: str = os.environ.get("PAYPAL_WEBHOOK_ID", "")
    paypal_webhook_tolerance_seconds: int = int(os.environ.get("PAYPAL_WEBHOOK_TOLERANCE_SECONDS", "300"))
    paypal_webhook_signature_secret: str = os.environ.get("PAYPAL_WEBHOOK_SIGNATURE_SECRET", "")
    paypal_plan_map: str = os.environ.get("PAYPAL_PLAN_MAP", "")
    paypal_mock_enabled: bool = os.environ.get("PAYPAL_MOCK_ENABLED", "0") == "1"
    # Stripe
    stripe_secret_key: str = os.environ.get("STRIPE_SECRET_KEY", "")
    stripe_publishable_key: str = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    stripe_webhook_secret: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    stripe_api_base: str = os.environ.get("STRIPE_API_BASE", "")
    stripe_default_currency: str = os.environ.get("STRIPE_DEFAULT_CURRENCY", "usd")
    stripe_success_url: str = os.environ.get("STRIPE_SUCCESS_URL", "")
    stripe_cancel_url: str = os.environ.get("STRIPE_CANCEL_URL", "")
    payment_incidents_table_name: str = os.environ.get("PAYMENT_INCIDENTS_TABLE_NAME", "payment_incidents")
    payment_incident_events_table_name: str = os.environ.get("PAYMENT_INCIDENT_EVENTS_TABLE_NAME", "payment_incident_events")
    payment_dispute_evidence_table_name: str = os.environ.get("PAYMENT_DISPUTE_EVIDENCE_TABLE_NAME", "payment_dispute_evidence")
    payment_retry_attempts_table_name: str = os.environ.get("PAYMENT_RETRY_ATTEMPTS_TABLE_NAME", "payment_retry_attempts")
    payment_incident_ticket_links_table_name: str = os.environ.get(
        "PAYMENT_INCIDENT_TICKET_LINKS_TABLE_NAME",
        "payment_incident_ticket_links",
    )
    payment_incidents_rollout_enabled: bool = os.environ.get("PAYMENT_INCIDENTS_ROLLOUT_ENABLED", "1") not in ("0", "false", "False")
    payment_incidents_rollout_providers: str = os.environ.get("PAYMENT_INCIDENTS_ROLLOUT_PROVIDERS", "stripe,paypal,ccbill")
    payment_incidents_shadow_mode: bool = os.environ.get("PAYMENT_INCIDENTS_SHADOW_MODE", "0") not in ("0", "false", "False")
    payment_incidents_shadow_providers: str = os.environ.get("PAYMENT_INCIDENTS_SHADOW_PROVIDERS", "")
    payment_incidents_shadow_audit_sample_limit: int = int(os.environ.get("PAYMENT_INCIDENTS_SHADOW_AUDIT_SAMPLE_LIMIT", "25"))
    payment_incidents_webhook_max_body_bytes: int = int(os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_MAX_BODY_BYTES", "262144"))
    payment_incidents_webhook_allowed_content_types: str = os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_ALLOWED_CONTENT_TYPES", "application/json")
    payment_incidents_webhook_max_signature_bytes: int = int(os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_MAX_SIGNATURE_BYTES", "2048"))
    payment_incidents_webhook_max_events: int = int(os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_MAX_EVENTS", "200"))
    payment_incidents_webhook_require_signature: bool = os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_REQUIRE_SIGNATURE", "1") not in ("0", "false", "False")
    payment_incidents_webhook_replay_ttl_seconds: int = int(os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_REPLAY_TTL_SECONDS", "300"))
    payment_incidents_webhook_replay_cache_size: int = int(os.environ.get("PAYMENT_INCIDENTS_WEBHOOK_REPLAY_CACHE_SIZE", "5000"))
    payment_incidents_backfill_apply_enabled: bool = os.environ.get("PAYMENT_INCIDENTS_BACKFILL_APPLY_ENABLED", "0") not in ("0", "false", "False")
    account_state_table_name: str = os.environ.get("ACCOUNT_STATE_TABLE_NAME", "account_state")
    billing_reconcile_enabled: bool = os.environ.get("BILLING_RECONCILE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    billing_reconcile_interval_seconds: int = int(os.environ.get("BILLING_RECONCILE_INTERVAL_SECONDS", "900"))
    billing_reconcile_pending_age_seconds: int = int(os.environ.get("BILLING_RECONCILE_PENDING_AGE_SECONDS", "3600"))
    billing_reconcile_scan_limit: int = int(os.environ.get("BILLING_RECONCILE_SCAN_LIMIT", "200"))
    billing_dunning_enabled: bool = os.environ.get("BILLING_DUNNING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    billing_dunning_interval_seconds: int = int(os.environ.get("BILLING_DUNNING_INTERVAL_SECONDS", "900"))
    billing_dunning_retry_schedule_seconds: str = os.environ.get("BILLING_DUNNING_RETRY_SCHEDULE_SECONDS", "3600,86400,172800")
    billing_dunning_scan_limit: int = int(os.environ.get("BILLING_DUNNING_SCAN_LIMIT", "200"))

    # Playback entitlement issuance and validation (VWD-018)
    playback_entitlement_secret: str = os.environ.get("PLAYBACK_ENTITLEMENT_SECRET", "")
    playback_entitlement_max_ttl_seconds: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_MAX_TTL_SECONDS", "300"))
    playback_entitlement_expected_audience: str = os.environ.get("PLAYBACK_ENTITLEMENT_EXPECTED_AUDIENCE", "playback")
    playback_entitlement_max_clock_skew_seconds: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_MAX_CLOCK_SKEW_SECONDS", "30"))
    playback_entitlement_replay_protection_enabled: bool = os.environ.get("PLAYBACK_ENTITLEMENT_REPLAY_PROTECTION_ENABLED", "0") not in ("0", "false", "False")
    playback_entitlement_max_token_length: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_MAX_TOKEN_LENGTH", "4096"))
    playback_entitlement_max_claim_length: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_MAX_CLAIM_LENGTH", "256"))
    playback_entitlement_replay_cache_max_entries: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_REPLAY_CACHE_MAX_ENTRIES", "100000"))
    playback_entitlement_revocation_jti_cache_max_entries: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_REVOCATION_JTI_CACHE_MAX_ENTRIES", "100000"))
    playback_entitlement_revocation_session_cache_max_entries: int = int(os.environ.get("PLAYBACK_ENTITLEMENT_REVOCATION_SESSION_CACHE_MAX_ENTRIES", "100000"))

    # DRM provider integration (VWD-017)
    drm_license_provider_mode: str = os.environ.get("DRM_LICENSE_PROVIDER_MODE", "mock")
    drm_provider_license_endpoint: str = os.environ.get("DRM_PROVIDER_LICENSE_ENDPOINT", "").strip()
    drm_provider_api_key: str = os.environ.get("DRM_PROVIDER_API_KEY", "")
    drm_provider_api_key_secret_name: str = os.environ.get("DRM_PROVIDER_API_KEY_SECRET_NAME", "DRM_PROVIDER_API_KEY")
    drm_provider_timeout_seconds: int = int(os.environ.get("DRM_PROVIDER_TIMEOUT_SECONDS", "5"))
    drm_key_rotation_enabled: bool = os.environ.get("DRM_KEY_ROTATION_ENABLED", "1") not in ("0", "false", "False")
    drm_key_rotation_seconds: int = int(os.environ.get("DRM_KEY_ROTATION_SECONDS", "300"))
    drm_key_rotation_salt: str = os.environ.get("DRM_KEY_ROTATION_SALT", "")

    # Tickets
    tickets_table_name: str = os.environ.get("TICKETS_TABLE_NAME", "tickets")
    tickets_owner_index_name: str = os.environ.get("TICKETS_OWNER_INDEX_NAME", "owner_sub-updated_at-index")
    tickets_assignee_index_name: str = os.environ.get("TICKETS_ASSIGNEE_INDEX_NAME", "assigned_admin_sub-updated_at-index")
    tickets_status_index_name: str = os.environ.get("TICKETS_STATUS_INDEX_NAME", "status-updated_at-index")
    tickets_space_index_name: str = os.environ.get("TICKETS_SPACE_INDEX_NAME", "space_id-updated_at-index")
    tickets_space_status_index_name: str = os.environ.get("TICKETS_SPACE_STATUS_INDEX_NAME", "space_status-updated_at-index")
    tickets_space_assignee_index_name: str = os.environ.get("TICKETS_SPACE_ASSIGNEE_INDEX_NAME", "space_assignee-updated_at-index")
    tickets_member_spaces_index_name: str = os.environ.get("TICKETS_MEMBER_SPACES_INDEX_NAME", "member_sub-space_id-index")
    # TKB: ticket boards (Kanban). Defaults OFF — when false the /boards router
    # is not registered and board columns are not seeded/back-filled, so legacy
    # space/ticket behavior is byte-for-byte unchanged.
    ticket_boards_enabled: bool = os.environ.get("TICKET_BOARDS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    tickets_jira_workspace_index_name: str = os.environ.get("TICKETS_JIRA_WORKSPACE_INDEX_NAME", "jira_workspace-updated_at-index")
    tickets_jira_issue_index_name: str = os.environ.get("TICKETS_JIRA_ISSUE_INDEX_NAME", "jira_issue-index")
    tickets_jira_sync_state_index_name: str = os.environ.get("TICKETS_JIRA_SYNC_STATE_INDEX_NAME", "jira_sync_state-updated_at-index")

    # Ticket bounties (TBT-001) — escrow-backed ticket bounties. Additive, default OFF.
    # When off, all bounty endpoints 404 and the ticket + billing systems are unchanged.
    ticket_bounties_enabled: bool = (
        os.environ.get("TICKET_BOUNTIES_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    )
    ticket_bounty_min_cents: int = int(os.environ.get("TICKET_BOUNTY_MIN_CENTS", "100"))
    ticket_bounty_max_cents: int = int(os.environ.get("TICKET_BOUNTY_MAX_CENTS", "10000000"))
    ticket_bounty_fee_bps: int = int(os.environ.get("TICKET_BOUNTY_FEE_BPS", "0"))
    ticket_bounty_payout_hold_seconds: int = int(
        os.environ.get("TICKET_BOUNTY_PAYOUT_HOLD_SECONDS", "0")
    )
    # Reserved / NOT enforced in v1 (audit D3 — no repost cap; bounty_repost_count
    # is tracked but unenforced). Kept so a future opt-in cap is a one-line flip.
    ticket_bounty_max_reposts: int = int(os.environ.get("TICKET_BOUNTY_MAX_REPOSTS", "3"))
    # TKA-001/002 — ticket file attachments (presign + store, list/download/delete). Default OFF.
    ticket_attachments_enabled: bool = os.environ.get("TICKET_ATTACHMENTS_ENABLED", "0").lower() not in ("0", "false", "no", "off", "")
    ticket_attachments_s3_bucket: str = os.environ.get("TICKET_ATTACHMENTS_S3_BUCKET", "")
    ticket_attachments_presign_ttl_seconds: int = int(os.environ.get("TICKET_ATTACHMENTS_PRESIGN_TTL_SECONDS", "900"))
    ticket_attachments_download_ttl_seconds: int = int(os.environ.get("TICKET_ATTACHMENTS_DOWNLOAD_TTL_SECONDS", "300"))
    # TBT-002 — sparse ByBounty GSI on the tickets table (funded+unclaimed board).
    tickets_bounty_index_name: str = os.environ.get(
        "TICKETS_BOUNTY_INDEX_NAME", "bounty-open-created_at-index"
    )

    # Jira integration feature flags and guardrails
    jira_sync_enabled: bool = os.environ.get("JIRA_SYNC_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    jira_sync_read_enabled: bool = os.environ.get("JIRA_SYNC_READ_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    jira_sync_outbound_enabled: bool = os.environ.get("JIRA_SYNC_OUTBOUND_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    jira_sync_inbound_enabled: bool = os.environ.get("JIRA_SYNC_INBOUND_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    jira_sync_outbound_kill_switch: bool = os.environ.get("JIRA_SYNC_OUTBOUND_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    jira_sync_workspace_allowlist: str = os.environ.get("JIRA_SYNC_WORKSPACE_ALLOWLIST", "")
    jira_sync_require_workspace_allowlist: bool = os.environ.get("JIRA_SYNC_REQUIRE_WORKSPACE_ALLOWLIST", "true").lower() == "true"
    jira_sync_require_oauth_config: bool = os.environ.get("JIRA_SYNC_REQUIRE_OAUTH_CONFIG", "true").lower() == "true"
    jira_sync_oauth_client_id: str = os.environ.get("JIRA_SYNC_OAUTH_CLIENT_ID", "")
    jira_sync_oauth_client_secret_ref: str = os.environ.get("JIRA_SYNC_OAUTH_CLIENT_SECRET_REF", "")
    jira_sync_oauth_client_secret_value: str = os.environ.get("JIRA_SYNC_OAUTH_CLIENT_SECRET_VALUE", "")
    jira_sync_oauth_authorize_url: str = os.environ.get("JIRA_SYNC_OAUTH_AUTHORIZE_URL", "https://auth.atlassian.com/authorize")
    jira_sync_oauth_token_url: str = os.environ.get("JIRA_SYNC_OAUTH_TOKEN_URL", "https://auth.atlassian.com/oauth/token")
    jira_sync_oauth_resources_url: str = os.environ.get("JIRA_SYNC_OAUTH_RESOURCES_URL", "https://api.atlassian.com/oauth/token/accessible-resources")
    jira_sync_oauth_audience: str = os.environ.get("JIRA_SYNC_OAUTH_AUDIENCE", "api.atlassian.com")
    jira_sync_oauth_scopes: str = os.environ.get("JIRA_SYNC_OAUTH_SCOPES", "read:jira-work write:jira-work offline_access")
    jira_sync_oauth_state_ttl_seconds: int = int(os.environ.get("JIRA_SYNC_OAUTH_STATE_TTL_SECONDS", "600"))
    jira_api_base_url: str = os.environ.get("JIRA_API_BASE_URL", "https://api.atlassian.com")
    jira_mock_enabled: bool = os.environ.get("JIRA_MOCK_ENABLED", "0") not in ("0", "false", "False")
    jira_api_timeout_seconds: int = int(os.environ.get("JIRA_API_TIMEOUT_SECONDS", "15"))
    jira_api_max_retries: int = int(os.environ.get("JIRA_API_MAX_RETRIES", "2"))
    jira_api_backoff_base_seconds: float = float(os.environ.get("JIRA_API_BACKOFF_BASE_SECONDS", "0.25"))

    # Profile
    profile_table_name: str = os.environ.get("PROFILE_TABLE_NAME", "profiles")
    addresses_table_name: str = os.environ.get("ADDRESSES_TABLE_NAME", "addresses")

    # Calendar
    calendar_table_name: str = os.environ.get("CALENDAR_TABLE_NAME", "calendar")
    google_calendar_sync_enabled: bool = os.environ.get("GOOGLE_CALENDAR_SYNC_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    google_calendar_writeback_enabled: bool = os.environ.get("GOOGLE_CALENDAR_WRITEBACK_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    google_calendar_tokens_kms_key_id: str = os.environ.get("GOOGLE_CALENDAR_TOKENS_KMS_KEY_ID", "")
    google_calendar_sync_rollout_mode: str = os.environ.get("GOOGLE_CALENDAR_SYNC_ROLLOUT_MODE", "all")
    google_calendar_sync_rollout_cohort_user_subs: str = os.environ.get("GOOGLE_CALENDAR_SYNC_ROLLOUT_COHORT_USER_SUBS", "")
    google_calendar_sync_rollout_percent: int = int(os.environ.get("GOOGLE_CALENDAR_SYNC_ROLLOUT_PERCENT", "100"))
    google_calendar_oauth_client_id: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_CLIENT_ID", "")
    google_calendar_oauth_redirect_uri: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_REDIRECT_URI", "")
    google_calendar_oauth_auth_base_url: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_AUTH_BASE_URL", "https://accounts.google.com/o/oauth2/v2/auth")
    google_calendar_oauth_scopes: str = os.environ.get(
        "GOOGLE_CALENDAR_OAUTH_SCOPES",
        "openid,email,profile,https://www.googleapis.com/auth/calendar.events",
    )
    google_calendar_oauth_state_ttl_seconds: int = int(os.environ.get("GOOGLE_CALENDAR_OAUTH_STATE_TTL_SECONDS", "600"))
    google_calendar_oauth_client_secret: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_CLIENT_SECRET", "")
    google_calendar_oauth_token_url: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token")
    google_calendar_oauth_userinfo_url: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_USERINFO_URL", "https://openidconnect.googleapis.com/v1/userinfo")
    google_calendar_connection_default_id: str = os.environ.get("GOOGLE_CALENDAR_CONNECTION_DEFAULT_ID", "google-primary")
    google_calendar_oauth_revoke_url: str = os.environ.get("GOOGLE_CALENDAR_OAUTH_REVOKE_URL", "https://oauth2.googleapis.com/revoke")
    google_calendar_api_base_url: str = os.environ.get("GOOGLE_CALENDAR_API_BASE_URL", "https://www.googleapis.com/calendar/v3")
    google_calendar_mock_enabled: bool = os.environ.get("GOOGLE_CALENDAR_MOCK_ENABLED", "0") not in ("0", "false", "False")
    google_calendar_api_timeout_seconds: int = int(os.environ.get("GOOGLE_CALENDAR_API_TIMEOUT_SECONDS", "20"))
    google_calendar_outbound_retry_max_attempts: int = int(os.environ.get("GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_ATTEMPTS", "5"))
    google_calendar_outbound_retry_base_seconds: float = float(os.environ.get("GOOGLE_CALENDAR_OUTBOUND_RETRY_BASE_SECONDS", "5"))
    google_calendar_outbound_retry_max_seconds: float = float(os.environ.get("GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_SECONDS", "300"))
    google_calendar_outbound_retry_jitter_ratio: float = float(os.environ.get("GOOGLE_CALENDAR_OUTBOUND_RETRY_JITTER_RATIO", "0.2"))
    google_calendar_full_import_past_days: int = int(os.environ.get("GOOGLE_CALENDAR_FULL_IMPORT_PAST_DAYS", "365"))
    google_calendar_full_import_future_days: int = int(os.environ.get("GOOGLE_CALENDAR_FULL_IMPORT_FUTURE_DAYS", "365"))
    google_calendar_event_tombstone_retention_days: int = int(os.environ.get("GOOGLE_CALENDAR_EVENT_TOMBSTONE_RETENTION_DAYS", "90"))

    # Contacts
    contacts_table_name: str = os.environ.get("DDB_CONTACTS_TABLE", "Contacts")

    # Sales pipeline (OPP-001)
    sales_pipeline_enabled: bool = os.environ.get(
        "SALES_PIPELINE_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    sales_pipeline_allow_reopen: bool = os.environ.get(
        "SALES_PIPELINE_ALLOW_REOPEN", "true"
    ).lower() in ("1", "true", "yes", "on")
    sales_opportunities_table_name: str = os.environ.get(
        "DDB_SALES_OPPORTUNITIES_TABLE", "sales_opportunities"
    )
    sales_quotas_table_name: str = os.environ.get(
        "DDB_SALES_QUOTAS_TABLE", "sales_quotas"
    )

    # Messaging
    broadcast_profiles_table_name: str = os.environ.get("DDB_BROADCAST_PROFILES", "BroadcastProfiles")
    broadcast_promo_posts_table_name: str = os.environ.get("DDB_BROADCAST_PROMO_POSTS", "BroadcastPromoPosts")
    broadcast_sessions_table_name: str = os.environ.get("DDB_BROADCAST_SESSIONS", "BroadcastSessions")
    broadcast_outputs_table_name: str = os.environ.get("DDB_BROADCAST_OUTPUTS", "BroadcastOutputs")
    broadcast_session_transitions_table_name: str = os.environ.get(
        "DDB_BROADCAST_SESSION_TRANSITIONS",
        "BroadcastSessionTransitions",
    )
    broadcast_action_audit_table_name: str = os.environ.get(
        "DDB_BROADCAST_ACTION_AUDIT",
        "BroadcastActionAudit",
    )
    broadcast_secrets_backend: str = os.environ.get("BROADCAST_SECRETS_BACKEND", "secrets_manager")
    broadcast_secret_rotation_interval_seconds: int = int(
        os.environ.get("BROADCAST_SECRET_ROTATION_INTERVAL_SECONDS", "86400")
    )
    broadcast_provider: str = os.environ.get("BROADCAST_PROVIDER", "local")
    broadcast_local_drm_token_secret: str = os.environ.get("BROADCAST_LOCAL_DRM_TOKEN_SECRET", "local-drm-secret")
    broadcast_local_drm_static_token: str = os.environ.get("BROADCAST_LOCAL_DRM_STATIC_TOKEN", "dev-token")
    broadcast_local_drm_key_root: str = os.environ.get("BROADCAST_LOCAL_DRM_KEY_ROOT", "tmp/broadcast-hls/keys")
    broadcast_local_archive_bucket: str = os.environ.get("BROADCAST_LOCAL_ARCHIVE_BUCKET", "broadcast-archive")
    broadcast_local_archive_prefix: str = os.environ.get("BROADCAST_LOCAL_ARCHIVE_PREFIX", "sessions")
    broadcast_local_cache_public_base_url: str = os.environ.get("BROADCAST_LOCAL_CACHE_PUBLIC_BASE_URL", "http://localhost:8090").rstrip("/")
    broadcast_local_cache_token_secret: str = os.environ.get("BROADCAST_LOCAL_CACHE_TOKEN_SECRET", "local-cache-secret")
    broadcast_local_cache_token_ttl_seconds: int = int(os.environ.get("BROADCAST_LOCAL_CACHE_TOKEN_TTL_SECONDS", "600"))
    broadcast_devtools_enabled: bool = os.environ.get("BROADCAST_DEVTOOLS_ENABLED", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
    broadcast_local_hls_root: str = os.environ.get("BROADCAST_LOCAL_HLS_ROOT", "tmp/broadcast-hls")
    broadcast_local_archive_root: str = os.environ.get("BROADCAST_LOCAL_ARCHIVE_ROOT", "tmp/broadcast-archive")
    broadcast_local_ffmpeg_log_path: str = os.environ.get("BROADCAST_LOCAL_FFMPEG_LOG_PATH", "tmp/broadcast-logs/ffmpeg-worker.log")
    broadcast_archive_bucket: str = os.environ.get("BROADCAST_ARCHIVE_BUCKET", "broadcast-archive")
    broadcast_archive_prefix_root: str = os.environ.get("BROADCAST_ARCHIVE_PREFIX_ROOT", "sessions")
    broadcast_archive_retention_days: int = int(os.environ.get("BROADCAST_ARCHIVE_RETENTION_DAYS", "30"))
    broadcast_cloudfront_domain: str = os.environ.get("BROADCAST_CLOUDFRONT_DOMAIN", "")
    broadcast_cloudfront_signing_secret: str = os.environ.get("BROADCAST_CLOUDFRONT_SIGNING_SECRET", "dev-cloudfront-secret")
    broadcast_cloudfront_token_ttl_seconds: int = int(os.environ.get("BROADCAST_CLOUDFRONT_TOKEN_TTL_SECONDS", "600"))
    broadcast_cloudfront_cache_policy_id: str = os.environ.get("BROADCAST_CLOUDFRONT_CACHE_POLICY_ID", "managed-caching-optimized")
    broadcast_cloudfront_response_headers_policy_id: str = os.environ.get("BROADCAST_CLOUDFRONT_RESPONSE_HEADERS_POLICY_ID", "managed-security-headers")
    broadcast_cloudfront_waf_acl_arn: str = os.environ.get("BROADCAST_CLOUDFRONT_WAF_ACL_ARN", "")
    broadcast_cloudfront_geo_allowlist: str = os.environ.get("BROADCAST_CLOUDFRONT_GEO_ALLOWLIST", "")
    broadcast_viewers_table_name: str = os.environ.get("DDB_BROADCAST_VIEWERS", "BroadcastViewers")
    broadcast_health_snapshots_table_name: str = os.environ.get("DDB_BROADCAST_HEALTH_SNAPSHOTS", "BroadcastHealthSnapshots")
    broadcast_chat_messages_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MESSAGES", "BroadcastChatMessages")
    broadcast_chat_mutes_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MUTES", "BroadcastChatMutes")
    broadcast_chat_rate_limit_ms: int = int(os.environ.get("BROADCAST_CHAT_RATE_LIMIT_MS", "2000"))
    broadcast_chat_max_message_length: int = int(os.environ.get("BROADCAST_CHAT_MAX_MESSAGE_LENGTH", "280"))
    broadcast_chat_history_default_limit: int = int(os.environ.get("BROADCAST_CHAT_HISTORY_DEFAULT_LIMIT", "100"))
    broadcast_viewer_ttl_seconds: int = int(os.environ.get("BROADCAST_VIEWER_TTL_SECONDS", "60"))
    broadcast_health_poll_interval_seconds: int = int(os.environ.get("BROADCAST_HEALTH_POLL_INTERVAL_SECONDS", "10"))
    broadcast_reconciler_enabled: bool = os.environ.get("BROADCAST_RECONCILER_ENABLED", "1") not in ("0", "false", "False")
    broadcast_reconciler_interval_seconds: int = int(os.environ.get("BROADCAST_RECONCILER_INTERVAL_SECONDS", "30"))
    broadcast_drift_sla_seconds: int = int(os.environ.get("BROADCAST_DRIFT_SLA_SECONDS", "120"))
    broadcast_stale_session_seconds: int = int(os.environ.get("BROADCAST_STALE_SESSION_SECONDS", "300"))
    broadcast_aws_start_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_START_TIMEOUT_SECONDS", "120"))
    broadcast_aws_stop_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_STOP_TIMEOUT_SECONDS", "120"))
    broadcast_aws_poll_interval_seconds: int = int(os.environ.get("BROADCAST_AWS_POLL_INTERVAL_SECONDS", "5"))
    # Broadcast tipping (BCAST-013)
    broadcast_tipping_enabled: bool = os.environ.get("BROADCAST_TIPPING_ENABLED", "1") not in ("0", "false", "False")
    broadcast_tip_min_cents: int = int(os.environ.get("BROADCAST_TIP_MIN_CENTS", "100"))
    broadcast_tip_max_cents: int = int(os.environ.get("BROADCAST_TIP_MAX_CENTS", "100000"))
    broadcast_tip_rate_limit_ms: int = int(os.environ.get("BROADCAST_TIP_RATE_LIMIT_MS", "3000"))
    broadcast_tip_goals_table_name: str = os.environ.get("DDB_BROADCAST_TIP_GOALS", "BroadcastTipGoals")
    broadcast_max_goals_per_session: int = int(os.environ.get("BROADCAST_TIP_GOALS_MAX", "5"))
    # Broadcast Ad Breaks (ADS-006)
    broadcast_preroll_enabled: bool = os.environ.get("BROADCAST_PREROLL_ENABLED", "1") not in ("0", "false", "False")
    broadcast_midroll_enabled: bool = os.environ.get("BROADCAST_MIDROLL_ENABLED", "1") not in ("0", "false", "False")
    broadcast_ad_events_table_name: str = os.environ.get("DDB_BROADCAST_AD_EVENTS", "BroadcastAdEvents")
    # Broadcast ad billing (ADS-020) — guards charge_impression + creator revenue
    # split for broadcast ad events. Default off (money-moving code; keeps dev/test
    # deterministic). Enable explicitly in production after smoke testing.
    broadcast_ads_billing_enabled: bool = os.environ.get("BROADCAST_ADS_BILLING_ENABLED", "0") not in ("0", "false", "False")
    # Broadcast Q&A (ENGAGE-003)
    broadcast_qa_enabled: bool = os.environ.get("BROADCAST_QA_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    broadcast_qa_questions_table_name: str = os.environ.get("DDB_BROADCAST_QA_QUESTIONS", "broadcast_qa_questions")
    # Live Q&A Mode (ENGAGE-003 — distinct implementation)
    live_qa_enabled: bool = os.environ.get("LIVE_QA_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    live_qa_questions_table_name: str = os.environ.get("DDB_LIVE_QA_QUESTIONS", "live_qa_questions")
    live_qa_rate_limit_ms: int = int(os.environ.get("LIVE_QA_RATE_LIMIT_MS", "30000"))
    live_qa_max_question_length: int = int(os.environ.get("LIVE_QA_MAX_QUESTION_LENGTH", "500"))
    # Broadcast lottery (BCAST-014)
    broadcast_lottery_enabled: bool = os.environ.get("BROADCAST_LOTTERY_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    broadcast_lottery_max_outcomes: int = int(os.environ.get("BROADCAST_LOTTERY_MAX_OUTCOMES", "10"))
    broadcast_lottery_max_entry_fee_cents: int = int(os.environ.get("BROADCAST_LOTTERY_MAX_ENTRY_FEE_CENTS", "10000"))
    broadcast_lottery_max_duration_seconds: int = int(os.environ.get("BROADCAST_LOTTERY_MAX_DURATION_SECONDS", "3600"))

    message_visibility_overrides_table_name: str = os.environ.get(
        "DDB_MESSAGE_VISIBILITY_OVERRIDES",
        "MessageVisibilityOverrides",
    )
    conversation_pins_table_name: str = os.environ.get(
        "DDB_CONVERSATION_PINS",
        "ConversationPins",
    )
    message_reports_table_name: str = os.environ.get(
        "DDB_MESSAGE_REPORTS",
        "MessageReports",
    )
    mass_message_campaigns_table_name: str = os.environ.get(
        "DDB_MASS_MESSAGE_CAMPAIGNS",
        "MassMessageCampaigns",
    )
    mass_message_campaign_destinations_table_name: str = os.environ.get(
        "DDB_MASS_MESSAGE_CAMPAIGN_DESTINATIONS",
        "MassMessageCampaignDestinations",
    )
    message_report_context_table_name: str = os.environ.get(
        "DDB_MESSAGE_REPORT_CONTEXT",
        "MessageReportContext",
    )
    message_threads_table_name: str = os.environ.get(
        "DDB_MESSAGE_THREADS",
        "MessageThreads",
    )
    message_call_sessions_table_name: str = os.environ.get(
        "DDB_MESSAGE_CALL_SESSIONS",
        "MessageCallSessions",
    )
    content_reports_table_name: str = os.environ.get(
        "DDB_CONTENT_REPORTS",
        "ContentReports",
    )
    moderation_tickets_table_name: str = os.environ.get(
        "DDB_MODERATION_TICKETS",
        "ModerationTickets",
    )
    moderation_actions_table_name: str = os.environ.get(
        "DDB_MODERATION_ACTIONS",
        "ModerationActions",
    )
    moderation_audit_log_table_name: str = os.environ.get(
        "DDB_MODERATION_AUDIT_LOG",
        "ModerationAuditLog",
    )
    moderation_video_queue_table_name: str = os.environ.get(
        "DDB_MODERATION_VIDEO_QUEUE",
        "ModerationVideoQueue",
    )
    moderation_video_queue_enabled: bool = os.environ.get(
        "MODERATION_VIDEO_QUEUE_ENABLED",
        "1",
    ) not in ("0", "false", "False")
    user_enforcement_history_table_name: str = os.environ.get(
        "DDB_USER_ENFORCEMENT_HISTORY",
        "UserEnforcementHistory",
    )
    dmca_claims_table_name: str = os.environ.get("DDB_DMCA_CLAIMS", "DmcaClaims")
    moderation_dual_approval_permanent_ban_enabled: bool = os.environ.get(
        "MODERATION_DUAL_APPROVAL_PERMANENT_BAN_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    moderation_kpi_lookback_hours: int = int(os.environ.get("MODERATION_KPI_LOOKBACK_HOURS", "24"))
    moderation_kpi_surge_window_minutes: int = int(os.environ.get("MODERATION_KPI_SURGE_WINDOW_MINUTES", "15"))
    moderation_alert_extortion_criminal_surge_threshold: int = int(
        os.environ.get("MODERATION_ALERT_EXTORTION_CRIMINAL_SURGE_THRESHOLD", "10")
    )
    moderation_alert_sla_open_critical_threshold: int = int(
        os.environ.get("MODERATION_ALERT_SLA_OPEN_CRITICAL_THRESHOLD", "20")
    )
    moderation_alert_sla_oldest_open_minutes_threshold: int = int(
        os.environ.get("MODERATION_ALERT_SLA_OLDEST_OPEN_MINUTES_THRESHOLD", "120")
    )
    moderation_alert_sla_window_minutes: int = int(os.environ.get("MODERATION_ALERT_SLA_WINDOW_MINUTES", "30"))
    moderation_oncall_user_subs: str = os.environ.get("MODERATION_ONCALL_USER_SUBS", "")
    message_legal_holds_table_name: str = os.environ.get(
        "DDB_MESSAGE_LEGAL_HOLDS",
        "MessageLegalHolds",
    )
    lottery_message_config_table_name: str = os.environ.get(
        "DDB_LOTTERY_MESSAGE_CONFIG",
        "LotteryMessageConfig",
    )
    lottery_message_unlocks_table_name: str = os.environ.get(
        "DDB_LOTTERY_MESSAGE_UNLOCKS",
        "LotteryMessageUnlocks",
    )
    messaging_hidden_timeline_filter_enabled: bool = os.environ.get(
        "MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_hide_controls_enabled: bool = os.environ.get(
        "MESSAGING_HIDE_CONTROLS_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_pins_enabled: bool = os.environ.get(
        "MESSAGING_PINS_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_reporting_enabled: bool = os.environ.get(
        "MESSAGING_REPORTING_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_report_rate_limit_enabled: bool = os.environ.get(
        "MESSAGING_REPORT_RATE_LIMIT_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_report_rate_limit_user_window_seconds: int = int(
        os.environ.get("MESSAGING_REPORT_RATE_LIMIT_USER_WINDOW_SECONDS", "60")
    )
    messaging_report_rate_limit_user_max: int = int(
        os.environ.get("MESSAGING_REPORT_RATE_LIMIT_USER_MAX", "5")
    )
    messaging_report_rate_limit_conversation_window_seconds: int = int(
        os.environ.get("MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_WINDOW_SECONDS", "60")
    )
    messaging_report_rate_limit_conversation_max: int = int(
        os.environ.get("MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_MAX", "20")
    )
    messaging_dm_lottery_unlock_rate_limit_enabled: bool = os.environ.get(
        "MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_ENABLED",
        "true",
    ).lower() in ("1", "true", "yes", "on")
    messaging_dm_lottery_unlock_rate_limit_window_seconds: int = int(
        os.environ.get("MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_WINDOW_SECONDS", "60")
    )
    messaging_dm_lottery_unlock_rate_limit_max: int = int(
        os.environ.get("MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_MAX", "20")
    )
    messaging_compliance_archive_enabled: bool = os.environ.get(
        "MESSAGING_COMPLIANCE_ARCHIVE_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    messaging_compliance_archive_enforce_write_success: bool = os.environ.get(
        "MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    messaging_compliance_archive_storage_mode: str = os.environ.get(
        "MESSAGING_COMPLIANCE_ARCHIVE_STORAGE_MODE",
        "filesystem",
    )
    messaging_compliance_archive_root_dir: str = os.environ.get(
        "MESSAGING_COMPLIANCE_ARCHIVE_ROOT_DIR",
        ".compliance_archive",
    )
    messaging_archive_retention_default_class: str = os.environ.get(
        "MESSAGING_ARCHIVE_RETENTION_DEFAULT_CLASS",
        "regulatory",
    )
    messaging_archive_retention_class_days_json: str = os.environ.get(
        "MESSAGING_ARCHIVE_RETENTION_CLASS_DAYS_JSON",
        '{"short":30,"standard":365,"regulatory":2555}',
    )
    messaging_archive_retention_event_class_overrides_json: str = os.environ.get(
        "MESSAGING_ARCHIVE_RETENTION_EVENT_CLASS_OVERRIDES_JSON",
        "{}",
    )
    messaging_archive_retention_tenant_overrides_json: str = os.environ.get(
        "MESSAGING_ARCHIVE_RETENTION_TENANT_OVERRIDES_JSON",
        "{}",
    )
    message_archive_chain_heads_table_name: str = os.environ.get(
        "DDB_MESSAGE_ARCHIVE_CHAIN_HEADS",
        "MessageArchiveChainHeads",
    )
    message_compliance_exports_table_name: str = os.environ.get(
        "DDB_MESSAGE_COMPLIANCE_EXPORTS",
        "MessageComplianceExports",
    )
    messaging_compliance_export_root_dir: str = os.environ.get(
        "MESSAGING_COMPLIANCE_EXPORT_ROOT_DIR",
        ".compliance_exports",
    )
    messaging_compliance_export_default_ttl_seconds: int = int(
        os.environ.get("MESSAGING_COMPLIANCE_EXPORT_DEFAULT_TTL_SECONDS", str(7 * 24 * 3600))
    )
    messaging_compliance_export_manifest_signing_key: str = os.environ.get(
        "MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY",
        "dev-export-signing-key",
    )
    messaging_compliance_export_manifest_signing_key_id: str = os.environ.get(
        "MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY_ID",
        "dev-key-v1",
    )
    messaging_compliance_export_enabled: bool = os.environ.get(
        "MESSAGING_COMPLIANCE_EXPORT_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    messaging_compliance_legal_hold_enabled: bool = os.environ.get(
        "MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    messaging_supervisory_feed_enabled: bool = os.environ.get(
        "MESSAGING_SUPERVISORY_FEED_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")
    messaging_supervisory_feed_mode: str = os.environ.get(
        "MESSAGING_SUPERVISORY_FEED_MODE",
        "log",
    )
    messaging_supervisory_feed_queue_url: str = os.environ.get(
        "MESSAGING_SUPERVISORY_FEED_QUEUE_URL",
        "",
    )
    messaging_supervisory_feed_file_path: str = os.environ.get(
        "MESSAGING_SUPERVISORY_FEED_FILE_PATH",
        ".supervisory_feed/events.jsonl",
    )
    messaging_supervisory_feed_rules_json: str = os.environ.get(
        "MESSAGING_SUPERVISORY_FEED_RULES_JSON",
        '{"report.":{"priority":"high","assignment_queue":"moderation"},"message.deleted":{"priority":"medium","assignment_queue":"supervision"},"message.revoked":{"priority":"medium","assignment_queue":"supervision"},"legal_hold.":{"priority":"high","assignment_queue":"compliance"}}',
    )

    # Purchase history
    purchase_transactions_table_name: str = os.environ.get(
        "PURCHASE_TRANSACTIONS_TABLE_NAME",
        "purchase_transactions",
    )
    purchase_events_table_name: str = os.environ.get(
        "PURCHASE_EVENTS_TABLE_NAME",
        "purchase_transaction_events",
    )
    # Shopping cart
    shopping_cart_table_name: str = os.environ.get("SHOPPING_CART_TABLE_NAME", "shopping_cart")
    # Cart Abandonment (SHOP-003)
    cart_abandonment_enabled: bool = os.environ.get("CART_ABANDONMENT_ENABLED", "1") not in ("0", "false", "False")
    cart_abandonment_threshold_hours: int = int(os.environ.get("CART_ABANDONMENT_THRESHOLD_HOURS", "24"))
    cart_abandonment_scan_interval_sec: int = int(os.environ.get("CART_ABANDONMENT_SCAN_INTERVAL_SEC", "300"))
    cart_abandonment_max_reminders: int = int(os.environ.get("CART_ABANDONMENT_MAX_REMINDERS", "2"))
    cart_abandonment_reminder_cooldown_hours: int = int(os.environ.get("CART_ABANDONMENT_REMINDER_COOLDOWN_HOURS", "48"))
    cart_abandonment_expire_hours: int = int(os.environ.get("CART_ABANDONMENT_EXPIRE_HOURS", "720"))
    cart_ttl_days: int = int(os.environ.get("CART_TTL_DAYS", "30"))
    # Multi-stage cart reminders (GAP-0189 / FIN-003)
    cart_reminders_enabled: bool = os.environ.get("CART_REMINDERS_ENABLED", "1") not in ("0", "false", "False")
    cart_reminder_config_table_name: str = os.environ.get("CART_REMINDER_CONFIG_TABLE", "cart_reminder_config")
    # PRT-001: ATS Career Portal
    career_portal_enabled: bool = os.environ.get("CAREER_PORTAL_ENABLED", "0") not in ("0", "false", "False")
    career_portal_table_name: str = os.environ.get("DDB_CAREER_PORTAL_TABLE", "CareerPortal")
    career_portal_apply_rate_limit_per_ip_per_hour: int = int(
        os.environ.get("CAREER_PORTAL_APPLY_RATE_LIMIT_PER_IP_PER_HOUR", "10")
    )
    career_portal_resume_max_bytes: int = int(
        os.environ.get("CAREER_PORTAL_RESUME_MAX_BYTES", str(10 * 1024 * 1024))
    )
    career_portal_slug_prefix: str = os.environ.get("CAREER_PORTAL_SLUG_PREFIX", "")
    career_portal_rss_max_items: int = int(
        os.environ.get("CAREER_PORTAL_RSS_MAX_ITEMS", "50")
    )
    # PRT-004 apply autoresponder
    career_portal_apply_autoresponder_enabled: bool = (
        os.environ.get("CAREER_PORTAL_APPLY_AUTORESPONDER_ENABLED", "0") not in ("0", "false", "False")
    )
    career_portal_apply_autoresponder_subject: str = (
        os.environ.get("CAREER_PORTAL_APPLY_AUTORESPONDER_SUBJECT", "We received your application")
    )
    career_portal_apply_notify_email: str = os.environ.get("CAREER_PORTAL_APPLY_NOTIFY_EMAIL", "")
    # Cart recovery one-time link signing (GAP-0190 / FIN-003). Defaults to the
    # UI access-token secret so dev (no extra env) and prod (set via env) both
    # produce verifiable signed tokens — dev/prod parity (SECOPS-007).
    cart_recovery_link_secret: str = (
        os.environ.get("CART_RECOVERY_LINK_SECRET")
        or os.environ.get("UI_ACCESS_TOKEN_SECRET", "")
    )
    cart_recovery_link_ttl_days: int = int(os.environ.get("CART_RECOVERY_LINK_TTL_DAYS", "7"))
    # OFBiz Manufacturing/MRP (MFG-001..MFG-014). Master switch defaults OFF.
    manufacturing_mrp_enabled: bool = os.environ.get("MANUFACTURING_MRP_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    mfg_boms_table_name: str = os.environ.get("MFG_BOMS_TABLE_NAME", "mfg_boms")
    mfg_work_centers_table_name: str = os.environ.get("MFG_WORK_CENTERS_TABLE_NAME", "mfg_work_centers")
    mfg_work_orders_table_name: str = os.environ.get("MFG_WORK_ORDERS_TABLE_NAME", "mfg_work_orders")
    mfg_mrp_table_name: str = os.environ.get("MFG_MRP_TABLE_NAME", "mfg_mrp")
    mfg_mrp_default_horizon_days: int = int(os.environ.get("MFG_MRP_DEFAULT_HORIZON_DAYS", "30"))
    mfg_bom_max_explosion_depth: int = int(os.environ.get("MFG_BOM_MAX_EXPLOSION_DEPTH", "5"))
    manufacturing_cost_posting_enabled: bool = os.environ.get("MANUFACTURING_COST_POSTING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    # Catalog
    catalog_table_name: str = os.environ.get("CATALOG_TABLE_NAME", "shopping_catalog")
    catalog_default_low_stock_threshold: int = int(os.environ.get("CATALOG_LOW_STOCK_THRESHOLD", "5"))
    catalog_stock_alerts_enabled: bool = os.environ.get("CATALOG_STOCK_ALERTS_ENABLED", "1") not in ("0", "false", "False")
    # OFBiz Catalog/Product Depth (PRD-001..PRD-016)
    # Master switch defaults OFF. Sub-flags default True so enabling the master
    # activates all depth features; operators can disable individual axes.
    product_depth_enabled: bool = os.environ.get("PRODUCT_DEPTH_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    product_depth_table_name: str = os.environ.get("PRODUCT_DEPTH_TABLE_NAME", "product_depth")
    product_depth_variants_enabled: bool = os.environ.get("PRODUCT_DEPTH_VARIANTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    product_depth_bundles_enabled: bool = os.environ.get("PRODUCT_DEPTH_BUNDLES_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    product_depth_features_enabled: bool = os.environ.get("PRODUCT_DEPTH_FEATURES_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    product_depth_price_components_enabled: bool = os.environ.get("PRODUCT_DEPTH_PRICE_COMPONENTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    product_depth_max_category_depth: int = int(os.environ.get("PRODUCT_DEPTH_MAX_CATEGORY_DEPTH", "10"))
    product_depth_max_variants_per_item: int = int(os.environ.get("PRODUCT_DEPTH_MAX_VARIANTS_PER_ITEM", "1000"))

    # OFBiz commerce/ERP — Phase 1: inventory & soft reservations (ADR-001, OFB-002/003/004).
    # Master switch defaults OFF: with it off, the catalog/cart/billing decrement-at-purchase
    # path is byte-for-byte unchanged; the inventory service is dormant.
    inventory_reservations_enabled: bool = os.environ.get("INVENTORY_RESERVATIONS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    inventory_reservation_ttl_seconds: int = int(os.environ.get("INVENTORY_RESERVATION_TTL_SECONDS", "1800"))
    inventory_table_name: str = os.environ.get("INVENTORY_TABLE_NAME", "inventory")
    reservations_table_name: str = os.environ.get("RESERVATIONS_TABLE_NAME", "reservations")
    gl_double_entry_enabled: bool = os.environ.get("GL_DOUBLE_ENTRY_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    gl_accounts_table_name: str = os.environ.get("GL_ACCOUNTS_TABLE_NAME", "gl_accounts")
    gl_journal_table_name: str = os.environ.get("GL_JOURNAL_TABLE_NAME", "gl_journal")
    gl_ar_ap_enabled: bool = os.environ.get("GL_AR_AP_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    ar_ap_subledgers_enabled: bool = os.environ.get("AR_AP_SUBLEDGERS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    ar_ap_snapshots_table_name: str = os.environ.get("AR_AP_SNAPSHOTS_TABLE_NAME", "ar_ap_snapshots")
    pricing_rules_enabled: bool = os.environ.get("PRICING_RULES_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    pricing_rules_table_name: str = os.environ.get("PRICING_RULES_TABLE_NAME", "PricingRules")
    # OFBiz commerce/ERP Milestone 3 — Returns / RMA (ADR-001, OFB-008..010).
    # Master switch defaults OFF: with it off the returns/RMA endpoints 404 and
    # the module is dormant; existing order/billing behavior is unchanged.
    # Store integration layer (ECM-002 / Phase 8-J). Master switch: when False the entire store-integration layer is dormant and the catalog/cart/checkout paths are byte-for-byte unchanged.
    store_integration_enabled: bool = os.environ.get("STORE_INTEGRATION_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    # Per-surface sub-flags — each is AND-ed with the master switch inside _integration_enabled(sub_flag). All default false so production deployments can enable surfaces incrementally without a code change.
    store_show_live_availability: bool = os.environ.get("STORE_SHOW_LIVE_AVAILABILITY", "false").lower() in ("1", "true", "yes", "on")
    store_apply_pricing_rules: bool = os.environ.get("STORE_APPLY_PRICING_RULES", "false").lower() in ("1", "true", "yes", "on")
    store_show_fulfillment_status: bool = os.environ.get("STORE_SHOW_FULFILLMENT_STATUS", "false").lower() in ("1", "true", "yes", "on")
    store_variant_selection_enabled: bool = os.environ.get("STORE_VARIANT_SELECTION_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    # ECM-008: reserve-on-add-to-cart flag (both this AND inventory_reservations_enabled must be true)
    store_cart_reservations_enabled: bool = os.environ.get("STORE_CART_RESERVATIONS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    returns_rma_enabled: bool = os.environ.get("RETURNS_RMA_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    returns_table_name: str = os.environ.get("RETURNS_TABLE_NAME", "returns")

    # File manager
    filemgr_table_name: str = os.environ.get("FILEMGR_TABLE", "")
    filemgr_mounts_table_name: str = os.environ.get("FILEMGR_MOUNTS_TABLE_NAME", "filemgr_mounts")
    filemgr_mount_secret_prefix: str = os.environ.get("FILEMGR_MOUNT_SECRET_PREFIX", "filemgr/mounts")
    filemgr_mount_secret_kms_key_id: str = os.environ.get("FILEMGR_MOUNT_SECRET_KMS_KEY_ID", "")
    filemgr_mount_secret_require_cmk: bool = os.environ.get("FILEMGR_MOUNT_SECRET_REQUIRE_CMK", "1") not in ("0", "false", "False")
    filemgr_mount_initiate_max_per_window: int = int(os.environ.get("FILEMGR_MOUNT_INITIATE_MAX_PER_WINDOW", "5"))
    filemgr_mount_initiate_window_seconds: int = int(os.environ.get("FILEMGR_MOUNT_INITIATE_WINDOW_SECONDS", "900"))
    filemgr_mount_verify_max_per_window: int = int(os.environ.get("FILEMGR_MOUNT_VERIFY_MAX_PER_WINDOW", "10"))
    filemgr_mount_verify_window_seconds: int = int(os.environ.get("FILEMGR_MOUNT_VERIFY_WINDOW_SECONDS", "900"))
    filemgr_mount_rotate_max_per_window: int = int(os.environ.get("FILEMGR_MOUNT_ROTATE_MAX_PER_WINDOW", "6"))
    filemgr_mount_rotate_window_seconds: int = int(os.environ.get("FILEMGR_MOUNT_ROTATE_WINDOW_SECONDS", "900"))
    filemgr_mount_revoke_max_per_window: int = int(os.environ.get("FILEMGR_MOUNT_REVOKE_MAX_PER_WINDOW", "4"))
    filemgr_mount_revoke_window_seconds: int = int(os.environ.get("FILEMGR_MOUNT_REVOKE_WINDOW_SECONDS", "900"))
    filemgr_mount_verify_session_max_attempts: int = int(os.environ.get("FILEMGR_MOUNT_VERIFY_SESSION_MAX_ATTEMPTS", "5"))
    filemgr_icloud_provider_enabled: bool = os.environ.get("FILEMGR_ICLOUD_PROVIDER_ENABLED", "0") == "1"
    filemgr_icloud_read_only: bool = os.environ.get("FILEMGR_ICLOUD_READ_ONLY", "0") not in ("0", "false", "False")
    filemgr_icloud_mount_enabled: bool = os.environ.get("FILEMGR_ICLOUD_MOUNT_ENABLED", "1") == "1"
    filemgr_icloud_mount_rollout_mode: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_ROLLOUT_MODE", "ga")
    filemgr_icloud_mount_environment: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_ENVIRONMENT", os.environ.get("ENVIRONMENT", "dev"))
    filemgr_icloud_mount_rollout_mode_by_env: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_ROLLOUT_MODE_BY_ENV", "")
    filemgr_icloud_mount_kill_switch: bool = os.environ.get("FILEMGR_ICLOUD_MOUNT_KILL_SWITCH", "0") == "1"
    filemgr_icloud_mount_enabled_tenant_ids: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_ENABLED_TENANT_IDS", "")

    # Property management — Tenants (TEN-001)
    property_tenants_enabled: bool = os.environ.get("PROPERTY_TENANTS_ENABLED", "0") not in ("0", "false", "False")
    property_tenants_table_name: str = os.environ.get("DDB_PROPERTY_TENANTS_TABLE", "property_tenants")
    filemgr_icloud_mount_disabled_tenant_ids: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_DISABLED_TENANT_IDS", "")
    filemgr_icloud_mount_internal_user_subs: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_INTERNAL_USER_SUBS", "")
    filemgr_icloud_mount_internal_tenant_ids: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_INTERNAL_TENANT_IDS", "")
    filemgr_icloud_mount_beta_user_subs: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_BETA_USER_SUBS", "")
    filemgr_icloud_mount_beta_tenant_ids: str = os.environ.get("FILEMGR_ICLOUD_MOUNT_BETA_TENANT_IDS", "")
    filemgr_icloud_read_cache_enabled: bool = os.environ.get("FILEMGR_ICLOUD_READ_CACHE_ENABLED", "0") == "1"
    filemgr_icloud_read_cache_ttl_seconds: int = int(os.environ.get("FILEMGR_ICLOUD_READ_CACHE_TTL_SECONDS", "120"))
    filemgr_icloud_read_cache_min_bytes: int = int(os.environ.get("FILEMGR_ICLOUD_READ_CACHE_MIN_BYTES", str(1024 * 1024)))
    filemgr_icloud_read_cache_freq_threshold: int = int(os.environ.get("FILEMGR_ICLOUD_READ_CACHE_FREQ_THRESHOLD", "3"))
    filemgr_icloud_read_cache_max_entries: int = int(os.environ.get("FILEMGR_ICLOUD_READ_CACHE_MAX_ENTRIES", "256"))
    filemgr_icloud_retry_max_attempts: int = int(os.environ.get("FILEMGR_ICLOUD_RETRY_MAX_ATTEMPTS", "3"))
    filemgr_icloud_retry_base_seconds: float = float(os.environ.get("FILEMGR_ICLOUD_RETRY_BASE_SECONDS", "0.2"))
    filemgr_icloud_retry_cap_seconds: float = float(os.environ.get("FILEMGR_ICLOUD_RETRY_CAP_SECONDS", "2.0"))
    filemgr_mount_degraded_fail_threshold: int = int(os.environ.get("FILEMGR_MOUNT_DEGRADED_FAIL_THRESHOLD", "3"))
    filemgr_mount_reauth_fail_threshold: int = int(os.environ.get("FILEMGR_MOUNT_REAUTH_FAIL_THRESHOLD", "2"))
    filemgr_mount_unavailable_fail_threshold: int = int(os.environ.get("FILEMGR_MOUNT_UNAVAILABLE_FAIL_THRESHOLD", "6"))
    filemgr_mount_recovery_success_threshold: int = int(os.environ.get("FILEMGR_MOUNT_RECOVERY_SUCCESS_THRESHOLD", "2"))
    filemgr_mount_status_update_sla_seconds: int = int(os.environ.get("FILEMGR_MOUNT_STATUS_UPDATE_SLA_SECONDS", "30"))
    filemgr_mount_reconcile_enabled: bool = os.environ.get("FILEMGR_MOUNT_RECONCILE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_mount_reconcile_interval_seconds: int = int(os.environ.get("FILEMGR_MOUNT_RECONCILE_INTERVAL_SECONDS", "900"))
    filemgr_mount_reconcile_scan_limit: int = int(os.environ.get("FILEMGR_MOUNT_RECONCILE_SCAN_LIMIT", "100"))
    filemgr_mount_reconcile_local_page_limit: int = int(os.environ.get("FILEMGR_MOUNT_RECONCILE_LOCAL_PAGE_LIMIT", "200"))
    filemgr_mount_reconcile_dry_run: bool = os.environ.get("FILEMGR_MOUNT_RECONCILE_DRY_RUN", "true").lower() == "true"
    projects_table_name: str = os.environ.get("PROJECTS_TABLE_NAME", "projects")
    signature_packets_table_name: str = os.environ.get("SIGNATURE_PACKETS_TABLE_NAME", "signature_packets")
    signature_packet_signers_table_name: str = os.environ.get(
        "SIGNATURE_PACKET_SIGNERS_TABLE_NAME",
        "signature_packet_signers",
    )
    signature_packet_fields_table_name: str = os.environ.get(
        "SIGNATURE_PACKET_FIELDS_TABLE_NAME",
        "signature_packet_fields",
    )
    signature_packet_events_table_name: str = os.environ.get(
        "SIGNATURE_PACKET_EVENTS_TABLE_NAME",
        "signature_packet_events",
    )
    signature_packet_artifacts_table_name: str = os.environ.get(
        "SIGNATURE_PACKET_ARTIFACTS_TABLE_NAME",
        "signature_packet_artifacts",
    )
    signature_pdf_enabled: bool = os.environ.get("SIGNATURE_PDF_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    signature_packet_expiration_hours: int = int(os.environ.get("SIGNATURE_PACKET_EXPIRATION_HOURS", "168"))
    signature_packet_max_signers: int = int(os.environ.get("SIGNATURE_PACKET_MAX_SIGNERS", "10"))
    signature_packet_max_fields: int = int(os.environ.get("SIGNATURE_PACKET_MAX_FIELDS", "200"))
    signature_packet_renderer_timeout_seconds: int = int(
        os.environ.get("SIGNATURE_PACKET_RENDERER_TIMEOUT_SECONDS", "60")
    )
    signature_packet_legal_notice_version: str = os.environ.get("SIGNATURE_PACKET_LEGAL_NOTICE_VERSION", "2026-01")
    signature_packet_legal_notice_text: str = os.environ.get(
        "SIGNATURE_PACKET_LEGAL_NOTICE_TEXT",
        "By signing this document, you agree your signature is legally binding.",
    )
    signature_packet_reminder_schedule_hours: str = os.environ.get("SIGNATURE_PACKET_REMINDER_SCHEDULE_HOURS", "24,72,168")
    # SUX-001: public tokenized signing links. Mirrors cart_recovery_link_* —
    # secret falls back to the UI access-token secret so dev (no extra env) and
    # prod (set via env) both verify, dev/prod parity (SECOPS-007). Flag default
    # OFF so existing behaviour is byte-for-byte unchanged until enabled.
    signature_public_link_enabled: bool = os.environ.get("SIGNATURE_PUBLIC_LINK_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    signature_packet_public_link_secret: str = (
        os.environ.get("SIGNATURE_PACKET_PUBLIC_LINK_SECRET")
        or os.environ.get("UI_ACCESS_TOKEN_SECRET", "")
    )
    signature_packet_public_link_ttl_days: int = int(os.environ.get("SIGNATURE_PACKET_PUBLIC_LINK_TTL_DAYS", "14"))
    signature_public_link_rate_max_per_window: int = int(os.environ.get("SIGNATURE_PUBLIC_LINK_RATE_MAX_PER_WINDOW", "60"))
    signature_public_link_rate_window_seconds: int = int(os.environ.get("SIGNATURE_PUBLIC_LINK_RATE_WINDOW_SECONDS", "3600"))
    signature_templates_table_name: str = os.environ.get(
        "SIGNATURE_TEMPLATES_TABLE_NAME",
        "signature_templates",
    )
    signature_template_versioning_enabled: bool = os.environ.get(
        "SIGNATURE_TEMPLATE_VERSIONING_ENABLED",
        "true",
    ).lower() not in ("0", "false", "no", "off")
    filemgr_bucket: str = os.environ.get("FILEMGR_BUCKET", "")
    filemgr_retention_days: int = int(os.environ.get("FILEMGR_RETENTION_DAYS", "30"))
    filemgr_purge_scan_limit: int = int(os.environ.get("FILEMGR_PURGE_SCAN_LIMIT", "200"))
    filemgr_purge_enabled: bool = os.environ.get("FILEMGR_PURGE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_purge_interval_seconds: int = int(os.environ.get("FILEMGR_PURGE_INTERVAL_SECONDS", "900"))
    filemgr_admin_content_access_tier: str = os.environ.get("FILEMGR_ADMIN_CONTENT_ACCESS_TIER", "none")
    filemgr_purge_index_name: str = os.environ.get("FILEMGR_PURGE_INDEX_NAME", "GSI_PURGE")
    filemgr_s3_mounts_enabled: bool = os.environ.get("FILEMGR_S3_MOUNTS_ENABLED", "false").lower() == "true"
    filemgr_s3_mounts_write_enabled: bool = os.environ.get("FILEMGR_S3_MOUNTS_WRITE_ENABLED", "false").lower() == "true"
    filemgr_s3_mounts_allowed_bucket_patterns: str = os.environ.get("FILEMGR_S3_MOUNTS_ALLOWED_BUCKET_PATTERNS", "")
    filemgr_s3_mounts_max_upload_bytes: int = int(os.environ.get("FILEMGR_S3_MOUNTS_MAX_UPLOAD_BYTES", "0"))
    filemgr_s3_mounts_max_download_bytes: int = int(os.environ.get("FILEMGR_S3_MOUNTS_MAX_DOWNLOAD_BYTES", "0"))
    filemgr_s3_mounts_upload_rate_per_minute: int = int(os.environ.get("FILEMGR_S3_MOUNTS_UPLOAD_RATE_PER_MINUTE", "0"))
    filemgr_s3_mounts_download_rate_per_minute: int = int(os.environ.get("FILEMGR_S3_MOUNTS_DOWNLOAD_RATE_PER_MINUTE", "0"))

    # Encrypted one-time share links (FILES-001)
    file_share_links_enabled: bool = os.environ.get("FILE_SHARE_LINKS_ENABLED", "true").lower() == "true"
    ddb_file_share_links_table: str = os.environ.get("DDB_FILE_SHARE_LINKS_TABLE", "file_share_links")
    share_link_default_expiry_hours: int = int(os.environ.get("SHARE_LINK_DEFAULT_EXPIRY_HOURS", "24"))
    share_link_max_expiry_hours: int = int(os.environ.get("SHARE_LINK_MAX_EXPIRY_HOURS", "720"))  # 30 days
    share_link_max_file_size_bytes: int = int(os.environ.get("SHARE_LINK_MAX_FILE_SIZE", "1073741824"))  # 1GB
    share_link_s3_prefix: str = os.environ.get("SHARE_LINK_S3_PREFIX", "share-links")
    share_link_base_url: str = os.environ.get("SHARE_LINK_BASE_URL", "http://localhost:3000/share").rstrip("/")

    projects_reconcile_enabled: bool = os.environ.get("PROJECTS_RECONCILE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    projects_reconcile_interval_seconds: int = int(os.environ.get("PROJECTS_RECONCILE_INTERVAL_SECONDS", "900"))
    projects_reconcile_scan_limit: int = int(os.environ.get("PROJECTS_RECONCILE_SCAN_LIMIT", "200"))
    projects_reconcile_max_attempts: int = int(os.environ.get("PROJECTS_RECONCILE_MAX_ATTEMPTS", "3"))
    projects_reconcile_backoff_seconds: float = float(os.environ.get("PROJECTS_RECONCILE_BACKOFF_SECONDS", "0.2"))
    projects_provider_failure_alert_threshold: int = int(
        os.environ.get("PROJECTS_PROVIDER_FAILURE_ALERT_THRESHOLD", "5")
    )
    github_api_base_url: str = os.environ.get("GITHUB_API_BASE_URL", "https://api.github.com").rstrip("/")
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    # Name/ARN of an AWS Secrets Manager secret holding the GitHub token (GAP-0102).
    # In prod the raw token is resolved from Secrets Manager by name; in dev the
    # ``github_token`` env var is used as a fallback. The raw token is never stored
    # in DynamoDB config nor returned in API responses.
    github_token_secret_name: str = os.environ.get("GITHUB_TOKEN_SECRET_NAME", "")
    github_webhook_secret: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    gitlab_api_base_url: str = os.environ.get("GITLAB_API_BASE_URL", "https://gitlab.com/api/v4").rstrip("/")
    google_oauth_client_id: str = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "")
    google_oauth_client_secret: str = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "")
    google_oauth_redirect_uri: str = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI", "")
    google_oauth_redirect_uri_allowlist: str = os.environ.get("GOOGLE_OAUTH_REDIRECT_URI_ALLOWLIST", "")
    google_oauth_scopes: str = os.environ.get("GOOGLE_OAUTH_SCOPES", "https://www.googleapis.com/auth/drive.file")
    google_oauth_state_ttl_seconds: int = int(os.environ.get("GOOGLE_OAUTH_STATE_TTL_SECONDS", "600"))
    google_oauth_state_signing_secret: str = os.environ.get("GOOGLE_OAUTH_STATE_SIGNING_SECRET", "")
    google_oauth_token_url: str = os.environ.get("GOOGLE_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token")
    google_drive_api_base_url: str = os.environ.get("GOOGLE_DRIVE_API_BASE_URL", "https://www.googleapis.com/drive/v3").rstrip("/")
    google_drive_upload_api_base_url: str = os.environ.get("GOOGLE_DRIVE_UPLOAD_API_BASE_URL", "https://www.googleapis.com/upload/drive/v3").rstrip("/")
    google_drive_mock_enabled: bool = os.environ.get("GOOGLE_DRIVE_MOCK_ENABLED", "0") not in ("0", "false", "False")
    google_drive_api_timeout_seconds: float = float(os.environ.get("GOOGLE_DRIVE_API_TIMEOUT_SECONDS", "10"))
    google_drive_api_retry_max_attempts: int = int(os.environ.get("GOOGLE_DRIVE_API_RETRY_MAX_ATTEMPTS", "3"))
    google_drive_api_retry_base_delay_seconds: float = float(os.environ.get("GOOGLE_DRIVE_API_RETRY_BASE_DELAY_SECONDS", "0.2"))
    google_drive_api_retry_jitter_seconds: float = float(os.environ.get("GOOGLE_DRIVE_API_RETRY_JITTER_SECONDS", "0.1"))
    google_drive_resumable_upload_threshold_bytes: int = int(os.environ.get("GOOGLE_DRIVE_RESUMABLE_UPLOAD_THRESHOLD_BYTES", "8388608"))
    filemgr_google_drive_mounts_enabled: bool = os.environ.get("FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_zip_max_entries: int = int(os.environ.get("FILEMGR_ZIP_MAX_ENTRIES", "1000"))
    filemgr_zip_max_total_uncompressed_bytes: int = int(
        os.environ.get("FILEMGR_ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES", "524288000")
    )
    filemgr_zip_max_entry_uncompressed_bytes: int = int(
        os.environ.get("FILEMGR_ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES", "52428800")
    )
    filemgr_zip_max_compression_ratio: float = float(os.environ.get("FILEMGR_ZIP_MAX_COMPRESSION_RATIO", "100.0"))
    filemgr_zip_extract_timeout_seconds: int = int(os.environ.get("FILEMGR_ZIP_EXTRACT_TIMEOUT_SECONDS", "30"))
    filemgr_preview_max_bytes: int = int(os.environ.get("FILEMGR_PREVIEW_MAX_BYTES", "10485760"))
    filemgr_preview_text_max_lines: int = int(os.environ.get("FILEMGR_PREVIEW_TEXT_MAX_LINES", "5000"))
    filemgr_preview_table_max_rows: int = int(os.environ.get("FILEMGR_PREVIEW_TABLE_MAX_ROWS", "5000"))
    filemgr_preview_table_max_cols: int = int(os.environ.get("FILEMGR_PREVIEW_TABLE_MAX_COLS", "200"))
    filemgr_preview_parse_timeout_seconds: int = int(os.environ.get("FILEMGR_PREVIEW_PARSE_TIMEOUT_SECONDS", "10"))
    filemgr_media_previews_v1: bool = os.environ.get("FILEMGR_MEDIA_PREVIEWS_V1", "false").lower() == "true"
    filemgr_video_hover_clip_enabled: bool = os.environ.get("FILEMGR_VIDEO_HOVER_CLIP_ENABLED", "true").lower() == "true"
    filemgr_audio_waveform_enabled: bool = os.environ.get("FILEMGR_AUDIO_WAVEFORM_ENABLED", "true").lower() == "true"
    filemgr_video_preview_max_mb: int = int(os.environ.get("FILEMGR_VIDEO_PREVIEW_MAX_MB", "200"))
    filemgr_video_preview_max_duration_seconds: int = int(os.environ.get("FILEMGR_VIDEO_PREVIEW_MAX_DURATION_SECONDS", "600"))
    filemgr_video_preview_clip_seconds: int = int(os.environ.get("FILEMGR_VIDEO_PREVIEW_CLIP_SECONDS", "6"))
    filemgr_video_preview_target_height: int = int(os.environ.get("FILEMGR_VIDEO_PREVIEW_TARGET_HEIGHT", "360"))
    filemgr_audio_waveform_max_mb: int = int(os.environ.get("FILEMGR_AUDIO_WAVEFORM_MAX_MB", "100"))
    filemgr_preview_job_timeout_seconds: int = int(os.environ.get("FILEMGR_PREVIEW_JOB_TIMEOUT_SECONDS", "120"))
    filemgr_preview_worker_concurrency: int = int(os.environ.get("FILEMGR_PREVIEW_WORKER_CONCURRENCY", "4"))
    filemgr_preview_job_max_attempts: int = int(os.environ.get("FILEMGR_PREVIEW_JOB_MAX_ATTEMPTS", "3"))
    filemgr_media_preview_cdn_base_url: str = os.environ.get("FILEMGR_MEDIA_PREVIEW_CDN_BASE_URL", "")
    # GAP-0182: comma-separated allowlist of GIF CDN domains accepted for newsfeed gif comments.
    gif_cdn_allowed_domains: str = os.environ.get(
        "GIF_CDN_ALLOWED_DOMAINS",
        "media.giphy.com,media0.giphy.com,media1.giphy.com,media2.giphy.com,"
        "media3.giphy.com,media4.giphy.com,media.tenor.com,c.tenor.com",
    )
    # GAP-0183: comma-separated allowlist of additional platform sticker URL prefixes
    # (relative paths or absolute CDN origins) accepted for newsfeed sticker comments.
    sticker_cdn_allowed_prefixes: str = os.environ.get("STICKER_CDN_ALLOWED_PREFIXES", "")
    filemgr_media_preview_url_ttl_seconds: int = int(os.environ.get("FILEMGR_MEDIA_PREVIEW_URL_TTL_SECONDS", "900"))
    filemgr_media_preview_private: bool = os.environ.get("FILEMGR_MEDIA_PREVIEW_PRIVATE", "true").lower() == "true"
    filemgr_usage_upload_limit_bytes: int = int(os.environ.get("FILEMGR_USAGE_UPLOAD_LIMIT_BYTES", "0"))
    filemgr_usage_download_limit_bytes: int = int(os.environ.get("FILEMGR_USAGE_DOWNLOAD_LIMIT_BYTES", "0"))
    filemgr_usage_storage_limit_bytes: int = int(os.environ.get("FILEMGR_USAGE_STORAGE_LIMIT_BYTES", "0"))
    filemgr_usage_message_send_limit_count: int = int(os.environ.get("FILEMGR_USAGE_MESSAGE_SEND_LIMIT_COUNT", "0"))
    filemgr_usage_post_publish_limit_count: int = int(os.environ.get("FILEMGR_USAGE_POST_PUBLISH_LIMIT_COUNT", "0"))
    filemgr_usage_default_plan: str = os.environ.get("FILEMGR_USAGE_DEFAULT_PLAN", "default")
    filemgr_usage_plan_limits: str = os.environ.get("FILEMGR_USAGE_PLAN_LIMITS", "")
    filemgr_usage_user_plan_overrides: str = os.environ.get("FILEMGR_USAGE_USER_PLAN_OVERRIDES", "")
    filemgr_download_policy_mode: str = os.environ.get("FILEMGR_DOWNLOAD_POLICY_MODE", "off")
    filemgr_usage_pricing_catalog: str = os.environ.get("FILEMGR_USAGE_PRICING_CATALOG", "")
    filemgr_usage_default_pricing_catalog_version: str = os.environ.get("FILEMGR_USAGE_DEFAULT_PRICING_CATALOG_VERSION", "v1")
    filemgr_usage_event_retention_days: int = int(os.environ.get("FILEMGR_USAGE_EVENT_RETENTION_DAYS", "365"))
    filemgr_usage_aggregate_retention_days: int = int(os.environ.get("FILEMGR_USAGE_AGGREGATE_RETENTION_DAYS", "1095"))
    filemgr_usage_snapshot_retention_days: int = int(os.environ.get("FILEMGR_USAGE_SNAPSHOT_RETENTION_DAYS", "2555"))
    filemgr_usage_billing_record_retention_days: int = int(os.environ.get("FILEMGR_USAGE_BILLING_RECORD_RETENTION_DAYS", "2555"))
    filemgr_admin_users: str = os.environ.get("FILEMGR_ADMIN_USERS", "")
    filemgr_sftp_mounts_enabled: bool = os.environ.get("FILEMGR_SFTP_MOUNTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_sftp_mounts_write_enabled: bool = os.environ.get("FILEMGR_SFTP_MOUNTS_WRITE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_sftp_mounts_share_enabled: bool = os.environ.get("FILEMGR_SFTP_MOUNTS_SHARE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_sftp_credentials_table_name: str = os.environ.get("FILEMGR_SFTP_CREDENTIALS_TABLE_NAME", "")
    filemgr_sftp_credentials_kms_key_id: str = os.environ.get("FILEMGR_SFTP_CREDENTIALS_KMS_KEY_ID", "")
    filemgr_sftp_mounts_table_name: str = os.environ.get("FILEMGR_SFTP_MOUNTS_TABLE_NAME", "")
    filemgr_sftp_mounts_owner_index_name: str = os.environ.get("FILEMGR_SFTP_MOUNTS_OWNER_INDEX_NAME", "GSI1")
    filemgr_sftp_mounts_lookup_index_name: str = os.environ.get("FILEMGR_SFTP_MOUNTS_LOOKUP_INDEX_NAME", "GSI2")
    filemgr_sftp_connect_timeout_seconds: int = int(os.environ.get("FILEMGR_SFTP_CONNECT_TIMEOUT_SECONDS", "10"))
    filemgr_sftp_pool_max_connections: int = int(os.environ.get("FILEMGR_SFTP_POOL_MAX_CONNECTIONS", "64"))
    filemgr_sftp_host_key_policy: str = os.environ.get("FILEMGR_SFTP_HOST_KEY_POLICY", "strict")
    filemgr_sftp_operation_timeout_seconds: int = int(os.environ.get("FILEMGR_SFTP_OPERATION_TIMEOUT_SECONDS", "20"))
    filemgr_sftp_retry_max_attempts: int = int(os.environ.get("FILEMGR_SFTP_RETRY_MAX_ATTEMPTS", "2"))
    filemgr_sftp_retry_backoff_ms: int = int(os.environ.get("FILEMGR_SFTP_RETRY_BACKOFF_MS", "100"))
    filemgr_sftp_circuit_failure_threshold: int = int(os.environ.get("FILEMGR_SFTP_CIRCUIT_FAILURE_THRESHOLD", "5"))
    filemgr_sftp_circuit_open_seconds: int = int(os.environ.get("FILEMGR_SFTP_CIRCUIT_OPEN_SECONDS", "30"))
    filemgr_sftp_health_refresh_enabled: bool = os.environ.get("FILEMGR_SFTP_HEALTH_REFRESH_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    filemgr_sftp_health_refresh_interval_seconds: int = int(os.environ.get("FILEMGR_SFTP_HEALTH_REFRESH_INTERVAL_SECONDS", "300"))
    filemgr_sftp_health_refresh_limit: int = int(os.environ.get("FILEMGR_SFTP_HEALTH_REFRESH_LIMIT", "20"))
    filemgr_sftp_destination_policy_mode: str = os.environ.get("FILEMGR_SFTP_DESTINATION_POLICY_MODE", "allow_all")
    filemgr_sftp_allowed_destinations: str = os.environ.get("FILEMGR_SFTP_ALLOWED_DESTINATIONS", "")
    filemgr_sftp_backend: str = os.environ.get("FILEMGR_SFTP_BACKEND", "paramiko")
    filemgr_sftp_mock_root_dir: str = os.environ.get("FILEMGR_SFTP_MOCK_ROOT_DIR", "/tmp/filemgr-sftp-mock")
    filemgr_sftp_mock_scan_max_entries: int = int(os.environ.get("FILEMGR_SFTP_MOCK_SCAN_MAX_ENTRIES", "5000"))
    filemgr_sftp_mock_path_max_depth: int = int(os.environ.get("FILEMGR_SFTP_MOCK_PATH_MAX_DEPTH", "32"))
    filemgr_sftp_mock_rate_limit_per_minute: int = int(os.environ.get("FILEMGR_SFTP_MOCK_RATE_LIMIT_PER_MINUTE", "120"))

    # API usage metering policy
    api_usage_billable_status_classes: str = os.environ.get("API_USAGE_BILLABLE_STATUS_CLASSES", "2xx")
    api_usage_quota_status_classes: str = os.environ.get("API_USAGE_QUOTA_STATUS_CLASSES", "2xx,4xx,5xx")
    api_usage_rate_limit_billable: bool = os.environ.get("API_USAGE_RATE_LIMIT_BILLABLE", "false").lower() in ("1", "true", "yes", "on")
    api_usage_rate_limit_counts_toward_quota: bool = os.environ.get("API_USAGE_RATE_LIMIT_COUNTS_TOWARD_QUOTA", "true").lower() in ("1", "true", "yes", "on")
    api_usage_auth_failed_billable: bool = os.environ.get("API_USAGE_AUTH_FAILED_BILLABLE", "false").lower() in ("1", "true", "yes", "on")
    api_usage_auth_failed_counts_toward_quota: bool = os.environ.get("API_USAGE_AUTH_FAILED_COUNTS_TOWARD_QUOTA", "true").lower() in ("1", "true", "yes", "on")


    # Newsfeed rich-content validation
    newsfeed_content_max_plain_chars: int = int(os.environ.get("NEWSFEED_CONTENT_MAX_PLAIN_CHARS", "10000"))
    newsfeed_content_max_markdown_chars: int = int(os.environ.get("NEWSFEED_CONTENT_MAX_MARKDOWN_CHARS", "20000"))
    newsfeed_content_max_rich_nodes: int = int(os.environ.get("NEWSFEED_CONTENT_MAX_RICH_NODES", "500"))
    newsfeed_content_max_rich_depth: int = int(os.environ.get("NEWSFEED_CONTENT_MAX_RICH_DEPTH", "20"))
    newsfeed_feed_max_scanned_pages: int = int(os.environ.get("NEWSFEED_FEED_MAX_SCANNED_PAGES", "20"))
    newsfeed_feed_max_elapsed_ms: int = int(os.environ.get("NEWSFEED_FEED_MAX_ELAPSED_MS", "2000"))
    newsfeed_feed_max_query_chars: int = int(os.environ.get("NEWSFEED_FEED_MAX_QUERY_CHARS", "200"))
    newsfeed_feed_max_cursor_chars: int = int(os.environ.get("NEWSFEED_FEED_MAX_CURSOR_CHARS", "2048"))
    newsfeed_feed_max_window_days: int = int(os.environ.get("NEWSFEED_FEED_MAX_WINDOW_DAYS", "365"))
    newsfeed_feed_query_max_per_window: int = int(os.environ.get("NEWSFEED_FEED_QUERY_MAX_PER_WINDOW", "180"))
    newsfeed_feed_query_window_seconds: int = int(os.environ.get("NEWSFEED_FEED_QUERY_WINDOW_SECONDS", "60"))
    api_usage_pricing_catalog: str = os.environ.get("API_USAGE_PRICING_CATALOG", "")
    api_usage_default_pricing_catalog_version: str = os.environ.get("API_USAGE_DEFAULT_PRICING_CATALOG_VERSION", "v1")
    api_usage_pricing_missing_route_behavior: str = os.environ.get("API_USAGE_PRICING_MISSING_ROUTE_BEHAVIOR", "default_route")
    api_usage_table_name: str = os.environ.get("API_USAGE_TABLE_NAME", "api_usage_events")
    api_usage_event_retention_days: int = int(os.environ.get("API_USAGE_EVENT_RETENTION_DAYS", "365"))
    api_usage_account_rps_limit: int = int(os.environ.get("API_USAGE_ACCOUNT_RPS_LIMIT", "0"))
    api_usage_account_rpm_limit: int = int(os.environ.get("API_USAGE_ACCOUNT_RPM_LIMIT", "0"))
    api_usage_account_daily_calls_limit: int = int(os.environ.get("API_USAGE_ACCOUNT_DAILY_CALLS_LIMIT", "0"))
    api_usage_account_monthly_calls_limit: int = int(os.environ.get("API_USAGE_ACCOUNT_MONTHLY_CALLS_LIMIT", "0"))
    api_usage_account_monthly_spend_micros_limit: int = int(os.environ.get("API_USAGE_ACCOUNT_MONTHLY_SPEND_MICROS_LIMIT", "0"))

    # Catalog commercialization
    catalog_commercialization_enabled: bool = os.environ.get("CATALOG_COMMERCIALIZATION_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    catalog_file_bundle_enabled: bool = os.environ.get("CATALOG_FILE_BUNDLE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    catalog_api_package_enabled: bool = os.environ.get("CATALOG_API_PACKAGE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    catalog_internal_api_package_enabled: bool = os.environ.get("CATALOG_INTERNAL_API_PACKAGE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    catalog_pricing_catalog: str = os.environ.get("CATALOG_PRICING_CATALOG", "")
    catalog_products_table_name: str = os.environ.get("CATALOG_PRODUCTS_TABLE_NAME", "catalog_products")
    catalog_product_versions_table_name: str = os.environ.get("CATALOG_PRODUCT_VERSIONS_TABLE_NAME", "catalog_product_versions")
    orders_table_name: str = os.environ.get("ORDERS_TABLE_NAME", "orders")
    order_items_table_name: str = os.environ.get("ORDER_ITEMS_TABLE_NAME", "order_items")
    payments_table_name: str = os.environ.get("PAYMENTS_TABLE_NAME", "payments")
    entitlements_table_name: str = os.environ.get("ENTITLEMENTS_TABLE_NAME", "entitlements")
    entitlement_usage_events_table_name: str = os.environ.get("ENTITLEMENT_USAGE_EVENTS_TABLE_NAME", "entitlement_usage_events")
    api_entitlement_low_balance_thresholds: str = os.environ.get("API_ENTITLEMENT_LOW_BALANCE_THRESHOLDS", "0.2,0.1,0.05")
    api_entitlement_near_cap_thresholds: str = os.environ.get("API_ENTITLEMENT_NEAR_CAP_THRESHOLDS", "0.8,0.9,0.95")

    # Order lifecycle state machine (ORD-002)
    order_lifecycle_enabled: bool = os.environ.get("ORDER_LIFECYCLE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    order_lifecycle_auto_approve: bool = os.environ.get("ORDER_LIFECYCLE_AUTO_APPROVE", "false").lower() in ("1", "true", "yes", "on")
    order_backorder_enabled: bool = os.environ.get("ORDER_BACKORDER_ENABLED", "false").lower() in ("1", "true", "yes", "on")


    # Newsfeed rich-content feature flags
    newsfeed_markdown_enabled: bool = os.environ.get("NEWSFEED_MARKDOWN_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    newsfeed_richtext_enabled: bool = os.environ.get("NEWSFEED_RICHTEXT_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    # FEED-004: emoji/GIF/sticker comments
    rich_comments_enabled: bool = os.environ.get("RICH_COMMENTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    newsfeed_drafts_enabled: bool = os.environ.get("NEWSFEED_DRAFTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    newsfeed_drafts_enabled_user_ids: str = os.environ.get("NEWSFEED_DRAFTS_ENABLED_USER_IDS", "")
    newsfeed_drafts_disabled_user_ids: str = os.environ.get("NEWSFEED_DRAFTS_DISABLED_USER_IDS", "")
    newsfeed_scheduling_api_enabled: bool = os.environ.get("NEWSFEED_SCHEDULING_API_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    newsfeed_scheduling_worker_enabled: bool = os.environ.get("NEWSFEED_SCHEDULING_WORKER_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    newsfeed_scheduling_min_lead_seconds: int = int(os.environ.get("NEWSFEED_SCHEDULING_MIN_LEAD_SECONDS", "5"))
    newsfeed_scheduling_max_horizon_seconds: int = int(os.environ.get("NEWSFEED_SCHEDULING_MAX_HORIZON_SECONDS", "31536000"))
    newsfeed_unlock_limit_enabled: bool = os.environ.get("NEWSFEED_UNLOCK_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    newsfeed_unlock_limit_rollout_mode: str = os.environ.get("NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE", "broad")
    newsfeed_unlock_limit_internal_user_ids: str = os.environ.get("NEWSFEED_UNLOCK_LIMIT_INTERNAL_USER_IDS", "")
    newsfeed_unlock_limit_cohort_user_ids: str = os.environ.get("NEWSFEED_UNLOCK_LIMIT_COHORT_USER_IDS", "")
    newsfeed_unlock_attempt_stale_seconds: int = int(os.environ.get("NEWSFEED_UNLOCK_ATTEMPT_STALE_SECONDS", "300"))
    newsfeed_unlock_throttle_window_seconds: int = int(os.environ.get("NEWSFEED_UNLOCK_THROTTLE_WINDOW_SECONDS", "10"))
    newsfeed_unlock_throttle_max_attempts: int = int(os.environ.get("NEWSFEED_UNLOCK_THROTTLE_MAX_ATTEMPTS", "6"))
    newsfeed_tip_lottery_enabled: bool = os.environ.get("NEWSFEED_TIP_LOTTERY_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # Sponsored posts (ADS-005)
    sponsored_posts_enabled: bool = os.environ.get("SPONSORED_POSTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    ad_feedback_enabled: bool = os.environ.get("AD_FEEDBACK_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    sponsored_post_interval: int = int(os.environ.get("SPONSORED_POST_INTERVAL", "5"))
    sponsored_post_max_per_page: int = int(os.environ.get("SPONSORED_POST_MAX_PER_PAGE", "3"))

    # Countdown posts (FEED-005)
    countdown_posts_enabled: bool = os.environ.get("COUNTDOWN_POSTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # Newsfeed polls (ENGAGE-002)
    newsfeed_polls_enabled: bool = os.environ.get("NEWSFEED_POLLS_ENABLED", "1") not in ("0", "false", "False")
    newsfeed_poll_max_options: int = int(os.environ.get("NEWSFEED_POLL_MAX_OPTIONS", "10"))
    newsfeed_poll_max_duration_hours: int = int(os.environ.get("NEWSFEED_POLL_MAX_DURATION_HOURS", "168"))

    # Image optimization (PLATFORM-004)
    image_optimization_enabled: bool = os.environ.get("IMAGE_OPTIMIZATION_ENABLED", "1") not in ("0", "false", "False")
    image_variant_sm_max_width: int = int(os.environ.get("IMAGE_VARIANT_SM_MAX_WIDTH", "480"))
    image_variant_md_max_width: int = int(os.environ.get("IMAGE_VARIANT_MD_MAX_WIDTH", "960"))
    image_variant_lg_max_width: int = int(os.environ.get("IMAGE_VARIANT_LG_MAX_WIDTH", "1920"))
    image_webp_quality: int = int(os.environ.get("IMAGE_WEBP_QUALITY", "80"))
    image_optimizations_table_name: str = os.environ.get("IMAGE_OPTIMIZATIONS_TABLE_NAME", "image_optimizations")

    # VOD File Bridge (VOD-014)
    vod_file_bridge_enabled: bool = os.environ.get("VOD_FILE_BRIDGE_ENABLED", "1") not in ("0", "false", "False")
    vod_file_bridge_default_folder: str = os.environ.get("VOD_FILE_BRIDGE_DEFAULT_FOLDER", "/Videos/")
    vod_file_bridge_auto_link: bool = os.environ.get("VOD_FILE_BRIDGE_AUTO_LINK", "1") not in ("0", "false", "False")

    # VOD Sharing (VOD-013)
    video_sharing_enabled: bool = os.environ.get("VIDEO_SHARING_ENABLED", "1") not in ("0", "false", "False")
    video_share_playback_token_ttl_seconds: int = int(os.environ.get("VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS", "300"))

    # Messaging feature flags
    messaging_encrypted_messages_enabled: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_encrypted_messages_kill_switch: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    countdown_messages_enabled: bool = os.environ.get("COUNTDOWN_MESSAGES_ENABLED", "true").lower() == "true"
    # GIF & Sticker messages (MSG-008)
    gif_messages_enabled: bool = os.environ.get("GIF_MESSAGES_ENABLED", "true").lower() == "true"
    sticker_messages_enabled: bool = os.environ.get("STICKER_MESSAGES_ENABLED", "true").lower() == "true"
    ddb_sticker_collections_table: str = os.environ.get("DDB_STICKER_COLLECTIONS_TABLE", "sticker_collections")
    gif_provider: str = os.environ.get("GIF_PROVIDER", "mock")
    # GAP-0316: comma-separated allowlist of GIF CDN hostnames accepted by the
    # messaging GIF endpoint. Relative dev mock URLs (/mock/gifs/...) are always
    # allowed in send_gif_message regardless of this list. Empty default keeps
    # only relative mock URLs valid until prod sets the real CDN domains.
    gif_allowed_domains: str = os.environ.get(
        "GIF_ALLOWED_DOMAINS",
        "media.giphy.com,media0.giphy.com,media1.giphy.com,media2.giphy.com,"
        "media3.giphy.com,media4.giphy.com,media.tenor.com,media1.tenor.com,c.tenor.com",
    )
    sticker_max_file_size_bytes: int = int(os.environ.get("STICKER_MAX_FILE_SIZE", "524288"))
    sticker_max_per_collection: int = int(os.environ.get("STICKER_MAX_PER_COLLECTION", "100"))
    # Custom emojis (MSG-007)
    custom_emojis_enabled: bool = os.environ.get("CUSTOM_EMOJIS_ENABLED", "true").lower() == "true"
    ddb_custom_emojis_table: str = os.environ.get("DDB_CUSTOM_EMOJIS_TABLE", "custom_emojis")
    custom_emoji_max_file_size_bytes: int = int(os.environ.get("CUSTOM_EMOJI_MAX_FILE_SIZE", "262144"))
    custom_emoji_max_dimension_px: int = int(os.environ.get("CUSTOM_EMOJI_MAX_DIMENSION", "128"))
    custom_emoji_max_per_user: int = int(os.environ.get("CUSTOM_EMOJI_MAX_PER_USER", "100"))
    custom_emoji_s3_prefix: str = os.environ.get("CUSTOM_EMOJI_S3_PREFIX", "emojis")
    messaging_gallery_enabled: bool = os.environ.get("MESSAGING_GALLERY_ENABLED", "true").lower() == "true"
    # Find-a-DateTime messages (MSG-009)
    find_datetime_enabled: bool = os.environ.get("FIND_DATETIME_ENABLED", "true").lower() == "true"
    find_datetime_max_date_range_days: int = int(os.environ.get("FIND_DATETIME_MAX_DATE_RANGE", "14"))
    find_datetime_max_slots_per_user: int = int(os.environ.get("FIND_DATETIME_MAX_SLOTS", "500"))
    # Find-a-DateTime newsfeed posts (FEED-003)
    find_datetime_posts_enabled: bool = os.environ.get("FIND_DATETIME_POSTS_ENABLED", "true").lower() == "true"
    messaging_gallery_kill_switch: bool = os.environ.get("MESSAGING_GALLERY_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    messaging_gallery_index_enabled: bool = os.environ.get("MESSAGING_GALLERY_INDEX_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_mass_send_enabled: bool = os.environ.get("MESSAGING_MASS_SEND_ENABLED", "true").lower() == "true"
    messaging_mass_send_kill_switch: bool = os.environ.get("MESSAGING_MASS_SEND_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    messaging_mass_send_campaigns_per_user_per_hour: int = int(os.environ.get("MESSAGING_MASS_SEND_CAMPAIGNS_PER_USER_PER_HOUR", "20"))
    messaging_mass_send_campaigns_per_tenant_per_hour: int = int(os.environ.get("MESSAGING_MASS_SEND_CAMPAIGNS_PER_TENANT_PER_HOUR", "500"))
    messaging_mass_send_max_destinations_per_campaign: int = int(os.environ.get("MESSAGING_MASS_SEND_MAX_DESTINATIONS_PER_CAMPAIGN", "100"))
    messaging_mass_send_max_concurrent_workers: int = int(os.environ.get("MESSAGING_MASS_SEND_MAX_CONCURRENT_WORKERS", "8"))
    messaging_dm_lottery_enabled: bool = os.environ.get("MESSAGING_DM_LOTTERY_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_dm_lottery_kill_switch: bool = os.environ.get("MESSAGING_DM_LOTTERY_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    # Canonical profile rollout flags (UPR-020)
    profile_lookup_audience_filtering_enabled: bool = os.environ.get("PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_webrtc_direct_call_enabled: bool = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_webrtc_direct_call_kill_switch: bool = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH", "false").lower() in ("1", "true", "yes", "on")
    messaging_webrtc_direct_call_mode: str = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_MODE", "enabled")
    messaging_webrtc_direct_call_enabled_tenant_ids: str = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_ENABLED_TENANT_IDS", "")
    messaging_webrtc_direct_call_internal_tenant_ids: str = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_INTERNAL_TENANT_IDS", "internal")
    messaging_webrtc_direct_call_enabled_cohorts: str = os.environ.get("MESSAGING_WEBRTC_DIRECT_CALL_ENABLED_COHORTS", "")
    messaging_webrtc_turn_enabled: bool = os.environ.get("MESSAGING_WEBRTC_TURN_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    messaging_webrtc_turn_urls: str = os.environ.get("MESSAGING_WEBRTC_TURN_URLS", "")
    messaging_webrtc_turn_secret: str = os.environ.get("MESSAGING_WEBRTC_TURN_SECRET", "")
    messaging_webrtc_turn_ttl_seconds: int = int(os.environ.get("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "600"))
    messaging_webrtc_call_ringing_timeout_seconds: int = int(os.environ.get("MESSAGING_WEBRTC_CALL_RINGING_TIMEOUT_SECONDS", "30"))
    messaging_screen_share_enabled: bool = os.environ.get("MESSAGING_SCREEN_SHARE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    # Subscriptions
    subscriptions_table_name: str = os.environ.get("SUBSCRIPTIONS_TABLE_NAME", "subscriptions")
    content_boosts_table_name: str = os.environ.get("CONTENT_BOOSTS_TABLE_NAME", "content_boosts")
    questionnaire_table_name: str = os.environ.get("QUESTIONNAIRE_TABLE_NAME", "questionnaires")
    questionnaire_owner_index_name: str = os.environ.get("QUESTIONNAIRE_OWNER_INDEX_NAME", "owner-updated-index")
    questionnaire_status_index_name: str = os.environ.get("QUESTIONNAIRE_STATUS_INDEX_NAME", "status-updated-index")
    questionnaire_published_index_name: str = os.environ.get("QUESTIONNAIRE_PUBLISHED_INDEX_NAME", "published_slug-index")
    questionnaire_response_status_index_name: str = os.environ.get("QUESTIONNAIRE_RESPONSE_STATUS_INDEX_NAME", "response_status-updated-index")
    questionnaire_anon_submit_max_per_window: int = int(os.environ.get("QUESTIONNAIRE_ANON_SUBMIT_MAX_PER_WINDOW", "30"))
    questionnaire_anon_submit_window_seconds: int = int(os.environ.get("QUESTIONNAIRE_ANON_SUBMIT_WINDOW_SECONDS", "300"))
    questionnaire_captcha_required_anonymous: bool = os.environ.get("QUESTIONNAIRE_CAPTCHA_REQUIRED_ANONYMOUS", "false").lower() in ("1", "true", "yes", "on")
    questionnaire_captcha_static_token: str = os.environ.get("QUESTIONNAIRE_CAPTCHA_STATIC_TOKEN", "")
    questionnaire_encrypt_sensitive_answers: bool = os.environ.get("QUESTIONNAIRE_ENCRYPT_SENSITIVE_ANSWERS", "false").lower() in ("1", "true", "yes", "on")
    kyc_cases_table_name: str = os.environ.get("KYC_CASES_TABLE_NAME", "kyc_cases")
    kyc_cases_owner_index_name: str = os.environ.get("KYC_CASES_OWNER_INDEX_NAME", "owner-updated-index")
    kyc_cases_status_index_name: str = os.environ.get("KYC_CASES_STATUS_INDEX_NAME", "status-updated-index")
    # GAP-0282 (KYC-019): sparse GSI on entity_type+admin_sub so admin availability
    # records are fetched with a targeted Query instead of a full-table Scan.
    kyc_cases_entity_type_index_name: str = os.environ.get("KYC_CASES_ENTITY_TYPE_INDEX_NAME", "entity-type-index")
    # GAP-0283 (KYC-019): sparse GSI keyed on the top-level denormalized
    # ``assigned_admin_sub`` (PK) + ``gsi_status_pk`` (SK). Only cases that carry
    # an assignment project into this index, so per-admin active-case counts use a
    # targeted ``Select=COUNT`` Query instead of scanning every active case.
    kyc_cases_assigned_admin_index_name: str = os.environ.get("KYC_CASES_ASSIGNED_ADMIN_INDEX_NAME", "assigned-admin-index")
    # KYC-023: PII field-level encryption & audited decryption
    kyc_encryption_enabled: bool = os.environ.get("KYC_ENCRYPTION_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_encryption_audit_enabled: bool = os.environ.get("KYC_ENCRYPTION_AUDIT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_dek_rotation_days: int = int(os.environ.get("KYC_DEK_ROTATION_DAYS", "90"))
    kyc_pii_reveal_timeout_seconds: int = int(os.environ.get("KYC_PII_REVEAL_TIMEOUT_SECONDS", "30"))
    kyc_pii_audit_accessor_index_name: str = os.environ.get("KYC_PII_AUDIT_ACCESSOR_INDEX_NAME", "pii-audit-accessor-index")
    kyc_retention_rejected_days: int = int(os.environ.get("KYC_RETENTION_REJECTED_DAYS", "30"))
    kyc_retention_expired_days: int = int(os.environ.get("KYC_RETENTION_EXPIRED_DAYS", "7"))
    # KYC disputes & retry (KYD-001). Both gates DEFAULT OFF so the dispute /
    # reopen-and-resubmit flows are inert until explicitly enabled — with the
    # flags off, rejected/expired cases remain terminal exactly as before.
    kyc_dispute_enabled: bool = os.environ.get("KYC_DISPUTE_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    kyc_retry_enabled: bool = os.environ.get("KYC_RETRY_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    kyc_retry_max_attempts: int = int(os.environ.get("KYC_RETRY_MAX_ATTEMPTS", "3"))
    kyc_dispute_window_days: int = int(os.environ.get("KYC_DISPUTE_WINDOW_DAYS", "30"))
    kyc_retention_approved_days: int = int(os.environ.get("KYC_RETENTION_APPROVED_DAYS", "365"))
    kyc_review_ticket_space_id: str = os.environ.get("KYC_REVIEW_TICKET_SPACE_ID", "kyc-ops")
    kyc_review_ticket_category: str = os.environ.get("KYC_REVIEW_TICKET_CATEGORY", "kyc_review")

    # KYC Case Assignment & Workload Management (KYC-019)
    kyc_assignment_enabled: bool = os.environ.get("KYC_ASSIGNMENT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_sla_checker_enabled: bool = os.environ.get("KYC_SLA_CHECKER_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_auto_assign_on_submit: bool = os.environ.get("KYC_AUTO_ASSIGN_ON_SUBMIT", "false").lower() in ("1", "true", "yes", "on")
    kyc_assignment_default_max_cases: int = int(os.environ.get("KYC_ASSIGNMENT_DEFAULT_MAX_CASES", "20"))
    kyc_sla_tier1_hours: int = int(os.environ.get("KYC_SLA_TIER1_HOURS", "24"))
    kyc_sla_tier2_hours: int = int(os.environ.get("KYC_SLA_TIER2_HOURS", "48"))
    kyc_sla_tier3_hours: int = int(os.environ.get("KYC_SLA_TIER3_HOURS", "120"))

    # KYC for Business / Corporate Accounts (KYB) (KYC-015)
    kyc_business_enabled: bool = os.environ.get("KYC_BUSINESS_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_business_cases_table_name: str = os.environ.get("KYC_BUSINESS_CASES_TABLE_NAME", "kyc_business_cases")
    kyc_business_cases_owner_index_name: str = os.environ.get("KYC_BUSINESS_CASES_OWNER_INDEX_NAME", "owner-updated-index")
    kyc_business_cases_status_index_name: str = os.environ.get("KYC_BUSINESS_CASES_STATUS_INDEX_NAME", "status-updated-index")
    kyc_business_cases_org_index_name: str = os.environ.get("KYC_BUSINESS_CASES_ORG_INDEX_NAME", "org-index")

    # KYC Risk Scoring (KYC-008)
    kyc_risk_scores_table_name: str = os.environ.get("KYC_RISK_SCORES_TABLE_NAME", "kyc_risk_scores")
    kyc_risk_auto_approve_enabled: bool = os.environ.get("KYC_RISK_AUTO_APPROVE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_risk_auto_approve_max_score: int = int(os.environ.get("KYC_RISK_AUTO_APPROVE_MAX_SCORE", "20"))
    kyc_risk_auto_escalate_enabled: bool = os.environ.get("KYC_RISK_AUTO_ESCALATE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_risk_auto_escalate_min_score: int = int(os.environ.get("KYC_RISK_AUTO_ESCALATE_MIN_SCORE", "81"))
    kyc_risk_scoring_model_version: str = os.environ.get("KYC_RISK_SCORING_MODEL_VERSION", "v1.0")
    risk_high_threshold: int = int(os.environ.get("RISK_HIGH_THRESHOLD", "70"))
    # KYC tiered verification levels (KYC-009)
    kyc_tier_gating_enabled: bool = os.environ.get("KYC_TIER_GATING_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    # KYC-009 / GAP-0268: router-level enforcement of require_kyc_tier() gates.
    # Defaults OFF so existing tier-0 users (dev/E2E) are never blocked. When False,
    # require_kyc_tier is a pure pass-through. Must be explicitly enabled (and accounts
    # pre-seeded at the right tier) before turning on per the Phase 2-4 rollout plan.
    kyc_tier_enforcement_enabled: bool = os.environ.get("KYC_TIER_ENFORCEMENT_ENABLED", "false").lower() in ("1", "true", "yes", "on")

    # KYC enhanced/high-risk residency readiness gate (KYC-004 / GAP-0252)
    kyc_residency_gate_enabled: bool = os.environ.get("KYC_RESIDENCY_GATE_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # KYC Ongoing Monitoring & Periodic Review (KYC-016)
    kyc_review_schedule_table_name: str = os.environ.get("KYC_REVIEW_SCHEDULE_TABLE_NAME", "kyc_review_schedule")
    kyc_review_grace_period_days: int = int(os.environ.get("KYC_REVIEW_GRACE_PERIOD_DAYS", "30"))
    kyc_large_transaction_threshold_cents: int = int(os.environ.get("KYC_LARGE_TRANSACTION_THRESHOLD_CENTS", "500000"))
    kyc_rescreening_enabled: bool = os.environ.get("KYC_RESCREENING_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # KYC Identity Document Verification (KYC-002)
    kyc_documents_table_name: str = os.environ.get("KYC_DOCUMENTS_TABLE_NAME", "kyc_documents")
    kyc_documents_status_index_name: str = os.environ.get("KYC_DOCUMENTS_STATUS_INDEX_NAME", "ByStatus")
    kyc_documents_bucket: str = os.environ.get("KYC_DOCUMENTS_BUCKET", "local-uploads")
    kyc_documents_s3_prefix: str = os.environ.get("KYC_DOCUMENTS_S3_PREFIX", "kyc-documents/")

    # KYC Partner API (KYC-021) — per-API-key rate limits (GAP-0286) and the
    # S3 storage location for partner-uploaded documents (GAP-0287). Same code
    # path dev (in-process moto / DynamoDB Local) + prod (real S3/DDB) per
    # SECOPS-007 — no dev_mode bypass; limits/bucket are env-configurable.
    kyc_partner_api_docs_bucket: str = os.environ.get(
        "KYC_PARTNER_API_DOCS_BUCKET", os.environ.get("KYC_DOCUMENTS_BUCKET", "local-uploads")
    )
    kyc_partner_api_docs_s3_prefix: str = os.environ.get(
        "KYC_PARTNER_API_DOCS_S3_PREFIX", "kyc-api-docs/"
    )
    kyc_partner_api_rl_applications_per_hour: int = int(
        os.environ.get("KYC_PARTNER_API_RL_APPLICATIONS_PER_HOUR", "100")
    )
    kyc_partner_api_rl_documents_per_hour: int = int(
        os.environ.get("KYC_PARTNER_API_RL_DOCUMENTS_PER_HOUR", "200")
    )
    kyc_partner_api_rl_read_per_hour: int = int(
        os.environ.get("KYC_PARTNER_API_RL_READ_PER_HOUR", "1000")
    )
    kyc_partner_api_rl_webhook_test_per_hour: int = int(
        os.environ.get("KYC_PARTNER_API_RL_WEBHOOK_TEST_PER_HOUR", "10")
    )
    kyc_documents_verification_enabled: bool = os.environ.get(
        "KYC_DOCUMENTS_VERIFICATION_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # When False (default) a deterministic mock provider is used; when True a "real"
    # extraction provider would be invoked (not wired in dev / E2E).
    kyc_documents_real_extraction_enabled: bool = os.environ.get(
        "KYC_DOCUMENTS_REAL_EXTRACTION_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    kyc_documents_provider: str = os.environ.get("KYC_DOCUMENTS_PROVIDER", "mock_ocr")
    kyc_documents_name_match_threshold: float = float(
        os.environ.get("KYC_DOCUMENTS_NAME_MATCH_THRESHOLD", "0.85")
    )

    # KYC Passport / National-ID Scanner (KYC-010)
    kyc_id_scans_table_name: str = os.environ.get("KYC_ID_SCANS_TABLE_NAME", "kyc_id_scans")
    kyc_id_scanner_status_index_name: str = os.environ.get(
        "KYC_ID_SCANNER_STATUS_INDEX_NAME", "ByStatus"
    )
    kyc_id_scanner_bucket: str = os.environ.get("KYC_ID_SCANNER_BUCKET", "local-uploads")
    kyc_id_scanner_s3_prefix: str = os.environ.get("KYC_ID_SCANNER_S3_PREFIX", "kyc-id-scans/")
    kyc_id_scanner_enabled: bool = os.environ.get(
        "KYC_ID_SCANNER_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # When False (default) deterministic mock MRZ extraction is used; when True a
    # "real" OCR/MRZ provider would be invoked (not wired in dev / E2E).
    kyc_id_scanner_real_ocr_enabled: bool = os.environ.get(
        "KYC_ID_SCANNER_REAL_OCR_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")

    # KYC Facial Comparison (KYC-014)
    kyc_face_comparison_enabled: bool = os.environ.get(
        "KYC_FACE_COMPARISON_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_face_admin_override_enabled: bool = os.environ.get(
        "KYC_FACE_ADMIN_OVERRIDE_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_face_auto_compare: bool = os.environ.get(
        "KYC_FACE_AUTO_COMPARE", "false"
    ).lower() in ("1", "true", "yes", "on")
    # When True, uses the deterministic mock comparison even in non-dev mode
    # (safety valve for staging environments where AWS Rekognition is not yet
    # provisioned). MUST be False in production. See GAP-0275 / SECOPS-007.
    kyc_face_comparison_use_mock: bool = os.environ.get(
        "KYC_FACE_COMPARISON_USE_MOCK", "false"
    ).lower() in ("1", "true", "yes", "on")

    # KYC Electronic Identity Verification / eIDV (KYC-022)
    kyc_eid_enabled: bool = os.environ.get(
        "KYC_EID_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_eid_mock_enabled: bool = os.environ.get(
        "KYC_EID_MOCK_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_eid_auto_tier_upgrade: bool = os.environ.get(
        "KYC_EID_AUTO_TIER_UPGRADE", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_eid_schemes: str = os.environ.get(
        "KYC_EID_SCHEMES", "eidas,digid,bankid,aadhaar"
    )
    kyc_eid_mock_signing_key: str = os.environ.get(
        "KYC_EID_MOCK_SIGNING_KEY", "dev-mock-eid-signing-key"
    )

    # KYC Proof of Residency Verification (KYC-004)
    kyc_residency_documents_table_name: str = os.environ.get(
        "KYC_RESIDENCY_DOCUMENTS_TABLE_NAME", "kyc_residency_documents"
    )
    kyc_residency_documents_status_index_name: str = os.environ.get(
        "KYC_RESIDENCY_DOCUMENTS_STATUS_INDEX_NAME", "ByStatus"
    )
    kyc_residency_bucket: str = os.environ.get("KYC_RESIDENCY_BUCKET", "local-uploads")
    kyc_residency_s3_prefix: str = os.environ.get("KYC_RESIDENCY_S3_PREFIX", "kyc-residency/")
    kyc_residency_enabled: bool = os.environ.get(
        "KYC_RESIDENCY_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # When False (default) a deterministic mock provider is used; when True a
    # "real" extraction provider would be invoked (not wired in dev / E2E).
    kyc_residency_real_extraction_enabled: bool = os.environ.get(
        "KYC_RESIDENCY_REAL_EXTRACTION_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    kyc_residency_provider: str = os.environ.get("KYC_RESIDENCY_PROVIDER", "mock_extract")
    # Recency window in days; documents dated older than this are not recent.
    kyc_residency_recency_days: int = int(
        os.environ.get("KYC_RESIDENCY_RECENCY_DAYS", "90")
    )
    # KYC-005 / GAP-0255: periodic background task that transitions verified
    # residency documents whose document_date has aged out of the recency
    # window to ``expired`` so a stale submission stops satisfying readiness
    # gates forever. Default on (compliance requirement); flag exists only for
    # emergency rollback without a code deploy.
    kyc_residency_expiry_enabled: bool = os.environ.get(
        "KYC_RESIDENCY_EXPIRY_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")

    # KYC-018: Address Verification Service
    # Master switch for the address verification feature.
    kyc_address_verification_enabled: bool = os.environ.get(
        "KYC_ADDRESS_VERIFICATION_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # Enable mock geocoding (deterministic lat/lng derived from address hash).
    kyc_address_geocoding_enabled: bool = os.environ.get(
        "KYC_ADDRESS_GEOCODING_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # When False (default) a deterministic mock provider is used; when True a
    # "real" external postal provider would be invoked (not wired in dev / E2E).
    kyc_address_real_provider_enabled: bool = os.environ.get(
        "KYC_ADDRESS_REAL_PROVIDER_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    kyc_address_provider: str = os.environ.get(
        "KYC_ADDRESS_PROVIDER", "mock_postal"
    )
    # Confidence threshold (inclusive) at/above which a result buckets to
    # "verified"; below this but above the review floor buckets to
    # "needs_review"; below the review floor buckets to "failed".
    kyc_address_verified_threshold: float = float(
        os.environ.get("KYC_ADDRESS_VERIFIED_THRESHOLD", "0.9")
    )
    kyc_address_review_threshold: float = float(
        os.environ.get("KYC_ADDRESS_REVIEW_THRESHOLD", "0.5")
    )
    # Cross-reference match score (inclusive) at/above which a profile-vs-doc
    # comparison is considered a "high" match (no discrepancy flag).
    kyc_address_cross_reference_match_threshold: float = float(
        os.environ.get("KYC_ADDRESS_CROSS_REFERENCE_MATCH_THRESHOLD", "0.8")
    )

    # KYC-006: Sanctions / PEP Screening
    kyc_screening_results_table_name: str = os.environ.get(
        "KYC_SCREENING_RESULTS_TABLE_NAME", "kyc_screening_results"
    )
    kyc_screening_status_index_name: str = os.environ.get(
        "KYC_SCREENING_STATUS_INDEX_NAME", "ByStatus"
    )
    kyc_screening_user_index_name: str = os.environ.get(
        "KYC_SCREENING_USER_INDEX_NAME", "ByUserSub"
    )
    kyc_screening_enabled: bool = os.environ.get(
        "KYC_SCREENING_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # When False (default) a deterministic mock watchlist provider is used; when
    # True a "real" screening provider would be invoked (not wired in dev / E2E).
    kyc_screening_real_provider_enabled: bool = os.environ.get(
        "KYC_SCREENING_REAL_PROVIDER_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    kyc_screening_provider: str = os.environ.get("KYC_SCREENING_PROVIDER", "mock_screening")
    # Minimum normalized-name similarity (0.0-1.0) required to register a match.
    kyc_screening_match_threshold: float = float(
        os.environ.get("KYC_SCREENING_MATCH_THRESHOLD", "0.85")
    )

    # KYC-003: Liveness Video Verification Call
    kyc_liveness_calls_table_name: str = os.environ.get(
        "KYC_LIVENESS_CALLS_TABLE_NAME", "kyc_liveness_calls"
    )
    kyc_liveness_call_status_index_name: str = os.environ.get(
        "KYC_LIVENESS_CALL_STATUS_INDEX_NAME", "ByStatus"
    )
    kyc_liveness_call_bucket: str = os.environ.get("KYC_LIVENESS_CALL_BUCKET", "local-uploads")
    kyc_liveness_call_s3_prefix: str = os.environ.get(
        "KYC_LIVENESS_CALL_S3_PREFIX", "kyc-liveness-calls/"
    )
    kyc_liveness_call_enabled: bool = os.environ.get(
        "KYC_LIVENESS_CALL_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    # Minimum lead time (seconds) between "now" and the scheduled call start.
    kyc_liveness_call_min_lead_seconds: int = int(
        os.environ.get("KYC_LIVENESS_CALL_MIN_LEAD_SECONDS", "0")
    )
    # Window (seconds) before scheduled_at within which the join link is active.
    kyc_liveness_call_join_window_seconds: int = int(
        os.environ.get("KYC_LIVENESS_CALL_JOIN_WINDOW_SECONDS", "300")
    )
    # Calls not started before scheduled_at + this many seconds are expirable.
    kyc_liveness_call_expiry_seconds: int = int(
        os.environ.get("KYC_LIVENESS_CALL_EXPIRY_SECONDS", "86400")
    )
    # KYC Analytics & Funnel Dashboard (KYC-024)
    kyc_analytics_precompute_enabled: bool = os.environ.get("KYC_ANALYTICS_PRECOMPUTE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_analytics_cache_ttl: int = int(os.environ.get("KYC_ANALYTICS_CACHE_TTL", "300"))
    kyc_analytics_max_scan_items: int = int(os.environ.get("KYC_ANALYTICS_MAX_SCAN_ITEMS", "10000"))
    kyc_analytics_trend_max_periods: int = int(os.environ.get("KYC_ANALYTICS_TREND_MAX_PERIODS", "90"))

    # Video metadata (VOD-001)
    video_metadata_table_name: str = os.environ.get("DDB_VIDEO_METADATA", "VideoMetadata")
    vod_entitlements_table_name: str = os.environ.get("DDB_VOD_ENTITLEMENTS", "VodEntitlements")

    # Video upload (VOD-002)
    video_upload_bucket: str = os.environ.get("VIDEO_UPLOAD_BUCKET", "local-uploads")

    # Transcode job queue (VOD-003)
    transcode_jobs_table_name: str = os.environ.get("DDB_TRANSCODE_JOBS", "TranscodeJobs")
    transcode_worker_enabled: bool = os.environ.get("TRANSCODE_WORKER_ENABLED", os.environ.get("DEV_MODE", "0")) not in ("0", "false", "False")
    transcode_max_concurrent_jobs: int = int(os.environ.get("TRANSCODE_MAX_CONCURRENT", "2"))
    transcode_poll_interval_seconds: int = int(os.environ.get("TRANSCODE_POLL_INTERVAL", "10"))
    transcode_max_attempts: int = int(os.environ.get("TRANSCODE_MAX_ATTEMPTS", "3"))
    transcode_output_bucket: str = os.environ.get("TRANSCODE_OUTPUT_BUCKET", "vod-output")
    transcode_output_prefix: str = os.environ.get("TRANSCODE_OUTPUT_PREFIX", "tenants")
    transcode_scratch_dir: str = os.environ.get("TRANSCODE_SCRATCH_DIR", "tmp/transcode-scratch")
    transcode_progress_update_interval_seconds: int = int(os.environ.get("TRANSCODE_PROGRESS_UPDATE_INTERVAL", "5"))
    transcode_rendition_timeout_seconds: int = int(os.environ.get("TRANSCODE_RENDITION_TIMEOUT_SECONDS", "1800"))

    # VOD S3 upload (VOD-005)
    vod_output_bucket: str = os.environ.get("VOD_OUTPUT_BUCKET", "vod-output")
    vod_output_prefix: str = os.environ.get("VOD_OUTPUT_PREFIX", "tenants")
    vod_output_retention_days: int = int(os.environ.get("VOD_OUTPUT_RETENTION_DAYS", "30"))
    vod_upload_concurrency: int = int(os.environ.get("VOD_UPLOAD_CONCURRENCY", "4"))
    vod_upload_multipart_threshold_mb: int = int(os.environ.get("VOD_UPLOAD_MULTIPART_THRESHOLD_MB", "8"))
    vod_upload_multipart_chunksize_mb: int = int(os.environ.get("VOD_UPLOAD_MULTIPART_CHUNKSIZE_MB", "8"))

    # VOD playback token TTL (VOD-006)
    video_playback_token_ttl_seconds: int = int(os.environ.get("VIDEO_PLAYBACK_TOKEN_TTL", "300"))

    # VOD playback URLs (VOD-005)
    vod_playback_url_ttl_seconds: int = int(os.environ.get("VOD_PLAYBACK_URL_TTL_SECONDS", "3600"))
    vod_cloudfront_domain: str = os.environ.get("VOD_CLOUDFRONT_DOMAIN", "")
    vod_cloudfront_signing_secret: str = os.environ.get("VOD_CLOUDFRONT_SIGNING_SECRET", "dev-vod-cf-secret")

    # VOD thumbnails (VOD-005)
    vod_thumbnail_enabled: bool = os.environ.get("VOD_THUMBNAIL_ENABLED", "1") not in ("0", "false", "False")
    vod_thumbnail_timestamps: str = os.environ.get("VOD_THUMBNAIL_TIMESTAMPS", "0,10,30")
    vod_thumbnail_width: int = int(os.environ.get("VOD_THUMBNAIL_WIDTH", "640"))
    vod_thumbnail_quality: int = int(os.environ.get("VOD_THUMBNAIL_QUALITY", "5"))

    # FFmpeg executor (VOD-004)
    ffmpeg_max_threads_per_job: int = int(os.environ.get("FFMPEG_MAX_THREADS_PER_JOB", "0"))  # 0 = auto
    ffmpeg_max_memory_gb: int = int(os.environ.get("FFMPEG_MAX_MEMORY_GB", "8"))
    ffmpeg_grace_kill_seconds: int = int(os.environ.get("FFMPEG_GRACE_KILL_SECONDS", "5"))
    ffmpeg_min_free_disk_gb: float = float(os.environ.get("FFMPEG_MIN_FREE_DISK_GB", "5.0"))
    ffmpeg_binary_path: str = os.environ.get("FFMPEG_BINARY_PATH", "ffmpeg")

    # Google Calendar integration hardening/tuning
    google_calendar_oauth_require_refresh_token: bool = os.environ.get("GOOGLE_CALENDAR_OAUTH_REQUIRE_REFRESH_TOKEN", "true").lower() in ("1", "true", "yes", "on")
    google_calendar_api_retry_after_max_seconds: int = int(os.environ.get("GOOGLE_CALENDAR_API_RETRY_AFTER_MAX_SECONDS", "60"))

    # VOD DRM encryption (VOD-010)
    vod_drm_enabled: bool = os.environ.get("VOD_DRM_ENABLED", "1") not in ("0", "false", "False")
    vod_drm_key_root: str = os.environ.get("VOD_DRM_KEY_ROOT", "dev-vod-drm-root-key-change-me")
    vod_drm_key_server_base_url: str = os.environ.get("VOD_DRM_KEY_SERVER_BASE_URL", "http://localhost:8000/v1/vod/drm")
    # ContentKeys table (VOD-010 §4.2 / GAP-0374): DRM key revocation records + audit trail
    content_keys_table_name: str = os.environ.get("DDB_CONTENT_KEYS", "ContentKeys")

    # VOD Download (VOD-012)
    video_download_enabled: bool = os.environ.get("VIDEO_DOWNLOAD_ENABLED", "1") not in ("0", "false", "False")
    video_download_url_ttl_seconds: int = int(os.environ.get("VIDEO_DOWNLOAD_URL_TTL_SECONDS", "3600"))
    video_download_rate_limit_per_10m: int = int(os.environ.get("VIDEO_DOWNLOAD_RATE_LIMIT_PER_10M", "5"))

    # Broadcast Recording (BCAST-006)
    broadcast_recordings_table_name: str = os.environ.get("BROADCAST_RECORDINGS_TABLE", "BroadcastRecordings")
    broadcast_recording_enabled: bool = os.environ.get("BROADCAST_RECORDING_ENABLED", "1") not in ("0", "false", "False")
    broadcast_recording_playback_ttl_seconds: int = int(os.environ.get("BROADCAST_RECORDING_PLAYBACK_TTL_SECONDS", "14400"))
    broadcast_recording_vod_bucket: str = os.environ.get("BROADCAST_RECORDING_VOD_BUCKET", "broadcast-vod")
    broadcast_recording_vod_prefix: str = os.environ.get("BROADCAST_RECORDING_VOD_PREFIX", "recordings")
    broadcast_recording_max_segments: int = int(os.environ.get("BROADCAST_RECORDING_MAX_SEGMENTS", "10000"))
    broadcast_recording_worker_inline: bool = os.environ.get("BROADCAST_RECORDING_WORKER_INLINE", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
    broadcast_recording_mock_on_no_ffmpeg: bool = os.environ.get("BROADCAST_RECORDING_MOCK_ON_NO_FFMPEG", "1") not in ("0", "false", "False")

    # Recording MP4 download (BCAST-008)
    broadcast_recording_download_enabled: bool = os.environ.get("BROADCAST_RECORDING_DOWNLOAD_ENABLED", "1") not in ("0", "false", "False")
    broadcast_recording_download_ttl_seconds: int = int(os.environ.get("BROADCAST_RECORDING_DOWNLOAD_TTL_SECONDS", "14400"))
    broadcast_recording_mp4_auto_generate: bool = os.environ.get("BROADCAST_RECORDING_MP4_AUTO_GENERATE", "1") not in ("0", "false", "False")

    # Broadcast Product Shelf (LCOM-001)
    broadcast_product_shelf_table_name: str = os.environ.get("DDB_BROADCAST_PRODUCT_SHELF", "BroadcastProductShelf")

    # Newsfeed Video Posts (FEED-001)
    newsfeed_video_posts_enabled: bool = os.environ.get("NEWSFEED_VIDEO_POSTS_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # Call Recording (CALL-009)
    call_recording_enabled: bool = os.environ.get("CALL_RECORDING_ENABLED", "1") not in ("0", "false", "False")
    call_recording_max_duration_seconds: int = int(os.environ.get("CALL_RECORDING_MAX_DURATION_SECONDS", "3600"))
    call_recording_upload_ttl_seconds: int = int(os.environ.get("CALL_RECORDING_UPLOAD_TTL_SECONDS", "600"))
    call_recording_max_file_size_bytes: int = int(os.environ.get("CALL_RECORDING_MAX_FILE_SIZE_BYTES", str(2 * 1024**3)))
    call_recording_retention_days: int = int(os.environ.get("CALL_RECORDING_RETENTION_DAYS", "90"))
    call_recording_s3_prefix: str = os.environ.get("CALL_RECORDING_S3_PREFIX", "call-recordings/")
    call_recordings_table_name: str = os.environ.get("DDB_CALL_RECORDINGS_TABLE", "CallRecordings")
    call_recording_download_ttl_seconds: int = int(os.environ.get("CALL_RECORDING_DOWNLOAD_TTL_SECONDS", "3600"))

    # DMCA (MOD-002)
    dmca_strike_threshold: int = int(os.environ.get("DMCA_STRIKE_THRESHOLD", "3"))
    dmca_strike_lookback_days: int = int(os.environ.get("DMCA_STRIKE_LOOKBACK_DAYS", "365"))
    dmca_timer_enabled: bool = os.environ.get(
        "DMCA_TIMER_ENABLED", "0"
    ) not in ("0", "false", "False")
    dmca_timer_interval_seconds: int = int(
        os.environ.get("DMCA_TIMER_INTERVAL_SECONDS", "3600")
    )
    dmca_max_claims_per_claimant_per_day: int = int(
        os.environ.get("DMCA_MAX_CLAIMS_PER_CLAIMANT_PER_DAY", "20")
    )

    # Appeals (MOD-003)
    appeals_table_name: str = os.environ.get("DDB_APPEALS", "Appeals")

    # Creator Payouts (MON-004)
    creator_payouts_table_name: str = os.environ.get("DDB_CREATOR_PAYOUTS", "CreatorPayouts")
    payouts_table_name: str = os.environ.get("DDB_CREATOR_PAYOUTS", "CreatorPayouts")
    payout_hold_period_seconds: int = int(os.environ.get("PAYOUT_HOLD_PERIOD_SECONDS", "604800"))
    # Messaging: editable window after send (MSG-001 / GAP-0310). 0 = unlimited.
    message_edit_window_seconds: int = int(os.environ.get("MESSAGE_EDIT_WINDOW_SECONDS", str(15 * 60)))
    payout_hold_days: int = int(os.environ.get("PAYOUT_HOLD_DAYS", "7"))
    payout_minimum_cents: int = int(os.environ.get("PAYOUT_MINIMUM_CENTS", "1000"))
    payout_min_cents: int = int(os.environ.get("PAYOUT_MIN_CENTS", os.environ.get("PAYOUT_MINIMUM_CENTS", "1000")))
    # Bulk Payout & Refund Tools (FIN-017)
    bulk_payout_batches_table_name: str = os.environ.get("DDB_BULK_PAYOUT_BATCHES", "BulkPayoutBatches")
    bulk_payout_use_real_provider: bool = os.environ.get("BULK_PAYOUT_USE_REAL_PROVIDER", "0") not in ("0", "false", "False")

    # Pay-Per-Minute Calls (CALL-011)
    call_billing_enabled: bool = os.environ.get("CALL_BILLING_ENABLED", "1") not in ("0", "false", "False")
    call_billing_heartbeat_interval_seconds: int = int(os.environ.get("CALL_BILLING_HEARTBEAT_INTERVAL", "15"))
    call_billing_cycle_seconds: int = int(os.environ.get("CALL_BILLING_CYCLE_SECONDS", "60"))
    call_billing_low_balance_warning_cents: int = int(os.environ.get("CALL_BILLING_LOW_BALANCE_WARNING_CENTS", "500"))
    call_billing_grace_period_seconds: int = int(os.environ.get("CALL_BILLING_GRACE_PERIOD_SECONDS", "10"))
    call_billing_max_rate_cents_per_min: int = int(os.environ.get("CALL_BILLING_MAX_RATE_CENTS_PER_MIN", "9999"))
    call_billing_platform_fee_percent: int = int(os.environ.get("CALL_BILLING_PLATFORM_FEE_PERCENT", "20"))
    call_billing_ledger_table_name: str = os.environ.get("DDB_CALL_BILLING_LEDGER", "CallBillingLedger")
    call_billing_max_duration_seconds: int = int(os.environ.get("CALL_BILLING_MAX_DURATION_SECONDS", "7200"))
    call_billing_min_rate_cents: int = int(os.environ.get("CALL_BILLING_MIN_RATE_CENTS", "100"))
    call_billing_heartbeat_timeout_seconds: int = int(os.environ.get("CALL_BILLING_HEARTBEAT_TIMEOUT_SECONDS", "30"))
    call_billing_low_balance_minutes: int = int(os.environ.get("CALL_BILLING_LOW_BALANCE_MINUTES", "2"))

    # Broadcast Scheduling (BCAST-009)
    broadcast_scheduler_enabled: bool = os.environ.get("BROADCAST_SCHEDULER_ENABLED", os.environ.get("DEV_MODE", "0")) not in ("0", "false", "False")
    broadcast_scheduler_poll_interval_seconds: int = int(os.environ.get("BROADCAST_SCHEDULER_POLL_INTERVAL", "30"))
    broadcast_schedule_min_lead_time_seconds: int = int(os.environ.get("BROADCAST_SCHEDULE_MIN_LEAD_TIME", "300"))
    broadcast_reminders_table_name: str = os.environ.get("DDB_BROADCAST_REMINDERS", "BroadcastReminders")

    # Broadcast Newsfeed Promotion (BCAST-010)
    broadcast_newsfeed_promotion_enabled: bool = os.environ.get("BROADCAST_NEWSFEED_PROMOTION_ENABLED", "1") not in ("0", "false", "False")

    # Broadcast Go-Private (BCAST-011)
    broadcast_go_private_enabled: bool = os.environ.get("BROADCAST_GO_PRIVATE_ENABLED", "1") not in ("0", "false", "False")
    broadcast_private_sessions_table_name: str = os.environ.get("DDB_BROADCAST_PRIVATE_SESSIONS", "BroadcastPrivateSessions")
    broadcast_private_default_rate_cents_per_min: int = int(os.environ.get("BROADCAST_PRIVATE_DEFAULT_RATE", "500"))

    # Broadcast Go-Private Visibility / Allowlist (BCAST-011)
    broadcast_privacy_enabled: bool = os.environ.get("BROADCAST_PRIVACY_ENABLED", "1") not in ("0", "false", "False")
    broadcast_allowlist_table_name: str = os.environ.get("DDB_BROADCAST_ALLOWLIST", "BroadcastAllowlist")

    # Broadcast Private Chat Tiers (BCAST-012)
    broadcast_private_chat_enabled: bool = os.environ.get("BROADCAST_PRIVATE_CHAT_ENABLED", "1") not in ("0", "false", "False")
    broadcast_private_chat_max_duration_minutes: int = int(os.environ.get("BROADCAST_PRIVATE_CHAT_MAX_DURATION", "60"))
    broadcast_private_chat_voyeur_enabled: bool = os.environ.get("BROADCAST_PRIVATE_CHAT_VOYEUR_ENABLED", "1") not in ("0", "false", "False")

    # Multi-input / Co-streaming (BCAST-016)
    broadcast_inputs_table_name: str = os.environ.get("DDB_BROADCAST_INPUTS", "BroadcastInputs")
    broadcast_max_inputs_per_session: int = int(os.environ.get("BROADCAST_MAX_INPUTS_PER_SESSION", "4"))
    broadcast_guest_invite_expiry_seconds: int = int(os.environ.get("BROADCAST_GUEST_INVITE_EXPIRY_SECONDS", "3600"))
    broadcast_webrtc_relay_enabled: bool = os.environ.get("BROADCAST_WEBRTC_RELAY_ENABLED", "false").lower() in ("1", "true")
    broadcast_multi_input_enabled: bool = os.environ.get("BROADCAST_MULTI_INPUT_ENABLED", "1") not in ("0", "false", "False")
    broadcast_layout_switch_cooldown_seconds: int = int(os.environ.get("BROADCAST_LAYOUT_SWITCH_COOLDOWN_SECONDS", "2"))

    # Video Clipping (VOD-015)
    video_clipping_enabled: bool = os.environ.get("VIDEO_CLIPPING_ENABLED", "1") not in ("0", "false", "False")
    video_clip_min_duration_seconds: float = float(os.environ.get("VIDEO_CLIP_MIN_DURATION_SECONDS", "1.0"))
    video_clip_max_concurrent: int = int(os.environ.get("VIDEO_CLIP_MAX_CONCURRENT", "2"))

    # Video Concatenation (VOD-016)
    video_concat_enabled: bool = os.environ.get("VIDEO_CONCAT_ENABLED", "1") not in ("0", "false", "False")
    video_concat_max_inputs: int = int(os.environ.get("VIDEO_CONCAT_MAX_INPUTS", "10"))
    video_concat_max_duration_seconds: int = int(os.environ.get("VIDEO_CONCAT_MAX_DURATION_SECONDS", "14400"))
    video_concat_max_total_size_bytes: int = int(os.environ.get("VIDEO_CONCAT_MAX_TOTAL_SIZE_BYTES", str(10 * 1024 * 1024 * 1024)))
    video_concat_timeout_seconds: int = int(os.environ.get("VIDEO_CONCAT_TIMEOUT_SECONDS", "1800"))

    # Video Gallery (VOD-017)
    video_gallery_enabled: bool = os.environ.get("VIDEO_GALLERY_ENABLED", "1") not in ("0", "false", "False")
    video_views_table_name: str = os.environ.get("DDB_VIDEO_VIEWS", "VideoViews")
    video_comments_table_name: str = os.environ.get("DDB_VIDEO_COMMENTS", "VideoComments")
    video_likes_table_name: str = os.environ.get("DDB_VIDEO_LIKES", "VideoLikes")
    video_gallery_trending_decay_hours: int = int(os.environ.get("VIDEO_GALLERY_TRENDING_DECAY_HOURS", "72"))
    video_gallery_page_size: int = int(os.environ.get("VIDEO_GALLERY_PAGE_SIZE", "24"))

    # Ad-Supported Video (VOD-018)
    vod_ads_enabled: bool = os.environ.get("VOD_ADS_ENABLED", "1") not in ("0", "false", "False")
    vod_ad_cpm_cents: int = int(os.environ.get("VOD_AD_CPM_CENTS", "500"))
    ad_impressions_table_name: str = os.environ.get("DDB_AD_IMPRESSIONS", "AdImpressions")
    ad_accounts_table_name: str = os.environ.get("DDB_AD_ACCOUNTS", "AdAccounts")
    ad_campaigns_table_name: str = os.environ.get("DDB_AD_CAMPAIGNS", "AdCampaigns")
    ad_creatives_table_name: str = os.environ.get("DDB_AD_CREATIVES", "AdCreatives")
    ad_targeting_table_name: str = os.environ.get("DDB_AD_TARGETING", "AdTargeting")  # ADS-003
    # Content-Provider Ad Controls (ADS-010) — per-content ad overrides
    content_ad_controls_table_name: str = os.environ.get("DDB_CONTENT_AD_CONTROLS", "ContentAdControls")
    content_ad_controls_enabled: bool = os.environ.get("CONTENT_AD_CONTROLS_ENABLED", "1") not in ("0", "false", "False")
    # Admin Ad Platform Management (ADS-018) — moderation audit log
    ad_moderation_log_table_name: str = os.environ.get("DDB_AD_MODERATION_LOG", "AdModerationLog")
    admin_ad_platform_enabled: bool = os.environ.get("ADMIN_AD_PLATFORM_ENABLED", "1") not in ("0", "false", "False")

    # Ad Serving Engine (ADS-004)
    ad_serving_enabled: bool = os.environ.get("AD_SERVING_ENABLED", "1") not in ("0", "false", "False")
    ad_frequency_cap_hourly: int = int(os.environ.get("AD_FREQUENCY_CAP_HOURLY", "3"))
    ad_frequency_cap_daily: int = int(os.environ.get("AD_FREQUENCY_CAP_DAILY", "10"))
    ad_frequency_caps_table_name: str = os.environ.get("DDB_AD_FREQUENCY_CAPS", "AdFrequencyCaps")
    # Minutes between ad-analytics hourly-rollup ticks. Default 60 (top of each
    # clock hour); set lower in dev to see rollup data populate quickly.
    ad_analytics_rollup_interval_minutes: int = int(
        os.environ.get("AD_ANALYTICS_ROLLUP_INTERVAL_MINUTES", "60")
    )

    # Subscription-Gated VOD (MON-005)
    vod_subscription_gating_enabled: bool = os.environ.get("VOD_SUBSCRIPTION_GATING_ENABLED", "1") not in ("0", "false", "False")
    ad_billing_table_name: str = os.environ.get("DDB_AD_BILLING", "AdBilling")

    # Advertiser Accounts & Campaigns (ADS-001)

    # Sponsored Content & Creator Partnerships (ADS-013)
    sponsorship_deals_table_name: str = os.environ.get(
        "DDB_SPONSORSHIP_DEALS", "sponsorship_deals"
    )
    sponsorship_deals_enabled: bool = os.environ.get(
        "SPONSORSHIP_DEALS_ENABLED", "1"
    ) not in ("0", "false", "False")
    sponsorship_deals_commission_bps: int = int(
        os.environ.get("SPONSORSHIP_DEALS_COMMISSION_BPS", "1500")
    )

    # Ad Analytics Rollups (ADS-008)
    ad_analytics_rollups_table_name: str = os.environ.get("DDB_AD_ANALYTICS_ROLLUPS", "AdAnalyticsRollups")

    # Ad Fraud Prevention (ADS-014)
    ad_fraud_detection_enabled: bool = os.environ.get(
        "AD_FRAUD_DETECTION_ENABLED", "1"
    ) not in ("0", "false", "False")
    ad_fraud_events_table_name: str = os.environ.get("DDB_AD_FRAUD_EVENTS", "AdFraudEvents")
    ad_fraud_score_threshold: int = int(os.environ.get("AD_FRAUD_SCORE_THRESHOLD", "70"))
    ad_fraud_auto_suspend_rate_bps: int = int(os.environ.get("AD_FRAUD_AUTO_SUSPEND_RATE_BPS", "2000"))

    # Ad Scheduling & Dayparting (ADS-016)
    # Schedule (dayparting + flights) is stored on the existing campaign
    # record; no separate table is required.
    ad_dayparting_enabled: bool = os.environ.get(
        "AD_DAYPARTING_ENABLED", "1"
    ) not in ("0", "false", "False")
    ad_dayparting_default_timezone: str = os.environ.get(
        "AD_DAYPARTING_DEFAULT_TIMEZONE", "UTC"
    )

    # Ad Performance Optimization (ADS-017)
    ad_optimization_enabled: bool = os.environ.get(
        "AD_OPTIMIZATION_ENABLED", "1"
    ) not in ("0", "false", "False")
    ad_optimization_recommendations_table_name: str = os.environ.get(
        "DDB_AD_OPTIMIZATION_RECOMMENDATIONS", "AdOptimizationRecommendations"
    )

    # View-Once / Rental Access (VOD-019)
    vod_purchase_tiers_enabled: bool = os.environ.get("VOD_PURCHASE_TIERS_ENABLED", "1") not in ("0", "false", "False")
    vod_rental_default_duration_hours: int = int(os.environ.get("VOD_RENTAL_DEFAULT_DURATION_HOURS", "48"))
    vod_view_once_enabled: bool = os.environ.get("VOD_VIEW_ONCE_ENABLED", "1") not in ("0", "false", "False")
    # VOD-019 rental-access layer (dedicated vod_rentals table)
    vod_rentals_table_name: str = os.environ.get("DDB_VOD_RENTALS", "VodRentals")
    vod_rental_enabled: bool = os.environ.get("VOD_RENTAL_ENABLED", "1") not in ("0", "false", "False")
    vod_rental_playback_ttl_seconds: int = int(os.environ.get("VOD_RENTAL_PLAYBACK_TTL_SECONDS", "3600"))
    # VOD-018 ad-supported viewing tier (dedicated vod_ad_sessions table)
    vod_ad_supported_enabled: bool = os.environ.get("VOD_AD_SUPPORTED_ENABLED", "1") not in ("0", "false", "False")
    # When true, ad selection is deterministic (static placeholder creatives) instead of
    # calling the live ad_serving engine. Keeps E2E reproducible.
    vod_ad_supported_deterministic: bool = os.environ.get("VOD_AD_SUPPORTED_DETERMINISTIC", "1") not in ("0", "false", "False")
    vod_ad_supported_playback_ttl_seconds: int = int(os.environ.get("VOD_AD_SUPPORTED_PLAYBACK_TTL_SECONDS", "3600"))
    vod_ad_sessions_table_name: str = os.environ.get("DDB_VOD_AD_SESSIONS", "VodAdSessions")

    # Privacy / GDPR (PRIVACY-001)
    data_requests_table_name: str = os.environ.get("DATA_REQUESTS_TABLE_NAME", "data_requests")
    data_request_audit_table_name: str = os.environ.get("DATA_REQUEST_AUDIT_TABLE_NAME", "data_request_audit")
    privacy_export_enabled: bool = os.environ.get("PRIVACY_EXPORT_ENABLED", "1") not in ("0", "false", "False")
    privacy_deletion_enabled: bool = os.environ.get("PRIVACY_DELETION_ENABLED", "1") not in ("0", "false", "False")
    privacy_export_max_size_bytes: int = int(os.environ.get("PRIVACY_EXPORT_MAX_SIZE_BYTES", str(5 * 1024**3)))
    privacy_export_ttl_days: int = int(os.environ.get("PRIVACY_EXPORT_TTL_DAYS", "7"))
    privacy_deletion_grace_period_days: int = int(os.environ.get("PRIVACY_DELETION_GRACE_PERIOD_DAYS", "14"))
    privacy_billing_retention_years: int = int(os.environ.get("PRIVACY_BILLING_RETENTION_YEARS", "7"))
    privacy_export_s3_bucket: str = os.environ.get("PRIVACY_EXPORT_S3_BUCKET", "data-exports")
    privacy_export_rate_limit_hours: int = int(os.environ.get("PRIVACY_EXPORT_RATE_LIMIT_HOURS", "24"))

    # Account Deletion (PLATFORM-018)
    account_deletion_requests_table_name: str = os.environ.get(
        "ACCOUNT_DELETION_REQUESTS_TABLE_NAME", "account_deletion_requests"
    )
    account_deletion_enabled: bool = os.environ.get(
        "ACCOUNT_DELETION_ENABLED", "1"
    ) not in ("0", "false", "False")
    account_deletion_grace_period_days: int = int(
        os.environ.get("ACCOUNT_DELETION_GRACE_PERIOD_DAYS", "30")
    )
    account_deletion_scheduler_enabled: bool = os.environ.get(
        "ACCOUNT_DELETION_SCHEDULER_ENABLED", "0"
    ) not in ("0", "false", "False")
    account_deletion_scheduler_interval_seconds: int = int(
        os.environ.get("ACCOUNT_DELETION_SCHEDULER_INTERVAL_SECONDS", "21600")
    )
    account_deletion_export_ttl_days: int = int(
        os.environ.get("ACCOUNT_DELETION_EXPORT_TTL_DAYS", "7")
    )
    account_deletion_destructive: bool = os.environ.get(
        "ACCOUNT_DELETION_DESTRUCTIVE", "0"
    ) not in ("0", "false", "False")

    # Stories / Ephemeral Content (FEED-002)
    stories_enabled: bool = os.environ.get("STORIES_ENABLED", "1") not in ("0", "false", "False")
    story_max_duration_seconds: int = int(os.environ.get("STORY_MAX_DURATION_SECONDS", "60"))
    story_max_media_size_bytes: int = int(os.environ.get("STORY_MAX_MEDIA_SIZE_BYTES", "52428800"))
    story_expiry_seconds: int = int(os.environ.get("STORY_EXPIRY_SECONDS", "86400"))
    story_bar_max_followed: int = int(os.environ.get("STORY_BAR_MAX_FOLLOWED", "200"))
    story_max_per_day: int = int(os.environ.get("STORY_MAX_PER_DAY", "30"))

    # Referral / Affiliate System (AFFILIATE-001)
    referral_enabled: bool = os.environ.get("REFERRAL_ENABLED", "1") not in ("0", "false", "False")
    referral_cookie_max_age_days: int = int(os.environ.get("REFERRAL_COOKIE_MAX_AGE_DAYS", "30"))
    referral_commission_window_days: int = int(os.environ.get("REFERRAL_COMMISSION_WINDOW_DAYS", "365"))
    referral_standard_rate_bps: int = int(os.environ.get("REFERRAL_STANDARD_RATE_BPS", "500"))
    referral_premium_rate_bps: int = int(os.environ.get("REFERRAL_PREMIUM_RATE_BPS", "1000"))
    referral_max_codes_per_user: int = int(os.environ.get("REFERRAL_MAX_CODES_PER_USER", "5"))
    referral_holdback_days: int = int(os.environ.get("REFERRAL_HOLDBACK_DAYS", "7"))
    referral_min_withdrawal_cents: int = int(os.environ.get("REFERRAL_MIN_WITHDRAWAL_CENTS", "1000"))

    # Voice Messages (MSG-002)
    voice_message_enabled: bool = os.environ.get("VOICE_MESSAGE_ENABLED", "1") not in ("0", "false", "False")
    voice_message_max_duration_seconds: int = int(os.environ.get("VOICE_MESSAGE_MAX_DURATION_SECONDS", "300"))
    voice_message_max_size_bytes: int = int(os.environ.get("VOICE_MESSAGE_MAX_SIZE_BYTES", "52428800"))
    voice_message_waveform_samples: int = int(os.environ.get("VOICE_MESSAGE_WAVEFORM_SAMPLES", "100"))

    # Messenger Voice & Translation AI (MVA-001..MVA-003)
    # Flags default safely: translation on; transcription/TTS off until keys configured.
    messaging_translation_enabled: bool = os.environ.get("MESSAGING_TRANSLATION_ENABLED", "1") not in ("0", "false", "False")
    messaging_transcription_enabled: bool = os.environ.get("MESSAGING_TRANSCRIPTION_ENABLED", "0") not in ("0", "false", "False")
    messaging_tts_enabled: bool = os.environ.get("MESSAGING_TTS_ENABLED", "0") not in ("0", "false", "False")
    messaging_translation_provider: str = os.environ.get("MESSAGING_TRANSLATION_PROVIDER", "anthropic")
    messaging_tts_provider: str = os.environ.get("MESSAGING_TTS_PROVIDER", "elevenlabs")
    messaging_stt_provider: str = os.environ.get("MESSAGING_STT_PROVIDER", "elevenlabs")
    messaging_tts_max_chars: int = int(os.environ.get("MESSAGING_TTS_MAX_CHARS", "5000"))
    messaging_translation_cache_ttl_seconds: int = int(os.environ.get("MESSAGING_TRANSLATION_CACHE_TTL_SECONDS", "2592000"))
    message_ai_cache_table_name: str = os.environ.get("MESSAGE_AI_CACHE_TABLE_NAME", "message_ai_cache")
    # Per-feature rate-limit caps (requests per window).
    messaging_ai_translate_max_per_window: int = int(os.environ.get("MESSAGING_AI_TRANSLATE_RL_MAX", "60"))
    messaging_ai_translate_window_seconds: int = int(os.environ.get("MESSAGING_AI_TRANSLATE_RL_WINDOW", "60"))
    messaging_ai_transcribe_max_per_window: int = int(os.environ.get("MESSAGING_AI_TRANSCRIBE_RL_MAX", "20"))
    messaging_ai_transcribe_window_seconds: int = int(os.environ.get("MESSAGING_AI_TRANSCRIBE_RL_WINDOW", "60"))
    messaging_ai_tts_max_per_window: int = int(os.environ.get("MESSAGING_AI_TTS_RL_MAX", "20"))
    messaging_ai_tts_window_seconds: int = int(os.environ.get("MESSAGING_AI_TTS_RL_WINDOW", "60"))

    # Voicemail (CALL-014)
    voicemail_enabled: bool = os.environ.get("VOICEMAIL_ENABLED", "1") not in ("0", "false", "False")
    voicemail_max_duration_seconds: int = int(os.environ.get("VOICEMAIL_MAX_DURATION_SECONDS", "60"))
    voicemail_max_size_bytes: int = int(os.environ.get("VOICEMAIL_MAX_SIZE_BYTES", "52428800"))

    # Rate limiting (PLATFORM-001)
    rate_limits_table_name: str = os.environ.get("RATE_LIMITS_TABLE_NAME", "rate_limits")
    rate_limit_events_table_name: str = os.environ.get("RATE_LIMIT_EVENTS_TABLE_NAME", "rate_limit_events")
    rate_limit_global_enabled: bool = os.environ.get("RATE_LIMIT_GLOBAL_ENABLED", "1") not in ("0", "false", "False")
    rate_limit_per_endpoint_enabled: bool = os.environ.get("RATE_LIMIT_PER_ENDPOINT_ENABLED", "1") not in ("0", "false", "False")
    rate_limit_global_ip_window_seconds: int = int(os.environ.get("RATE_LIMIT_GLOBAL_IP_WINDOW_SECONDS", "60"))
    rate_limit_global_ip_max_requests: int = int(os.environ.get("RATE_LIMIT_GLOBAL_IP_MAX_REQUESTS", "300"))
    rate_limit_events_ttl_days: int = int(os.environ.get("RATE_LIMIT_EVENTS_TTL_DAYS", "30"))
    rate_limit_dashboard_enabled: bool = os.environ.get("RATE_LIMIT_DASHBOARD_ENABLED", "1") not in ("0", "false", "False")
    rate_limit_fail_open: bool = os.environ.get("RATE_LIMIT_FAIL_OPEN", "1") not in ("0", "false", "False")

    # Webhooks (PLATFORM-002)
    webhook_endpoints_table_name: str = os.environ.get("WEBHOOK_ENDPOINTS_TABLE_NAME", "webhook_endpoints")
    webhook_deliveries_table_name: str = os.environ.get("WEBHOOK_DELIVERIES_TABLE_NAME", "webhook_deliveries")
    webhooks_enabled: bool = os.environ.get("WEBHOOKS_ENABLED", "1") not in ("0", "false", "False")
    webhooks_max_endpoints_per_user: int = int(os.environ.get("WEBHOOKS_MAX_ENDPOINTS_PER_USER", "10"))
    webhooks_delivery_timeout_seconds: int = int(os.environ.get("WEBHOOKS_DELIVERY_TIMEOUT_SECONDS", "15"))
    webhooks_max_retries: int = int(os.environ.get("WEBHOOKS_MAX_RETRIES", "5"))
    webhooks_auto_disable_threshold: int = int(os.environ.get("WEBHOOKS_AUTO_DISABLE_THRESHOLD", "50"))
    webhooks_dispatcher_poll_interval: int = int(os.environ.get("WEBHOOKS_DISPATCHER_POLL_INTERVAL", "10"))
    webhooks_delivery_ttl_days: int = int(os.environ.get("WEBHOOKS_DELIVERY_TTL_DAYS", "30"))

    # Webhooks v2 (ENTERPRISE-005)
    webhooks_v2_enabled: bool = os.environ.get("WEBHOOKS_V2_ENABLED", "1") not in ("0", "false", "False")
    webhooks_circuit_breaker_enabled: bool = os.environ.get("WEBHOOKS_CIRCUIT_BREAKER_ENABLED", "1") not in ("0", "false", "False")
    webhooks_default_circuit_failure_threshold: int = int(os.environ.get("WEBHOOKS_DEFAULT_CIRCUIT_FAILURE_THRESHOLD", "10"))
    webhooks_circuit_initial_cooldown_seconds: int = int(os.environ.get("WEBHOOKS_CIRCUIT_INITIAL_COOLDOWN_SECONDS", "300"))
    webhooks_circuit_max_cooldown_seconds: int = int(os.environ.get("WEBHOOKS_CIRCUIT_MAX_COOLDOWN_SECONDS", "86400"))
    webhooks_stats_table_name: str = os.environ.get("WEBHOOKS_STATS_TABLE_NAME", "webhook_stats")
    webhooks_stats_retention_days: int = int(os.environ.get("WEBHOOKS_STATS_RETENTION_DAYS", "90"))
    webhooks_replay_rate_limit_per_hour: int = int(os.environ.get("WEBHOOKS_REPLAY_RATE_LIMIT_PER_HOUR", "100"))
    webhooks_signature_replay_window_seconds: int = int(os.environ.get("WEBHOOKS_SIGNATURE_REPLAY_WINDOW_SECONDS", "300"))
    webhooks_max_payload_size_bytes: int = int(os.environ.get("WEBHOOKS_MAX_PAYLOAD_SIZE_BYTES", "65536"))

    # Unified Content Scheduling (SCHED-001)
    scheduled_actions_table_name: str = os.environ.get("SCHEDULED_ACTIONS_TABLE_NAME", "scheduled_actions")
    unified_scheduler_enabled: bool = os.environ.get("UNIFIED_SCHEDULER_ENABLED", "1") not in ("0", "false", "False")
    unified_scheduler_poll_interval_seconds: int = int(os.environ.get("UNIFIED_SCHEDULER_POLL_INTERVAL_SECONDS", "15"))
    scheduled_actions_max_per_user: int = int(os.environ.get("SCHEDULED_ACTIONS_MAX_PER_USER", "100"))
    scheduled_actions_min_lead_time_seconds: int = int(os.environ.get("SCHEDULED_ACTIONS_MIN_LEAD_TIME_SECONDS", "300"))
    scheduled_actions_max_retries: int = int(os.environ.get("SCHEDULED_ACTIONS_MAX_RETRIES", "3"))
    scheduled_actions_ttl_days: int = int(os.environ.get("SCHEDULED_ACTIONS_TTL_DAYS", "90"))

    # Creator Analytics Dashboard (ANALYTICS-001)
    analytics_rollups_table_name: str = os.environ.get("DDB_ANALYTICS_ROLLUPS", "AnalyticsRollups")
    # GAP-0333 / PLATFORM-019: raw analytics events table (feeds the rollup job).
    analytics_events_table_name: str = os.environ.get("DDB_ANALYTICS_EVENTS", "AnalyticsEvents")
    analytics_rollup_enabled: bool = os.environ.get("ANALYTICS_ROLLUP_ENABLED", "1") not in ("0", "false", "False")
    analytics_rollup_interval_seconds: int = int(os.environ.get("ANALYTICS_ROLLUP_INTERVAL_SECONDS", "900"))
    analytics_rollup_lookback_days: int = int(os.environ.get("ANALYTICS_ROLLUP_LOOKBACK_DAYS", "3"))

    # Per-Content Revenue Breakdown (FIN-006)
    per_content_revenue_enabled: bool = os.environ.get("PER_CONTENT_REVENUE_ENABLED", "1") not in ("0", "false", "False")
    per_content_revenue_table_name: str = os.environ.get("DDB_PER_CONTENT_REVENUE", "PerContentRevenue")
    per_content_revenue_max_export_rows: int = int(os.environ.get("PER_CONTENT_REVENUE_MAX_EXPORT_ROWS", "10000"))

    # Geo-blocking (GEO-001)
    geo_blocking_enabled: bool = os.environ.get("GEO_BLOCKING_ENABLED", "1") not in ("0", "false", "False")
    geo_platform_block_countries: str = os.environ.get("GEO_PLATFORM_BLOCK_COUNTRIES", "")
    # GAP-0217 (GEO-001): DDB-backed, hot-reloadable platform block list. The env-var
    # above stays as a bootstrap override and is unioned with the DDB record. The table
    # holds a single record (pk="PLATFORM", sk="GEO_BLOCK"); the in-process cache below
    # bounds DDB reads so check_geo_access stays fast.
    geo_rules_table_name: str = os.environ.get("GEO_RULES_TABLE_NAME", "geo_rules")
    geo_platform_block_cache_ttl_seconds: int = int(os.environ.get("GEO_PLATFORM_BLOCK_CACHE_TTL_SECONDS", "60"))
    geo_maxmind_db_path: str = os.environ.get("GEO_MAXMIND_DB_PATH", "")
    geo_cache_ttl_seconds: int = int(os.environ.get("GEO_CACHE_TTL_SECONDS", "3600"))
    geo_cache_max_size: int = int(os.environ.get("GEO_CACHE_MAX_SIZE", "50000"))
    geo_fail_open_dev: bool = os.environ.get("GEO_FAIL_OPEN_DEV", "1") not in ("0", "false", "False")

    # Watermarked Downloads (VOD-020)
    watermark_downloads_enabled: bool = os.environ.get("WATERMARK_DOWNLOADS_ENABLED", "1") not in ("0", "false", "False")
    watermark_jobs_table_name: str = os.environ.get("WATERMARK_JOBS_TABLE_NAME", "watermark_jobs")
    watermark_opacity: float = float(os.environ.get("WATERMARK_OPACITY", "0.02"))
    watermark_font_size: int = int(os.environ.get("WATERMARK_FONT_SIZE", "8"))
    watermark_crf: int = int(os.environ.get("WATERMARK_CRF", "18"))
    watermark_preset: str = os.environ.get("WATERMARK_PRESET", "fast")
    watermark_timeout_seconds: int = int(os.environ.get("WATERMARK_TIMEOUT_SECONDS", "600"))
    watermark_cache_ttl_seconds: int = int(os.environ.get("WATERMARK_CACHE_TTL_SECONDS", "86400"))
    watermark_max_concurrent_jobs: int = int(os.environ.get("WATERMARK_MAX_CONCURRENT_JOBS", "5"))

    # Watermarked Downloads — per-viewer render flow (VOD-020, distinct pipeline)
    vod_watermark_download_enabled: bool = os.environ.get("VOD_WATERMARK_DOWNLOAD_ENABLED", "1") not in ("0", "false", "False")
    vod_watermark_download_real_ffmpeg: bool = os.environ.get("VOD_WATERMARK_DOWNLOAD_REAL_FFMPEG", "0") not in ("0", "false", "False")
    vod_watermark_downloads_table_name: str = os.environ.get("VOD_WATERMARK_DOWNLOADS_TABLE_NAME", "vod_watermark_downloads")
    vod_watermark_download_ttl_seconds: int = int(os.environ.get("VOD_WATERMARK_DOWNLOAD_TTL_SECONDS", "86400"))
    vod_watermark_download_url_ttl_seconds: int = int(os.environ.get("VOD_WATERMARK_DOWNLOAD_URL_TTL_SECONDS", "3600"))
    vod_watermark_download_max_concurrent: int = int(os.environ.get("VOD_WATERMARK_DOWNLOAD_MAX_CONCURRENT", "5"))
    vod_watermark_download_opacity: float = float(os.environ.get("VOD_WATERMARK_DOWNLOAD_OPACITY", "0.02"))

    # Subtitles / Closed Captions (VOD-021)
    video_subtitle_enabled: bool = os.environ.get("VIDEO_SUBTITLE_ENABLED", "1") not in ("0", "false", "False")
    video_subtitle_max_tracks: int = int(os.environ.get("VIDEO_SUBTITLE_MAX_TRACKS", "20"))
    video_subtitle_max_file_size_kb: int = int(os.environ.get("VIDEO_SUBTITLE_MAX_FILE_SIZE_KB", "512"))
    video_subtitle_allowed_formats: str = os.environ.get("VIDEO_SUBTITLE_ALLOWED_FORMATS", "vtt,srt")
    video_subtitle_url_ttl_seconds: int = int(os.environ.get("VIDEO_SUBTITLE_URL_TTL_SECONDS", "3600"))

    # Promo Codes & Coupons (PROMO-001)
    promo_codes_table_name: str = os.environ.get("DDB_PROMO_CODES", "PromoCodes")
    promo_codes_enabled: bool = os.environ.get("PROMO_CODES_ENABLED", "1") not in ("0", "false", "False")
    promo_code_max_per_creator: int = int(os.environ.get("PROMO_CODE_MAX_PER_CREATOR", "100"))
    promo_code_max_discount_percent: int = int(os.environ.get("PROMO_CODE_MAX_DISCOUNT_PERCENT", "100"))
    promo_code_max_free_trial_days: int = int(os.environ.get("PROMO_CODE_MAX_FREE_TRIAL_DAYS", "30"))

    # Content Recommendations (DISC-001)
    recommendations_table_name: str = os.environ.get("RECOMMENDATIONS_TABLE_NAME", "recommendations")
    recommendations_enabled: bool = os.environ.get("RECOMMENDATIONS_ENABLED", "1") not in ("0", "false", "False")
    reco_refresh_interval_hours: int = int(os.environ.get("RECO_REFRESH_INTERVAL_HOURS", "6"))
    reco_max_similar_users: int = int(os.environ.get("RECO_MAX_SIMILAR_USERS", "50"))
    reco_max_for_you_results: int = int(os.environ.get("RECO_MAX_FOR_YOU_RESULTS", "200"))
    reco_max_similar_videos: int = int(os.environ.get("RECO_MAX_SIMILAR_VIDEOS", "20"))
    reco_max_creator_suggestions: int = int(os.environ.get("RECO_MAX_CREATOR_SUGGESTIONS", "50"))
    reco_new_video_boost_hours: int = int(os.environ.get("RECO_NEW_VIDEO_BOOST_HOURS", "48"))
    reco_signal_retention_days: int = int(os.environ.get("RECO_SIGNAL_RETENTION_DAYS", "90"))

    # Newsfeed "For You" recommendations (NRS-001) — flag defaults OFF so existing
    # GET /feed behavior is byte-for-byte unchanged unless explicitly enabled.
    newsfeed_recsys_enabled: bool = os.environ.get("NEWSFEED_RECSYS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    newsfeed_recsys_refresh_interval_hours: int = int(os.environ.get("NEWSFEED_RECSYS_REFRESH_INTERVAL_HOURS", "6"))
    newsfeed_recsys_max_for_you_results: int = int(os.environ.get("NEWSFEED_RECSYS_MAX_FOR_YOU_RESULTS", "200"))
    newsfeed_recsys_candidate_followed_limit: int = int(os.environ.get("NEWSFEED_RECSYS_CANDIDATE_FOLLOWED_LIMIT", "200"))
    newsfeed_recsys_candidate_popular_limit: int = int(os.environ.get("NEWSFEED_RECSYS_CANDIDATE_POPULAR_LIMIT", "100"))
    newsfeed_recsys_candidate_affinity_limit: int = int(os.environ.get("NEWSFEED_RECSYS_CANDIDATE_AFFINITY_LIMIT", "100"))
    newsfeed_recsys_signal_retention_days: int = int(os.environ.get("NEWSFEED_RECSYS_SIGNAL_RETENTION_DAYS", "90"))
    newsfeed_recsys_new_post_boost_hours: int = int(os.environ.get("NEWSFEED_RECSYS_NEW_POST_BOOST_HOURS", "48"))
    # Ranking-weight knobs (consumed by score_post in NRS-005)
    newsfeed_recsys_weight_recency: float = float(os.environ.get("NEWSFEED_RECSYS_WEIGHT_RECENCY", "1.0"))
    newsfeed_recsys_weight_engagement: float = float(os.environ.get("NEWSFEED_RECSYS_WEIGHT_ENGAGEMENT", "1.0"))
    newsfeed_recsys_weight_affinity: float = float(os.environ.get("NEWSFEED_RECSYS_WEIGHT_AFFINITY", "3.0"))
    newsfeed_recsys_weight_content_type: float = float(os.environ.get("NEWSFEED_RECSYS_WEIGHT_CONTENT_TYPE", "0.5"))
    newsfeed_recsys_weight_personal_history: float = float(os.environ.get("NEWSFEED_RECSYS_WEIGHT_PERSONAL_HISTORY", "2.0"))
    newsfeed_recsys_engagement_decay_factor: float = float(os.environ.get("NEWSFEED_RECSYS_ENGAGEMENT_DECAY_FACTOR", "0.95"))

    # Refund Requests (BILLING-001)
    refund_requests_table_name: str = os.environ.get("DDB_REFUND_REQUESTS", "RefundRequests")
    refund_requests_enabled: bool = os.environ.get("REFUND_REQUESTS_ENABLED", "1") not in ("0", "false", "False")
    refund_request_window_days: int = int(os.environ.get("REFUND_WINDOW_DAYS", "30"))
    max_refund_requests_per_month: int = int(os.environ.get("MAX_REFUND_REQUESTS_PER_MONTH", "3"))
    refund_max_amount_cents: int = int(os.environ.get("REFUND_MAX_AMOUNT_CENTS", "100000"))

    # Billing Disputes / Chargebacks (BILLING-001)
    billing_disputes_table_name: str = os.environ.get("DDB_BILLING_DISPUTES", "BillingDisputes")
    billing_disputes_enabled: bool = os.environ.get("BILLING_DISPUTES_ENABLED", "1") not in ("0", "false", "False")
    billing_disputes_default_deadline_days: int = int(os.environ.get("BILLING_DISPUTES_DEADLINE_DAYS", "14"))

    # Notification Delivery Enhancements (NOTIFY-001)
    notification_dispatch_enabled: bool = os.environ.get("NOTIFICATION_DISPATCH_ENABLED", "1") not in ("0", "false", "False")
    notification_email_templates_enabled: bool = os.environ.get("NOTIFICATION_EMAIL_TEMPLATES_ENABLED", "1") not in ("0", "false", "False")

    # EML-002: Admin runtime email settings override
    email_settings_table_name: str = os.environ.get("EMAIL_SETTINGS_TABLE_NAME", "email_settings")
    email_settings_cache_ttl_seconds: int = int(os.environ.get("EMAIL_SETTINGS_CACHE_TTL_SECONDS", "60"))
    admin_email_settings_enabled: bool = os.environ.get("ADMIN_EMAIL_SETTINGS_ENABLED", "0") not in ("0", "false", "False")

    # EML-003: Per-user email account connections
    user_email_accounts_table_name: str = os.environ.get("USER_EMAIL_ACCOUNTS_TABLE_NAME", "user_email_accounts")
    email_client_enabled: bool = os.environ.get("EMAIL_CLIENT_ENABLED", "0") not in ("0", "false", "False")

    # EML-004: IMAP inbox sync
    user_email_messages_table_name: str = os.environ.get("USER_EMAIL_MESSAGES_TABLE_NAME", "user_email_messages")
    email_messages_ttl_days: int = int(os.environ.get("EMAIL_MESSAGES_TTL_DAYS", "90"))
    email_imap_max_fetch: int = int(os.environ.get("EMAIL_IMAP_MAX_FETCH", "200"))
    email_imap_timeout_seconds: int = int(os.environ.get("EMAIL_IMAP_TIMEOUT_SECONDS", "30"))
    email_bodies_s3_bucket: str = os.environ.get("EMAIL_BODIES_S3_BUCKET", "local-uploads")
    email_bodies_s3_prefix: str = os.environ.get("EMAIL_BODIES_S3_PREFIX", "email-bodies/")

    # EML-007: Email archiving
    email_archive_table_name: str = os.environ.get("EMAIL_ARCHIVE_TABLE_NAME", "email_archive")
    email_archiving_enabled: bool = os.environ.get("EMAIL_ARCHIVING_ENABLED", "0") not in ("0", "false", "False")

    # EML-009: Campaign email templates
    campaign_email_templates_enabled: bool = os.environ.get("CAMPAIGN_EMAIL_TEMPLATES_ENABLED", "0") not in ("0", "false", "False")
    notification_toast_enabled: bool = os.environ.get("NOTIFICATION_TOAST_ENABLED", "1") not in ("0", "false", "False")
    notification_unread_count_enabled: bool = os.environ.get("NOTIFICATION_UNREAD_COUNT_ENABLED", "1") not in ("0", "false", "False")
    toast_default_duration_ms: int = int(os.environ.get("TOAST_DEFAULT_DURATION_MS", "5000"))
    toast_urgent_duration_ms: int = int(os.environ.get("TOAST_URGENT_DURATION_MS", "0"))
    toast_low_duration_ms: int = int(os.environ.get("TOAST_LOW_DURATION_MS", "3000"))
    vapid_public_key: str = os.environ.get("VAPID_PUBLIC_KEY", "")
    vapid_private_key: str = os.environ.get("VAPID_PRIVATE_KEY", "")
    vapid_subject: str = os.environ.get("VAPID_SUBJECT", "mailto:admin@testlogon.local")
    web_push_enabled: bool = os.environ.get("WEB_PUSH_ENABLED", "1") not in ("0", "false", "False")

    # Internationalization (PLATFORM-003)
    translations_table_name: str = os.environ.get("TRANSLATIONS_TABLE_NAME", "translations")
    i18n_default_locale: str = os.environ.get("I18N_DEFAULT_LOCALE", "en")
    i18n_supported_locales: str = os.environ.get("I18N_SUPPORTED_LOCALES", "en,es,fr")
    i18n_enabled: bool = os.environ.get("I18N_ENABLED", "1") not in ("0", "false", "False")
    i18n_rtl_enabled: bool = os.environ.get("I18N_RTL_ENABLED", "1") not in ("0", "false", "False")
    i18n_admin_management_enabled: bool = os.environ.get("I18N_ADMIN_MANAGEMENT_ENABLED", "1") not in ("0", "false", "False")

    # KYC Multi-Language Support (KYC-020)
    kyc_translations_table_name: str = os.environ.get("KYC_TRANSLATIONS_TABLE_NAME", "kyc_translations")
    i18n_kyc_supported_locales: str = os.environ.get(
        "I18N_KYC_SUPPORTED_LOCALES", "en,es,fr,de,pt,zh,ja,ko,ar,hi"
    )
    i18n_kyc_default_locale: str = os.environ.get("I18N_KYC_DEFAULT_LOCALE", "en")
    i18n_kyc_localization_enabled: bool = os.environ.get(
        "I18N_KYC_LOCALIZATION_ENABLED", "1"
    ) not in ("0", "false", "False")

    # Group Video Calls (CALL-012)
    group_call_sessions_table_name: str = os.environ.get("DDB_GROUP_CALL_SESSIONS", "GroupCallSessions")
    group_calls_enabled: bool = os.environ.get("GROUP_CALLS_ENABLED", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
    group_call_max_participants: int = int(os.environ.get("GROUP_CALL_MAX_PARTICIPANTS", "8"))
    group_call_max_duration_seconds: int = int(os.environ.get("GROUP_CALL_MAX_DURATION_SECONDS", "14400"))
    group_call_sfu_endpoint: str = os.environ.get("GROUP_CALL_SFU_ENDPOINT", "")
    group_call_dev_mesh_max_participants: int = int(os.environ.get("GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS", "4"))

    # Collaboration Requests (CREATOR-001)
    collaborations_enabled: bool = os.environ.get("COLLABORATIONS_ENABLED", "1") not in ("0", "false", "False")
    collaboration_agreements_table_name: str = os.environ.get("DDB_COLLABORATION_AGREEMENTS", "collaboration_agreements")
    # Collaboration Revenue Splitting (FIN-011)
    collaboration_revenue_enabled: bool = os.environ.get("COLLABORATION_REVENUE_ENABLED", "1") not in ("0", "false", "False")

    # Organizations / Workspaces (ENTERPRISE-003)
    orgs_enabled: bool = os.environ.get("ORGS_ENABLED", "0") not in ("0", "false", "False")
    organizations_table_name: str = os.environ.get("ORGANIZATIONS_TABLE_NAME", "organizations")
    org_max_members: int = int(os.environ.get("ORG_MAX_MEMBERS", "100"))
    org_max_per_user: int = int(os.environ.get("ORG_MAX_PER_USER", "50"))
    org_invite_ttl_seconds: int = int(os.environ.get("ORG_INVITE_TTL_SECONDS", str(7 * 24 * 3600)))

    # User Groups (GROUP-001 / GROUP-002)
    user_groups_enabled: bool = os.environ.get("USER_GROUPS_ENABLED", "1") not in ("0", "false", "False")
    ddb_user_groups_table: str = os.environ.get("DDB_USER_GROUPS_TABLE", "user_groups")
    user_group_max_members: int = int(os.environ.get("USER_GROUP_MAX_MEMBERS", "10000"))
    user_group_max_per_user: int = int(os.environ.get("USER_GROUP_MAX_PER_USER", "50"))
    group_feed_enabled: bool = os.environ.get("GROUP_FEED_ENABLED", "1") not in ("0", "false", "False")

    # Fan Clubs / Membership Tiers (CREATOR-002)
    fan_clubs_enabled: bool = os.environ.get("FAN_CLUBS_ENABLED", "1") not in ("0", "false", "False")
    fan_club_channels_table_name: str = os.environ.get("FAN_CLUB_CHANNELS_TABLE_NAME", "fan_club_channels")
    fan_club_messages_table_name: str = os.environ.get("FAN_CLUB_MESSAGES_TABLE_NAME", "fan_club_messages")

    # Affiliate Links (CREATOR-004)
    affiliate_links_enabled: bool = os.environ.get("AFFILIATE_LINKS_ENABLED", "1") not in ("0", "false", "False")
    affiliate_default_commission_percent: int = int(os.environ.get("AFFILIATE_DEFAULT_COMMISSION_PERCENT", "10"))
    affiliate_max_commission_percent: int = int(os.environ.get("AFFILIATE_MAX_COMMISSION_PERCENT", "50"))
    affiliate_cookie_duration_days: int = int(os.environ.get("AFFILIATE_COOKIE_DURATION_DAYS", "30"))
    affiliate_links_table_name: str = os.environ.get("DDB_AFFILIATE_LINKS", "AffiliateLinks")
    affiliate_clicks_table_name: str = os.environ.get("DDB_AFFILIATE_CLICKS", "AffiliateClicks")

    # Ad Creative Affiliate Discounts (ADS-015)
    ad_creative_affiliate_enabled: bool = os.environ.get("AD_CREATIVE_AFFILIATE_ENABLED", "1") not in ("0", "false", "False")
    ad_creative_affiliate_promo_cookie_max_age: int = int(os.environ.get("AD_CREATIVE_AFFILIATE_PROMO_COOKIE_MAX_AGE", "86400"))
    ad_creative_affiliates_table_name: str = os.environ.get("DDB_AD_CREATIVE_AFFILIATES", "AdCreativeAffiliates")
    # When enabled, ad_analytics.get_summary enriches campaign summaries with a
    # real ROAS value (from conversion attribution) so optimization alerts stop
    # reading roas=0 (GAP-0062 / ADS-015).
    roas_in_summary_enabled: bool = os.environ.get("ROAS_IN_SUMMARY_ENABLED", "1") not in ("0", "false", "False")

    # Achievements & Gamification (ENGAGE-001)
    achievements_enabled: bool = os.environ.get("ACHIEVEMENTS_ENABLED", "0") not in ("0", "false", "False")
    achievements_table_name: str = os.environ.get("ACHIEVEMENTS_TABLE_NAME", "achievements")
    user_achievements_table_name: str = os.environ.get("USER_ACHIEVEMENTS_TABLE_NAME", "user_achievements")
    user_achievement_progress_table_name: str = os.environ.get("USER_ACHIEVEMENT_PROGRESS_TABLE_NAME", "user_achievement_progress")
    achievement_leaderboard_table_name: str = os.environ.get("ACHIEVEMENT_LEADERBOARD_TABLE_NAME", "achievement_leaderboard")

    # Audit Log Export (ENTERPRISE-004)
    audit_export_enabled: bool = os.environ.get("AUDIT_EXPORT_ENABLED", "1") not in ("0", "false", "False")
    audit_export_table_name: str = os.environ.get("DDB_AUDIT_EXPORTS", "AuditExports")
    audit_export_max_date_range_days: int = int(os.environ.get("AUDIT_EXPORT_MAX_DATE_RANGE_DAYS", "90"))
    audit_export_max_events: int = int(os.environ.get("AUDIT_EXPORT_MAX_EVENTS", "10000000"))
    audit_export_s3_bucket: str = os.environ.get("AUDIT_EXPORT_S3_BUCKET", "data-exports")
    audit_export_url_ttl_seconds: int = int(os.environ.get("AUDIT_EXPORT_URL_TTL_SECONDS", "86400"))
    audit_export_signing_key: str = os.environ.get(
        "AUDIT_EXPORT_SIGNING_KEY",
        os.environ.get("MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY", "dev-export-signing-key"),
    )
    audit_export_signing_key_id: str = os.environ.get(
        "AUDIT_EXPORT_SIGNING_KEY_ID",
        os.environ.get("MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY_ID", "dev-key-v1"),
    )
    audit_export_worker_enabled: bool = os.environ.get("AUDIT_EXPORT_WORKER_ENABLED", "1") not in ("0", "false", "False")
    audit_export_worker_poll_interval_seconds: int = int(os.environ.get("AUDIT_EXPORT_WORKER_POLL_INTERVAL_SECONDS", "10"))
    audit_export_worker_max_concurrent: int = int(os.environ.get("AUDIT_EXPORT_WORKER_MAX_CONCURRENT", "3"))
    # GAP-0210: scheduled (recurring) audit export reports (FIN-016).
    audit_export_scheduler_enabled: bool = os.environ.get("AUDIT_EXPORT_SCHEDULER_ENABLED", "1") not in ("0", "false", "False")
    audit_export_scheduler_poll_interval_seconds: int = int(os.environ.get("AUDIT_EXPORT_SCHEDULER_POLL_INTERVAL_SECONDS", "3600"))

    # Broadcast Clips (ENGAGE-005)
    broadcast_clips_table_name: str = os.environ.get("BROADCAST_CLIPS_TABLE_NAME", "broadcast_clips")

    # Watch Parties (ENGAGE-004)
    watch_parties_table_name: str = os.environ.get("WATCH_PARTIES_TABLE_NAME", "watch_parties")
    watch_party_participants_table_name: str = os.environ.get("WATCH_PARTY_PARTICIPANTS_TABLE_NAME", "watch_party_participants")

    # SSO / SAML (ENTERPRISE-002)
    sso_saml_enabled: bool = os.environ.get("SSO_SAML_ENABLED", "1") not in ("0", "false", "False")
    sso_providers_table_name: str = os.environ.get("SSO_PROVIDERS_TABLE_NAME", "sso_providers")
    sso_sessions_table_name: str = os.environ.get("SSO_SESSIONS_TABLE_NAME", "sso_sessions")
    sso_assertion_cache_table_name: str = os.environ.get("SSO_ASSERTION_CACHE_TABLE_NAME", "sso_assertion_cache")
    sso_assertion_max_age_seconds: int = int(os.environ.get("SSO_ASSERTION_MAX_AGE_SECONDS", "300"))
    sso_assertion_max_clock_skew_seconds: int = int(os.environ.get("SSO_ASSERTION_MAX_CLOCK_SKEW_SECONDS", "180"))
    sso_session_link_ttl_seconds: int = int(os.environ.get("SSO_SESSION_LINK_TTL_SECONDS", "86400"))

    # Delegates (DELEGATE-001)
    delegates_table_name: str = os.environ.get("DELEGATES_TABLE_NAME", "delegates")
    # Delegation API (DELEGATE-005)
    delegation_api_enabled: bool = os.environ.get("DELEGATION_API_ENABLED", "true").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    delegation_api_keys_table_name: str = os.environ.get(
        "DELEGATION_API_KEYS_TABLE_NAME", "delegation_api_keys"
    )
    delegation_api_default_rate_limit_rpm: int = int(
        os.environ.get("DELEGATION_API_DEFAULT_RATE_LIMIT_RPM", "60")
    )
    delegation_api_max_rate_limit_rpm: int = int(
        os.environ.get("DELEGATION_API_MAX_RATE_LIMIT_RPM", "300")
    )
    # Bot Framework (BOT-001)
    bot_framework_enabled: bool = os.environ.get("BOT_FRAMEWORK_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    chat_bots_table_name: str = os.environ.get("CHAT_BOTS_TABLE_NAME", "chat_bots")
    bot_assignments_table_name: str = os.environ.get("BOT_ASSIGNMENTS_TABLE_NAME", "bot_assignments")
    bot_max_per_creator: int = int(os.environ.get("BOT_MAX_PER_CREATOR", "10"))
    # Bot Templates & Scheduled Messages (BOT-002)
    bot_templates_enabled: bool = os.environ.get("BOT_TEMPLATES_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    bot_scheduled_messages_enabled: bool = os.environ.get("BOT_SCHEDULED_MESSAGES_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    bot_templates_table_name: str = os.environ.get("BOT_TEMPLATES_TABLE_NAME", "bot_templates")
    bot_scheduled_sends_table_name: str = os.environ.get("BOT_SCHEDULED_SENDS_TABLE_NAME", "bot_scheduled_sends")

    # Multi-Tenancy (ENTERPRISE-001)
    multi_tenancy_enabled: bool = os.environ.get("MULTI_TENANCY_ENABLED", "0") not in ("0", "false", "False")
    tenants_table_name: str = os.environ.get("TENANTS_TABLE_NAME", "tenants")
    tenant_domains_table_name: str = os.environ.get("TENANT_DOMAINS_TABLE_NAME", "tenant_domains")
    tenant_members_table_name: str = os.environ.get("TENANT_MEMBERS_TABLE_NAME", "tenant_members")
    tenant_domain_cache_ttl_seconds: int = int(os.environ.get("TENANT_DOMAIN_CACHE_TTL_SECONDS", "300"))
    default_tenant_id: str = os.environ.get("DEFAULT_TENANT_ID", "default")

    # Agent LLM Key Management (AGENT-001)
    agent_llm_keys_enabled: bool = os.environ.get("AGENT_LLM_KEYS_ENABLED", "1") not in ("0", "false", "False")
    agent_llm_key_testing_enabled: bool = os.environ.get("AGENT_LLM_KEY_TESTING_ENABLED", "1") not in ("0", "false", "False")
    llm_provider_keys_table_name: str = os.environ.get("LLM_PROVIDER_KEYS_TABLE_NAME", "llm_provider_keys")
    # Syndicates (SYND-001)
    syndicates_table_name: str = os.environ.get("SYNDICATES_TABLE_NAME", "syndicates")
    # Syndicate Revenue Splitting (SYND-003)
    syndicate_revenue_split_table_name: str = os.environ.get(
        "SYNDICATE_REVENUE_SPLIT_TABLE_NAME", "syndicate_revenue_split"
    )
    # Syndicate Treasury / Fund Management (SYND-004)
    syndicate_treasury_table_name: str = os.environ.get(
        "SYNDICATE_TREASURY_TABLE_NAME", "syndicate_treasury"
    )
    syndicate_treasury_enabled: bool = os.environ.get(
        "SYNDICATE_TREASURY_ENABLED", "true"
    ) not in ("0", "false", "False")
    # Syndicate Page & Newsfeed (SYND-005)
    syndicate_posts_table_name: str = os.environ.get(
        "SYNDICATE_POSTS_TABLE_NAME", "syndicate_posts"
    )
    syndicate_feed_enabled: bool = os.environ.get(
        "SYNDICATE_FEED_ENABLED", "true"
    ) not in ("0", "false", "False")
    # Syndicate Advertising (SYND-006)
    syndicate_ad_campaigns_table_name: str = os.environ.get(
        "SYNDICATE_AD_CAMPAIGNS_TABLE_NAME", "syndicate_ad_campaigns"
    )
    syndicate_advertising_enabled: bool = os.environ.get(
        "SYNDICATE_ADVERTISING_ENABLED", "true"
    ) not in ("0", "false", "False")
    # Syndicate Open Licensing (LICENSE-005)
    syndicate_open_licensing_table_name: str = os.environ.get(
        "SYNDICATE_OPEN_LICENSING_TABLE_NAME", "syndicate_open_licensing"
    )
    syndicate_open_licensing_enabled: bool = os.environ.get(
        "SYNDICATE_OPEN_LICENSING_ENABLED", "true"
    ) not in ("0", "false", "False")
    # User Groups (GROUP-001)
    # SSH Key Manager (INFRA-002)
    ssh_keys_table_name: str = os.environ.get("SSH_KEYS_TABLE_NAME", "ssh_keys")
    ssh_key_max_per_user: int = int(os.environ.get("SSH_KEY_MAX_PER_USER", "20"))
    # Issued Licenses (LICENSE-002)
    issued_licenses_table_name: str = os.environ.get("ISSUED_LICENSES_TABLE_NAME", "issued_licenses")
    # License Agreements (LICENSE-001)
    license_agreements_table_name: str = os.environ.get("LICENSE_AGREEMENTS_TABLE_NAME", "license_agreements")
    license_agreements_bucket: str = os.environ.get("LICENSE_AGREEMENTS_BUCKET", "")
    license_agreements_enabled: bool = os.environ.get("LICENSE_MANAGEMENT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    # License Compliance Verification (LICENSE-006)
    license_compliance_checks_table_name: str = os.environ.get("LICENSE_COMPLIANCE_CHECKS_TABLE_NAME", "license_compliance_checks")
    license_compliance_enabled: bool = os.environ.get("LICENSE_COMPLIANCE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    # Syndicates (SYND-001)
    # Delegates (DELEGATE-001)
    # Bot Framework (BOT-001)
    # Bot Templates & Scheduled Messages (BOT-002)
    # Bot Auto-Reply (BOT-003)
    bot_auto_reply_enabled: bool = os.environ.get("BOT_AUTO_REPLY_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    # Media Preferences (CALL-003)
    media_preferences_table_name: str = os.environ.get("MEDIA_PREFERENCES_TABLE_NAME", "media_preferences")

    # EC2 Instance Launcher (INFRA-003)
    ec2_instances_table_name: str = os.environ.get("EC2_INSTANCES_TABLE_NAME", "ec2_instances")
    ec2_mock_enabled: bool = os.environ.get("EC2_MOCK_ENABLED", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
    ec2_max_instances_per_user: int = int(os.environ.get("EC2_MAX_INSTANCES_PER_USER", "5"))
    ec2_auto_terminate_enabled: bool = os.environ.get("EC2_AUTO_TERMINATE_ENABLED", "1") not in ("0", "false", "False")
    # Real AWS AMI IDs per platform alias — required only when ec2_mock_enabled is False (prod).
    ec2_real_ami_ubuntu_2204: str = os.environ.get("EC2_REAL_AMI_UBUNTU_2204", "")
    ec2_real_ami_ubuntu_2404: str = os.environ.get("EC2_REAL_AMI_UBUNTU_2404", "")
    ec2_real_ami_amzn2: str = os.environ.get("EC2_REAL_AMI_AMZN2", "")
    ec2_real_ami_windows_2022: str = os.environ.get("EC2_REAL_AMI_WINDOWS_2022", "")

    # Instance Monitoring & Health (INFRA-008)
    instance_monitoring_enabled: bool = os.environ.get("INSTANCE_MONITORING_ENABLED", "true").lower() not in ("0", "false", "no")
    instance_metrics_table_name: str = os.environ.get("INSTANCE_METRICS_TABLE_NAME", "instance_metrics")
    instance_monitoring_retention_points: int = int(os.environ.get("INSTANCE_MONITORING_RETENTION_POINTS", "500"))
    instance_monitoring_max_query_points: int = int(os.environ.get("INSTANCE_MONITORING_MAX_QUERY_POINTS", "200"))
    instance_monitoring_ttl_seconds: int = int(os.environ.get("INSTANCE_MONITORING_TTL_SECONDS", "604800"))
    instance_monitoring_alerts_enabled: bool = os.environ.get("INSTANCE_MONITORING_ALERTS_ENABLED", "true").lower() not in ("0", "false", "no")
    # Auto-restart policy (GAP-0230). Default OFF so dev/test never auto-restarts;
    # must be explicitly enabled in prod (SECOPS-007).
    instance_monitoring_auto_restart_enabled: bool = os.environ.get(
        "INSTANCE_MONITORING_AUTO_RESTART_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    # Health thresholds (percent). At-or-above warning -> warning; at-or-above critical -> critical.
    instance_monitoring_cpu_warning_pct: int = int(os.environ.get("INSTANCE_MONITORING_CPU_WARNING_PCT", "75"))
    instance_monitoring_cpu_critical_pct: int = int(os.environ.get("INSTANCE_MONITORING_CPU_CRITICAL_PCT", "90"))
    instance_monitoring_mem_warning_pct: int = int(os.environ.get("INSTANCE_MONITORING_MEM_WARNING_PCT", "80"))
    instance_monitoring_mem_critical_pct: int = int(os.environ.get("INSTANCE_MONITORING_MEM_CRITICAL_PCT", "92"))
    instance_monitoring_disk_warning_pct: int = int(os.environ.get("INSTANCE_MONITORING_DISK_WARNING_PCT", "80"))
    instance_monitoring_disk_critical_pct: int = int(os.environ.get("INSTANCE_MONITORING_DISK_CRITICAL_PCT", "95"))

    # Security Groups & Network Rules (INFRA-009)
    security_groups_table_name: str = os.environ.get("SECURITY_GROUPS_TABLE_NAME", "security_groups")
    security_groups_enabled: bool = os.environ.get("SECURITY_GROUPS_ENABLED", "true").lower() not in ("0", "false", "no")
    security_groups_block_dangerous_rules: bool = os.environ.get("SG_BLOCK_DANGEROUS_RULES", "true").lower() not in ("0", "false", "no")
    security_groups_max_rules: int = int(os.environ.get("SG_MAX_RULES", "50"))
    security_groups_platform_egress_cidrs: str = os.environ.get("SECURITY_GROUPS_PLATFORM_EGRESS_CIDRS", "127.0.0.1/32,10.0.0.0/8")

    # SSH Session Recording & Playback (INFRA-010)
    ssh_session_recordings_table_name: str = os.environ.get("SSH_SESSION_RECORDINGS_TABLE_NAME", "ssh_session_recordings")
    ssh_session_recording_enabled: bool = os.environ.get("SSH_SESSION_RECORDING_ENABLED", "true").lower() not in ("0", "false", "no")
    ssh_session_recording_default_enabled: bool = os.environ.get("SSH_SESSION_RECORDING_DEFAULT_ENABLED", "true").lower() not in ("0", "false", "no")
    ssh_session_recording_retention_days: int = int(os.environ.get("SSH_SESSION_RECORDING_RETENTION_DAYS", "90"))
    ssh_session_recording_max_events: int = int(os.environ.get("SSH_SESSION_RECORDING_MAX_EVENTS", "50000"))
    ssh_session_recording_max_bytes: int = int(os.environ.get("SSH_SESSION_RECORDING_MAX_BYTES", "5242880"))
    # INFRA-010 / GAP-0234: optional global override — record EVERY browser SSH
    # session regardless of the per-host record_sessions flag. Defaults False so
    # per-host opt-in remains the controlling mechanism.
    ssh_session_recording_always_record: bool = os.environ.get("SSH_SESSION_RECORDING_ALWAYS_RECORD", "false").lower() not in ("0", "false", "no")

    # Multi-Hop SSH Bastion (INFRA-011)
    ssh_bastion_paths_table_name: str = os.environ.get("SSH_BASTION_PATHS_TABLE_NAME", "ssh_bastion_paths")
    ssh_bastion_enabled: bool = os.environ.get("SSH_BASTION_ENABLED", "true").lower() not in ("0", "false", "no")
    ssh_bastion_max_hops: int = int(os.environ.get("SSH_BASTION_MAX_HOPS", "3"))
    ssh_bastion_max_paths_per_user: int = int(os.environ.get("SSH_BASTION_MAX_PATHS_PER_USER", "50"))

    # Connection Profiles & Quick Connect (INFRA-006)
    connection_profiles_table_name: str = os.environ.get("CONNECTION_PROFILES_TABLE_NAME", "connection_profiles")
    connection_profiles_enabled: bool = os.environ.get("CONNECTION_PROFILES_ENABLED", "true").lower() not in ("0", "false", "no")
    connection_profiles_max_per_user: int = int(os.environ.get("CONNECTION_PROFILES_MAX_PER_USER", "100"))

    # Background Job Dashboard (PLATFORM-008)
    job_runs_table_name: str = os.environ.get("JOB_RUNS_TABLE_NAME", "job_runs")
    job_dashboard_max_runs_per_job: int = int(os.environ.get("JOB_DASHBOARD_MAX_RUNS_PER_JOB", "200"))
    job_dashboard_ttl_days: int = int(os.environ.get("JOB_DASHBOARD_TTL_DAYS", "30"))

    # License Revenue (LICENSE-003)
    license_revenue_table_name: str = os.environ.get("LICENSE_REVENUE_TABLE_NAME", "license_revenue")
    license_revenue_platform_fee_pct: int = int(os.environ.get("LICENSE_REVENUE_PLATFORM_FEE_PCT", "20"))
    # Activity Feed (SOC-003)
    activity_feed_table_name: str = os.environ.get("ACTIVITY_FEED_TABLE_NAME", "activity_feed")
    activity_feed_ttl_days: int = int(os.environ.get("ACTIVITY_FEED_TTL_DAYS", "30"))
    # Delegates (DELEGATE-001..003)
    delegate_feed_enabled: bool = os.environ.get("DELEGATE_FEED_ENABLED", "1") not in ("0", "false", "False")
    # Notification Engine (SOC-004)
    notifications_engine_table_name: str = os.environ.get("NOTIFICATIONS_ENGINE_TABLE_NAME", "notifications_engine")
    notification_ttl_days: int = int(os.environ.get("NOTIFICATION_TTL_DAYS", "90"))
    notification_batch_window_seconds: int = int(os.environ.get("NOTIFICATION_BATCH_WINDOW_SECONDS", "300"))
    # Call History (CALL-004)
    call_history_table_name: str = os.environ.get("CALL_HISTORY_TABLE_NAME", "call_history")
    # Licensing (LICENSE-002 / LICENSE-004)


    # Delegates (DELEGATE-001)

    # Broadcast Moderation (DELEGATE-004)
    broadcast_moderation_table_name: str = os.environ.get("BROADCAST_MODERATION_TABLE_NAME", "broadcast_moderation")

    # Kubernetes Container Launcher (INFRA-004)
    k8s_pods_table_name: str = os.environ.get("K8S_PODS_TABLE_NAME", "k8s_pods")
    k8s_mock_enabled: bool = os.environ.get("K8S_MOCK_ENABLED", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
    k8s_max_pods_per_user: int = int(os.environ.get("K8S_MAX_PODS_PER_USER", "5"))
    k8s_ttl_checker_enabled: bool = os.environ.get("K8S_TTL_CHECKER_ENABLED", "1") not in ("0", "false", "False")

    # Agent Worker Provisioning (AGENT-002)
    agent_workers_table_name: str = os.environ.get("AGENT_WORKERS_TABLE_NAME", "agent_workers")
    agent_max_workers_per_user: int = int(os.environ.get("AGENT_MAX_WORKERS_PER_USER", "5"))

    # Interactive Claude Code Sessions (ACS-001 / ADR-002). Master gate defaults
    # OFF; with it off the agent-session WS path and REST routes 404/410 and the
    # raw Browser SSH terminal is byte-for-byte unchanged.
    agent_claude_code_session_enabled: bool = os.environ.get("AGENT_CLAUDE_CODE_SESSION_ENABLED", "0") not in ("0", "false", "False")
    agent_claude_code_session_allowed_roles: str = os.environ.get("AGENT_CLAUDE_CODE_SESSION_ALLOWED_ROLES", "admin,root")
    agent_claude_code_session_max_per_user: int = int(os.environ.get("AGENT_CLAUDE_CODE_SESSION_MAX_PER_USER", "2"))
    agent_claude_code_session_idle_timeout_seconds: int = int(os.environ.get("AGENT_CLAUDE_CODE_SESSION_IDLE_TIMEOUT_SECONDS", "1800"))
    agent_claude_code_session_replay_bytes: int = int(os.environ.get("AGENT_CLAUDE_CODE_SESSION_REPLAY_BYTES", "65536"))
    agent_sessions_table_name: str = os.environ.get("AGENT_SESSIONS_TABLE_NAME", "agent_sessions")
    # User Groups (GROUP-001)

    # Group Treasury (GROUP-004)
    group_treasury_enabled: bool = os.environ.get("GROUP_TREASURY_ENABLED", "1") not in ("0", "false", "False")
    # Group Advertising & Fundraising (GROUP-003)
    group_fundraising_enabled: bool = os.environ.get("GROUP_FUNDRAISING_ENABLED", "1") not in ("0", "false", "False")
    group_fundraising_campaigns_table_name: str = os.environ.get("GROUP_FUNDRAISING_CAMPAIGNS_TABLE_NAME", "group_fundraising_campaigns")

    # PLATFORM-013: per-user theme customization
    user_themes_table_name: str = os.environ.get("USER_THEMES_TABLE_NAME", "user_themes")
    # Agent Orchestration (AGENT-002 / AGENT-003)
    # Rent Ledger (open-property vertical, RNT cluster). Default-OFF.
    rent_ledger_enabled: bool = os.environ.get("RENT_LEDGER_ENABLED", "0") not in ("0", "false", "False")
    rent_run_enabled: bool = os.environ.get("RENT_RUN_ENABLED", "0") not in ("0", "false", "False")
    rent_run_poll_interval: int = int(os.environ.get("RENT_RUN_POLL_INTERVAL", "3600"))
    rent_period_markers_table_name: str = os.environ.get("RENT_PERIOD_MARKERS_TABLE_NAME", "rent_period_markers")
    rent_periods_default_count: int = int(os.environ.get("RENT_PERIODS_DEFAULT_COUNT", "12"))
    # Compute Cost Tracking (INFRA-005)
    compute_billing_table_name: str = os.environ.get("COMPUTE_BILLING_TABLE_NAME", "compute_billing")
    compute_billing_enabled: bool = os.environ.get("COMPUTE_BILLING_ENABLED", "1") not in ("0", "false", "False")
    compute_billing_poll_interval: int = int(os.environ.get("COMPUTE_BILLING_POLL_INTERVAL", "300"))
    compute_billing_default_budget_cents: int = int(os.environ.get("COMPUTE_BILLING_DEFAULT_BUDGET_CENTS", "5000"))
    # Admin Compute Dashboard (INFRA-012)
    compute_quotas_table_name: str = os.environ.get("COMPUTE_QUOTAS_TABLE_NAME", "compute_quotas")
    admin_compute_dashboard_enabled: bool = os.environ.get("ADMIN_COMPUTE_DASHBOARD_ENABLED", "1") not in ("0", "false", "False")
    compute_quota_default_max_ec2: int = int(os.environ.get("COMPUTE_QUOTA_DEFAULT_MAX_EC2", "3"))
    compute_quota_default_max_k8s: int = int(os.environ.get("COMPUTE_QUOTA_DEFAULT_MAX_K8S", "5"))
    compute_quota_default_max_spend_cents: int = int(os.environ.get("COMPUTE_QUOTA_DEFAULT_MAX_SPEND_CENTS", "5000"))
    # Instance Templates & Presets (INFRA-007)
    instance_templates_table_name: str = os.environ.get("INSTANCE_TEMPLATES_TABLE_NAME", "instance_templates")
    instance_templates_enabled: bool = os.environ.get("INSTANCE_TEMPLATES_ENABLED", "true").lower() not in ("0", "false", "no")
    template_launch_enabled: bool = os.environ.get("TEMPLATE_LAUNCH_ENABLED", "true").lower() not in ("0", "false", "no")
    # Platform Financial Dashboard (FIN-013)
    platform_financial_dashboard_rollups_table_name: str = os.environ.get("PLATFORM_FINANCIAL_DASHBOARD_ROLLUPS_TABLE_NAME", "financial_rollups")
    platform_financial_dashboard_enabled: bool = os.environ.get("PLATFORM_FINANCIAL_DASHBOARD_ENABLED", "true").lower() not in ("0", "false", "no")
    # Agent Platform (AGENT-001 .. AGENT-004)
    # LLM Provider Keys (AGENT-001)

    # Kubernetes pods (INFRA-006)

    # Agent Workers (AGENT-002)

    # Compute Billing (INFRA-005)

    # Agent Memory (AGENT-005)
    agent_memory_table_name: str = os.environ.get("AGENT_MEMORY_TABLE_NAME", "agent_memory")
    agent_memory_max_entries: int = int(os.environ.get("AGENT_MEMORY_MAX_ENTRIES", "200"))
    agent_memory_max_token_count: int = int(os.environ.get("AGENT_MEMORY_MAX_TOKEN_COUNT", "100000"))
    # Agent Feedback & Terminal Monitoring (AGENT-006)
    agent_feedback_table_name: str = os.environ.get("AGENT_FEEDBACK_TABLE_NAME", "agent_feedback")
    agent_feedback_timeout_seconds: int = int(os.environ.get("AGENT_FEEDBACK_TIMEOUT_SECONDS", "14400"))

    # Coder Agent (AGENT-008)
    agent_types_table_name: str = os.environ.get("AGENT_TYPES_TABLE_NAME", "agent_types")
    agent_runs_table_name: str = os.environ.get("AGENT_RUNS_TABLE_NAME", "agent_runs")
    tickets_label_index_name: str = os.environ.get("TICKETS_LABEL_INDEX_NAME", "gsi_label")
    # When false (default), the coder lifecycle never runs real shell/git/PR commands —
    # the workflow is generated and executed in mock/dry-run mode so E2E tests are deterministic.
    agent_coder_enabled: bool = os.environ.get("AGENT_CODER_ENABLED", "1") not in ("0", "false", "False")
    agent_coder_execute_commands: bool = os.environ.get("AGENT_CODER_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")

    # Stylist / UI Agent (AGENT-016). Reuses the agent_types table for stylist_config.
    stylist_ui_reviews_table_name: str = os.environ.get("STYLIST_UI_REVIEWS_TABLE_NAME", "stylist_ui_reviews")
    stylist_design_rules_table_name: str = os.environ.get("STYLIST_DESIGN_RULES_TABLE_NAME", "stylist_design_rules")
    stylist_agent_enabled: bool = os.environ.get("STYLIST_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # When false (default, and always in E2E), the stylist lifecycle never drives a
    # real browser / Playwright capture — review payloads are accepted/generated and
    # stored verbatim so the lifecycle is deterministic / testable.
    stylist_agent_execute_commands: bool = os.environ.get("STYLIST_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")
    stylist_agent_pr_trigger_enabled: bool = os.environ.get("STYLIST_PR_TRIGGER_ENABLED", "0") not in ("0", "false", "False")
    stylist_agent_ticket_creation_enabled: bool = os.environ.get("STYLIST_TICKET_CREATION_ENABLED", "0") not in ("0", "false", "False")

    # Documentation Agent (AGENT-014). Reuses the agent_types table for doc_config.
    agent_doc_coverage_table_name: str = os.environ.get("AGENT_DOC_COVERAGE_TABLE_NAME", "agent_doc_coverage")
    agent_doc_templates_table_name: str = os.environ.get("AGENT_DOC_TEMPLATES_TABLE_NAME", "agent_doc_templates")
    # Master kill switch + sub-flags for the doc agent. When disabled the real
    # doc-writing / PR-trigger paths are off; freshness comparison and coverage
    # tracking remain available (deterministic, mockable) so E2E stays green.
    doc_agent_enabled: bool = os.environ.get("DOC_AGENT_ENABLED", "1") not in ("0", "false", "False")
    doc_pr_trigger_enabled: bool = os.environ.get("DOC_PR_TRIGGER_ENABLED", "0") not in ("0", "false", "False")
    doc_inline_tickets_enabled: bool = os.environ.get("DOC_INLINE_TICKETS_ENABLED", "1") not in ("0", "false", "False")

    # Agent SSH QA (ADR-003 / AQA). Outbound, agent-driven non-interactive SSH
    # exec for QA. Master flag defaults OFF — when off the router is not
    # registered and the runner does not start (mirrors AUDIT_EXPORT_WORKER).
    # Reuses the existing `agent_qa_execute_commands` gate (below) to decide
    # whether a real SSH dial occurs vs an in-memory simulation.
    agent_ssh_qa_enabled: bool = os.environ.get("AGENT_SSH_QA_ENABLED", "0") not in ("0", "false", "False")
    agent_actions_table_name: str = os.environ.get("AGENT_ACTIONS_TABLE_NAME", "agent_actions")
    agent_ssh_qa_action_timeout_seconds: int = int(os.environ.get("AGENT_SSH_QA_ACTION_TIMEOUT_SECONDS", "300"))
    agent_ssh_qa_max_concurrent_per_worker: int = int(os.environ.get("AGENT_SSH_QA_MAX_CONCURRENT_PER_WORKER", "1"))
    agent_ssh_qa_rate_limit_count: int = int(os.environ.get("AGENT_SSH_QA_RATE_LIMIT_COUNT", "10"))
    agent_ssh_qa_rate_limit_window_seconds: int = int(os.environ.get("AGENT_SSH_QA_RATE_LIMIT_WINDOW_SECONDS", "60"))
    agent_ssh_qa_command_max_length: int = int(os.environ.get("AGENT_SSH_QA_COMMAND_MAX_LENGTH", "4096"))
    agent_ssh_qa_command_denylist: str = os.environ.get("AGENT_SSH_QA_COMMAND_DENYLIST", "")
    agent_vnc_screenshot_enabled: bool = os.environ.get("AGENT_VNC_SCREENSHOT_ENABLED", "0") not in ("0", "false", "False")

    # QA Agent (AGENT-009). Reuses the agent_types / agent_runs tables.
    agent_qa_enabled: bool = os.environ.get("QA_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # When false (default, and always in E2E), the QA lifecycle never runs real
    # shell/git/test/PR commands — the workflow is generated and driven in-memory
    # so tests are deterministic.
    agent_qa_execute_commands: bool = os.environ.get("QA_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")
    agent_qa_screenshot_bucket: str = os.environ.get("QA_AGENT_SCREENSHOT_BUCKET", os.environ.get("S3_BUCKET", "local-bucket"))
    agent_qa_screenshot_url_ttl_seconds: int = int(os.environ.get("QA_AGENT_SCREENSHOT_URL_TTL_SECONDS", "900"))
    agent_qa_max_screenshots: int = int(os.environ.get("QA_AGENT_MAX_SCREENSHOTS", "50"))
    # DevOps/SRE Agent (AGENT-010)
    deployment_log_table_name: str = os.environ.get("DEPLOYMENT_LOG_TABLE_NAME", "deployment_log")
    agent_devops_enabled: bool = os.environ.get("DEVOPS_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # When false (default, and always in E2E), the devops lifecycle never runs real
    # commands/infra — the deployment state machine is driven in-memory (mock mode).
    agent_devops_execute_commands: bool = os.environ.get("DEVOPS_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")
    # Solution Architect Agent (AGENT-011)
    feature_decompositions_table_name: str = os.environ.get(
        "FEATURE_DECOMPOSITIONS_TABLE_NAME", "feature_decompositions"
    )
    architect_agent_enabled: bool = os.environ.get("ARCHITECT_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # Force human review before ticket creation (mirrors ARCHITECT_DESIGN_REVIEW_REQUIRED flag).
    architect_design_review_required: bool = os.environ.get(
        "ARCHITECT_DESIGN_REVIEW_REQUIRED", "0"
    ) not in ("0", "false", "False")
    # When false (default, and always in E2E), the architect lifecycle never runs real
    # shell/git/coding-tool commands — the workflow is generated and driven in mock mode.
    architect_execute_commands: bool = os.environ.get("ARCHITECT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")

    # Product Manager Agent (AGENT-013)
    agent_feature_ideas_table_name: str = os.environ.get(
        "AGENT_FEATURE_IDEAS_TABLE_NAME", "agent_feature_ideas"
    )
    agent_preference_learning_table_name: str = os.environ.get(
        "AGENT_PREFERENCE_LEARNING_TABLE_NAME", "agent_preference_learning"
    )
    # Master kill switch for the PM agent feature.
    pm_agent_enabled: bool = os.environ.get("PM_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # When false (default, and always in E2E), the PM review lifecycle never runs real
    # Playwright/browsing commands — the review is generated and driven in mock mode.
    pm_agent_execute_commands: bool = os.environ.get("PM_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")
    pm_competitor_analysis_enabled: bool = os.environ.get("PM_COMPETITOR_ANALYSIS_ENABLED", "0") not in ("0", "false", "False")
    pm_support_analysis_enabled: bool = os.environ.get("PM_SUPPORT_ANALYSIS_ENABLED", "1") not in ("0", "false", "False")
    pm_auto_ticket_creation: bool = os.environ.get("PM_AUTO_TICKET_CREATION", "1") not in ("0", "false", "False")
    # Project Manager Agent (AGENT-012). Reuses the agent_types / agent_runs / tickets tables.
    product_ideas_table_name: str = os.environ.get("PRODUCT_IDEAS_TABLE_NAME", "product_ideas")
    project_sprints_table_name: str = os.environ.get("PROJECT_SPRINTS_TABLE_NAME", "project_sprints")
    project_reports_table_name: str = os.environ.get("PROJECT_REPORTS_TABLE_NAME", "project_reports")
    # When false (default, and always in E2E), idea triage / orchestration never invokes a
    # real coding tool / LLM — triage uses a deterministic formula scorer so tests are reproducible.
    pm_execute_commands: bool = os.environ.get("PM_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")

    # Marketing Agent (AGENT-017). Reuses the agent_types table for marketing_config.
    marketing_agent_enabled: bool = os.environ.get("MARKETING_AGENT_ENABLED", "1") not in ("0", "false", "False")
    marketing_content_table_name: str = os.environ.get("MARKETING_CONTENT_TABLE_NAME", "marketing_content")
    marketing_engagement_table_name: str = os.environ.get("MARKETING_ENGAGEMENT_TABLE_NAME", "marketing_engagement")
    # When false (default, and always in E2E), content generation never invokes a real LLM —
    # generation uses a deterministic template producer so tests are reproducible.
    marketing_agent_execute_commands: bool = os.environ.get("MARKETING_AGENT_EXECUTE_COMMANDS", "0") not in ("0", "false", "False")
    marketing_agent_auto_publish: bool = os.environ.get("MARKETING_AGENT_AUTO_PUBLISH", "0") not in ("0", "false", "False")
    # Compliance & Security Agent (AGENT-015). Reuses the agent_types table for security_config.
    compliance_security_findings_table_name: str = os.environ.get(
        "COMPLIANCE_SECURITY_FINDINGS_TABLE_NAME", "compliance_security_findings"
    )
    compliance_security_audits_table_name: str = os.environ.get(
        "COMPLIANCE_SECURITY_AUDITS_TABLE_NAME", "compliance_security_audits"
    )
    # Master kill switch for the compliance/security agent feature.
    compliance_agent_enabled: bool = os.environ.get("COMPLIANCE_AGENT_ENABLED", "1") not in ("0", "false", "False")
    # When false (default, and always in E2E), the scanning lifecycle never runs real
    # shell/git/scanner commands — findings + audits are driven in-memory (mock mode)
    # so tests are deterministic.
    compliance_agent_execute_commands: bool = os.environ.get(
        "COMPLIANCE_AGENT_EXECUTE_COMMANDS", "0"
    ) not in ("0", "false", "False")

    # Admin Subscription Tier Manager (ADMIN-001).
    admin_subscription_tiers_table_name: str = os.environ.get(
        "ADMIN_SUBSCRIPTION_TIERS_TABLE_NAME", "admin_subscription_tiers"
    )
    admin_subscription_tiers_enabled: bool = os.environ.get(
        "ADMIN_SUBSCRIPTION_TIERS_ENABLED", "1"
    ) not in ("0", "false", "False")
    # Accountant / Cost Tracking Agent (AGENT-018). Reuses the agent_types table
    # for accountant_config; cost data lives in dedicated accountant_* tables.
    agent_costs_table_name: str = os.environ.get("AGENT_COSTS_TABLE_NAME", "accountant_costs")
    agent_ticket_costs_table_name: str = os.environ.get(
        "AGENT_TICKET_COSTS_TABLE_NAME", "accountant_ticket_costs"
    )
    agent_cost_budgets_table_name: str = os.environ.get(
        "AGENT_COST_BUDGETS_TABLE_NAME", "accountant_cost_budgets"
    )
    agent_cost_alerts_table_name: str = os.environ.get(
        "AGENT_COST_ALERTS_TABLE_NAME", "accountant_cost_alerts"
    )
    # Master kill switch + execution gate for the accountant agent. When
    # execute-commands is false (default, and always in E2E) the agent never
    # polls real provider/AWS billing APIs and never auto-pauses workers —
    # budgets/alerts are evaluated deterministically over recorded cost data.
    accountant_agent_enabled: bool = os.environ.get("ACCOUNTANT_AGENT_ENABLED", "1") not in ("0", "false", "False")
    accountant_agent_auto_alert: bool = os.environ.get("ACCOUNTANT_AGENT_AUTO_ALERT", "0") not in ("0", "false", "False")
    accountant_agent_execute_commands: bool = os.environ.get(
        "ACCOUNTANT_AGENT_EXECUTE_COMMANDS", "0"
    ) not in ("0", "false", "False")
    # FIN-001: Invoices / Receipt PDF
    invoices_table_name: str = os.environ.get("INVOICES_TABLE_NAME", "invoices")
    invoices_enabled: bool = os.environ.get("INVOICES_ENABLED", "true").lower() not in ("0", "false")
    invoices_tax_bps: int = int(os.environ.get("INVOICES_TAX_BPS", "0"))
    # QUO-001: Sales Quotes (AOS). Default OFF — no routes / DDB writes when off.
    aos_quotes_enabled: bool = os.environ.get("AOS_QUOTES_ENABLED", "0") in ("1", "true", "True")
    aos_quotes_table_name: str = os.environ.get("AOS_QUOTES_TABLE_NAME", "aos_quotes")
    # QUO-004: CRM Contracts (AOS). Default OFF.
    aos_contracts_enabled: bool = os.environ.get("AOS_CONTRACTS_ENABLED", "0") in ("1", "true", "True")
    aos_contracts_table_name: str = os.environ.get("AOS_CONTRACTS_TABLE_NAME", "aos_contracts")
    aos_contracts_renewal_notifications_enabled: bool = os.environ.get(
        "AOS_CONTRACTS_RENEWAL_NOTIFICATIONS_ENABLED", "0"
    ) in ("1", "true", "True")
    aos_contracts_renewal_check_interval_seconds: int = int(
        os.environ.get("AOS_CONTRACTS_RENEWAL_CHECK_INTERVAL_SECONDS", "3600")
    )
    # QUO-005: Standalone invoice lifecycle (AOS-INV-001 / VOID). Default OFF.
    aos_standalone_invoices_enabled: bool = os.environ.get(
        "AOS_STANDALONE_INVOICES_ENABLED", "0"
    ) in ("1", "true", "True")
    aos_invoice_overdue_checker_enabled: bool = os.environ.get(
        "AOS_INVOICE_OVERDUE_CHECKER_ENABLED", "0"
    ) in ("1", "true", "True")
    aos_invoice_overdue_check_interval_seconds: int = int(
        os.environ.get("AOS_INVOICE_OVERDUE_CHECK_INTERVAL_SECONDS", "3600")
    )
    # INV-001: AOS invoice extended fields (unit_price_cents, discount, shipping,
    # billing/shipping addresses). Default OFF — existing invoice callers unchanged.
    aos_invoice_fields_enabled: bool = os.environ.get(
        "AOS_INVOICE_FIELDS_ENABLED", "0"
    ).lower() in ("1", "true", "yes", "on")
    # INV-002: Admin currency registry (default OFF).
    crm_currencies_enabled: bool = os.environ.get(
        "CRM_CURRENCIES_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    crm_currencies_table_name: str = os.environ.get(
        "CRM_CURRENCIES_TABLE_NAME", "crm_currencies"
    )
    # INV-003: snapshot USD equivalent at invoice creation time (default OFF).
    aos_invoice_currency_conversion_enabled: bool = os.environ.get(
        "AOS_INVOICE_CURRENCY_CONVERSION_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    # INV-004: multi-currency display on invoice PDF (default OFF).
    aos_invoice_multicurrency_display_enabled: bool = os.environ.get(
        "AOS_INVOICE_MULTICURRENCY_DISPLAY_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    # INV-005: Named tax rate registry (default OFF).
    crm_tax_rates_enabled: bool = os.environ.get(
        "CRM_TAX_RATES_ENABLED", "0"
    ).lower() in ("1", "true", "yes", "on")
    crm_tax_rates_table_name: str = os.environ.get(
        "CRM_TAX_RATES_TABLE_NAME", "crm_tax_rates"
    )
    # INV-006: Per-line-item tax rate assignment on invoices (default OFF).
    aos_per_line_tax_enabled: bool = os.environ.get(
        "AOS_PER_LINE_TAX_ENABLED", "0"
    ).lower() in ("1", "true", "yes", "on")
    # FIN-004: Consumer Tax Documents (annual creator earnings / 1099-style summaries)
    tax_documents_table_name: str = os.environ.get("TAX_DOCUMENTS_TABLE_NAME", "tax_documents")
    tax_documents_enabled: bool = os.environ.get("TAX_DOCUMENTS_ENABLED", "true").lower() not in (
        "0",
        "false",
    )
    # Minimum yearly credited earnings (cents) required to issue a tax document.
    tax_documents_min_earnings_cents: int = int(
        os.environ.get("TAX_DOCUMENTS_MIN_EARNINGS_CENTS", "0")
    )
    # FIN-008: Creator 1099 / Tax-Form generation (platform-issuer 1099-NEC forms
    # for creators/payees). DISTINCT from consumer tax documents above.
    tax_forms_1099_table_name: str = os.environ.get(
        "TAX_FORMS_1099_TABLE_NAME", "tax_forms_1099"
    )
    tax_form_1099_enabled: bool = os.environ.get(
        "TAX_FORM_1099_ENABLED", "true"
    ).lower() not in (
        "0",
        "false",
    )
    # IRS reportable threshold: 1099-NEC issued at $600.00 (60000 cents).
    tax_form_1099_min_reportable_cents: int = int(
        os.environ.get("TAX_FORM_1099_MIN_REPORTABLE_CENTS", "60000")
    )
    # GAP-0020 / FIN-008: W-9 / TIN collection table (KMS-encrypted TIN storage).
    # Records: pk=USER#{user_sub} sk=TAX_INFO. All access by user PK; no GSI.
    tax_info_table_name: str = os.environ.get("TAX_INFO_TABLE_NAME", "tax_info")
    # Platform's own EIN, printed as the Payer TIN on every 1099-NEC. Populated
    # from prod secrets; never logged. Empty in dev unless set in .env.local.
    platform_ein: str = os.environ.get("PLATFORM_EIN", "")
    # FIN-014: Payment Provider Health monitoring. Records per-provider
    # success/failure/latency of payment operations, computes health status,
    # error rates, and a recent-incident timeline.
    payment_provider_health_table_name: str = os.environ.get(
        "PAYMENT_PROVIDER_HEALTH_TABLE_NAME", "payment_provider_health"
    )
    payment_provider_health_enabled: bool = os.environ.get(
        "PAYMENT_PROVIDER_HEALTH_ENABLED", "true"
    ).lower() not in ("0", "false", "no")

    # KYC Proof of Funds / Source of Funds (KYC-005)
    kyc_proof_of_funds_table_name: str = os.environ.get(
        "KYC_PROOF_OF_FUNDS_TABLE_NAME", "kyc_proof_of_funds"
    ) if True else None
    kyc_proof_of_funds_real_analysis_enabled: bool = os.environ.get(
        "KYC_PROOF_OF_FUNDS_REAL_ANALYSIS_ENABLED", ""
    ) not in ("", "0", "false", "False")
    kyc_proof_of_funds_validity_days: int = int(
        os.environ.get("KYC_PROOF_OF_FUNDS_VALIDITY_DAYS", "365")
    )

    # FIN-018: Billing Configuration UI. Runtime-editable billing parameters
    # (platform fee bps, payout minimum, deposit min/max, currency, tax rate)
    # stored as DDB overrides; effective value = DB override if set else env default.
    billing_config_table_name: str = os.environ.get(
        "BILLING_CONFIG_TABLE_NAME", "billing_config"
    )
    billing_config_ddb_enabled: bool = os.environ.get(
        "BILLING_CONFIG_DDB_ENABLED", "true"
    ).lower() not in ("0", "false", "no")
    billing_config_cache_ttl_seconds: int = int(
        os.environ.get("BILLING_CONFIG_CACHE_TTL_SECONDS", "60")
    )

    # FIN-015: Fraud Detection Dashboard
    ddb_fraud_cases_table: str = os.environ.get(
        "DDB_FRAUD_CASES_TABLE", "fraud_detection"
    )
    fraud_detection_enabled: bool = os.environ.get(
        "FRAUD_DETECTION_ENABLED", "true"
    ).lower() not in ("0", "false", "no")
    fraud_block_enabled: bool = os.environ.get(
        "FRAUD_BLOCK_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    fraud_freeze_enabled: bool = os.environ.get(
        "FRAUD_FREEZE_ENABLED", "true"
    ).lower() not in ("0", "false", "no")
    fraud_score_threshold: int = int(
        os.environ.get("FRAUD_SCORE_THRESHOLD", "70")
    )

    # HNY (Security tooling & honeypots) — all DEFENSIVE-only, default OFF.
    # SECOPS-007 dev/prod parity: no dev_mode branch; the code paths gated by
    # these flags short-circuit to current behavior when the flag is off.
    security_events_table_name: str = os.environ.get(
        "SECURITY_EVENTS_TABLE_NAME", "security_events"
    )
    honeytokens_table_name: str = os.environ.get(
        "HONEYTOKENS_TABLE_NAME", "honeytokens"
    )
    honeytoken_enabled: bool = os.environ.get(
        "HONEYTOKEN_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    honeypot_endpoints_enabled: bool = os.environ.get(
        "HONEYPOT_ENDPOINTS_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    honeypot_tarpit_enabled: bool = os.environ.get(
        "HONEYPOT_TARPIT_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    honeypot_tarpit_max_seconds: int = int(
        os.environ.get("HONEYPOT_TARPIT_MAX_SECONDS", "5")
    )
    ids_enabled: bool = os.environ.get(
        "IDS_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    ids_impossible_travel_enabled: bool = os.environ.get(
        "IDS_IMPOSSIBLE_TRAVEL_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    ids_credential_stuffing_enabled: bool = os.environ.get(
        "IDS_CREDENTIAL_STUFFING_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    ids_scanning_detection_enabled: bool = os.environ.get(
        "IDS_SCANNING_DETECTION_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    security_dashboard_enabled: bool = os.environ.get(
        "SECURITY_DASHBOARD_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    security_webhooks_enabled: bool = os.environ.get(
        "SECURITY_WEBHOOKS_ENABLED", "false"
    ).lower() not in ("0", "false", "no")
    ids_credential_stuffing_max_failures: int = int(
        os.environ.get("IDS_CREDENTIAL_STUFFING_MAX_FAILURES", "10")
    )
    ids_credential_stuffing_window_seconds: int = int(
        os.environ.get("IDS_CREDENTIAL_STUFFING_WINDOW_SECONDS", "300")
    )
    ids_scanning_max_404_per_min: int = int(
        os.environ.get("IDS_SCANNING_MAX_404_PER_MIN", "30")
    )
    ids_impossible_travel_min_kmh: int = int(
        os.environ.get("IDS_IMPOSSIBLE_TRAVEL_MIN_KMH", "900")
    )

    # KYC-017: Document Signing Template Library
    kyc_document_templates_table_name: str = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_TABLE_NAME", "kyc_document_templates"
    )
    kyc_document_templates_slug_index: str = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_SLUG_INDEX", "slug-status-index"
    )
    kyc_document_templates_status_index: str = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_STATUS_INDEX", "status-updated-index"
    )
    kyc_document_templates_bucket: str = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_BUCKET", "local-uploads"
    )
    kyc_document_templates_s3_prefix: str = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_S3_PREFIX", "kyc-document-templates/"
    )
    kyc_document_templates_enabled: bool = os.environ.get(
        "KYC_DOCUMENT_TEMPLATES_ENABLED", "true"
    ).lower() in ("1", "true", "yes", "on")
    kyc_document_templates_max_pdf_bytes: int = int(
        os.environ.get("KYC_DOCUMENT_TEMPLATES_MAX_PDF_BYTES", str(10 * 1024 * 1024))
    )
    # GAP-0279 (KYC-017 §3.6): gate KYC case submission on all tier-required
    # document templates being signed. Defaults ON for dev/prod parity
    # (SECOPS-007); when no active templates exist the gate is a no-op, so it
    # does not block dev/e2e. Set KYC_TEMPLATE_READINESS_GATE=false for an
    # emergency rollback (e.g. retroactively unblocking in-progress cases).
    kyc_template_readiness_gate_enabled: bool = os.environ.get(
        "KYC_TEMPLATE_READINESS_GATE", "true"
    ).lower() in ("1", "true", "yes", "on")

    # QloApps hotel-PMS vertical (HTL) — master flag + reservations (HTL-001..HTL-021)
    hotel_pms_enabled: bool = os.environ.get(
        "HOTEL_PMS_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")
    hotel_reservations_table_name: str = os.environ.get(
        "HOTEL_RESERVATIONS_TABLE_NAME", "hotel_reservations"
    )
    # OFBiz Facility / Fulfillment (FAC-001..FAC-010, ADR-001 Milestone 4+).
    # Master switch defaults OFF. With it off every facility/transfer/receiving/
    # picklist/shipment endpoint returns 404 and all service modules are dormant.
    # Existing inventory, shop, cart, orders, and billing paths are unchanged.
    facility_fulfillment_enabled: bool = os.environ.get(
        "FACILITY_FULFILLMENT_ENABLED", "false"
    ).lower() == "true"
    # Table name settings (default to literal names; override in prod for prefix).
    facilities_table_name: str = os.environ.get("FACILITIES_TABLE_NAME", "facilities")
    transfers_table_name: str = os.environ.get("TRANSFERS_TABLE_NAME", "transfers")
    receipts_table_name: str = os.environ.get("RECEIPTS_TABLE_NAME", "receipts")
    picklists_table_name: str = os.environ.get("PICKLISTS_TABLE_NAME", "picklists")
    shipments_table_name: str = os.environ.get("SHIPMENTS_TABLE_NAME", "shipments")
    # Stretch: lot/serial tracking (deferred to FAC-011+, default OFF).
    facility_lot_serial_enabled: bool = os.environ.get(
        "FACILITY_LOT_SERIAL_ENABLED", "false"
    ).lower() == "true"
    lot_serial_table_name: str = os.environ.get("LOT_SERIAL_TABLE_NAME", "lot_serial")

    # INFRA-001: Host Inventory Management
    ddb_host_inventory_table: str = os.environ.get(
        "DDB_HOST_INVENTORY_TABLE", "host_inventory"
    )
    host_inventory_enabled: bool = os.environ.get(
        "HOST_INVENTORY_ENABLED", "true"
    ).lower() not in ("0", "false", "no")
    host_inventory_max_per_user: int = int(os.environ.get("HOST_INVENTORY_MAX_PER_USER", "500"))

    # OBP umbrella flag (ACC-001) — gates entire Open Bank Project vertical
    open_bank_project_enabled: bool = os.environ.get(
        "OPEN_BANK_PROJECT_ENABLED", "false"
    ).lower() in ("1", "true", "yes", "on")

    # VEW — Account Views (gates VEW-001..VEW-003)
    account_views_enabled: bool = os.environ.get("ACCOUNT_VIEWS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    account_views_table_name: str = os.environ.get("ACCOUNT_VIEWS_TABLE", "account_views")
    account_view_public_secret: str = os.environ.get("ACCOUNT_VIEW_PUBLIC_SECRET") or os.environ.get("UI_ACCESS_TOKEN_SECRET", "")
    account_view_public_link_ttl_days: int = int(os.environ.get("ACCOUNT_VIEW_PUBLIC_LINK_TTL_DAYS", "7"))
    account_views_max_per_resource: int = int(os.environ.get("ACCOUNT_VIEWS_MAX_PER_RESOURCE", "25"))

    # VEW — Entitlement Requests (gates VEW-004)
    entitlement_requests_enabled: bool = os.environ.get("ENTITLEMENT_REQUESTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    entitlement_requests_table_name: str = os.environ.get("ENTITLEMENT_REQUESTS_TABLE", "entitlement_requests")
    entitlement_request_max_open_per_user: int = int(os.environ.get("ENTITLEMENT_REQUEST_MAX_OPEN_PER_USER", "10"))
    entitlement_request_max_per_window: int = int(os.environ.get("ENTITLEMENT_REQUEST_MAX_PER_WINDOW", "20"))
    entitlement_request_window_seconds: int = int(os.environ.get("ENTITLEMENT_REQUEST_WINDOW_SECONDS", "3600"))

    # LEX (Legal & DSAR export). Master flag DEFAULTS OFF: with it off, the
    # legal-export/legal-hold endpoints all 404/403 and no deletion-path
    # behavior changes (legal-hold enforcement is gated on this flag).
    legal_export_enabled: bool = os.environ.get(
        "LEGAL_EXPORT_ENABLED", "0"
    ).lower() in ("1", "true", "yes", "on")
    legal_holds_table_name: str = os.environ.get(
        "LEGAL_HOLDS_TABLE_NAME", "legal_holds"
    )
    legal_exports_table_name: str = os.environ.get(
        "LEGAL_EXPORTS_TABLE_NAME", "legal_exports"
    )
    legal_export_s3_bucket: str = os.environ.get(
        "LEGAL_EXPORT_S3_BUCKET", "data-exports"
    )
    legal_export_ttl_days: int = int(os.environ.get("LEGAL_EXPORT_TTL_DAYS", "90"))
    legal_export_url_ttl_seconds: int = int(
        os.environ.get("LEGAL_EXPORT_URL_TTL_SECONDS", "900")
    )
    # Comma-separated list of user_subs granted the LEGAL capability (in
    # addition to ROOT, which is always permitted). Empty by default.
    legal_export_authorized_subs: str = os.environ.get(
        "LEGAL_EXPORT_AUTHORIZED_SUBS", ""
    )

    # Platform branding (BRAND-001 / decision D6). Env values are the DEFAULTS;
    # the PLATFORM#BRANDING settings row overrides them at runtime when set.
    platform_name: str = os.environ.get("PLATFORM_NAME", "testlogon")
    platform_logo_url: str = os.environ.get("PLATFORM_LOGO_URL", "")
    platform_support_email: str = os.environ.get("PLATFORM_SUPPORT_EMAIL", "")
    platform_settings_table_name: str = os.environ.get("PLATFORM_SETTINGS_TABLE_NAME", "platform_settings")
    branding_cache_ttl_seconds: int = int(os.environ.get("BRANDING_CACHE_TTL_SECONDS", "60"))
    # Party / CRM (PTY-001 — OFBiz Party Manager, Phase 1)
    # All flags default OFF. Turn on per-environment when Party/CRM is ready.
    party_crm_enabled: bool = os.environ.get("PARTY_CRM_ENABLED", "0") not in ("0", "false", "False")
    party_crm_contacts_migration_enabled: bool = os.environ.get("PARTY_CRM_CONTACTS_MIGRATION_ENABLED", "0") not in ("0", "false", "False")
    party_crm_org_accounts_enabled: bool = os.environ.get("PARTY_CRM_ORG_ACCOUNTS_ENABLED", "0") not in ("0", "false", "False")
    party_crm_profile_sync_enabled: bool = os.environ.get("PARTY_CRM_PROFILE_SYNC_ENABLED", "0") not in ("0", "false", "False")
    party_table_name: str = os.environ.get("DDB_PARTY_TABLE", "party")

    # ATS Candidates (CND-001)
    # Master switch defaults OFF. With it off every CND route returns 404/503
    # and no DynamoDB or S3 write is attempted. No existing table, endpoint, or
    # service is modified when this flag is False.
    candidates_enabled: bool = (
        os.environ.get("CANDIDATES_ENABLED", "0") not in ("0", "false", "False")
    )
    candidates_table_name: str = os.environ.get("DDB_CANDIDATES_TABLE", "candidates")
    candidate_resume_bucket: str = os.environ.get("CANDIDATE_RESUME_BUCKET", "local-uploads")
    candidate_resume_s3_prefix: str = os.environ.get(
        "CANDIDATE_RESUME_S3_PREFIX", "candidate-resumes/"
    )
    candidate_resume_max_bytes: int = int(
        os.environ.get("CANDIDATE_RESUME_MAX_BYTES", "20971520")   # 20 MB
    )
    candidate_resume_max_per_candidate: int = int(
        os.environ.get("CANDIDATE_RESUME_MAX_PER_CANDIDATE", "25")
    )
    # ATS / Recruiting — Job Orders (JOB-001)
    ats_enabled: bool = os.environ.get("ATS_ENABLED", "0") not in ("0", "false", "False")
    job_orders_enabled: bool = os.environ.get("JOB_ORDERS_ENABLED", "0") not in ("0", "false", "False")
    job_orders_table_name: str = os.environ.get("DDB_JOB_ORDERS_TABLE", "job_orders")
    # JOB-002: allow closed job orders to be reopened (default True)
    job_order_allow_reopen: bool = os.environ.get("JOB_ORDER_ALLOW_REOPEN", "1") not in ("0", "false", "False")
    # Property management (open-property vertical, PROP-001..PROP-005). Default OFF.
    property_mgmt_enabled: bool = os.environ.get("PROPERTY_MGMT_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    properties_table_name: str = os.environ.get("PROPERTIES_TABLE_NAME", "properties")
    # QloApps hotel-PMS vertical (HTL) — master flag, default OFF; with it off
    # the hotel routers (HTL-003) are mounted but every handler 404s and the
    # platform is byte-for-byte unchanged.
    hotels_table_name: str = os.environ.get("HOTELS_TABLE_NAME", "hotels")
    hotel_amenities_table_name: str = os.environ.get("HOTEL_AMENITIES_TABLE_NAME", "hotel_amenities")

    # OpenBankProject umbrella master flag (cross-series, decision D4).
    # One kill-switch for the entire banking vertical; every OBP series gate

    # Banking accounts feature flags (ACC-001..ACC-004), all default OFF.
    banking_accounts_enabled: bool = os.environ.get(
        "BANKING_ACCOUNTS_ENABLED", "0"
    ) not in ("0", "false", "False")
    banking_account_metadata_enabled: bool = os.environ.get(
        "BANKING_ACCOUNT_METADATA_ENABLED", "0"
    ) not in ("0", "false", "False")
    banking_account_views_enabled: bool = os.environ.get(
        "BANKING_ACCOUNT_VIEWS_ENABLED", "0"
    ) not in ("0", "false", "False")

    # Banking accounts table + house-bank seed values.
    banking_accounts_table_name: str = os.environ.get(
        "BANKING_ACCOUNTS_TABLE_NAME", "banking_accounts"
    )
    banking_default_bank_id: str = os.environ.get("BANKING_DEFAULT_BANK_ID", "testlogon")
    banking_default_bank_name: str = os.environ.get("BANKING_DEFAULT_BANK_NAME", "Testlogon")

    # ACC-003 transaction-metadata config.
    banking_s3_bucket: str = os.environ.get("BANKING_S3_BUCKET", "")
    banking_image_max_bytes: int = int(os.environ.get("BANKING_IMAGE_MAX_BYTES", "5242880"))
    banking_metadata_write_rate_limit: int = int(
        os.environ.get("BANKING_METADATA_WRITE_RATE_LIMIT", "60")
    )
    # CRM Leads module (LED-001). Master switch defaults OFF: with it off all
    # new routes return 404 and no background work starts; existing behavior
    # is byte-for-byte unchanged.
    leads_enabled: bool = os.environ.get("LEADS_ENABLED", "0") not in ("0", "false", "False")
    leads_table_name: str = os.environ.get("DDB_LEADS_TABLE", "leads")
    # Sub-flags — all default OFF; enabled individually as downstream LED
    # tickets are deployed.
    leads_scoring_enabled: bool = os.environ.get("LEADS_SCORING_ENABLED", "0") not in ("0", "false", "False")
    leads_drip_enabled: bool = os.environ.get("LEADS_DRIP_ENABLED", "0") not in ("0", "false", "False")
    leads_assignment_enabled: bool = os.environ.get("LEADS_ASSIGNMENT_ENABLED", "0") not in ("0", "false", "False")
    # CRM Reports & Dashboards (RPT-001)
    crm_reports_enabled: bool = os.environ.get("CRM_REPORTS_ENABLED", "0") not in ("0", "false", "False")
    crm_reports_table_name: str = os.environ.get("CRM_REPORTS_TABLE_NAME", "crm_reports")
    crm_dashboards_table_name: str = os.environ.get("CRM_DASHBOARDS_TABLE_NAME", "crm_dashboards")
    crm_saved_searches_table_name: str = os.environ.get("CRM_SAVED_SEARCHES_TABLE_NAME", "crm_saved_searches")
    # RPT-002: run rate limiting
    crm_reports_run_rate_limit: int = int(os.environ.get("CRM_REPORTS_RUN_RATE_LIMIT", "10"))
    crm_reports_run_rate_window: int = int(os.environ.get("CRM_REPORTS_RUN_RATE_WINDOW", "60"))
    crm_reports_max_rows: int = int(os.environ.get("CRM_REPORTS_MAX_ROWS", "2000"))
    # RPT-004: scheduled report email delivery
    crm_reports_scheduler_enabled: bool = os.environ.get("CRM_REPORTS_SCHEDULER_ENABLED", "0") not in ("0", "false", "False")
    crm_reports_scheduler_poll_interval: int = int(os.environ.get("CRM_REPORTS_SCHEDULER_POLL_INTERVAL", "300"))
    # RPT-008: saved search run cap
    crm_saved_search_run_max_rows: int = int(os.environ.get("CRM_SAVED_SEARCH_RUN_MAX_ROWS", "500"))
    # CRM Workflow & Process Automation (WFL-001)
    crm_workflow_enabled: bool = os.environ.get("CRM_WORKFLOW_ENABLED", "0") not in ("0", "false", "False")
    crm_workflow_rules_table_name: str = os.environ.get("CRM_WORKFLOW_RULES_TABLE_NAME", "crm_workflow_rules")
    crm_workflow_runs_table_name: str = os.environ.get("CRM_WORKFLOW_RUNS_TABLE_NAME", "crm_workflow_runs")
    crm_workflow_poll_interval_seconds: int = int(os.environ.get("CRM_WORKFLOW_POLL_INTERVAL_SECONDS", "60"))
    crm_workflow_max_rules_per_module: int = int(os.environ.get("CRM_WORKFLOW_MAX_RULES_PER_MODULE", "50"))
    crm_workflow_max_conditions_per_rule: int = int(os.environ.get("CRM_WORKFLOW_MAX_CONDITIONS_PER_RULE", "10"))
    crm_workflow_max_actions_per_rule: int = int(os.environ.get("CRM_WORKFLOW_MAX_ACTIONS_PER_RULE", "10"))
    # CRM Cases, Customer Support & Customer Portal (CAS-001..CAS-017)
    # Master switch — default OFF. Sub-flags also default OFF; they are only
    # evaluated when crm_cases_enabled is True.
    crm_cases_enabled: bool = os.environ.get(
        "CRM_CASES_ENABLED", "false"
    ).lower() == "true"

    # Sub-flags
    crm_cases_sla_enabled: bool = os.environ.get(
        "CRM_CASES_SLA_ENABLED", "false"
    ).lower() == "true"
    crm_cases_portal_enabled: bool = os.environ.get(
        "CRM_CASES_PORTAL_ENABLED", "false"
    ).lower() == "true"
    crm_cases_kb_enabled: bool = os.environ.get(
        "CRM_CASES_KB_ENABLED", "false"
    ).lower() == "true"
    crm_cases_csat_enabled: bool = os.environ.get(
        "CRM_CASES_CSAT_ENABLED", "false"
    ).lower() == "true"
    crm_cases_email_inbound_enabled: bool = os.environ.get(
        "CRM_CASES_EMAIL_INBOUND_ENABLED", "false"
    ).lower() == "true"

    # Table names (CAS-001)
    crm_cases_counter_table: str = os.environ.get(
        "CRM_CASES_COUNTER_TABLE", "crm_cases_counters"
    )
    crm_cases_links_table: str = os.environ.get(
        "CRM_CASES_LINKS_TABLE", "crm_cases_links"
    )
    crm_cases_templates_table: str = os.environ.get(
        "CRM_CASES_TEMPLATES_TABLE", "crm_cases_templates"
    )
    crm_cases_portal_sessions_table: str = os.environ.get(
        "CRM_CASES_PORTAL_SESSIONS_TABLE", "crm_cases_portal_sessions"
    )
    crm_cases_sla_config_table: str = os.environ.get(
        "CRM_CASES_SLA_CONFIG_TABLE", "crm_cases_sla_config"
    )
    crm_kb_articles_table: str = os.environ.get(
        "CRM_KB_ARTICLES_TABLE", "crm_kb_articles"
    )

    # S3 attachment storage (CAS-001 — shared bucket, distinct prefix)
    crm_cases_attachments_bucket: str = os.environ.get(
        "CRM_CASES_ATTACHMENTS_BUCKET", "local-uploads"
    )
    crm_cases_attachments_s3_prefix: str = os.environ.get(
        "CRM_CASES_ATTACHMENTS_S3_PREFIX", "ticket-attachments/"
    )

    # CAS-003: priority GSI index name
    tickets_priority_index_name: str = os.environ.get(
        "TICKETS_PRIORITY_INDEX_NAME", "crm_cases_priority_index"
    )

    # CAS-005: contact/account GSI index names
    tickets_contact_index_name: str = os.environ.get(
        "TICKETS_CONTACT_INDEX_NAME", "crm_cases_contact_index"
    )
    tickets_account_index_name: str = os.environ.get(
        "TICKETS_ACCOUNT_INDEX_NAME", "crm_cases_account_index"
    )

    # CAS-004: maximum transactional ticket emails per user per hour (anti-spam)
    crm_cases_email_transactional_per_hour: int = int(
        os.environ.get("CRM_CASES_EMAIL_TRANSACTIONAL_PER_HOUR", "20")
    )

    # CAS-007: ticket watchers table name
    crm_cases_watchers_table: str = os.environ.get(
        "CRM_CASES_WATCHERS_TABLE", "crm_cases_watchers"
    )
    # CRM Security Suite, Studio & Admin (STU-001)
    # Both flags default OFF — platform is byte-for-byte unchanged when absent.
    crm_acl_enabled: bool = os.environ.get("CRM_ACL_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    crm_studio_enabled: bool = os.environ.get("CRM_STUDIO_ENABLED", "false").lower() in ("1", "true", "yes", "on")

    # CRM table names (STU-001 scaffold)
    crm_acl_roles_table_name: str = os.environ.get("CRM_ACL_ROLES_TABLE", "crm_acl_roles")
    crm_security_groups_table_name: str = os.environ.get("CRM_SECURITY_GROUPS_TABLE", "crm_security_groups")
    crm_studio_fields_table_name: str = os.environ.get("CRM_STUDIO_FIELDS_TABLE", "crm_studio_fields")
    crm_studio_modules_table_name: str = os.environ.get("CRM_STUDIO_MODULES_TABLE", "crm_studio_modules")
    crm_studio_layouts_table_name: str = os.environ.get("CRM_STUDIO_LAYOUTS_TABLE", "crm_studio_layouts")
    crm_studio_dropdowns_table_name: str = os.environ.get("CRM_STUDIO_DROPDOWNS_TABLE", "crm_studio_dropdowns")
    crm_audit_trail_table_name: str = os.environ.get("CRM_AUDIT_TRAIL_TABLE", "crm_audit_trail")
    currencies_table_name: str = os.environ.get("CURRENCIES_TABLE", "currencies")
    search_config_table_name: str = os.environ.get("SEARCH_CONFIG_TABLE", "search_config")
    email_queue_table_name: str = os.environ.get("EMAIL_QUEUE_TABLE", "email_queue")

    # STU-011 Studio tunable constants
    crm_studio_max_fields_per_entity: int = int(os.environ.get("CRM_STUDIO_MAX_FIELDS_PER_ENTITY", "200"))
    crm_studio_field_cache_ttl_seconds: int = int(os.environ.get("CRM_STUDIO_FIELD_CACHE_TTL_SECONDS", "60"))

    # CRM Project Management (PRJ-001) — default OFF
    crm_projects_enabled: bool = (
        os.environ.get("CRM_PROJECTS_ENABLED", "0") not in ("0", "false", "False")
    )
    crm_pm_projects_table_name: str = os.environ.get(
        "DDB_CRM_PM_PROJECTS_TABLE", "crm_pm_projects"
    )
    crm_pm_tasks_table_name: str = os.environ.get(
        "DDB_CRM_PM_TASKS_TABLE", "crm_pm_tasks"
    )
    crm_pm_members_table_name: str = os.environ.get(
        "DDB_CRM_PM_MEMBERS_TABLE", "crm_pm_members"
    )
    crm_pm_templates_table_name: str = os.environ.get(
        "DDB_CRM_PM_TEMPLATES_TABLE", "crm_pm_templates"
    )
    # Hotel PMS / availability (QloApps vertical, HTL-010..HTL-013). Default OFF.
    hotel_availability_table_name: str = os.environ.get("HOTEL_AVAILABILITY_TABLE_NAME", "hotel_availability")
    hotel_hold_ttl_seconds: int = int(os.environ.get("HOTEL_HOLD_TTL_SECONDS", "900"))
    # Hotel PMS (HTL-001 flag reused by HTL-014..HTL-016).
    # The master flag already exists here; HTL-014 adds only the table-name setting.
    # Hotel rate plans (HTL-014). Gated by the existing HOTEL_PMS_ENABLED master flag.
    hotel_rate_plans_table_name: str = os.environ.get("HOTEL_RATE_PLANS_TABLE_NAME", "hotel_rate_plans")

    # PIP-001: ATS Recruiting Pipeline
    ats_pipeline_enabled: bool = (
        os.environ.get("ATS_PIPELINE_ENABLED", "false").lower()
        in ("1", "true", "yes", "on")
    )
    ats_pipeline_table_name: str = os.environ.get(
        "ATS_PIPELINE_TABLE_NAME", "ats_pipeline"
    )
    # Knowledge Base (KB-001)
    knowledge_base_enabled: bool = os.environ.get("KNOWLEDGE_BASE_ENABLED", "0") not in ("0", "false", "False")
    kb_articles_table: str = os.environ.get("KB_ARTICLES_TABLE", "crm_kb_articles")
    kb_attachments_bucket: str = os.environ.get("KB_ATTACHMENTS_BUCKET", "local-uploads")
    kb_attachments_s3_prefix: str = os.environ.get("KB_ATTACHMENTS_S3_PREFIX", "kb-attachments/")
    kb_attachment_max_bytes: int = int(os.environ.get("KB_ATTACHMENT_MAX_BYTES", str(20 * 1024 * 1024)))
    # KB-002: expiry checker
    kb_expiry_checker_interval_seconds: int = int(os.environ.get("KB_EXPIRY_CHECKER_INTERVAL_SECONDS", "3600"))
    # QloApps hotel-PMS (HTL-005..009): rooms table (master flag hotel_pms_enabled defined above)
    hotel_rooms_table_name: str = os.environ.get("HOTEL_ROOMS_TABLE_NAME", "hotel_rooms")

    # Leases (open-property vertical — LSE cluster)
    leases_enabled: bool = os.environ.get("LEASES_ENABLED", "0") not in (
        "0", "false", "False"
    )
    leases_table_name: str = os.environ.get("LEASES_TABLE_NAME", "leases")
    leases_renewal_notifications_enabled: bool = os.environ.get(
        "LEASES_RENEWAL_NOTIFICATIONS_ENABLED", "0"
    ) not in ("0", "false", "False")
    leases_renewal_check_interval_seconds: int = int(
        os.environ.get("LEASES_RENEWAL_CHECK_INTERVAL_SECONDS", "3600")
    )
    # ATS Recruiting — RSK reuses the master flag candidates_enabled owned by CND-001 (defined above)
    ats_skills_table_name: str = os.environ.get("ATS_SKILLS_TABLE_NAME", "ats_skills")
    ats_skills_enabled: bool = os.environ.get(
        "ATS_SKILLS_ENABLED", "1"
    ) not in ("0", "false", "False")

    # RSK-002 — Résumé text extraction
    ats_resume_extract_max_chars: int = int(
        os.environ.get("ATS_RESUME_EXTRACT_MAX_CHARS", "50000")
    )
    ats_resume_extract_max_bytes: int = int(
        os.environ.get("ATS_RESUME_EXTRACT_MAX_BYTES", str(10 * 1024 * 1024))
    )
    # --- OBP Transaction Requests + Step-Up SCA (TXR-001..TXR-005) ---
    # Per-series flag (default OFF). The effective gate ANDs this with the
    # umbrella S.open_bank_project_enabled (defined in ACC-001; referenced
    # defensively via getattr so this series builds independently of ACC).
    txn_requests_enabled: bool = os.environ.get(
        "TXN_REQUESTS_ENABLED", "0"
    ) not in ("0", "false", "False")
    txn_requests_table_name: str = os.environ.get(
        "TXN_REQUESTS_TABLE", "txn_requests"
    )
    # TXR-002 — per-type amount ceilings (0 = no limit).
    txn_request_limit_wallet_transfer_cents: int = int(
        os.environ.get("TXN_REQUEST_LIMIT_WALLET_TRANSFER_CENTS", "0")
    )
    txn_request_limit_counterparty_cents: int = int(
        os.environ.get("TXN_REQUEST_LIMIT_COUNTERPARTY_CENTS", "0")
    )
    txn_request_limit_payout_cents: int = int(
        os.environ.get("TXN_REQUEST_LIMIT_PAYOUT_CENTS", "0")
    )
    txn_request_limit_refund_cents: int = int(
        os.environ.get("TXN_REQUEST_LIMIT_REFUND_CENTS", "0")
    )
    txn_request_limit_free_form_cents: int = int(
        os.environ.get("TXN_REQUEST_LIMIT_FREE_FORM_CENTS", "0")
    )
    # TXR-003 — step-up SCA threshold + always-sensitive types.
    txn_request_sca_threshold_cents: int = int(
        os.environ.get("TXN_REQUEST_SCA_THRESHOLD_CENTS", "5000")
    )
    txn_request_sca_sensitive_types: frozenset = frozenset(
        t.strip().upper()
        for t in os.environ.get(
            "TXN_REQUEST_SCA_SENSITIVE_TYPES", "PAYOUT,REFUND,COUNTERPARTY"
        ).split(",")
        if t.strip()
    )
    # TXR-004 — transient IN_FLIGHT cleanup TTL (seconds).
    txn_request_in_flight_ttl_seconds: int = int(
        os.environ.get("TXN_REQUEST_IN_FLIGHT_TTL_SECONDS", "300")
    )
    # HTL front-desk (HTL-022..024) reuses hotel_pms_enabled + the hotel_reservations / hotel_rooms tables (declared above)

    # OBP umbrella gate (ACC-001 §6, decision D4) — kills the entire OBP banking vertical.
    # Every OBP series _require_enabled() gate is S.open_bank_project_enabled AND S.<series>_enabled.
    # REUSE: do NOT redefine if already present from sibling ACC-001 code.

    # OAU-001: OAuth consumer-app registry
    oauth_provider_enabled: bool = os.environ.get("OAUTH_PROVIDER_ENABLED", "0") not in ("0", "false", "False")
    oauth_consumers_table_name: str = os.environ.get("OAUTH_CONSUMERS_TABLE_NAME", "oauth_consumers")
    oauth_consumers_owner_index: str = os.environ.get("OAUTH_CONSUMERS_OWNER_INDEX", "ByOwner")

    # OAU-002: Authorization-code flow + token settings
    oauth_access_token_ttl_seconds: int = int(os.environ.get("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "900"))
    oauth_code_ttl_seconds: int = int(os.environ.get("OAUTH_CODE_TTL_SECONDS", "60"))
    oauth_refresh_token_ttl_seconds: int = int(os.environ.get("OAUTH_REFRESH_TOKEN_TTL_SECONDS", "2592000"))
    oauth_always_issue_refresh_token: bool = os.environ.get("OAUTH_ALWAYS_ISSUE_REFRESH_TOKEN", "0") not in ("0", "false", "False")
    oauth_provider_directlogin_enabled: bool = os.environ.get("OAUTH_PROVIDER_DIRECTLOGIN_ENABLED", "0") not in ("0", "false", "False")

    # OAU-003: OIDC layer
    oauth_provider_oidc_enabled: bool = os.environ.get("OAUTH_PROVIDER_OIDC_ENABLED", "0") not in ("0", "false", "False")
    oidc_id_token_ttl_seconds: int = int(os.environ.get("OIDC_ID_TOKEN_TTL_SECONDS", "3600"))
    oidc_issuer_url: str = os.environ.get("OIDC_ISSUER_URL", "")

    # OAU-004: Per-consumer scope enforcement
    oauth_provider_scope_enforcement_enabled: bool = os.environ.get(
        "OAUTH_PROVIDER_SCOPE_ENFORCEMENT_ENABLED", "0"
    ) not in ("0", "false", "False")

    # ── CRM Activities (ACT-001..ACT-010) ────────────────────────────────────
    # Master switch — all sub-flags AND table access depend on this being true.
    # Default OFF; sub-flags also default OFF so enabling master alone is safe.
    crm_activities_enabled: bool = os.environ.get(
        "CRM_ACTIVITIES_ENABLED", "false"
    ).lower() == "true"

    # Module-level sub-flags
    crm_tasks_enabled: bool = os.environ.get(
        "CRM_TASKS_ENABLED", "false"
    ).lower() == "true"
    crm_notes_enabled: bool = os.environ.get(
        "CRM_NOTES_ENABLED", "false"
    ).lower() == "true"
    crm_activity_timeline_enabled: bool = os.environ.get(
        "CRM_ACTIVITY_TIMELINE_ENABLED", "false"
    ).lower() == "true"
    crm_event_rsvp_enabled: bool = os.environ.get(
        "CRM_EVENT_RSVP_ENABLED", "false"
    ).lower() == "true"
    crm_event_reminders_enabled: bool = os.environ.get(
        "CRM_EVENT_REMINDERS_ENABLED", "false"
    ).lower() == "true"

    # DynamoDB table name settings
    crm_tasks_table_name: str = os.environ.get("DDB_CRM_TASKS_TABLE", "crm_tasks")
    crm_notes_table_name: str = os.environ.get("DDB_CRM_NOTES_TABLE", "crm_notes")
    crm_activity_timeline_table_name: str = os.environ.get(
        "DDB_CRM_ACTIVITY_TIMELINE_TABLE", "crm_activity_timeline"
    )
    crm_event_rsvp_table_name: str = os.environ.get(
        "DDB_CRM_EVENT_RSVP_TABLE", "crm_event_rsvp"
    )
    crm_event_reminders_table_name: str = os.environ.get(
        "DDB_CRM_EVENT_REMINDERS_TABLE", "crm_event_reminders"
    )

    # ACT-004: poller tuning
    crm_event_reminders_poll_interval_seconds: int = int(
        os.environ.get("CRM_EVENT_REMINDERS_POLL_INTERVAL_SECONDS", "60")
    )

    # ACT-010: S3 bucket for note attachments
    crm_notes_s3_bucket: str = os.environ.get(
        "CRM_NOTES_S3_BUCKET", "local-uploads"
    )
    # Maintenance Work Orders (WOV-001..WOV-004) — default OFF
    maintenance_orders_enabled: bool = os.environ.get("MAINTENANCE_ORDERS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    maintenance_orders_table_name: str = os.environ.get("MAINTENANCE_ORDERS_TABLE_NAME", "maintenance_orders")
    maintenance_vendors_table_name: str = os.environ.get("MAINTENANCE_VENDORS_TABLE_NAME", "maintenance_vendors")
    maintenance_orders_escrow_enabled: bool = os.environ.get("MAINTENANCE_ORDERS_ESCROW_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    maintenance_escrow_min_cents: int = int(os.environ.get("MAINTENANCE_ESCROW_MIN_CENTS", "100"))
    maintenance_escrow_max_cents: int = int(os.environ.get("MAINTENANCE_ESCROW_MAX_CENTS", "10000000"))
    maintenance_escrow_fee_bps: int = int(os.environ.get("MAINTENANCE_ESCROW_FEE_BPS", "0"))
    maintenance_escrow_payout_hold_seconds: int = int(os.environ.get("MAINTENANCE_ESCROW_PAYOUT_HOLD_SECONDS", "0"))

    # QloApps Booking-Engine Storefront (HTL-025..HTL-027) — master flag reused from HTL-001 vertical (hotel_pms_enabled defined above via getattr). Table + RL settings owned here.
    hotels_table_name: str = os.environ.get("HOTELS_TABLE_NAME", "hotels")
    hotel_booking_search_rl_max: int = int(os.environ.get("HOTEL_BOOKING_SEARCH_RL_MAX", "60"))
    hotel_booking_search_rl_window: int = int(os.environ.get("HOTEL_BOOKING_SEARCH_RL_WINDOW", "3600"))
    hotel_booking_search_max_los_nights: int = int(os.environ.get("HOTEL_BOOKING_SEARCH_MAX_LOS_NIGHTS", "30"))
    hotel_booking_search_max_rooms: int = int(os.environ.get("HOTEL_BOOKING_SEARCH_MAX_ROOMS", "8"))
    hotel_booking_cart_rl_max: int = int(os.environ.get("HOTEL_BOOKING_CART_RL_MAX", "120"))
    hotel_booking_cart_rl_window: int = int(os.environ.get("HOTEL_BOOKING_CART_RL_WINDOW", "3600"))
    hotel_booking_checkout_rl_max: int = int(os.environ.get("HOTEL_BOOKING_CHECKOUT_RL_MAX", "20"))
    hotel_booking_checkout_rl_window: int = int(os.environ.get("HOTEL_BOOKING_CHECKOUT_RL_WINDOW", "3600"))

    # OFBiz Phase 8 — Shipping/Logistics (SHP-001+). Master switch defaults OFF. With it off all new shipping endpoints return 404 and existing shop/cart/orders/billing is unchanged.
    shipping_enabled: bool = os.environ.get("SHIPPING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    shipping_rate_estimation_enabled: bool = os.environ.get("SHIPPING_RATE_ESTIMATION_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    shipping_default_currency: str = os.environ.get("SHIPPING_DEFAULT_CURRENCY", "usd")
    shipping_default_item_weight_oz: int = int(os.environ.get("SHIPPING_DEFAULT_ITEM_WEIGHT_OZ", "16"))
    shipping_dim_divisor: int = int(os.environ.get("SHIPPING_DIM_DIVISOR", "139"))
    shipping_carriers_table_name: str = os.environ.get("SHIPPING_CARRIERS_TABLE_NAME", "shipping_carriers")
    shipment_items_table_name: str = os.environ.get("SHIPMENT_ITEMS_TABLE_NAME", "shipment_items")
    shipment_packages_table_name: str = os.environ.get("SHIPMENT_PACKAGES_TABLE_NAME", "shipment_packages")

    customer_entity_enabled: bool = os.environ.get("CUSTOMER_ENTITY_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    customers_table_name: str = os.environ.get("CUSTOMERS_TABLE_NAME", "customers")
    financial_products_enabled: bool = os.environ.get("FINANCIAL_PRODUCTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    financial_products_table_name: str = os.environ.get("FINANCIAL_PRODUCTS_TABLE_NAME", "financial_products")

    # QloApps hotel-PMS vertical (HTL) — master flag + folio/payments tables
    hotel_folios_table_name: str = os.environ.get("HOTEL_FOLIOS_TABLE_NAME", "hotel_folios")

    # PUR-001/002: Purchasing / SCM
    purchasing_scm_enabled: bool = os.environ.get("PURCHASING_SCM_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    suppliers_table_name: str = os.environ.get("SUPPLIERS_TABLE_NAME", "suppliers")
    supplier_products_table_name: str = os.environ.get("SUPPLIER_PRODUCTS_TABLE_NAME", "supplier_products")
    purchase_orders_table_name: str = os.environ.get("PURCHASE_ORDERS_TABLE_NAME", "purchase_orders")
    po_receipts_table_name: str = os.environ.get("PO_RECEIPTS_TABLE_NAME", "po_receipts")
    purchase_order_reorder_suggestions_enabled: bool = os.environ.get("PURCHASE_ORDER_REORDER_SUGGESTIONS_ENABLED", "false").lower() in ("1", "true", "yes", "on")


    # PSD2 Consents (CSN-001/002)
    psd2_consents_enabled: bool = os.environ.get("PSD2_CONSENTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    consents_table_name: str = os.environ.get("CONSENTS_TABLE_NAME", "consents")
    consents_consumer_index: str = os.environ.get("CONSENTS_CONSUMER_INDEX", "ByConsumer")
    consents_status_index: str = os.environ.get("CONSENTS_STATUS_INDEX", "ByStatusExpiry")
    consents_by_payment_ref_index: str = os.environ.get("CONSENTS_BY_PAYMENT_REF_INDEX", "ByPaymentRef")
    psd2_consent_default_ttl_days: int = int(os.environ.get("PSD2_CONSENT_DEFAULT_TTL_DAYS", "90"))
    psd2_consent_max_ttl_days: int = int(os.environ.get("PSD2_CONSENT_MAX_TTL_DAYS", "365"))
    psd2_consent_expiry_poll_interval: int = int(os.environ.get("PSD2_CONSENT_EXPIRY_POLL_INTERVAL", "300"))
    psd2_consent_sca_threshold_cents: int = int(os.environ.get("PSD2_CONSENT_SCA_THRESHOLD_CENTS", "0"))
    psd2_consent_pis_require_sca_factor: bool = os.environ.get("PSD2_CONSENT_PIS_REQUIRE_SCA_FACTOR", "true").lower() in ("1", "true", "yes", "on")
    psd2_consent_rl_read_per_hour: int = int(os.environ.get("PSD2_CONSENT_RL_READ_PER_HOUR", "1000"))
    psd2_consent_rl_refresh_per_hour: int = int(os.environ.get("PSD2_CONSENT_RL_REFRESH_PER_HOUR", "100"))

    # Dynamic Entities (CSN-003)
    dynamic_entities_enabled: bool = os.environ.get("DYNAMIC_ENTITIES_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    dynamic_entity_defs_table_name: str = os.environ.get("DYNAMIC_ENTITY_DEFS_TABLE_NAME", "dynamic_entity_defs")
    dynamic_entity_rows_table_name: str = os.environ.get("DYNAMIC_ENTITY_ROWS_TABLE_NAME", "dynamic_entity_rows")
    dynamic_entity_defs_creator_index: str = os.environ.get("DYNAMIC_ENTITY_DEFS_CREATOR_INDEX", "created_by-created_at-index")
    dynamic_entity_rows_owner_index: str = os.environ.get("DYNAMIC_ENTITY_ROWS_OWNER_INDEX", "owner_sub-created_at-index")
    dynamic_entity_max_properties: int = int(os.environ.get("DYNAMIC_ENTITY_MAX_PROPERTIES", "50"))
    dynamic_entity_max_depth: int = int(os.environ.get("DYNAMIC_ENTITY_MAX_DEPTH", "3"))
    dynamic_entity_max_required: int = int(os.environ.get("DYNAMIC_ENTITY_MAX_REQUIRED", "20"))
    dynamic_entity_row_write_rate_per_hour: int = int(os.environ.get("DYNAMIC_ENTITY_ROW_WRITE_RATE_PER_HOUR", "200"))

    # Dynamic Endpoints (CSN-004)
    dynamic_endpoints_enabled: bool = os.environ.get("DYNAMIC_ENDPOINTS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    dynamic_endpoints_table_name: str = os.environ.get("DYNAMIC_ENDPOINTS_TABLE_NAME", "dynamic_endpoints")
    dynamic_endpoints_method_path_index: str = os.environ.get("DYNAMIC_ENDPOINTS_METHOD_PATH_INDEX", "method_path-sk-index")
    dynamic_endpoints_created_by_index: str = os.environ.get("DYNAMIC_ENDPOINTS_CREATED_BY_INDEX", "created_by-created_at-index")
    dynamic_endpoints_invoke_rate_per_hour: int = int(os.environ.get("DYNAMIC_ENDPOINTS_INVOKE_RATE_PER_HOUR", "1000"))

    # Open Data: Branches + ATMs (CSN-005)
    open_data_enabled: bool = os.environ.get("OPEN_DATA_ENABLED", "0") not in ("0", "false", "False")
    open_data_table_name: str = os.environ.get("OPEN_DATA_TABLE_NAME", "open_data")
    open_data_active_index: str = os.environ.get("OPEN_DATA_ACTIVE_INDEX", "ByActive")
    open_data_list_max_limit: int = int(os.environ.get("OPEN_DATA_LIST_MAX_LIMIT", "200"))

    # CRM Events (EVT-001) — Master flag default OFF.
    # With flag off: all /ui/crm/events/* routes return 404; no workers start.
    crm_events_enabled: bool = os.environ.get("CRM_EVENTS_ENABLED", "0").lower() in ("1", "true", "yes", "on")
    crm_events_table_name: str = os.environ.get("CRM_EVENTS_TABLE_NAME", "crm_events")
    crm_event_registrations_table_name: str = os.environ.get("CRM_EVENT_REGISTRATIONS_TABLE_NAME", "crm_event_registrations")

    # CRM Survey Distribution (EVT-008) — default OFF
    crm_survey_distribution_enabled: bool = os.environ.get("CRM_SURVEY_DISTRIBUTION_ENABLED", "0").lower() in ("1", "true", "yes", "on")
    survey_distribution_rate_limit_max: int = int(os.environ.get("SURVEY_DISTRIBUTION_RATE_LIMIT_MAX", "10"))
    survey_distribution_rate_limit_window: int = int(os.environ.get("SURVEY_DISTRIBUTION_RATE_LIMIT_WINDOW", "3600"))

    # CRM Document Library (EVT-011) — default OFF
    crm_document_library_enabled: bool = os.environ.get("CRM_DOCUMENT_LIBRARY_ENABLED", "0").lower() in ("1", "true", "yes", "on")

    # CRM Contact SMS (EVT-014) — default OFF
    crm_contact_sms_enabled: bool = os.environ.get("CRM_CONTACT_SMS_ENABLED", "0").lower() in ("1", "true", "yes", "on")
    crm_contact_sms_log_table_name: str = os.environ.get("CRM_CONTACT_SMS_LOG_TABLE", "crm_contact_sms_log")
    crm_contact_sms_rate_max: int = int(os.environ.get("CRM_CONTACT_SMS_RATE_MAX", "20"))
    crm_contact_sms_rate_window_seconds: int = int(os.environ.get("CRM_CONTACT_SMS_RATE_WINDOW_SECONDS", "3600"))

    # CRM Audit Log Browse (EVT-015) — default OFF
    crm_audit_log_browse_enabled: bool = os.environ.get("CRM_AUDIT_LOG_BROWSE_ENABLED", "false") == "1"
    crm_audit_log_browse_rate_limit_per_minute: int = int(os.environ.get("CRM_AUDIT_LOG_BROWSE_RATE_LIMIT", "60"))

    # OBP umbrella master flag (ACC-001 §6) — single kill-switch for the entire

    # PLT-001: Per-consumer API rate-limit middleware
    api_consumer_rate_limit_enabled: bool = os.environ.get("API_CONSUMER_RATE_LIMIT_ENABLED", "0") not in ("0", "false", "False")
    api_consumer_rate_limit_minute: int = int(os.environ.get("API_CONSUMER_RATE_LIMIT_MINUTE", "0"))
    api_consumer_rate_limit_hour: int = int(os.environ.get("API_CONSUMER_RATE_LIMIT_HOUR", "0"))
    api_consumer_rate_limit_day: int = int(os.environ.get("API_CONSUMER_RATE_LIMIT_DAY", "0"))
    api_consumer_rate_limit_week: int = int(os.environ.get("API_CONSUMER_RATE_LIMIT_WEEK", "0"))
    api_consumer_rate_limit_month: int = int(os.environ.get("API_CONSUMER_RATE_LIMIT_MONTH", "0"))

    # PLT-002: Top-N API usage metrics leaderboard
    metrics_leaderboard_enabled: bool = os.environ.get("METRICS_LEADERBOARD_ENABLED", "0") not in ("0", "false", "False")
    metrics_leaderboard_max_top_n: int = int(os.environ.get("METRICS_LEADERBOARD_MAX_TOP_N", "100"))

    # PLT-003: Glossary endpoint
    glossary_enabled: bool = os.environ.get("GLOSSARY_ENABLED", "0") not in ("0", "false", "False")
    glossary_table_name: str = os.environ.get("GLOSSARY_TABLE_NAME", "glossary")
    glossary_definition_max_chars: int = int(os.environ.get("GLOSSARY_DEFINITION_MAX_CHARS", "4096"))

    # PLT-004: Sandbox JSON import
    sandbox_import_enabled: bool = os.environ.get("SANDBOX_IMPORT_ENABLED", "0") not in ("0", "false", "False")
    sandbox_import_max_items: int = int(os.environ.get("SANDBOX_IMPORT_MAX_ITEMS", "500"))

    # PLT-005: Account/ledger webhook events
    account_ledger_webhooks_enabled: bool = os.environ.get("ACCOUNT_LEDGER_WEBHOOKS_ENABLED", "0") not in ("0", "false", "False")

    # HTL-035 KPI caps (hotel_pms_enabled + hotel table names declared above)
    hotel_kpi_max_range_days: int = int(os.environ.get("HOTEL_KPI_MAX_RANGE_DAYS", "366"))
    hotel_kpi_max_stay_nights: int = int(os.environ.get("HOTEL_KPI_MAX_STAY_NIGHTS", "370"))

    # Human Resources (HRM-001) — Phase M of the OFBiz ERP buildout.
    # Master switch defaults OFF: with it off all HR endpoints 404 and the
    # hr DynamoDB table need not exist; no other module is affected.
    hr_enabled: bool = os.environ.get("HR_ENABLED", "0") not in ("0", "false", "False")
    # Sub-gate for payroll run CRUD. Checked only when hr_enabled is True.
    hr_payroll_enabled: bool = os.environ.get("HR_PAYROLL_ENABLED", "0") not in ("0", "false", "False")
    # Sub-gate for double-entry GL journal-entry write on payroll approval.
    # Checked only when hr_payroll_enabled is True.
    hr_payroll_gl_posting_enabled: bool = os.environ.get("HR_PAYROLL_GL_POSTING_ENABLED", "0") not in ("0", "false", "False")
    # DynamoDB table name for all HR single-table rows.
    hr_table_name: str = os.environ.get("DDB_HR_TABLE", "hrm")
    # GL account code for the Salaries & Wages Expense debit side of payroll
    # journal entries (HRM-010). Must match a code in the seeded chart of
    # accounts (OFB-013). Default "6000" = conventional OFBiz expense code.
    hr_payroll_expense_account_code: str = os.environ.get("HR_PAYROLL_EXPENSE_ACCOUNT_CODE", "6000")
    # If True, terminating an employment reverts the linked position to OPEN.
    hr_position_revert_on_terminate: bool = os.environ.get("HR_POSITION_REVERT_ON_TERMINATE", "1") not in ("0", "false", "False")

    # OFBiz Phase N — Fixed Assets (FXA-001/FXA-002).
    # Master switch defaults OFF: with it off the existing shop/cart/orders/billing
    # paths are byte-for-byte unchanged; the fixed-assets service is dormant.
    # FIXED_ASSETS_DEPRECIATION_POSTING_ENABLED is a secondary gate for the
    # background depreciation poster — meaningful only when the master switch is on.
    fixed_assets_enabled: bool = os.environ.get("FIXED_ASSETS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    fixed_assets_depreciation_posting_enabled: bool = os.environ.get("FIXED_ASSETS_DEPRECIATION_POSTING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    fixed_assets_depreciation_poll_interval: int = int(os.environ.get("FIXED_ASSETS_DEPRECIATION_POLL_INTERVAL", "86400"))
    fixed_assets_table_name: str = os.environ.get("FIXED_ASSETS_TABLE_NAME", "fixed_assets")
    fixed_asset_schedule_table_name: str = os.environ.get("FIXED_ASSET_SCHEDULE_TABLE_NAME", "fixed_asset_schedule")

    # OFBiz commerce/ERP — POS (Point of Sale) channel (POS-001..POS-NNN).
    # Master switch defaults OFF. With pos_enabled=False every POS endpoint returns
    # 404 and the module is dormant; existing shop/cart/orders/billing bytes are unchanged.
    pos_enabled: bool = os.environ.get("POS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    pos_table_name: str = os.environ.get("POS_TABLE_NAME", "pos")
    pos_cash_drawer_required: bool = os.environ.get("POS_CASH_DRAWER_REQUIRED", "false").lower() in ("1", "true", "yes", "on")
    pos_default_tax_rate_bps: int = int(os.environ.get("POS_DEFAULT_TAX_RATE_BPS", "0"))
    pos_receipt_store_name: str = os.environ.get("POS_RECEIPT_STORE_NAME", "")


    # Marketing Campaigns module (MKT-002). Default OFF.
    marketing_campaigns_enabled: bool = os.environ.get("MARKETING_CAMPAIGNS_ENABLED", "0") not in ("0", "false", "False")
    marketing_campaigns_table_name: str = os.environ.get("DDB_MARKETING_CAMPAIGNS", "MarketingCampaigns")
    contact_lists_table_name: str = os.environ.get("DDB_CONTACT_LISTS", "ContactLists")
    party_segments_table_name: str = os.environ.get("DDB_PARTY_SEGMENTS", "PartySegments")
    tracking_codes_table_name: str = os.environ.get("DDB_TRACKING_CODES", "TrackingCodes")
    marketing_send_log_table_name: str = os.environ.get("DDB_MARKETING_SEND_LOG", "MarketingCampaignSendLog")

    # OBP PAY cluster (counterparties, standing orders, mandates, FX). Owns ONLY the per-series flag + tables; umbrella S.open_bank_project_enabled (D4) is declared by ACC and read via getattr — never redeclared here.
    payments_counterparties_enabled: bool = os.environ.get("PAYMENTS_COUNTERPARTIES_ENABLED", "0").lower() not in ("0", "false", "no")
    counterparties_table_name: str = os.environ.get("COUNTERPARTIES_TABLE_NAME", "counterparties")
    standing_orders_table_name: str = os.environ.get("STANDING_ORDERS_TABLE_NAME", "standing_orders")
    direct_debit_mandates_table_name: str = os.environ.get("DIRECT_DEBIT_MANDATES_TABLE_NAME", "direct_debit_mandates")
    fx_rates_table_name: str = os.environ.get("FX_RATES_TABLE_NAME", "fx_rates")

    # EVT-005: CRM Geocoding — address-to-lat/lng (default OFF)
    crm_geocoding_enabled: bool = os.environ.get("CRM_GEOCODING_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    crm_geocoding_provider_url: str = os.environ.get("CRM_GEOCODING_PROVIDER_URL", "")
    crm_geocoding_batch_limit: int = int(os.environ.get("CRM_GEOCODING_BATCH_LIMIT", "100"))

    # EVT-006: CRM Proximity Search — Haversine radius query (default OFF)
    crm_proximity_search_enabled: bool = os.environ.get("CRM_PROXIMITY_SEARCH_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    crm_proximity_search_max_radius_km: float = float(os.environ.get("CRM_PROXIMITY_SEARCH_MAX_RADIUS_KM", "20000.0"))
    crm_proximity_search_rate_limit_n: int = int(os.environ.get("CRM_PROXIMITY_SEARCH_RATE_LIMIT_N", "30"))
    crm_proximity_search_rate_limit_win: int = int(os.environ.get("CRM_PROXIMITY_SEARCH_RATE_LIMIT_WIN", "60"))

    # EVT-007: CRM Map View — Leaflet pin-drop page (default OFF, controlled by crm_geocoding_enabled)
    crm_map_default_lat: float = float(os.environ.get("CRM_MAP_DEFAULT_LAT", "37.7749"))
    crm_map_default_lng: float = float(os.environ.get("CRM_MAP_DEFAULT_LNG", "-122.4194"))
    crm_map_default_radius_km: float = float(os.environ.get("CRM_MAP_DEFAULT_RADIUS_KM", "50.0"))
    crm_map_max_radius_km: float = float(os.environ.get("CRM_MAP_MAX_RADIUS_KM", "500.0"))
    crm_map_max_pins: int = int(os.environ.get("CRM_MAP_MAX_PINS", "200"))

    # ATI (OpenCATS ATS Integration) — ATI-owned cross-link bridge flag + table. Default OFF; AND-ed with candidates_enabled (CND-001 authoritative gate) inside ats_integration.py. Do NOT redeclare candidates_enabled/party_crm_*/job_orders_* here (sibling-owned).
    ats_integration_enabled: bool = os.environ.get("ATS_INTEGRATION_ENABLED", "0").lower() not in ("0", "false", "no", "off", "")
    ats_integration_links_table_name: str = os.environ.get("DDB_ATS_INTEGRATION_LINKS_TABLE", "ats_integration_links")

    # CCT (SuiteCRM Contacts Extra) — PTY-001 + CCT-001..CCT-006
    party_dedup_match_threshold: float = float(os.environ.get("PARTY_DEDUP_MATCH_THRESHOLD", "0.70"))

    # CMP-001..CMP-008: SuiteCRM Campaigns-Extra subsystem (default OFF)
    crm_campaigns_enabled: bool = os.environ.get("CRM_CAMPAIGNS_ENABLED", "0") not in ("0", "false", "False")
    crm_campaigns_table_name: str = os.environ.get("DDB_MARKETING_CAMPAIGNS", "CrmCampaigns")
    crm_campaign_send_log_table_name: str = os.environ.get("DDB_MARKETING_SEND_LOG", "CrmCampaignSendLog")
    marketing_email_templates_table_name: str = os.environ.get("DDB_MARKETING_EMAIL_TEMPLATES", "MarketingEmailTemplates")
    marketing_contact_lists_table_name: str = os.environ.get("DDB_MARKETING_CONTACT_LISTS", "MarketingContactLists")
    marketing_tracking_codes_table_name: str = os.environ.get("DDB_MARKETING_TRACKING_CODES", "MarketingTrackingCodes")
    marketing_web_lead_captures_table_name: str = os.environ.get("DDB_WEB_LEAD_CAPTURES_TABLE", "WebLeadCaptures")
    marketing_unsubscribe_secret: str = (os.environ.get("MARKETING_UNSUBSCRIBE_SECRET") or os.environ.get("UI_ACCESS_TOKEN_SECRET", ""))
    marketing_open_tracking_enabled: bool = os.environ.get("MARKETING_OPEN_TRACKING_ENABLED", "0") not in ("0", "false", "False")
    marketing_open_tracking_bot_ignore_uas: str = os.environ.get("MARKETING_OPEN_TRACKING_BOT_IGNORE_UAS", "Barracuda,Proofpoint,SafeBrowsing,Google Image Proxy,Yahoo! Slurp,Googlebot")
    web_to_lead_enabled: bool = os.environ.get("WEB_TO_LEAD_ENABLED", "0") not in ("0", "false", "False")
    web_to_lead_autoresponder_enabled: bool = os.environ.get("WEB_TO_LEAD_AUTORESPONDER_ENABLED", "0") not in ("0", "false", "False")
    web_to_lead_max_per_ip_per_hour: int = int(os.environ.get("WEB_TO_LEAD_MAX_PER_IP_PER_HOUR", "10"))
    marketing_unsubscribe_token_ttl_days: int = int(os.environ.get("MARKETING_UNSUBSCRIBE_TOKEN_TTL_DAYS", "30"))


S = Settings()
