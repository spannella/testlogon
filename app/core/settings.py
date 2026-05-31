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
    ccbill_webhook_ip_enforce: bool = os.environ.get("CCBILL_WEBHOOK_IP_ENFORCE", "false").lower() == "true"
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
    # Billing / PayPal
    billing_table_name: str = os.environ.get("BILLING_TABLE_NAME", os.environ.get("DDB_TABLE", ""))
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
    billing_reconcile_enabled: bool = os.environ.get("BILLING_RECONCILE_ENABLED", "false").lower() == "true"
    billing_reconcile_interval_seconds: int = int(os.environ.get("BILLING_RECONCILE_INTERVAL_SECONDS", "900"))
    billing_reconcile_pending_age_seconds: int = int(os.environ.get("BILLING_RECONCILE_PENDING_AGE_SECONDS", "3600"))
    billing_reconcile_scan_limit: int = int(os.environ.get("BILLING_RECONCILE_SCAN_LIMIT", "200"))
    billing_dunning_enabled: bool = os.environ.get("BILLING_DUNNING_ENABLED", "false").lower() == "true"
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
    tickets_jira_workspace_index_name: str = os.environ.get("TICKETS_JIRA_WORKSPACE_INDEX_NAME", "jira_workspace-updated_at-index")
    tickets_jira_issue_index_name: str = os.environ.get("TICKETS_JIRA_ISSUE_INDEX_NAME", "jira_issue-index")
    tickets_jira_sync_state_index_name: str = os.environ.get("TICKETS_JIRA_SYNC_STATE_INDEX_NAME", "jira_sync_state-updated_at-index")

    # Jira integration feature flags and guardrails
    jira_sync_enabled: bool = os.environ.get("JIRA_SYNC_ENABLED", "false").lower() == "true"
    jira_sync_read_enabled: bool = os.environ.get("JIRA_SYNC_READ_ENABLED", "false").lower() == "true"
    jira_sync_outbound_enabled: bool = os.environ.get("JIRA_SYNC_OUTBOUND_ENABLED", "false").lower() == "true"
    jira_sync_inbound_enabled: bool = os.environ.get("JIRA_SYNC_INBOUND_ENABLED", "false").lower() == "true"
    jira_sync_outbound_kill_switch: bool = os.environ.get("JIRA_SYNC_OUTBOUND_KILL_SWITCH", "false").lower() == "true"
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

    # Messaging
    broadcast_profiles_table_name: str = os.environ.get("DDB_BROADCAST_PROFILES", "BroadcastProfiles")
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
    cart_ttl_days: int = int(os.environ.get("CART_TTL_DAYS", "30"))
    # Catalog
    catalog_table_name: str = os.environ.get("CATALOG_TABLE_NAME", "shopping_catalog")
    catalog_default_low_stock_threshold: int = int(os.environ.get("CATALOG_LOW_STOCK_THRESHOLD", "5"))
    catalog_stock_alerts_enabled: bool = os.environ.get("CATALOG_STOCK_ALERTS_ENABLED", "1") not in ("0", "false", "False")

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
    filemgr_mount_reconcile_enabled: bool = os.environ.get("FILEMGR_MOUNT_RECONCILE_ENABLED", "false").lower() == "true"
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
    filemgr_bucket: str = os.environ.get("FILEMGR_BUCKET", "")
    filemgr_retention_days: int = int(os.environ.get("FILEMGR_RETENTION_DAYS", "30"))
    filemgr_purge_scan_limit: int = int(os.environ.get("FILEMGR_PURGE_SCAN_LIMIT", "200"))
    filemgr_purge_enabled: bool = os.environ.get("FILEMGR_PURGE_ENABLED", "false").lower() == "true"
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
    projects_reconcile_enabled: bool = os.environ.get("PROJECTS_RECONCILE_ENABLED", "false").lower() == "true"
    projects_reconcile_interval_seconds: int = int(os.environ.get("PROJECTS_RECONCILE_INTERVAL_SECONDS", "900"))
    projects_reconcile_scan_limit: int = int(os.environ.get("PROJECTS_RECONCILE_SCAN_LIMIT", "200"))
    projects_reconcile_max_attempts: int = int(os.environ.get("PROJECTS_RECONCILE_MAX_ATTEMPTS", "3"))
    projects_reconcile_backoff_seconds: float = float(os.environ.get("PROJECTS_RECONCILE_BACKOFF_SECONDS", "0.2"))
    projects_provider_failure_alert_threshold: int = int(
        os.environ.get("PROJECTS_PROVIDER_FAILURE_ALERT_THRESHOLD", "5")
    )
    github_api_base_url: str = os.environ.get("GITHUB_API_BASE_URL", "https://api.github.com").rstrip("/")
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
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
    api_usage_table_name: str = os.environ.get("API_USAGE_TABLE_NAME", "")
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


    # Newsfeed rich-content feature flags
    newsfeed_markdown_enabled: bool = os.environ.get("NEWSFEED_MARKDOWN_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    newsfeed_richtext_enabled: bool = os.environ.get("NEWSFEED_RICHTEXT_ENABLED", "false").lower() in ("1", "true", "yes", "on")
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

    # Newsfeed polls (ENGAGE-002)
    newsfeed_polls_enabled: bool = os.environ.get("NEWSFEED_POLLS_ENABLED", "1") not in ("0", "false", "False")
    newsfeed_poll_max_options: int = int(os.environ.get("NEWSFEED_POLL_MAX_OPTIONS", "10"))
    newsfeed_poll_max_duration_hours: int = int(os.environ.get("NEWSFEED_POLL_MAX_DURATION_HOURS", "168"))

    # Image optimization (PLATFORM-004)
    image_optimization_enabled: bool = os.environ.get("IMAGE_OPTIMIZATION_ENABLED", "1") not in ("0", "false", "False")

    # VOD File Bridge (VOD-014)
    vod_file_bridge_enabled: bool = os.environ.get("VOD_FILE_BRIDGE_ENABLED", "1") not in ("0", "false", "False")
    vod_file_bridge_default_folder: str = os.environ.get("VOD_FILE_BRIDGE_DEFAULT_FOLDER", "/Videos/")
    vod_file_bridge_auto_link: bool = os.environ.get("VOD_FILE_BRIDGE_AUTO_LINK", "1") not in ("0", "false", "False")

    # VOD Sharing (VOD-013)
    video_sharing_enabled: bool = os.environ.get("VIDEO_SHARING_ENABLED", "1") not in ("0", "false", "False")
    video_share_playback_token_ttl_seconds: int = int(os.environ.get("VIDEO_SHARE_PLAYBACK_TOKEN_TTL_SECONDS", "300"))

    # Messaging feature flags
    messaging_encrypted_messages_enabled: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_ENABLED", "false").lower() == "true"
    messaging_encrypted_messages_kill_switch: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH", "false").lower() == "true"
    messaging_gallery_enabled: bool = os.environ.get("MESSAGING_GALLERY_ENABLED", "true").lower() == "true"
    messaging_gallery_kill_switch: bool = os.environ.get("MESSAGING_GALLERY_KILL_SWITCH", "false").lower() == "true"
    messaging_gallery_index_enabled: bool = os.environ.get("MESSAGING_GALLERY_INDEX_ENABLED", "false").lower() == "true"
    messaging_mass_send_enabled: bool = os.environ.get("MESSAGING_MASS_SEND_ENABLED", "true").lower() == "true"
    messaging_mass_send_kill_switch: bool = os.environ.get("MESSAGING_MASS_SEND_KILL_SWITCH", "false").lower() == "true"
    messaging_mass_send_campaigns_per_user_per_hour: int = int(os.environ.get("MESSAGING_MASS_SEND_CAMPAIGNS_PER_USER_PER_HOUR", "20"))
    messaging_mass_send_campaigns_per_tenant_per_hour: int = int(os.environ.get("MESSAGING_MASS_SEND_CAMPAIGNS_PER_TENANT_PER_HOUR", "500"))
    messaging_mass_send_max_destinations_per_campaign: int = int(os.environ.get("MESSAGING_MASS_SEND_MAX_DESTINATIONS_PER_CAMPAIGN", "100"))
    messaging_mass_send_max_concurrent_workers: int = int(os.environ.get("MESSAGING_MASS_SEND_MAX_CONCURRENT_WORKERS", "8"))
    messaging_dm_lottery_enabled: bool = os.environ.get("MESSAGING_DM_LOTTERY_ENABLED", "false").lower() == "true"
    messaging_dm_lottery_kill_switch: bool = os.environ.get("MESSAGING_DM_LOTTERY_KILL_SWITCH", "false").lower() == "true"
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
    kyc_retention_rejected_days: int = int(os.environ.get("KYC_RETENTION_REJECTED_DAYS", "30"))
    kyc_retention_expired_days: int = int(os.environ.get("KYC_RETENTION_EXPIRED_DAYS", "7"))
    kyc_retention_approved_days: int = int(os.environ.get("KYC_RETENTION_APPROVED_DAYS", "365"))
    kyc_review_ticket_space_id: str = os.environ.get("KYC_REVIEW_TICKET_SPACE_ID", "kyc-ops")
    kyc_review_ticket_category: str = os.environ.get("KYC_REVIEW_TICKET_CATEGORY", "kyc_review")

    # KYC Risk Scoring (KYC-008)
    kyc_risk_scores_table_name: str = os.environ.get("KYC_RISK_SCORES_TABLE_NAME", "kyc_risk_scores")
    kyc_risk_auto_approve_enabled: bool = os.environ.get("KYC_RISK_AUTO_APPROVE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    kyc_risk_auto_approve_max_score: int = int(os.environ.get("KYC_RISK_AUTO_APPROVE_MAX_SCORE", "20"))
    kyc_risk_auto_escalate_min_score: int = int(os.environ.get("KYC_RISK_AUTO_ESCALATE_MIN_SCORE", "81"))
    kyc_risk_scoring_model_version: str = os.environ.get("KYC_RISK_SCORING_MODEL_VERSION", "v1.0")
    risk_high_threshold: int = int(os.environ.get("RISK_HIGH_THRESHOLD", "70"))
    # KYC tiered verification levels (KYC-009)
    kyc_tier_gating_enabled: bool = os.environ.get("KYC_TIER_GATING_ENABLED", "true").lower() in ("1", "true", "yes", "on")

    # KYC Identity Document Verification (KYC-002)
    kyc_documents_table_name: str = os.environ.get("KYC_DOCUMENTS_TABLE_NAME", "kyc_documents")
    kyc_documents_status_index_name: str = os.environ.get("KYC_DOCUMENTS_STATUS_INDEX_NAME", "ByStatus")
    kyc_documents_bucket: str = os.environ.get("KYC_DOCUMENTS_BUCKET", "local-uploads")
    kyc_documents_s3_prefix: str = os.environ.get("KYC_DOCUMENTS_S3_PREFIX", "kyc-documents/")
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

    # Appeals (MOD-003)
    appeals_table_name: str = os.environ.get("DDB_APPEALS", "Appeals")

    # Creator Payouts (MON-004)
    creator_payouts_table_name: str = os.environ.get("DDB_CREATOR_PAYOUTS", "CreatorPayouts")
    payouts_table_name: str = os.environ.get("DDB_CREATOR_PAYOUTS", "CreatorPayouts")
    payout_hold_period_seconds: int = int(os.environ.get("PAYOUT_HOLD_PERIOD_SECONDS", "604800"))
    payout_hold_days: int = int(os.environ.get("PAYOUT_HOLD_DAYS", "7"))
    payout_minimum_cents: int = int(os.environ.get("PAYOUT_MINIMUM_CENTS", "1000"))
    payout_min_cents: int = int(os.environ.get("PAYOUT_MIN_CENTS", os.environ.get("PAYOUT_MINIMUM_CENTS", "1000")))

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

    # Ad Serving Engine (ADS-004)
    ad_serving_enabled: bool = os.environ.get("AD_SERVING_ENABLED", "1") not in ("0", "false", "False")
    ad_frequency_cap_hourly: int = int(os.environ.get("AD_FREQUENCY_CAP_HOURLY", "3"))
    ad_frequency_cap_daily: int = int(os.environ.get("AD_FREQUENCY_CAP_DAILY", "10"))
    ad_frequency_caps_table_name: str = os.environ.get("DDB_AD_FREQUENCY_CAPS", "AdFrequencyCaps")

    # Subscription-Gated VOD (MON-005)
    vod_subscription_gating_enabled: bool = os.environ.get("VOD_SUBSCRIPTION_GATING_ENABLED", "1") not in ("0", "false", "False")
    ad_billing_table_name: str = os.environ.get("DDB_AD_BILLING", "AdBilling")

    # Advertiser Accounts & Campaigns (ADS-001)

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

    # View-Once / Rental Access (VOD-019)
    vod_purchase_tiers_enabled: bool = os.environ.get("VOD_PURCHASE_TIERS_ENABLED", "1") not in ("0", "false", "False")
    vod_rental_default_duration_hours: int = int(os.environ.get("VOD_RENTAL_DEFAULT_DURATION_HOURS", "48"))
    vod_view_once_enabled: bool = os.environ.get("VOD_VIEW_ONCE_ENABLED", "1") not in ("0", "false", "False")
    # VOD-019 rental-access layer (dedicated vod_rentals table)
    vod_rentals_table_name: str = os.environ.get("DDB_VOD_RENTALS", "VodRentals")
    vod_rental_enabled: bool = os.environ.get("VOD_RENTAL_ENABLED", "1") not in ("0", "false", "False")
    vod_rental_playback_ttl_seconds: int = int(os.environ.get("VOD_RENTAL_PLAYBACK_TTL_SECONDS", "3600"))

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
    # User Groups (GROUP-001)

    # Group Treasury (GROUP-004)
    group_treasury_enabled: bool = os.environ.get("GROUP_TREASURY_ENABLED", "1") not in ("0", "false", "False")
    # Agent Orchestration (AGENT-002 / AGENT-003)
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
    # FIN-014: Payment Provider Health monitoring. Records per-provider
    # success/failure/latency of payment operations, computes health status,
    # error rates, and a recent-incident timeline.
    payment_provider_health_table_name: str = os.environ.get(
        "PAYMENT_PROVIDER_HEALTH_TABLE_NAME", "payment_provider_health"
    )
    payment_provider_health_enabled: bool = os.environ.get(
        "PAYMENT_PROVIDER_HEALTH_ENABLED", "true"
    ).lower() not in ("0", "false", "no")


S = Settings()
