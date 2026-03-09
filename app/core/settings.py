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
    alerts_webhook_url: str = os.environ.get("ALERTS_WEBHOOK_URL", "")
    alerts_webhook_secret: str = os.environ.get("ALERTS_WEBHOOK_SECRET", "")
    alerts_webhook_timeout_seconds: int = int(os.environ.get("ALERTS_WEBHOOK_TIMEOUT_SECONDS", "5"))
    alerts_webhook_event_types: str = os.environ.get("ALERTS_WEBHOOK_EVENT_TYPES", "")
    alerts_webhook_enabled: bool = os.environ.get("ALERTS_WEBHOOK_ENABLED", "0") not in ("0","false","False")
    alerts_webhook_max_per_window: int = int(os.environ.get("ALERTS_WEBHOOK_MAX_PER_WINDOW", "30"))
    alerts_webhook_window_seconds: int = int(os.environ.get("ALERTS_WEBHOOK_WINDOW_SECONDS", "3600"))
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
    default_monthly_price_cents: int = int(os.environ.get("DEFAULT_MONTHLY_PRICE_CENTS", "999"))
    default_currency: str = os.environ.get("DEFAULT_CURRENCY", "usd").lower()

    paypal_env: str = os.environ.get("PAYPAL_ENV", "sandbox").lower()
    paypal_client_id: str = os.environ.get("PAYPAL_CLIENT_ID", "")
    paypal_client_secret: str = os.environ.get("PAYPAL_CLIENT_SECRET", "")
    paypal_webhook_id: str = os.environ.get("PAYPAL_WEBHOOK_ID", "")
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
    billing_table_name: str = os.environ.get("BILLING_TABLE_NAME", "billing")
    account_state_table_name: str = os.environ.get("ACCOUNT_STATE_TABLE_NAME", "account_state")
    billing_reconcile_enabled: bool = os.environ.get("BILLING_RECONCILE_ENABLED", "false").lower() == "true"
    billing_reconcile_interval_seconds: int = int(os.environ.get("BILLING_RECONCILE_INTERVAL_SECONDS", "900"))
    billing_reconcile_pending_age_seconds: int = int(os.environ.get("BILLING_RECONCILE_PENDING_AGE_SECONDS", "3600"))
    billing_reconcile_scan_limit: int = int(os.environ.get("BILLING_RECONCILE_SCAN_LIMIT", "200"))
    billing_dunning_enabled: bool = os.environ.get("BILLING_DUNNING_ENABLED", "false").lower() == "true"
    billing_dunning_interval_seconds: int = int(os.environ.get("BILLING_DUNNING_INTERVAL_SECONDS", "900"))
    billing_dunning_retry_schedule_seconds: str = os.environ.get("BILLING_DUNNING_RETRY_SCHEDULE_SECONDS", "3600,86400,172800")
    billing_dunning_scan_limit: int = int(os.environ.get("BILLING_DUNNING_SCAN_LIMIT", "200"))

    # Tickets
    tickets_table_name: str = os.environ.get("TICKETS_TABLE_NAME", "tickets")
    tickets_owner_index_name: str = os.environ.get("TICKETS_OWNER_INDEX_NAME", "owner_sub-updated_at-index")
    tickets_assignee_index_name: str = os.environ.get("TICKETS_ASSIGNEE_INDEX_NAME", "assigned_admin_sub-updated_at-index")
    tickets_status_index_name: str = os.environ.get("TICKETS_STATUS_INDEX_NAME", "status-updated_at-index")
    tickets_space_index_name: str = os.environ.get("TICKETS_SPACE_INDEX_NAME", "space_id-updated_at-index")
    tickets_space_status_index_name: str = os.environ.get("TICKETS_SPACE_STATUS_INDEX_NAME", "space_status-updated_at-index")
    tickets_space_assignee_index_name: str = os.environ.get("TICKETS_SPACE_ASSIGNEE_INDEX_NAME", "space_assignee-updated_at-index")
    tickets_member_spaces_index_name: str = os.environ.get("TICKETS_MEMBER_SPACES_INDEX_NAME", "member_sub-space_id-index")

    # Profile
    profile_table_name: str = os.environ.get("PROFILE_TABLE_NAME", "profiles")
    addresses_table_name: str = os.environ.get("ADDRESSES_TABLE_NAME", "addresses")

    # Calendar
    calendar_table_name: str = os.environ.get("CALENDAR_TABLE_NAME", "calendar")

    # Contacts
    contacts_table_name: str = os.environ.get("DDB_CONTACTS_TABLE", "Contacts")

    # Messaging
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
    message_report_context_table_name: str = os.environ.get(
        "DDB_MESSAGE_REPORT_CONTEXT",
        "MessageReportContext",
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
    user_enforcement_history_table_name: str = os.environ.get(
        "DDB_USER_ENFORCEMENT_HISTORY",
        "UserEnforcementHistory",
    )
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
    # Catalog
    catalog_table_name: str = os.environ.get("CATALOG_TABLE_NAME", "shopping_catalog")

    # File manager
    filemgr_table_name: str = os.environ.get("FILEMGR_TABLE", "")
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
    gitlab_api_base_url: str = os.environ.get("GITLAB_API_BASE_URL", "https://gitlab.com/api/v4").rstrip("/")
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

    # Messaging feature flags
    messaging_encrypted_messages_enabled: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_ENABLED", "false").lower() == "true"
    messaging_encrypted_messages_kill_switch: bool = os.environ.get("MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH", "false").lower() == "true"
    messaging_gallery_enabled: bool = os.environ.get("MESSAGING_GALLERY_ENABLED", "true").lower() == "true"
    messaging_gallery_kill_switch: bool = os.environ.get("MESSAGING_GALLERY_KILL_SWITCH", "false").lower() == "true"
    messaging_gallery_index_enabled: bool = os.environ.get("MESSAGING_GALLERY_INDEX_ENABLED", "false").lower() == "true"
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


S = Settings()
