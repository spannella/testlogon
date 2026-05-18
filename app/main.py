from __future__ import annotations

import os

from app.auth.root_invariant import validate_startup_root_invariant
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.settings import Settings
from app.metrics import METRICS_ENABLED, metrics_endpoint, metrics_middleware, set_app_info
from app.routers.ui_session import router as ui_session_router
from app.routers.ui_mfa import router as ui_mfa_router
from app.routers.mfa_devices import router as mfa_devices_router
from app.routers.api_keys import router as api_keys_router
from app.routers.api_usage import router as api_usage_router
from app.routers.alerts import router as alerts_router
from app.routers.account import router as account_router
from app.routers.push import router as push_router
from app.routers.recovery import router as recovery_router
from app.routers.password_recovery import router as password_recovery_router
from app.routers.passwordless import router as passwordless_router
from app.routers.register import router as register_router
from app.routers.webauthn import router as webauthn_router
from app.routers.root_auth import router as root_auth_router
from app.routers.admin_roles import router as admin_roles_router
from app.routers.admin_impersonation import router as admin_impersonation_router
from app.routers.misc import router as misc_router
from app.routers.billing_ccbill import router as billing_ccbill_router
from app.routers.ccbill_mock import router as ccbill_mock_router
from app.routers.paypal_mock import router as paypal_mock_router
from app.routers.s3_mock import router as s3_mock_router, list_buckets as _s3_list_buckets
from app.core.dev_s3 import start_s3_mock as _start_s3_mock
from app.core.settings import S as _S
from app.routers.paypal import router as paypal_router
from app.routers.billing import router as billing_router
from app.routers.account_state import router as account_state_router
from app.routers.profile import router as profile_router
from app.routers.messaging import router as messaging_router
from app.routers.filemanager import router as filemanager_router
from app.routers.signature_packets import router as signature_packets_router
from app.routers.addresses import router as addresses_router
from app.routers.calendar import public_router as calendar_public_router
from app.routers.calendar import public_event_router as calendar_public_event_router
from app.routers.calendar import integration_router as calendar_integration_router
from app.routers.calendar import router as calendar_router
from app.routers.admin_calendar_integrations import router as admin_calendar_integrations_router
from app.routers.device_trust import router as device_trust_router
from app.routers.newsfeed import router as newsfeed_router, startup as newsfeed_startup
from app.routers.purchase_history import router as purchase_history_router
from app.routers.shoppingcart import router as shoppingcart_router
from app.routers.catalog import router as catalog_router
from app.routers.subscription_server import router as subscription_server_router
from app.routers.admin_usage import router as admin_usage_router
from app.routers.admin_entitlements import router as admin_entitlements_router
from app.routers.ups import router as ups_router
from app.routers.projects import router as projects_router
from app.routers.contacts import router as contacts_router
from app.routers.entitlements import router as entitlements_router
from app.routers.commercial_checkout import router as commercial_checkout_router
from app.routers.tickets import router as tickets_router
from app.routers.ticket_spaces import router as ticket_spaces_router
from app.routers.internal_devtools import router as internal_devtools_router
from app.routers.browser_ssh_terminal import (
    browser_ssh_terminal_enabled,
    router as browser_ssh_terminal_router,
)
from app.routers.questionnaires import router as questionnaires_router
from app.routers.vnc_sessions import router as vnc_sessions_router
from app.routers.moderation import router as moderation_router, compat_router as moderation_compat_router
from app.routers.admin_moderation import router as admin_moderation_router
from app.services.billing_reconcile import start_billing_reconcile_task
from app.services.billing_dunning import start_billing_dunning_task
from app.services.filemanager import start_filemgr_purge_task
from app.services.api_usage_metering import record_api_usage_from_response, enforce_account_quota_pre_request
from app.services.api_metering_policy import build_limit_denial_headers
from app.routers.messaging import start_scheduled_messages_task
from app.services.projects_reconcile import start_projects_reconcile_task
from app.services.provider_oauth import validate_google_drive_mount_oauth_configuration
from app.services.filemanager_mount_reconcile import start_filemgr_mount_reconcile_task
from app.services.api_usage_entitlements import enforce_api_package_entitlement_pre_request
from app.services.calendar_integrations.registry import initialize_calendar_integration_registry
from app.services.jira_feature_flags import validate_jira_integration_startup_config
from app.routers.admin_jira_integration import router as admin_jira_integration_router
from app.routers.jira_integrations import router as jira_integrations_router


def _api_usage_metering_middleware():
    async def _middleware(request: Request, call_next):
        quota_headers = {}
        entitlement_headers = {}
        try:
            entitlement_headers = enforce_api_package_entitlement_pre_request(request)
            quota_headers = enforce_account_quota_pre_request(request)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"code": "api_limit_exceeded"}
            headers = build_limit_denial_headers(detail)
            return JSONResponse(status_code=int(exc.status_code or 429), content={"detail": detail}, headers=headers)

        response = await call_next(request)
        for k, v in entitlement_headers.items():
            response.headers.setdefault(k, v)
        for k, v in quota_headers.items():
            response.headers.setdefault(k, v)
        try:
            record_api_usage_from_response(request, response.status_code)
        except Exception:
            pass
        return response
    return _middleware

def _security_headers_middleware(default_csp: str):
    async def _middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", default_csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response
    return _middleware
  
def _to_bool(value: str, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


def _build_cors_options() -> dict[str, object]:
    raw_origins = os.environ.get("CORS_ALLOW_ORIGINS", "*")
    allow_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    allow_origin_regex = os.environ.get("CORS_ALLOW_ORIGIN_REGEX")

    # Browsers reject `Access-Control-Allow-Origin: *` when credentials are included.
    # If wildcard access is desired, use a regex so Starlette echoes the request origin.
    if "*" in allow_origins:
        allow_origins = [origin for origin in allow_origins if origin != "*"]
        allow_origin_regex = allow_origin_regex or ".*"

    return {
        "allow_origins": allow_origins,
        "allow_origin_regex": allow_origin_regex,
        "allow_credentials": _to_bool(os.environ.get("CORS_ALLOW_CREDENTIALS"), default=True),
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }

def create_app() -> FastAPI:
    app = FastAPI(title="Security Backend (refactored)", version="0.1.0", redirect_slashes=False)
    settings = Settings()

    @app.get("/browser-ssh")
    async def browser_ssh_route():
        if not browser_ssh_terminal_enabled():
            raise HTTPException(status_code=404, detail="Not found")
        raise HTTPException(status_code=410, detail="Browser SSH terminal UI has moved to the frontend.")

    app.add_middleware(CORSMiddleware, **_build_cors_options())
    app.middleware("http")(_api_usage_metering_middleware())
    if METRICS_ENABLED:
        app.middleware("http")(metrics_middleware)
        set_app_info(app.title, app.version)
        app.get("/metrics")(metrics_endpoint)

    app.include_router(ui_session_router)
    app.include_router(ui_mfa_router)
    app.include_router(mfa_devices_router)
    app.include_router(api_keys_router)
    app.include_router(api_usage_router)
    app.include_router(alerts_router)
    app.include_router(account_router)
    app.include_router(push_router)
    app.include_router(recovery_router)
    app.include_router(password_recovery_router)
    app.include_router(passwordless_router)
    app.include_router(register_router)
    app.include_router(webauthn_router)
    app.include_router(root_auth_router)
    app.include_router(admin_roles_router)
    app.include_router(admin_impersonation_router)
    app.include_router(misc_router)
    app.include_router(billing_ccbill_router)
    app.include_router(ccbill_mock_router)
    app.include_router(paypal_mock_router)
    app.include_router(s3_mock_router, prefix="/mock/s3")
    # Also register GET /mock/s3 (no trailing slash) for boto3 list_buckets
    app.add_api_route("/mock/s3", _s3_list_buckets, methods=["GET"], include_in_schema=False)
    app.include_router(paypal_router)
    app.include_router(billing_router)
    app.include_router(account_state_router)
    app.include_router(profile_router)
    app.include_router(messaging_router)
    app.include_router(filemanager_router)
    app.include_router(signature_packets_router)
    app.include_router(addresses_router)
    app.include_router(calendar_router)
    app.include_router(calendar_integration_router)
    app.include_router(admin_calendar_integrations_router)
    app.include_router(calendar_public_router)
    app.include_router(calendar_public_event_router)
    app.include_router(device_trust_router)
    app.include_router(newsfeed_router)
    app.include_router(moderation_router)
    app.include_router(moderation_compat_router)
    app.include_router(admin_moderation_router)
    app.add_event_handler("startup", validate_startup_root_invariant)
    app.add_event_handler("startup", validate_google_drive_mount_oauth_configuration)
    app.add_event_handler("startup", lambda: setattr(app.state, "calendar_integration_registry", initialize_calendar_integration_registry()))
    app.add_event_handler("startup", validate_jira_integration_startup_config)
    if _S.dev_mode:
        _dev_buckets = [b for b in [
            _S.filemgr_bucket,
            os.environ.get("UPLOAD_BUCKET", ""),
            os.environ.get("S3_BUCKET_IMAGES", ""),
        ] if b]
        app.add_event_handler("startup", lambda: _start_s3_mock(_dev_buckets))


    app.add_event_handler("startup", newsfeed_startup)
    app.add_event_handler("startup", start_billing_dunning_task)
    app.add_event_handler("startup", start_filemgr_purge_task)
    app.add_event_handler("startup", start_scheduled_messages_task)
    app.include_router(purchase_history_router)
    app.include_router(shoppingcart_router)
    app.include_router(catalog_router)
    app.include_router(commercial_checkout_router)
    app.include_router(entitlements_router)
    app.include_router(subscription_server_router)
    app.include_router(admin_usage_router)
    app.include_router(admin_entitlements_router)
    app.include_router(ups_router)
    app.include_router(projects_router)
    app.include_router(contacts_router)
    app.include_router(tickets_router)
    app.include_router(ticket_spaces_router)
    app.include_router(internal_devtools_router)
    app.include_router(admin_jira_integration_router)
    app.include_router(jira_integrations_router)
    app.include_router(browser_ssh_terminal_router)
    app.include_router(questionnaires_router)
    app.include_router(vnc_sessions_router)
    app.add_event_handler("startup", start_billing_reconcile_task)
    app.add_event_handler("startup", start_projects_reconcile_task)
    app.add_event_handler("startup", start_filemgr_mount_reconcile_task)

    return app

app = create_app()
