from __future__ import annotations

import logging
import os
from pathlib import Path

from app.auth.root_invariant import validate_startup_root_invariant
from fastapi import FastAPI, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.settings import Settings
from app.metrics import METRICS_ENABLED, metrics_endpoint, metrics_middleware, set_app_info
from app.metrics import record_api_key_registry_drift
from app.routers.ui_session import router as ui_session_router
from app.routers.content_boost import content_boost_router
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
from app.routers.google_calendar_mock import router as google_calendar_mock_router
from app.routers.google_drive_mock import router as google_drive_mock_router
from app.routers.google_drive_integration import router as google_drive_integration_router
from app.routers.apple_caldav_mock import router as apple_caldav_mock_router
from app.routers.jira_mock import router as jira_mock_router
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
from app.routers.shoppingcart import router as shoppingcart_router, start_cart_abandonment_task
from app.routers.catalog import router as catalog_router
from app.routers.subscription_server import router as subscription_server_router
from app.routers.admin_usage import router as admin_usage_router
from app.routers.admin_entitlements import router as admin_entitlements_router
from app.routers.admin_subscription_tiers import admin_subscription_tiers_router
from app.routers.admin_tenant_watermark_assets import router as admin_tenant_watermark_assets_router
from app.routers.ups import router as ups_router
from app.routers.carrier_tracking_mock import router as carrier_tracking_mock_router
from app.routers.projects import router as projects_router
from app.routers.contacts import router as contacts_router
from app.routers.social import router as social_router
from app.routers.activity_feed import router as activity_feed_router
from app.routers.discovery import router as discovery_router
from app.routers.search import router as search_router
from app.routers.broadcast import router as broadcast_router
from app.routers.broadcast_promo import broadcast_promo_router
from app.routers.delegates import router as delegates_router
from app.routers.delegate_broadcast import router as delegate_broadcast_router
from app.routers.broadcast_clips import router as broadcast_clips_router
from app.routers.broadcast_devtools import router as broadcast_devtools_router
from app.routers.live_qa import live_qa_router
from app.routers.entitlements import router as entitlements_router
from app.routers.commercial_checkout import router as commercial_checkout_router
from app.routers.tickets import router as tickets_router
from app.routers.ticket_spaces import router as ticket_spaces_router
from app.routers.internal_devtools import router as internal_devtools_router
from app.routers.browser_ssh_terminal import (
    browser_ssh_terminal_enabled,
    router as browser_ssh_terminal_router,
)
from app.routers.ssh_key_manager import router as ssh_key_manager_router
from app.routers.questionnaires import router as questionnaires_router
from app.routers.vnc_sessions import router as vnc_sessions_router
from app.routers.kyc_cases import router as kyc_cases_router
from app.routers.risk_scoring import user_router as risk_scoring_user_router, admin_router as risk_scoring_admin_router
from app.routers.kyc_tiers import router as kyc_tiers_router
from app.routers.kyc_documents import kyc_documents_router
from app.routers.kyc_residency import kyc_residency_router
from app.routers.kyc_proof_of_funds import kyc_proof_of_funds_router
from app.routers.playback_entitlements import router as playback_entitlements_router
from app.routers.moderation import router as moderation_router, compat_router as moderation_compat_router
from app.routers.admin_moderation import router as admin_moderation_router
from app.routers.admin_video_review import router as admin_video_review_router
from app.routers.moderation_video_queue import moderation_video_queue_router
from app.routers.dmca import router as dmca_router
from app.routers.admin_dmca import router as admin_dmca_router
from app.routers.appeals import router as appeals_router
from app.routers.admin_appeals import router as admin_appeals_router
from app.routers.vod import router as vod_router
from app.routers.vod_rental import vod_rental_router
from app.routers.vod_ad_supported import vod_ad_supported_router
from app.routers.vod_drm import router as vod_drm_router
from app.routers.video_listing import router as video_listing_router
from app.routers.video_subtitles import router as video_subtitles_router
from app.routers.transcode_jobs import router as transcode_jobs_router, video_router as transcode_video_router
from app.routers.call_recording import router as call_recording_router
from app.routers.call_billing import router as call_billing_router
from app.routers.call_history import router as call_history_router
from app.routers.group_calls import router as group_calls_router
from app.routers.vod_bridge import router as vod_bridge_router
from app.routers.creator_earnings import router as creator_earnings_router
from app.routers.tip_leaderboard import router as tip_leaderboard_router
from app.routers.tip_leaderboard import internal_router as tip_leaderboard_internal_router
from app.routers.creator_analytics import router as creator_analytics_router
from app.routers.per_content_revenue import per_content_revenue_router
from app.routers.creator_dashboard import router as creator_dashboard_router
from app.routers.creator_payouts import router as creator_payouts_router
from app.routers.admin_payouts import router as admin_payouts_router
from app.routers.admin_rate_limits import router as admin_rate_limits_router
from app.routers.privacy import router as privacy_router, admin_router as admin_privacy_router
from app.routers.account_deletion import (
    account_deletion_router,
    account_deletion_admin_router,
)
from app.services.deletion_scheduler import start_deletion_scheduler_task
from app.routers.referrals import router as referrals_router, internal_router as referrals_internal_router
from app.routers.promo_codes import router as promo_codes_router
from app.routers.affiliate_links import router as affiliate_links_router
from app.routers.collaborations import router as collaborations_router
from app.routers.orgs import router as orgs_router
from app.routers.user_groups import router as user_groups_router
from app.routers.group_feed import router as group_feed_router, public_group_feed_router
from app.routers.fan_club import router as fan_club_router, public_router as fan_club_public_router
from app.routers.stories import router as stories_router
from app.routers.watermark import router as watermark_router, internal_router as watermark_internal_router
from app.routers.watch_party import router as watch_party_router
from app.routers.media_preferences import router as media_preferences_router
from app.middleware.rate_limit import rate_limit_middleware_factory
from app.services.billing_reconcile import start_billing_reconcile_task
from app.services.billing_dunning import start_billing_dunning_task
from app.services.filemanager import start_filemgr_purge_task
from app.services.api_usage_metering import record_api_usage_from_response, enforce_account_quota_pre_request
from app.services.api_metering_policy import build_limit_denial_headers
from app.routers.messaging import start_scheduled_messages_task
from app.services.broadcast_scheduler import start_broadcast_scheduler_task, start_broadcast_reminder_task
from app.services.projects_reconcile import start_projects_reconcile_task
from app.services.provider_oauth import validate_google_drive_mount_oauth_configuration
from app.services.filemanager_mount_reconcile import start_filemgr_mount_reconcile_task
from app.services.api_usage_entitlements import enforce_api_package_entitlement_pre_request
from app.services.calendar_integrations.registry import initialize_calendar_integration_registry
from app.services.jira_feature_flags import validate_jira_integration_startup_config
from app.routers.admin_jira_integration import router as admin_jira_integration_router
from app.routers.jira_integrations import router as jira_integrations_router
from app.services.api_key_route_scope_registry import (
    classify_registry_drift,
    API_KEY_ROUTE_SCOPE_REGISTRY,
    is_route_registered_or_exempt,
    summarize_registry_drift,
)
from app.services.api_key_rollout import validate_api_key_rollout_settings
from app.services.playback_entitlements import validate_playback_entitlement, PlaybackEntitlementError
from app.services.broadcast_reconciler import start_broadcast_reconciler_task
from app.services.transcode_worker import start_transcode_worker_task
from app.routers.webhooks import router as webhooks_router
from app.services.webhook_dispatcher import start_webhook_dispatcher_task
from app.routers.geo_rules import router as geo_rules_router
from app.routers.scheduler import router as scheduler_router
from app.routers.i18n import router as i18n_router
from app.services.unified_scheduler import start_unified_scheduler_task
from app.routers.csv_export import router as csv_export_router
from app.routers.audit_export import router as audit_export_router
from app.routers.refund_requests import router as refund_requests_router
from app.routers.billing_disputes import billing_disputes_router
from app.routers.achievements import router as achievements_router
from app.routers.admin_jobs import router as admin_jobs_router
from app.routers.job_dashboard import job_dashboard_router
from app.routers.admin_sms import router as admin_sms_router
from app.routers.admin_email import router as admin_email_router
from app.routers.admin_notifications import router as admin_notifications_router
from app.routers.ses_notifications import router as ses_notifications_router
from app.routers.recommendations import (
    gallery_for_you_router as reco_gallery_router,
    similar_router as reco_similar_router,
    creator_suggestions_router as reco_creator_router,
    engagement_router as reco_engagement_router,
    internal_router as reco_internal_router,
)
from app.routers.content_calendar import router as content_calendar_router
from app.routers.tenant_admin import router as tenant_admin_router, public_router as tenant_public_router
from app.routers.sso_saml import router as sso_saml_router
from app.routers.license_revenue import router as license_revenue_router, admin_router as license_revenue_admin_router
from app.routers.llm_provider_keys import router as llm_provider_keys_router
from app.routers.ads import router as ads_router, admin_router as ads_admin_router
from app.routers.delegates import router as delegates_router
from app.routers.syndicates import router as syndicates_router
from app.routers.syndicate_revenue_split import syndicate_revenue_split_router
from app.routers.chat_bot import router as chat_bot_router
from app.routers.user_groups import router as user_groups_router
from app.routers.ads import router as ads_router, admin_router as ads_admin_router
from app.routers.issued_licenses import router as issued_licenses_router
from app.routers.chat_bot import router as chat_bot_router
from app.routers.bot_template import router as bot_template_router
from app.services.bot_scheduler import start_bot_scheduler_task
from app.routers.ads_targeting import router as ads_targeting_router
from app.routers.syndicates import router as syndicates_router
from app.routers.ads import router as ads_router, admin_router as ads_admin_router
from app.routers.ec2_launcher import router as ec2_launcher_router
from app.routers.instance_monitoring import instance_monitoring_router
from app.routers.security_groups import security_groups_router
from app.services.ec2_launcher import start_ec2_idle_checker_task
from app.routers.admin_compute import router as admin_compute_router
from app.routers.bulk_payout_tools import bulk_payout_tools_router
from app.routers.platform_financial_dashboard import platform_financial_dashboard_router
from app.routers.chat_bot import router as chat_bot_router
from app.routers.bot_template import router as bot_template_router
from app.routers.bot_auto_reply import router as bot_auto_reply_router
from app.services.bot_scheduler import start_bot_scheduler_task
from app.routers.delegate_feed import router as delegate_feed_router
from app.routers.delegation_api import delegation_api_router
from app.routers.notification_engine import router as notification_engine_router
from app.routers.issued_licenses import router as issued_licenses_router
from app.routers.license_requests import router as license_requests_router
from app.routers.license_agreements import (
    license_agreements_router,
    license_agreements_admin_router,
)
from app.routers.license_compliance import (
    license_compliance_router,
    license_compliance_admin_router,
)
from app.routers.k8s_launcher import router as k8s_launcher_router
from app.services.k8s_launcher import start_k8s_ttl_checker_task
from app.routers.ssh_session_recording import ssh_session_recording_router
from app.services.ssh_session_recording import start_recording_cleanup_task
from app.routers.ssh_bastion import ssh_bastion_router
from app.routers.connection_profiles import connection_profiles_router
from app.routers.theme_customization import theme_customization_router
from app.routers.ads import router as ads_router, admin_router as ads_admin_router
from app.routers.ads_targeting import router as ads_targeting_router
from app.routers.ad_fraud import ad_fraud_router
from app.routers.agent_workers import router as agent_workers_router
from app.routers.ads import router as ads_router
from app.routers.agent_orchestrator import router as agent_orchestrator_router
from app.routers.ads import router as ads_router
from app.routers.agent_workers import router as agent_workers_router
from app.routers.agent_fleet import router as agent_fleet_router
from app.routers.agent_memory import router as agent_memory_router

logger = logging.getLogger(__name__)


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

def _playback_entitlement_middleware():
    async def _middleware(request: Request, call_next):
        path = request.url.path or ""
        if path.startswith("/v1/playback/protected"):
            auth = request.headers.get("authorization", "")
            if not auth.lower().startswith("bearer "):
                return JSONResponse(status_code=401, content={"detail": {"code": "missing_bearer", "message": "missing bearer token"}})
            token = auth.split(" ", 1)[1].strip()
            try:
                claims = validate_playback_entitlement(
                    token=token,
                    expected_audience=(getattr(Settings(), "playback_entitlement_expected_audience", "playback") or "playback"),
                )
                request.state.playback_claims = claims
            except PlaybackEntitlementError as exc:
                return JSONResponse(status_code=401, content={"detail": {"code": exc.code, "message": exc.message}})
        return await call_next(request)
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
    validate_api_key_rollout_settings()
    static_dir = Path(__file__).resolve().parent / "static"

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(static_dir / "index.html")

    @app.get("/internal/ffmpeg-status")
    def ffmpeg_status():
        from app.services.ffmpeg_manager import validate_ffmpeg
        return validate_ffmpeg()

    @app.get("/browser-ssh")
    async def browser_ssh_route():
        if not browser_ssh_terminal_enabled():
            raise HTTPException(status_code=404, detail="Not found")
        raise HTTPException(status_code=410, detail="Browser SSH terminal UI has moved to the frontend.")

    @app.get("/broadcast-devtools")
    async def broadcast_devtools_page():
        if not (_S.dev_mode and _S.broadcast_devtools_enabled):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(static_dir / "broadcast-devtools.html")

    app.add_middleware(CORSMiddleware, **_build_cors_options())
    if _S.multi_tenancy_enabled:
        from app.middleware.tenant import TenantMiddleware
        app.add_middleware(TenantMiddleware)
    app.middleware("http")(rate_limit_middleware_factory())
    app.middleware("http")(_api_usage_metering_middleware())
    app.middleware("http")(_playback_entitlement_middleware())
    if METRICS_ENABLED:
        app.middleware("http")(metrics_middleware)
        set_app_info(app.title, app.version)
        app.get("/metrics")(metrics_endpoint)

    app.include_router(ui_session_router)
    app.include_router(content_boost_router)
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
    app.include_router(google_calendar_mock_router)
    app.include_router(google_drive_mock_router)
    app.include_router(google_drive_integration_router)
    app.include_router(apple_caldav_mock_router)
    app.include_router(jira_mock_router)
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
    app.include_router(admin_video_review_router)
    app.include_router(moderation_video_queue_router)
    app.include_router(dmca_router)
    app.include_router(admin_dmca_router)
    app.include_router(appeals_router)
    app.include_router(admin_appeals_router)
    def _validate_ffmpeg_on_startup():
        from app.services.ffmpeg_manager import validate_ffmpeg
        result = validate_ffmpeg()
        if result["status"] == "unavailable":
            logger.warning("FFmpeg is not available — video features will be disabled")
        elif result["status"] == "degraded":
            logger.warning("FFmpeg validation issues: %s", result["issues"])
        else:
            logger.info("FFmpeg ready: %s at %s", result["version"], result["path"])

    app.add_event_handler("startup", _validate_ffmpeg_on_startup)

    def _seed_notification_templates_on_startup():
        try:
            from app.services.notification_templates import seed_default_templates
            seed_default_templates()
        except Exception:
            logger.warning("Failed to seed notification templates", exc_info=True)
    app.add_event_handler("startup", validate_startup_root_invariant)
    app.add_event_handler("startup", validate_google_drive_mount_oauth_configuration)
    app.add_event_handler("startup", lambda: setattr(app.state, "calendar_integration_registry", initialize_calendar_integration_registry()))
    app.add_event_handler("startup", validate_jira_integration_startup_config)
    if _S.dev_mode:
        _dev_buckets = [b for b in [
            _S.filemgr_bucket,
            os.environ.get("UPLOAD_BUCKET", ""),
            os.environ.get("S3_BUCKET_IMAGES", ""),
            _S.video_upload_bucket,
            _S.vod_output_bucket or "vod-output",
            _S.filemgr_bucket or "filemgr",  # FIN-001 invoice PDFs
        ] if b]
        app.add_event_handler("startup", lambda: _start_s3_mock(_dev_buckets))


    app.add_event_handler("startup", newsfeed_startup)
    app.add_event_handler("startup", start_billing_dunning_task)
    app.add_event_handler("startup", start_filemgr_purge_task)
    app.add_event_handler("startup", start_scheduled_messages_task)
    app.add_event_handler("startup", start_broadcast_scheduler_task)
    app.add_event_handler("startup", start_broadcast_reminder_task)
    app.add_event_handler("startup", _seed_notification_templates_on_startup)
    app.add_event_handler("startup", start_deletion_scheduler_task)
    app.include_router(purchase_history_router)
    app.include_router(shoppingcart_router)
    app.include_router(catalog_router)
    app.include_router(commercial_checkout_router)
    app.include_router(entitlements_router)
    app.include_router(subscription_server_router)
    app.include_router(admin_usage_router)
    app.include_router(admin_entitlements_router)
    app.include_router(admin_subscription_tiers_router)
    app.include_router(admin_tenant_watermark_assets_router)
    app.include_router(ups_router)
    app.include_router(carrier_tracking_mock_router)
    app.include_router(projects_router)
    app.include_router(contacts_router)
    app.include_router(social_router)
    app.include_router(activity_feed_router)
    app.include_router(discovery_router)
    app.include_router(search_router)
    app.include_router(broadcast_router)
    app.include_router(broadcast_promo_router)
    app.include_router(broadcast_clips_router)
    app.include_router(live_qa_router)
    app.include_router(broadcast_devtools_router)
    app.include_router(tickets_router)
    app.include_router(ticket_spaces_router)
    app.include_router(internal_devtools_router)
    app.include_router(admin_jira_integration_router)
    app.include_router(jira_integrations_router)
    app.include_router(browser_ssh_terminal_router)
    app.include_router(ssh_key_manager_router)
    app.include_router(questionnaires_router)
    app.include_router(kyc_cases_router)
    app.include_router(risk_scoring_user_router)
    app.include_router(risk_scoring_admin_router)
    app.include_router(kyc_tiers_router)
    app.include_router(kyc_documents_router)
    app.include_router(kyc_residency_router)
    app.include_router(kyc_proof_of_funds_router)
    app.include_router(vnc_sessions_router)
    app.include_router(playback_entitlements_router)
    # Recommendation routes MUST be registered before video_listing_router
    # so /gallery/for-you and /{video_id}/similar match before /{video_id}
    app.include_router(reco_gallery_router)
    app.include_router(reco_similar_router)
    app.include_router(reco_creator_router)
    app.include_router(reco_engagement_router)
    app.include_router(reco_internal_router)
    # Watermark router registered before video_listing_router so
    # /my-downloads matches before /{video_id} (VOD-020)
    app.include_router(watermark_router)
    app.include_router(video_listing_router)
    app.include_router(video_subtitles_router)
    app.include_router(vod_router)
    app.include_router(vod_rental_router)
    app.include_router(vod_ad_supported_router)
    app.include_router(vod_drm_router)
    app.include_router(transcode_jobs_router)
    app.include_router(transcode_video_router)
    app.include_router(call_recording_router)
    app.include_router(call_billing_router)
    app.include_router(call_history_router)
    app.include_router(group_calls_router)
    app.include_router(vod_bridge_router)
    app.include_router(creator_earnings_router)
    app.include_router(tip_leaderboard_router)
    app.include_router(tip_leaderboard_internal_router)
    app.include_router(creator_analytics_router)
    app.include_router(per_content_revenue_router)
    app.include_router(creator_dashboard_router)
    app.include_router(creator_payouts_router)
    app.include_router(admin_payouts_router)
    app.include_router(admin_rate_limits_router)
    app.include_router(admin_jobs_router)
    app.include_router(job_dashboard_router)
    app.include_router(admin_sms_router)
    app.include_router(admin_email_router)
    app.include_router(admin_notifications_router)
    app.include_router(ses_notifications_router)
    app.include_router(privacy_router)
    app.include_router(admin_privacy_router)
    app.include_router(account_deletion_router)
    app.include_router(account_deletion_admin_router)
    app.include_router(stories_router)
    app.include_router(referrals_router)
    app.include_router(referrals_internal_router)
    app.include_router(webhooks_router)
    app.include_router(csv_export_router)
    app.include_router(audit_export_router)
    app.include_router(refund_requests_router)
    app.include_router(billing_disputes_router)
    app.include_router(achievements_router)
    app.include_router(promo_codes_router)
    app.include_router(affiliate_links_router)
    app.include_router(collaborations_router)
    app.include_router(orgs_router)
    app.include_router(user_groups_router)
    app.include_router(group_feed_router)
    app.include_router(public_group_feed_router)
    app.include_router(fan_club_router)
    app.include_router(fan_club_public_router)
    app.include_router(geo_rules_router)
    app.include_router(scheduler_router)
    app.include_router(i18n_router)
    app.include_router(watermark_internal_router)
    app.include_router(watch_party_router)
    app.include_router(media_preferences_router)
    app.include_router(delegates_router)
    app.include_router(delegate_broadcast_router)
    app.include_router(content_calendar_router)
    app.include_router(tenant_admin_router)
    app.include_router(tenant_public_router)
    app.include_router(sso_saml_router)
    app.include_router(license_revenue_router)
    app.include_router(license_revenue_admin_router)
    app.include_router(llm_provider_keys_router)
    app.include_router(ads_router)
    app.include_router(ads_admin_router)
    app.include_router(delegates_router)
    app.include_router(syndicates_router)
    app.include_router(syndicate_revenue_split_router)
    app.include_router(chat_bot_router, prefix="/ui")
    app.include_router(user_groups_router)
    app.include_router(ads_router)
    app.include_router(ads_admin_router)
    app.include_router(issued_licenses_router)
    app.include_router(chat_bot_router, prefix="/ui")
    app.include_router(bot_template_router, prefix="/ui")
    app.add_event_handler("startup", start_bot_scheduler_task)
    app.include_router(ads_targeting_router)
    app.include_router(syndicates_router)
    app.include_router(ads_router)
    app.include_router(ads_admin_router)
    app.include_router(ec2_launcher_router)
    app.include_router(instance_monitoring_router)
    app.include_router(security_groups_router)
    app.add_event_handler("startup", start_ec2_idle_checker_task)
    app.include_router(chat_bot_router, prefix="/ui")
    app.include_router(bot_template_router, prefix="/ui")
    app.include_router(bot_auto_reply_router, prefix="/ui")
    app.add_event_handler("startup", start_bot_scheduler_task)
    app.include_router(delegate_feed_router)
    app.include_router(delegation_api_router)
    app.include_router(notification_engine_router)
    app.include_router(issued_licenses_router)
    app.include_router(license_requests_router)
    app.include_router(license_agreements_router)
    app.include_router(license_agreements_admin_router)
    app.include_router(license_compliance_router)
    app.include_router(license_compliance_admin_router)
    app.include_router(k8s_launcher_router)
    app.add_event_handler("startup", start_k8s_ttl_checker_task)
    app.include_router(ssh_session_recording_router)
    app.include_router(ssh_bastion_router)
    app.include_router(connection_profiles_router)
    app.include_router(theme_customization_router)
    app.add_event_handler("startup", start_recording_cleanup_task)
    app.include_router(ads_router)
    app.include_router(ads_admin_router)
    app.include_router(ads_targeting_router)
    app.include_router(ad_fraud_router)
    from app.routers.ad_dayparting import ad_dayparting_router
    app.include_router(ad_dayparting_router)
    app.include_router(agent_workers_router)
    app.include_router(ads_router)

    from app.routers.group_treasury import router as group_treasury_router
    app.include_router(group_treasury_router)

    from app.routers.group_fundraising import (
        group_fundraising_router,
        public_group_fundraising_router,
    )
    app.include_router(group_fundraising_router)
    app.include_router(public_group_fundraising_router)

    app.include_router(agent_orchestrator_router)
    app.include_router(ads_router)

    from app.routers.compute_billing import router as compute_billing_router
    app.include_router(compute_billing_router)
    app.include_router(admin_compute_router)
    app.include_router(bulk_payout_tools_router)
    from app.routers.admin_ad_platform import admin_ad_platform_router
    app.include_router(admin_ad_platform_router)
    app.include_router(platform_financial_dashboard_router)
    from app.routers.payment_provider_health import payment_provider_health_router
    app.include_router(payment_provider_health_router)

    app.include_router(agent_workers_router)
    app.include_router(agent_fleet_router)
    app.include_router(agent_memory_router)

    from app.routers.agent_feedback import router as agent_feedback_router
    app.include_router(agent_feedback_router)

    from app.routers.agent_pr_integration import (
        router as agent_pr_router,
        webhook_router as agent_pr_webhook_router,
        admin_router as agent_pr_admin_router,
    )
    app.include_router(agent_pr_router)
    app.include_router(agent_pr_webhook_router)
    app.include_router(agent_pr_admin_router)
    from app.routers.agent_coder import router as agent_coder_router
    app.include_router(agent_coder_router)
    from app.routers.agent_qa import router as agent_qa_router
    app.include_router(agent_qa_router)
    from app.routers.agent_devops import router as agent_devops_router
    app.include_router(agent_devops_router)
    from app.routers.agent_architect import router as agent_architect_router
    app.include_router(agent_architect_router)
    from app.routers.agent_docs import router as agent_docs_router
    app.include_router(agent_docs_router)
    from app.routers.agent_pm import router as agent_pm_router
    app.include_router(agent_pm_router)
    from app.routers.agent_project import router as agent_project_router
    app.include_router(agent_project_router)
    from app.routers.agent_stylist import agent_stylist_router
    app.include_router(agent_stylist_router)
    from app.routers.agent_marketing import agent_marketing_router
    app.include_router(agent_marketing_router)
    from app.routers.agent_compliance import agent_compliance_router
    app.include_router(agent_compliance_router)
    from app.routers.agent_accountant import agent_accountant_router
    app.include_router(agent_accountant_router)
    from app.routers.invoices import invoices_router, invoices_admin_router
    app.include_router(invoices_router)
    app.include_router(invoices_admin_router)
    from app.routers.consumer_tax_documents import (
        consumer_tax_documents_router,
        consumer_tax_documents_admin_router,
    )
    app.include_router(consumer_tax_documents_router)
    app.include_router(consumer_tax_documents_admin_router)

    app.add_event_handler("startup", start_unified_scheduler_task)
    app.add_event_handler("startup", start_billing_reconcile_task)
    app.add_event_handler("startup", start_projects_reconcile_task)
    app.add_event_handler("startup", start_filemgr_mount_reconcile_task)
    app.add_event_handler("startup", start_broadcast_reconciler_task)
    app.add_event_handler("startup", start_transcode_worker_task)
    app.add_event_handler("startup", start_webhook_dispatcher_task)
    app.add_event_handler("startup", start_cart_abandonment_task)

    uncovered_policy_routes: set[str] = set()
    for route in app.routes:
        path = str(getattr(route, "path", "") or "").strip()
        methods = set(getattr(route, "methods", set()) or set())
        dependant = getattr(route, "dependant", None)
        dependencies = list(getattr(dependant, "dependencies", []) or [])
        has_api_key_policy_dependency = any(
            str(getattr(getattr(dep, "call", None), "__name__", "")) == "maybe_enforce_api_key_route_policy"
            for dep in dependencies
        )
        if not path or not methods or not has_api_key_policy_dependency:
            continue
        for method in methods:
            m = str(method or "").upper().strip()
            if not m or m in {"HEAD", "OPTIONS"}:
                continue
            route_id = f"{m}:{path}"
            if not is_route_registered_or_exempt(route_id):
                uncovered_policy_routes.add(route_id)

    if uncovered_policy_routes:
        preview = ", ".join(sorted(uncovered_policy_routes)[:10])
        msg = (
            f"API key policy is mounted on routes missing registry/exemption entries: {preview}"
            + (" ..." if len(uncovered_policy_routes) > 10 else "")
        )
        if _S.dev_mode:
            logger.warning(msg)
        else:
            raise RuntimeError(msg)

    all_live_route_ids: set[str] = set()
    for route in app.routes:
        path = str(getattr(route, "path", "") or "").strip()
        methods = set(getattr(route, "methods", set()) or set())
        if not path or not methods:
            continue
        for method in methods:
            m = str(method or "").upper().strip()
            if not m or m in {"HEAD", "OPTIONS"}:
                continue
            all_live_route_ids.add(f"{m}:{path}")
    app.state.api_key_registry_drift = summarize_registry_drift(all_live_route_ids)
    drift_count = int((app.state.api_key_registry_drift or {}).get("stale_route_count") or 0)
    unregistered_live_count = int((app.state.api_key_registry_drift or {}).get("unregistered_live_route_count") or 0)
    drift_warn_threshold = int(getattr(_S, "api_key_registry_drift_warn_threshold", 0) or 0)
    drift_warn_exceeded = drift_count > drift_warn_threshold
    drift_status = classify_registry_drift(
        stale_route_count=drift_count,
        unregistered_live_route_count=unregistered_live_count,
        warn_threshold=drift_warn_threshold,
    )
    app.state.api_key_registry_drift["warn_threshold"] = drift_warn_threshold
    app.state.api_key_registry_drift["warn_threshold_exceeded"] = drift_warn_exceeded
    app.state.api_key_registry_drift["status"] = drift_status
    record_api_key_registry_drift(
        stale_route_count=drift_count,
        unregistered_live_route_count=unregistered_live_count,
    )
    if drift_warn_exceeded:
        logger.warning(
            "API-key route-scope registry drift exceeded threshold: stale_route_count=%s threshold=%s",
            drift_count,
            drift_warn_threshold,
        )
    if unregistered_live_count > 0:
        logger.warning(
            "API-key rollout surfaces include live routes missing registry/exemption coverage: count=%s preview=%s",
            unregistered_live_count,
            list((app.state.api_key_registry_drift or {}).get("unregistered_live_route_preview") or [])[:10],
        )

    def _custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            routes=app.routes,
        )

        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.setdefault(
            "ApiKeyAuth",
            {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "Use `X-API-Key: ak_<key_id>.<secret>` or `Authorization: ApiKey ak_<key_id>.<secret>`.",
            },
        )

        external_tags = {
            "filemanager": "File management APIs",
            "newsfeed": "Newsfeed APIs",
            "tickets": "Ticketing APIs",
            "messaging": "Messaging APIs",
            "shoppingcart": "Shopping cart APIs",
            "catalog": "Catalog APIs",
            "purchase-history": "Order and purchase APIs",
        }
        tag_rows = schema.setdefault("tags", [])
        by_name = {str(tag.get("name") or ""): tag for tag in tag_rows if isinstance(tag, dict)}
        for tag_name, desc in external_tags.items():
            row = by_name.get(tag_name)
            if row is None:
                tag_rows.append({"name": tag_name, "description": desc})
            else:
                row.setdefault("description", desc)

        schema["x-tagGroups"] = [
            {
                "name": "External Product APIs",
                "tags": list(external_tags.keys()),
            }
        ]

        idempotent_routes = {
            "POST:/ui/shoppingcart/carts/{cart_id}/purchase",
            "POST:/ui/purchase-history/transactions",
        }

        paths = schema.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if not isinstance(operation, dict):
                    continue
                route_id = f"{str(method).upper()}:{path}"
                policy = API_KEY_ROUTE_SCOPE_REGISTRY.get(route_id)
                if not policy:
                    continue

                required_scopes = list(policy.get("required_scopes") or [])
                entitlement_required = bool(policy.get("entitlement_required"))
                operation["x-api-key-scopes"] = required_scopes
                operation["x-api-key-entitlement-required"] = entitlement_required

                security = operation.setdefault("security", [])
                if {"ApiKeyAuth": []} not in security:
                    security.append({"ApiKeyAuth": []})

                params = operation.setdefault("parameters", [])
                names_in = {(str(p.get("name") or ""), str(p.get("in") or "")) for p in params if isinstance(p, dict)}
                if ("X-API-Key", "header") not in names_in:
                    params.append(
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"},
                            "example": "ak_k1234.very-secret-value",
                            "description": "API key auth header. Alternative: `Authorization: ApiKey <token>`.",
                        }
                    )
                if route_id in idempotent_routes and ("X-Idempotency-Key", "header") not in names_in:
                    params.append(
                        {
                            "name": "X-Idempotency-Key",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "minLength": 1},
                            "example": "checkout-2026-04-04-001",
                            "description": "Required idempotency key for safe retries.",
                        }
                    )

                responses = operation.setdefault("responses", {})
                bad_request = responses.setdefault("400", {"description": "Bad request"})
                if isinstance(bad_request, dict):
                    bad_content = bad_request.setdefault("content", {})
                    bad_json = bad_content.setdefault("application/json", {})
                    bad_json.setdefault(
                        "examples",
                        {
                            "dual_credential_conflict": {
                                "summary": "Bearer and API key provided together (reject mode)",
                                "value": {
                                    "detail": {
                                        "code": "api_key_dual_credential_conflict",
                                        "reason": "dual_credential_conflict",
                                        "message": "Both API key and Bearer credentials were provided",
                                    }
                                },
                            }
                        },
                    )

                unauthorized = responses.setdefault("401", {"description": "Unauthorized"})
                if isinstance(unauthorized, dict):
                    unauth_content = unauthorized.setdefault("content", {})
                    unauth_json = unauth_content.setdefault("application/json", {})
                    unauth_json.setdefault(
                        "examples",
                        {
                            "invalid_api_key": {
                                "summary": "API key is invalid/revoked/expired",
                                "value": {
                                    "detail": {
                                        "code": "api_key_invalid",
                                        "reason": "invalid_key",
                                    }
                                },
                            }
                        },
                    )

                forbidden = responses.setdefault("403", {"description": "Forbidden"})
                if isinstance(forbidden, dict):
                    content = forbidden.setdefault("content", {})
                    app_json = content.setdefault("application/json", {})
                    app_json.setdefault(
                        "examples",
                        {
                            "missing_scope": {
                                "summary": "API key missing required scope",
                                "value": {
                                    "detail": {
                                        "code": "api_key_scope_denied",
                                        "reason": "missing_scope",
                                        "required_scopes": required_scopes,
                                    }
                                },
                            },
                            "entitlement_denied": {
                                "summary": "API entitlement denied",
                                "value": {
                                    "detail": {
                                        "code": "api_entitlement_denied",
                                        "reason": "api_entitlement_denied",
                                    }
                                },
                            },
                        },
                    )

                too_many = responses.setdefault("429", {"description": "Too many requests"})
                if isinstance(too_many, dict):
                    tm_content = too_many.setdefault("content", {})
                    tm_json = tm_content.setdefault("application/json", {})
                    tm_json.setdefault(
                        "examples",
                        {
                            "api_rate_limited": {
                                "summary": "API rate limit exceeded",
                                "value": {
                                    "detail": {
                                        "code": "api_limit_exceeded",
                                        "reason": "limit_exceeded",
                                    }
                                },
                            }
                        },
                    )

                scope_note = f"Required API key scope(s): `{', '.join(required_scopes)}`."
                entitlement_note = " API entitlement check is required." if entitlement_required else " API entitlement check is not required."
                dual_cred_note = (
                    " If both Bearer and API key credentials are sent, behavior follows `API_KEY_DUAL_CREDENTIAL_MODE`"
                    " (prefer_api_key / prefer_session / reject)."
                )
                operation["description"] = f"{(operation.get('description') or '').strip()}\n\n{scope_note}{entitlement_note}{dual_cred_note}".strip()

        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = _custom_openapi

    return app

app = create_app()
