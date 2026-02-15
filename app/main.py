from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.metrics import METRICS_ENABLED, metrics_endpoint, metrics_middleware, set_app_info
from app.routers.ui_session import router as ui_session_router
from app.routers.ui_mfa import router as ui_mfa_router
from app.routers.mfa_devices import router as mfa_devices_router
from app.routers.api_keys import router as api_keys_router
from app.routers.alerts import router as alerts_router
from app.routers.account import router as account_router
from app.routers.push import router as push_router
from app.routers.recovery import router as recovery_router
from app.routers.password_recovery import router as password_recovery_router
from app.routers.passwordless import router as passwordless_router
from app.routers.register import router as register_router
from app.routers.webauthn import router as webauthn_router
from app.routers.misc import router as misc_router
from app.routers.billing_ccbill import router as billing_ccbill_router
from app.routers.ccbill_mock import router as ccbill_mock_router
from app.routers.paypal import router as paypal_router
from app.routers.billing import router as billing_router
from app.routers.account_state import router as account_state_router
from app.routers.profile import router as profile_router
from app.routers.messaging import router as messaging_router
from app.routers.filemanager import router as filemanager_router
from app.routers.addresses import router as addresses_router
from app.routers.calendar import public_router as calendar_public_router
from app.routers.calendar import router as calendar_router
from app.routers.device_trust import router as device_trust_router
from app.routers.newsfeed import router as newsfeed_router, startup as newsfeed_startup
from app.routers.purchase_history import router as purchase_history_router
from app.routers.shoppingcart import router as shoppingcart_router
from app.routers.catalog import router as catalog_router
from app.routers.subscription_server import router as subscription_server_router
from app.routers.ups import router as ups_router
from app.services.billing_reconcile import start_billing_reconcile_task
from app.services.billing_dunning import start_billing_dunning_task
from app.services.filemanager import start_filemgr_purge_task


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
    app = FastAPI(title="Security Backend (refactored)", version="0.1.0")
    static_dir = Path(__file__).resolve().parent / "static"

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(static_dir / "index.html")

    app.add_middleware(CORSMiddleware, **_build_cors_options())
    if METRICS_ENABLED:
        app.middleware("http")(metrics_middleware)
        set_app_info(app.title, app.version)
        app.get("/metrics")(metrics_endpoint)

    app.include_router(ui_session_router)
    app.include_router(ui_mfa_router)
    app.include_router(mfa_devices_router)
    app.include_router(api_keys_router)
    app.include_router(alerts_router)
    app.include_router(account_router)
    app.include_router(push_router)
    app.include_router(recovery_router)
    app.include_router(password_recovery_router)
    app.include_router(passwordless_router)
    app.include_router(register_router)
    app.include_router(webauthn_router)
    app.include_router(misc_router)
    app.include_router(billing_ccbill_router)
    app.include_router(ccbill_mock_router)
    app.include_router(paypal_router)
    app.include_router(billing_router)
    app.include_router(account_state_router)
    app.include_router(profile_router)
    app.include_router(messaging_router)
    app.include_router(filemanager_router)
    app.include_router(addresses_router)
    app.include_router(calendar_router)
    app.include_router(calendar_public_router)
    app.include_router(device_trust_router)
    app.include_router(newsfeed_router)
    app.add_event_handler("startup", newsfeed_startup)
    app.add_event_handler("startup", start_billing_dunning_task)
    app.add_event_handler("startup", start_filemgr_purge_task)
    app.include_router(purchase_history_router)
    app.include_router(shoppingcart_router)
    app.include_router(catalog_router)
    app.include_router(subscription_server_router)
    app.include_router(ups_router)
    app.add_event_handler("startup", start_billing_reconcile_task)

    return app

app = create_app()
