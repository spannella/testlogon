from __future__ import annotations

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
from app.routers.misc import router as misc_router
from app.routers.billing_ccbill import router as billing_ccbill_router
from app.routers.paypal import router as paypal_router
from app.routers.billing import router as billing_router
from app.routers.account_state import router as account_state_router
from app.routers.profile import router as profile_router
from app.routers.messaging import router as messaging_router
from app.routers.filemanager import router as filemanager_router
from app.routers.addresses import router as addresses_router
from app.routers.calendar import router as calendar_router
from app.routers.shoppingcart import router as shoppingcart_router

def create_app() -> FastAPI:
    app = FastAPI(title="Security Backend (refactored)", version="0.1.0")
    static_dir = Path(__file__).resolve().parent / "static"

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(static_dir / "index.html")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
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
    app.include_router(misc_router)
    app.include_router(billing_ccbill_router)
    app.include_router(paypal_router)
    app.include_router(billing_router)
    app.include_router(account_state_router)
    app.include_router(profile_router)
    app.include_router(messaging_router)
    app.include_router(filemanager_router)
    app.include_router(addresses_router)
    app.include_router(calendar_router)
    app.include_router(shoppingcart_router)

    return app

app = create_app()
