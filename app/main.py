from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.routers.ui_session import router as ui_session_router
from app.routers.ui_mfa import router as ui_mfa_router
from app.routers.mfa_devices import router as mfa_devices_router
from app.routers.api_keys import router as api_keys_router
from app.routers.alerts import router as alerts_router
from app.routers.push import router as push_router
from app.routers.recovery import router as recovery_router
from app.routers.misc import router as misc_router

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

    app.include_router(ui_session_router)
    app.include_router(ui_mfa_router)
    app.include_router(mfa_devices_router)
    app.include_router(api_keys_router)
    app.include_router(alerts_router)
    app.include_router(push_router)
    app.include_router(recovery_router)
    app.include_router(misc_router)

    return app

app = create_app()
