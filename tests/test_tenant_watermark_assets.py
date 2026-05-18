from __future__ import annotations

from io import BytesIO

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.routers.admin_tenant_watermark_assets import router
from app.services import tenant_watermark_assets

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"x" * 64
SVG_BYTES = b"<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'></svg>"


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    tenant_watermark_assets.reset_tenant_watermark_asset_store()


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_authenticated_user] = lambda: AuthenticatedUser(sub="admin-1", role=Role.ADMIN)
    return TestClient(app)


def test_upload_and_assign_and_default_profile(client: TestClient) -> None:
    upload = client.post(
        "/v1/admin/tenants/tenant-a/watermark-assets/upload",
        files={"file": ("wm.png", BytesIO(PNG_BYTES), "image/png")},
        data={"profile_id": "brand-default"},
    )
    assert upload.status_code == 200
    asset = upload.json()["asset"]
    assert asset["tenant_id"] == "tenant-a"
    assert asset["content_type"] == "image/png"
    assert asset["assigned_profile_ids"] == ["brand-default"]

    set_default = client.put(
        "/v1/admin/tenants/tenant-a/watermark-default-profile",
        json={"profile_id": "brand-default"},
    )
    assert set_default.status_code == 200
    assert set_default.json()["default_profile_id"] == "brand-default"

    listed = client.get("/v1/admin/tenants/tenant-a/watermark-assets")
    assert listed.status_code == 200
    payload = listed.json()
    assert payload["default_profile_id"] == "brand-default"
    assert len(payload["assets"]) == 1


def test_assign_existing_asset_to_another_profile(client: TestClient) -> None:
    upload = client.post(
        "/v1/admin/tenants/tenant-a/watermark-assets/upload",
        files={"file": ("wm.svg", BytesIO(SVG_BYTES), "image/svg+xml")},
    )
    asset_id = upload.json()["asset"]["asset_id"]

    assign = client.post(f"/v1/admin/tenants/tenant-a/watermark-assets/{asset_id}/assign/mobile")
    assert assign.status_code == 200
    assert assign.json()["asset"]["assigned_profile_ids"] == ["mobile"]


def test_rejects_invalid_format_with_clear_error(client: TestClient) -> None:
    bad = client.post(
        "/v1/admin/tenants/tenant-a/watermark-assets/upload",
        files={"file": ("wm.jpg", BytesIO(b"not-an-image"), "image/jpeg")},
    )
    assert bad.status_code == 400
    assert "unsupported watermark asset format" in bad.json()["detail"]


def test_rejects_oversized_assets_with_clear_error() -> None:
    oversized = b"\x89PNG\r\n\x1a\n" + b"a" * (tenant_watermark_assets.MAX_WATERMARK_ASSET_BYTES + 1)
    with pytest.raises(HTTPException) as exc:
        tenant_watermark_assets.upload_tenant_watermark_asset(
            tenant_id="tenant-oversize",
            file_name="wm.png",
            content=oversized,
            content_type="image/png",
        )
    assert "exceeds" in str(exc.value)
