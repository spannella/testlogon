from __future__ import annotations

import io
import os
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
from fastapi import HTTPException, UploadFile

from app.services.filemanager_provider import (
    ICloudAuthExpiredError,
    ICloudConflictError,
    ICloudNotFoundError,
    ICloudProvider,
    ICloudThrottledError,
    ICloudTransientError,
    S3FileStorageProvider,
)


class _MockICloudTransport:
    def __init__(self):
        self.objects: Dict[str, Dict[str, Any]] = {
            "/icloud/": {"path": "/icloud/", "type": "folder", "name": "icloud"},
            "/icloud/docs/": {"path": "/icloud/docs/", "type": "folder", "name": "docs"},
            "/icloud/docs/a.txt": {
                "path": "/icloud/docs/a.txt",
                "type": "file",
                "name": "a.txt",
                "size": 5,
                "content_type": "text/plain",
            },
        }

    def list(self, *, user_sub: str, path: str) -> List[Dict[str, Any]]:
        del user_sub
        return [dict(v) for k, v in self.objects.items() if k != path and k.startswith(path)]

    def stat(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        del user_sub
        if path not in self.objects:
            raise ICloudNotFoundError("missing")
        return dict(self.objects[path])

    def read(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        node = self.stat(user_sub=user_sub, path=path)
        return {"node": node, "object": {"Body": io.BytesIO(b"hello")}}

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: str | None, overwrite: bool = False) -> Dict[str, Any]:
        del user_sub
        if (not overwrite) and path in self.objects:
            raise ICloudConflictError("exists")
        self.objects[path] = {
            "path": path,
            "type": "file",
            "name": path.rsplit("/", 1)[-1],
            "size": len(data),
            "content_type": content_type or "application/octet-stream",
        }
        return dict(self.objects[path])

    def delete(self, *, user_sub: str, path: str) -> Dict[str, Any]:
        del user_sub
        if path not in self.objects:
            raise ICloudNotFoundError("missing")
        del self.objects[path]
        return {"ok": True}

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False) -> Dict[str, Any]:
        del user_sub
        if src not in self.objects:
            raise ICloudNotFoundError("missing")
        if (not overwrite) and dst in self.objects:
            raise ICloudConflictError("exists")
        row = dict(self.objects[src])
        row["path"] = dst
        row["name"] = dst.rsplit("/", 1)[-1]
        self.objects[dst] = row
        del self.objects[src]
        return {"src": src, "dst": dst}


@dataclass
class _ProviderCase:
    name: str
    root: str

    def build(self):
        raise NotImplementedError

    def existing_file_path(self) -> str:
        raise NotImplementedError

    def new_file_path(self) -> str:
        raise NotImplementedError

    def moved_file_path(self) -> str:
        raise NotImplementedError

    def list_path(self) -> str:
        return self.root

    def setup_ctx(self):
        raise NotImplementedError

    def assert_not_found_semantics(self, provider: Any) -> None:
        raise NotImplementedError


class _S3Case(_ProviderCase):
    def __init__(self):
        super().__init__(name="s3", root="/docs/")

    def build(self):
        return S3FileStorageProvider()

    def existing_file_path(self) -> str:
        return "/docs/a.txt"

    def new_file_path(self) -> str:
        return "/docs/new.txt"

    def moved_file_path(self) -> str:
        return "/docs/b.txt"

    def setup_ctx(self):
        return (
            patch("app.services.filemanager.norm_path", side_effect=lambda p, is_folder=None: p),
            patch("app.services.filemanager.list_children", return_value=[{"path": "/docs/a.txt", "type": "file", "name": "a.txt"}]),
            patch("app.services.filemanager.get_node", return_value={"path": "/docs/a.txt", "type": "file", "name": "a.txt"}),
            patch("app.services.filemanager.download_file", return_value={"node": {"path": "/docs/a.txt"}, "object": {"Body": io.BytesIO(b"x")}}),
            patch("app.services.filemanager.upload_file", return_value={"path": "/docs/new.txt", "size": 3}),
            patch("app.services.filemanager.remove_file", return_value=None),
            patch("app.services.filemanager.create_empty_folder", return_value="/docs/newdir/"),
            patch("app.services.filemanager.move_node", return_value={"src": "/docs/a.txt", "dst": "/docs/b.txt"}),
        )

    def assert_not_found_semantics(self, provider: Any) -> None:
        with patch("app.services.filemanager.download_file", side_effect=HTTPException(status_code=404, detail="not found")):
            with pytest.raises(HTTPException) as ctx:
                provider.read("u1", "/docs/missing.txt")
        assert ctx.value.status_code == 404


class _ICloudCase(_ProviderCase):
    def __init__(self):
        super().__init__(name="icloud", root="/icloud/docs/")

    def build(self):
        provider = ICloudProvider(transport=_MockICloudTransport())
        return provider

    def existing_file_path(self) -> str:
        return "/icloud/docs/a.txt"

    def new_file_path(self) -> str:
        return "/icloud/docs/new.txt"

    def moved_file_path(self) -> str:
        return "/icloud/docs/b.txt"

    def setup_ctx(self):
        return (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
        )

    def assert_not_found_semantics(self, provider: Any) -> None:
        with pytest.raises(HTTPException) as ctx:
            provider.read("u1", "/icloud/docs/missing.txt")
        assert ctx.value.status_code == 404
        assert ctx.value.detail["code"] == "not_found"


def _selected_cases() -> List[_ProviderCase]:
    requested = (os.environ.get("FILEMGR_PROVIDER_CONTRACT_CASE") or "").strip().lower()
    all_cases: Dict[str, _ProviderCase] = {
        "s3": _S3Case(),
        "icloud": _ICloudCase(),
    }
    if not requested:
        return [all_cases["s3"], all_cases["icloud"]]
    if requested not in all_cases:
        raise RuntimeError(f"Unsupported FILEMGR_PROVIDER_CONTRACT_CASE: {requested}")
    return [all_cases[requested]]


@pytest.mark.parametrize("case", _selected_cases(), ids=lambda c: c.name)
def test_provider_contract_operation_parity(case: _ProviderCase):
    provider = case.build()
    upload = UploadFile(filename="new.txt", file=io.BytesIO(b"abc"))
    with ExitStack() as stack:
        for ctx in case.setup_ctx():
            stack.enter_context(ctx)
        rows = provider.list("u1", case.list_path())
        assert isinstance(rows, list)
        assert provider.stat("u1", case.existing_file_path())["path"] == case.existing_file_path()
        assert "object" in provider.read("u1", case.existing_file_path())
        if case.name == "icloud":
            with pytest.raises(HTTPException) as ro:
                provider.mkdir("u1", "/icloud/docs/newdir/")
            assert ro.value.status_code == 405
        else:
            assert provider.mkdir("u1", "/docs/newdir/") == "/docs/newdir/"
        assert provider.write("u1", case.new_file_path(), upload)["path"] == case.new_file_path()
        delete_resp = provider.delete("u1", case.new_file_path())
        if case.name == "icloud":
            assert delete_resp["ok"] is True
        assert provider.move("u1", case.existing_file_path(), case.moved_file_path())["dst"] == case.moved_file_path()


@pytest.mark.parametrize("case", _selected_cases(), ids=lambda c: c.name)
def test_provider_contract_not_found_semantics(case: _ProviderCase):
    provider = case.build()
    with ExitStack() as stack:
        for ctx in case.setup_ctx():
            stack.enter_context(ctx)
        case.assert_not_found_semantics(provider)


@pytest.mark.parametrize(
    "error,expected_status,expected_code",
    [
        (ICloudAuthExpiredError("expired"), 401, "auth_expired"),
        (ICloudThrottledError("rate"), 429, "throttled"),
        (ICloudTransientError("transient"), 503, "transient"),
        (ICloudConflictError("exists"), 409, "conflict"),
        (ICloudNotFoundError("missing"), 404, "not_found"),
    ],
)
def test_icloud_provider_contract_error_semantics(error: Exception, expected_status: int, expected_code: str):
    transport = _MockICloudTransport()

    def _raise(**_: Any):
        raise error

    transport.read = _raise  # type: ignore[assignment]
    provider = ICloudProvider(transport=transport)

    with patch.object(ICloudProvider, "_ensure_enabled", return_value=None):
        with pytest.raises(HTTPException) as ctx:
            provider.read("u1", "/icloud/docs/a.txt")

    assert ctx.value.status_code == expected_status
    assert ctx.value.detail["code"] == expected_code
