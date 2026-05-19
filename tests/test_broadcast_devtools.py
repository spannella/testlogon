from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import broadcast_devtools


def _ctx(role: str = "admin") -> dict:
    return {"user_sub": "u1", "session_id": "s1", "role": role}


def test_broadcast_devtools_disabled_returns_404() -> None:
    fake_settings = SimpleNamespace(dev_mode=False, broadcast_devtools_enabled=False)
    with patch.object(broadcast_devtools, "S", fake_settings):
        with pytest.raises(HTTPException) as exc:
            broadcast_devtools.get_broadcast_debug_status(ctx=_ctx())
    assert exc.value.status_code == 404


def test_broadcast_devtools_requires_admin_or_root() -> None:
    fake_settings = SimpleNamespace(dev_mode=True, broadcast_devtools_enabled=True)
    with patch.object(broadcast_devtools, "S", fake_settings):
        with pytest.raises(HTTPException) as exc:
            broadcast_devtools.get_broadcast_debug_status(ctx=_ctx(role="user"))
    assert exc.value.status_code == 403


def test_broadcast_devtools_status_payload(tmp_path: Path) -> None:
    hls_root = tmp_path / "hls"
    archive_root = tmp_path / "archive"
    logs_root = tmp_path / "logs"
    (hls_root / "devstream").mkdir(parents=True)
    (archive_root / "devstream").mkdir(parents=True)
    (archive_root / "devstream" / "master.m3u8").write_text("#EXTM3U\n", encoding="utf-8")
    logs_root.mkdir(parents=True)
    log_file = logs_root / "ffmpeg-worker.log"
    log_file.write_text("line1\nline2\n", encoding="utf-8")

    fake_settings = SimpleNamespace(
        dev_mode=True,
        broadcast_devtools_enabled=True,
        broadcast_local_hls_root=str(hls_root),
        broadcast_local_archive_root=str(archive_root),
        broadcast_local_ffmpeg_log_path=str(log_file),
        broadcast_local_cache_public_base_url="http://localhost:8090",
    )

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    with (
        patch.object(broadcast_devtools, "S", fake_settings),
        patch.object(broadcast_devtools, "urlopen", return_value=_Resp()),
    ):
        out = broadcast_devtools.get_broadcast_debug_status(ctx=_ctx(role="admin"))

    assert out.ingest.healthy is True
    assert out.stream_keys == ["devstream"]
    assert "md5=" in (out.manifest_url or "")
    assert out.archive_objects == ["devstream/master.m3u8"]
    assert out.transcoder_log_tail[-1] == "line2"
