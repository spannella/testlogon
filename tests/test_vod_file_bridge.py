"""Unit tests for VOD-014: VOD ↔ File Manager Bridge.

Tests bridge service functions directly and the /ui/vod-bridge/* endpoints.
DynamoDB is mocked via moto; S3 is not exercised (no S3 calls in bridge service).
"""
from __future__ import annotations

import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ─── Env / settings fixture ───────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")
    monkeypatch.setenv("FILEMGR_TABLE", "FileManager")
    monkeypatch.setenv("DDB_VIDEO_METADATA", "VideoMetadata")
    monkeypatch.setenv("VOD_FILE_BRIDGE_ENABLED", "1")


# ─── In-memory table stubs ────────────────────────────────────────────────────


class _InMemTable:
    """Minimal DynamoDB table stub (get/put/update_item)."""

    def __init__(self, pk: str, sk: str | None = None):
        self.items: dict = {}
        self._pk = pk
        self._sk = sk

    def _key_for(self, item: dict) -> tuple:
        if self._sk:
            return item[self._pk], item[self._sk]
        return (item[self._pk],)

    def _key_from_key(self, key: dict) -> tuple:
        if self._sk:
            return key[self._pk], key[self._sk]
        return (key[self._pk],)

    def put_item(self, *, Item, ConditionExpression=None):
        k = self._key_for(Item)
        if ConditionExpression is not None:
            expr = str(ConditionExpression)
            if "attribute_not_exists" in expr and k in self.items:
                from botocore.exceptions import ClientError
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}}, "put_item")
        self.items[k] = dict(Item)

    def get_item(self, *, Key, ConsistentRead=False):
        k = self._key_from_key(Key)
        item = self.items.get(k)
        return {"Item": dict(item)} if item else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues=None, **kwargs):
        k = self._key_from_key(Key)
        item = dict(self.items.get(k) or {})
        # Update only the SET fields (for tests: just keep the item updated).
        if ExpressionAttributeValues:
            # Parse field names from UpdateExpression roughly
            set_part = UpdateExpression.replace("SET ", "").split(",")
            for part in set_part:
                part = part.strip()
                if " = " in part:
                    field_name, placeholder = part.split(" = ", 1)
                    field_name = field_name.strip()
                    placeholder = placeholder.strip()
                    if placeholder in ExpressionAttributeValues:
                        item[field_name] = ExpressionAttributeValues[placeholder]
        self.items[k] = item

    def delete_item(self, *, Key):
        k = self._key_from_key(Key)
        self.items.pop(k, None)

    def scan(self, **kwargs):
        return {"Items": list(self.items.values()), "Count": len(self.items)}


def _make_tables():
    vm_table = _InMemTable("video_id")
    fm_table = _InMemTable("PK", "SK")
    return SimpleNamespace(video_metadata=vm_table), fm_table


# ─── Helpers for seeding a video in the in-memory store ───────────────────────


def _seed_video(
    vm_table,
    *,
    video_id: str = "v_aaaa" + "0" * 28,
    owner: str = "user_owner",
    title: str = "My Test Video",
    status: str = "published",
    visibility: str = "public",
    source_s3_key: str = "uploads/user_owner/raw.mp4",
    source_file_node_id: str | None = None,
    hls_manifest_url: str | None = None,
    thumbnail_url: str | None = None,
    duration_seconds: float | None = None,
    width: int | None = None,
    height: int | None = None,
):
    ts = int(time.time())
    item: dict = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": title,
        "status": status,
        "visibility": visibility,
        "source_type": "upload",
        "source_s3_key": source_s3_key,
        "created_at": ts,
        "updated_at": ts,
        "drm_enabled": False,
    }
    if source_file_node_id:
        item["source_file_node_id"] = source_file_node_id
    if hls_manifest_url:
        item["hls_manifest_url"] = hls_manifest_url
    if thumbnail_url:
        item["thumbnail_url"] = thumbnail_url
    if duration_seconds is not None:
        item["duration_seconds"] = duration_seconds
    if width is not None:
        item["width"] = width
    if height is not None:
        item["height"] = height
    vm_table.put_item(Item=item)
    return item


def _seed_file_node(fm_table, *, owner: str, path: str, content_type: str = "video/mp4", s3_key: str = "k", s3_bucket: str = "b", vod_video_id: str | None = None):
    from app.services.filemanager import pk_user, sk_node
    item = {
        "PK": pk_user(owner),
        "SK": sk_node(path),
        "type": "file",
        "path": path,
        "name": path.split("/")[-1],
        "name_lc": path.split("/")[-1].lower(),
        "parent": "/",
        "content_type": content_type,
        "s3_key": s3_key,
        "s3_bucket": s3_bucket,
    }
    if vod_video_id:
        item["vod_video_id"] = vod_video_id
    fm_table.put_item(Item=item)
    return item


# ─── Service-layer tests ───────────────────────────────────────────────────────


class TestSafeFilename:
    def test_safe_filename_sanitizes_special_chars(self):
        from app.services.vod_file_bridge import _safe_filename
        result = _safe_filename("My Video! #1", "uploads/raw.mp4")
        # Special chars like ! and # should be removed, extension preserved
        assert "!" not in result
        assert "#" not in result
        assert result.endswith(".mp4")

    def test_safe_filename_preserves_webm_extension(self):
        from app.services.vod_file_bridge import _safe_filename
        result = _safe_filename("My Video", "uploads/raw.webm")
        assert result.endswith(".webm")

    def test_safe_filename_defaults_to_mp4_when_no_key(self):
        from app.services.vod_file_bridge import _safe_filename
        result = _safe_filename("My Video", None)
        assert result.endswith(".mp4")

    def test_safe_filename_handles_empty_title(self):
        from app.services.vod_file_bridge import _safe_filename
        result = _safe_filename("!!!", "uploads/raw.mp4")
        assert result == "video.mp4"


class TestInferContentType:
    def test_infer_mp4(self):
        from app.services.vod_file_bridge import _infer_content_type
        assert _infer_content_type("path/to/file.mp4") == "video/mp4"

    def test_infer_webm(self):
        from app.services.vod_file_bridge import _infer_content_type
        assert _infer_content_type("path/to/clip.webm") == "video/webm"

    def test_infer_mov(self):
        from app.services.vod_file_bridge import _infer_content_type
        assert _infer_content_type("path/to/clip.MOV") == "video/quicktime"

    def test_infer_mkv(self):
        from app.services.vod_file_bridge import _infer_content_type
        assert _infer_content_type("path/to/clip.mkv") == "video/x-matroska"

    def test_infer_none_defaults_to_mp4(self):
        from app.services.vod_file_bridge import _infer_content_type
        assert _infer_content_type(None) == "video/mp4"


class TestLinkVideoToFilemanager:
    def test_link_video_creates_file_node(self):
        """link_video_to_filemanager creates a file node in the file manager."""
        T_ns, fm_table = _make_tables()
        video_id = "v_" + "a" * 32
        _seed_video(T_ns.video_metadata, video_id=video_id, source_s3_key="uploads/raw.mp4")

        from app.services.video_metadata_store import video_from_item

        def _get_video(vid):
            item = T_ns.video_metadata.get_item(Key={"video_id": vid}).get("Item") or {}
            return video_from_item(item)

        # get_node raises 404 so that the idempotency check is skipped (new node)
        with (
            patch("app.services.vod_file_bridge.S") as mock_s,
            patch("app.services.vod_file_bridge.get_video", side_effect=_get_video),
            patch("app.services.vod_file_bridge.get_node", side_effect=HTTPException(404, "not found")),
            patch("app.services.vod_file_bridge.put_node"),
            patch("app.services.vod_file_bridge._put_token_entries"),
            patch("app.services.vod_file_bridge._update_video_source_file_node"),
            patch("app.services.vod_file_bridge._ensure_videos_folder"),
            patch("app.services.vod_file_bridge._resolve_unique_path", return_value="/Videos/My Test Video.mp4"),
        ):
            mock_s.video_upload_bucket = "local-uploads"

            from app.services.vod_file_bridge import link_video_to_filemanager
            result = link_video_to_filemanager(video_id)

        assert result["video_id"] == video_id
        assert result["linked"] is True
        assert result["path"] == "/Videos/My Test Video.mp4"

    def test_link_video_no_s3_key_returns_not_linked(self):
        """Video without source_s3_key cannot be linked."""
        T_ns, fm_table = _make_tables()
        video_id = "v_" + "b" * 32
        _seed_video(T_ns.video_metadata, video_id=video_id, source_s3_key="uploads/raw.mp4")
        # Overwrite s3 key to empty
        key = (video_id,)
        T_ns.video_metadata.items[key]["source_s3_key"] = ""

        from app.services.video_metadata_store import video_from_item

        def _get_video(vid):
            item = T_ns.video_metadata.get_item(Key={"video_id": vid}).get("Item") or {}
            return video_from_item(item)

        with (
            patch("app.services.vod_file_bridge.S") as mock_s,
            patch("app.services.vod_file_bridge.get_video", side_effect=_get_video),
            patch("app.services.vod_file_bridge.get_node", side_effect=HTTPException(404, "not found")),
            patch("app.services.vod_file_bridge._ensure_videos_folder"),
            patch("app.services.vod_file_bridge._resolve_unique_path", return_value="/Videos/My Test Video.mp4"),
        ):
            mock_s.video_upload_bucket = "local-uploads"
            from app.services.vod_file_bridge import link_video_to_filemanager
            result = link_video_to_filemanager(video_id)

        assert result["linked"] is False

    def test_link_video_idempotent(self):
        """Second link call returns linked=False (already linked)."""
        T_ns, fm_table = _make_tables()
        video_id = "v_" + "c" * 32
        _seed_video(T_ns.video_metadata, video_id=video_id, source_s3_key="uploads/raw.mp4")

        from app.services.video_metadata_store import video_from_item

        def _get_video(vid):
            item = T_ns.video_metadata.get_item(Key={"video_id": vid}).get("Item") or {}
            return video_from_item(item)

        # After first call, get_node returns a node that already has vod_video_id set
        call_count = {"n": 0}

        def _get_node_mock(owner, path):
            call_count["n"] += 1
            if call_count["n"] <= 1:
                raise HTTPException(404, "not found")
            # Subsequent calls: return the previously linked node
            return {"vod_video_id": video_id}

        put_calls = []

        with (
            patch("app.services.vod_file_bridge.S") as mock_s,
            patch("app.services.vod_file_bridge.get_video", side_effect=_get_video),
            patch("app.services.vod_file_bridge.get_node", side_effect=_get_node_mock),
            patch("app.services.vod_file_bridge.put_node", side_effect=lambda item: put_calls.append(item)),
            patch("app.services.vod_file_bridge._put_token_entries"),
            patch("app.services.vod_file_bridge._update_video_source_file_node"),
            patch("app.services.vod_file_bridge._ensure_videos_folder"),
            patch("app.services.vod_file_bridge._resolve_unique_path", return_value="/Videos/My Test Video.mp4"),
            patch("app.services.vod_file_bridge._update_linked_node_vod_metadata"),
        ):
            mock_s.video_upload_bucket = "local-uploads"
            from app.services.vod_file_bridge import link_video_to_filemanager
            first = link_video_to_filemanager(video_id)
            second = link_video_to_filemanager(video_id)

        assert first["linked"] is True
        # Second call finds the existing node with vod_video_id set — linked=False
        assert second["linked"] is False


class TestResolveUniquePath:
    def test_resolve_unique_path_no_collision_returns_same(self):
        """When no file exists at base_path, returns it unchanged."""
        # get_node raises 404 → path is free → returns base_path unchanged
        with patch("app.services.vod_file_bridge.get_node", side_effect=HTTPException(404, "not found")):
            from app.services.vod_file_bridge import _resolve_unique_path
            result = _resolve_unique_path("owner123", "/Videos/myvideo.mp4")

        assert result == "/Videos/myvideo.mp4"


class TestImportFileToVod:
    def test_import_file_rejects_non_video(self):
        """Importing a non-video file raises HTTP 400."""
        # get_node returns a text/plain node
        txt_node = {
            "PK": "USER#user1",
            "SK": "NODE#/docs/readme.txt",
            "type": "file",
            "path": "/docs/readme.txt",
            "name": "readme.txt",
            "content_type": "text/plain",
            "s3_key": "k",
            "s3_bucket": "b",
        }

        with patch("app.services.vod_file_bridge.get_node", return_value=txt_node):
            from app.services.vod_file_bridge import import_file_to_vod
            with pytest.raises(HTTPException) as exc_info:
                import_file_to_vod("user1", "/docs/readme.txt")
        assert exc_info.value.status_code == 400
        assert "not a video" in str(exc_info.value.detail)

    def test_import_file_rejects_already_linked(self):
        """Importing a file already linked to a VOD record raises HTTP 409."""
        video_node = {
            "PK": "USER#user1",
            "SK": "NODE#/Videos/myvid.mp4",
            "type": "file",
            "path": "/Videos/myvid.mp4",
            "name": "myvid.mp4",
            "content_type": "video/mp4",
            "s3_key": "k",
            "s3_bucket": "b",
            "vod_video_id": "v_existingvideo" + "x" * 17,
        }

        with patch("app.services.vod_file_bridge.get_node", return_value=video_node):
            from app.services.vod_file_bridge import import_file_to_vod
            with pytest.raises(HTTPException) as exc_info:
                import_file_to_vod("user1", "/Videos/myvid.mp4")
        assert exc_info.value.status_code == 409


# ─── Endpoint tests (via mocked service layer) ────────────────────────────────


class TestBridgeEndpoints:
    """Test the /ui/vod-bridge/* endpoints via the service layer using mocks."""

    def test_bridge_endpoint_import_returns_video_id(self):
        """POST /ui/vod-bridge/import returns a video_id in the response."""
        expected = {"video_id": "v_" + "d" * 32, "status": "probing", "file_path": "/Videos/clip.mp4"}

        with (
            patch("app.routers.vod_bridge.import_file_to_vod", return_value=expected),
            patch("app.routers.vod_bridge.S") as mock_s,
        ):
            mock_s.vod_file_bridge_enabled = True
            from app.routers.vod_bridge import api_import_to_vod, ImportToVodIn
            inp = ImportToVodIn(file_path="/Videos/clip.mp4")
            user = {"user_sub": "user1"}
            result = api_import_to_vod(inp, user)

        assert result.video_id == expected["video_id"]
        assert result.status == "probing"
        assert result.file_path == "/Videos/clip.mp4"

    def test_bridge_endpoint_status_returns_correct_data(self):
        """GET /ui/vod-bridge/status/{id} returns video metadata."""
        from app.models_video import VideoMetadataModel
        video_id = "v_" + "e" * 32
        ts = int(time.time())
        mock_video = VideoMetadataModel(
            id=video_id,
            owner_user_id="user1",
            title="Test Video",
            status="published",
            created_at=ts,
            updated_at=ts,
            visibility="public",
            source_file_node_id="/Videos/test.mp4",
            hls_manifest_url="https://cdn.example.com/hls/index.m3u8",
            thumbnail_url="https://cdn.example.com/thumb.jpg",
            duration_seconds=120.0,
        )

        with (
            patch("app.routers.vod_bridge.get_video", return_value=mock_video),
            patch("app.routers.vod_bridge.S") as mock_s,
        ):
            mock_s.vod_file_bridge_enabled = True
            from app.routers.vod_bridge import api_get_bridge_status
            user = {"user_sub": "user1"}
            result = api_get_bridge_status(video_id, user)

        assert result.video_id == video_id
        assert result.vod_status == "published"
        assert result.file_path == "/Videos/test.mp4"
        assert result.hls_manifest_url is not None
        assert result.duration_seconds == 120.0

    def test_bridge_endpoint_status_403_for_non_owner(self):
        """GET /ui/vod-bridge/status/{id} returns 403 for non-owner."""
        from app.models_video import VideoMetadataModel
        video_id = "v_" + "f" * 32
        ts = int(time.time())
        mock_video = VideoMetadataModel(
            id=video_id,
            owner_user_id="user_owner",
            title="Test Video",
            status="published",
            created_at=ts,
            updated_at=ts,
            visibility="public",
        )

        with (
            patch("app.routers.vod_bridge.get_video", return_value=mock_video),
            patch("app.routers.vod_bridge.S") as mock_s,
        ):
            mock_s.vod_file_bridge_enabled = True
            from app.routers.vod_bridge import api_get_bridge_status
            user = {"user_sub": "another_user"}
            with pytest.raises(HTTPException) as exc_info:
                api_get_bridge_status(video_id, user)
        assert exc_info.value.status_code == 403

    def test_bridge_endpoint_unlink_removes_vod_fields(self):
        """DELETE /ui/vod-bridge/{id}/link returns unlinked=True."""
        expected = {"video_id": "v_" + "g" * 32, "unlinked": True}

        with (
            patch("app.routers.vod_bridge.unlink_video_from_filemanager", return_value=expected),
            patch("app.routers.vod_bridge.S") as mock_s,
        ):
            mock_s.vod_file_bridge_enabled = True
            from app.routers.vod_bridge import api_unlink
            user = {"user_sub": "user1"}
            result = api_unlink(expected["video_id"], user)

        assert result["unlinked"] is True
        assert result["video_id"] == expected["video_id"]

    def test_bridge_feature_disabled_returns_404(self):
        """When VOD file bridge is disabled, endpoints raise 404."""
        with patch("app.routers.vod_bridge.S") as mock_s:
            mock_s.vod_file_bridge_enabled = False
            from app.routers.vod_bridge import _require_bridge_enabled
            with pytest.raises(HTTPException) as exc_info:
                _require_bridge_enabled()
        assert exc_info.value.status_code == 404
