from __future__ import annotations

from pathlib import Path


COMPOSE_PATH = Path("docker-compose.video.local.yml")
DOC_PATH = Path("docs/video-local-stack.md")
INGEST_CONF_PATH = Path("docker/video/ingest/nginx.conf")


def test_compose_file_exists_and_declares_required_services() -> None:
    text = COMPOSE_PATH.read_text()
    for service in ("ingest:", "transcoder:", "packager:", "origin:", "license-mock:"):
        assert service in text


def test_compose_includes_shared_video_data_mounts_and_healthchecks() -> None:
    text = COMPOSE_PATH.read_text()
    assert "./video-data:/workspace/video-data" in text
    assert "healthcheck:" in text
    assert "video_local" in text


def test_startup_docs_reference_compose_up_and_manifest_urls() -> None:
    text = DOC_PATH.read_text()
    assert "docker compose -f docker-compose.video.local.yml up -d" in text
    assert "http://localhost:8089/hls/master.m3u8" in text
    assert "http://localhost:8089/dash/manifest.mpd" in text


def test_ingest_route_and_transcoder_pull_are_declared() -> None:
    compose = COMPOSE_PATH.read_text()
    docs = DOC_PATH.read_text()

    assert "./docker/video/ingest/nginx.conf:/etc/nginx/nginx.conf:ro" in compose
    assert "INPUT_URL: rtmp://ingest/live/localdemo" in compose
    assert "rtmp://localhost:1935/live/<stream_key>" in docs
    assert "retries" in docs.lower() or "retry" in docs.lower()


def test_ingest_config_enables_rtmp_live_application() -> None:
    ingest = INGEST_CONF_PATH.read_text()
    assert "rtmp" in ingest
    assert "application live" in ingest
    assert "wait_key on" in ingest


def test_docs_describe_abr_watermark_pipeline_outputs() -> None:
    text = DOC_PATH.read_text()
    assert "ABR + watermark pipeline" in text
    assert "video-data/hls/<rendition>/index.m3u8" in text
    assert "WATERMARK_MODE" in text


def test_docs_describe_packaging_outputs_and_shaka_config() -> None:
    text = DOC_PATH.read_text()
    assert "video-data/dash/manifest.mpd" in text
    assert "config/video/shaka_packager_config.json" in text
    assert "v_<rendition>" in text


def test_docs_include_one_command_demo_scripts() -> None:
    text = DOC_PATH.read_text()
    assert "./scripts/video/package_vod.sh" in text
    assert "./scripts/video/validate_manifests.sh" in text
