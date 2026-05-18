from __future__ import annotations

import json
from pathlib import Path

from app.services.local_packaging import (
    build_dash_manifest,
    build_hls_master_manifest,
    shaka_packager_config,
    write_local_manifests,
)


def test_hls_master_manifest_contains_canonical_variants() -> None:
    manifest = build_hls_master_manifest()
    for path in ("1080p/index.m3u8", "720p/index.m3u8", "540p/index.m3u8", "360p/index.m3u8"):
        assert path in manifest


def test_dash_manifest_contains_canonical_representation_ids() -> None:
    manifest = build_dash_manifest()
    for rep in ("v_1080p", "v_720p", "v_540p", "v_360p"):
        assert rep in manifest


def test_shaka_config_contains_streams_and_contract_paths() -> None:
    cfg = shaka_packager_config(output_root="/workspace/testlogon/video-data")
    names = [s["name"] for s in cfg["streams"]]
    assert names == ["1080p", "720p", "540p", "360p"]
    assert cfg["path_convention"]["hls_variant"] == "hls/<rendition>/index.m3u8"
    assert cfg["path_convention"]["dash_manifest"] == "dash/manifest.mpd"


def test_write_local_manifests_writes_hls_and_dash(tmp_path: Path) -> None:
    write_local_manifests(tmp_path)
    assert (tmp_path / "hls" / "master.m3u8").exists()
    assert (tmp_path / "dash" / "manifest.mpd").exists()
