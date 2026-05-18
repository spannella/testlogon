from __future__ import annotations

import json
from pathlib import Path

from app.services.video_abr_profile_exports import ffmpeg_abr_profiles, medialive_abr_profiles


def test_ffmpeg_export_uses_canonical_names() -> None:
    names = [item["name"] for item in ffmpeg_abr_profiles()]
    assert names == ["1080p", "720p", "540p", "360p"]


def test_medialive_export_uses_canonical_name_modifiers() -> None:
    modifiers = [item["NameModifier"] for item in medialive_abr_profiles()]
    assert modifiers == ["_1080p", "_720p", "_540p", "_360p"]


def test_generated_config_files_align_with_exports() -> None:
    ffmpeg_path = Path("config/video/ffmpeg_abr_profiles.json")
    medialive_path = Path("config/video/medialive_abr_profiles.json")

    assert ffmpeg_path.exists()
    assert medialive_path.exists()
    assert json.loads(ffmpeg_path.read_text()) == ffmpeg_abr_profiles()
    assert json.loads(medialive_path.read_text()) == medialive_abr_profiles()
