from __future__ import annotations

from pathlib import Path


MODULE_DIR = Path("infra/terraform/medialive")


def test_medialive_module_files_exist() -> None:
    for name in ("main.tf", "variables.tf", "outputs.tf", "channel_template.json.tpl", "README.md"):
        assert (MODULE_DIR / name).exists()


def test_main_tf_includes_input_and_iam_resources() -> None:
    text = (MODULE_DIR / "main.tf").read_text()
    assert "resource \"aws_iam_role\" \"medialive\"" in text
    assert "resource \"aws_medialive_input\" \"this\"" in text
    assert "resource \"aws_medialive_input_security_group\" \"this\"" in text


def test_channel_template_has_canonical_abr_outputs() -> None:
    text = (MODULE_DIR / "channel_template.json.tpl").read_text()
    for rendition in ("_1080p", "_720p", "_540p", "_360p"):
        assert rendition in text
    for vd in ("video_1080p", "video_720p", "video_540p", "video_360p"):
        assert vd in text
