from __future__ import annotations

from pathlib import Path


MODULE_DIR = Path("infra/terraform/mediapackage")


def test_mediapackage_module_files_exist() -> None:
    for name in ("main.tf", "variables.tf", "outputs.tf", "mediapackage_speke.yaml.tpl", "README.md"):
        assert (MODULE_DIR / name).exists()


def test_main_tf_has_cloudformation_stack_and_iam_role() -> None:
    text = (MODULE_DIR / "main.tf").read_text()
    assert "resource \"aws_cloudformation_stack\" \"mediapackage\"" in text
    assert "resource \"aws_iam_role\" \"speke_access\"" in text


def test_template_includes_hls_dash_endpoints_with_speke() -> None:
    text = (MODULE_DIR / "mediapackage_speke.yaml.tpl").read_text()
    assert "HlsEndpoint" in text
    assert "DashEndpoint" in text
    assert "SpekeKeyProvider" in text
