from __future__ import annotations

from pathlib import Path


MODULE_DIR = Path("infra/terraform/cloudfront_packaging")


def test_cloudfront_module_files_exist() -> None:
    for name in ("main.tf", "variables.tf", "outputs.tf", "README.md"):
        assert (MODULE_DIR / name).exists()


def test_main_tf_contains_distribution_tls_and_oac() -> None:
    text = (MODULE_DIR / "main.tf").read_text()
    assert "resource \"aws_cloudfront_distribution\" \"packaging\"" in text
    assert "minimum_protocol_version = \"TLSv1.2_2021\"" in text
    assert "resource \"aws_cloudfront_origin_access_control\" \"packaging\"" in text


def test_main_tf_contains_manifest_segment_cache_policies_and_signed_url_hooks() -> None:
    text = (MODULE_DIR / "main.tf").read_text()
    assert "resource \"aws_cloudfront_cache_policy\" \"manifest\"" in text
    assert "resource \"aws_cloudfront_cache_policy\" \"segment\"" in text
    assert "trusted_key_groups" in text
    assert "X-Origin-Verify" in text
