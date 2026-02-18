from __future__ import annotations

import json
from pathlib import Path

SWAGGER_PATH = Path("docs/swagger.json")


def test_projects_contract_paths_and_schemas_present() -> None:
    assert SWAGGER_PATH.exists(), "Canonical OpenAPI source missing: docs/swagger.json"
    spec = json.loads(SWAGGER_PATH.read_text())

    paths = spec.get("paths", {})
    assert "/v1/projects" in paths
    assert "/v1/projects/{project_id}" in paths
    assert "/v1/projects/{project_id}/files" in paths
    assert "/v1/projects/{project_id}/files/{tracked_file_id}" in paths
    assert "/v1/projects/{project_id}/detail" in paths
    assert "/v1/projects/{project_id}/events" in paths
    assert "/v1/projects/providers/{provider}/credentials" in paths

    schemas = spec.get("components", {}).get("schemas", {})
    assert "ProjectOut" in schemas
    assert "ProjectListOut" in schemas
    assert "ProjectDetailOut" in schemas
    assert "TrackedFileOut" in schemas
    assert "TrackedFileListOut" in schemas
    assert "ProjectEventOut" in schemas
    assert "ProjectEventListOut" in schemas
    assert "ProviderCredentialOut" in schemas
