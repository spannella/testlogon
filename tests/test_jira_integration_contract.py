from __future__ import annotations

from app.main import create_app


def _schema() -> dict:
    app = create_app()
    return app.openapi()


def test_openapi_includes_jira_integration_paths() -> None:
    schema = _schema()
    paths = schema.get("paths", {})
    required = {
        "/integrations/jira/connect",
        "/integrations/jira/callback",
        "/integrations/jira/projects",
        "/integrations/jira/webhook",
        "/tickets/{ticket_id}/external-links/jira",
        "/tickets/{ticket_id}/external-links/jira/link-existing",
        "/tickets/{ticket_id}/external-links/{link_id}",
        "/tickets/{ticket_id}/sync-status",
    }
    assert required.issubset(paths.keys())


def test_contract_documents_pagination_and_filters_for_projects() -> None:
    schema = _schema()
    params = schema["paths"]["/integrations/jira/projects"]["get"]["parameters"]
    by_name = {p["name"]: p for p in params}

    assert by_name["workspace_id"]["in"] == "query"
    assert by_name["cursor"]["in"] == "query"
    assert by_name["limit"]["in"] == "query"
    assert by_name["q"]["in"] == "query"
    assert by_name["project_keys"]["in"] == "query"


def test_contract_documents_idempotency_for_link_endpoints() -> None:
    schema = _schema()
    create_params = schema["paths"]["/tickets/{ticket_id}/external-links/jira"]["post"]["parameters"]
    existing_params = schema["paths"]["/tickets/{ticket_id}/external-links/jira/link-existing"]["post"]["parameters"]

    create_names = {(p["name"], p["in"]) for p in create_params}
    existing_names = {(p["name"], p["in"]) for p in existing_params}

    assert ("Idempotency-Key", "header") in create_names
    assert ("Idempotency-Key", "header") in existing_names


def test_contract_documents_error_responses() -> None:
    schema = _schema()
    responses = schema["paths"]["/integrations/jira/connect"]["post"]["responses"]
    for status in ("400", "401", "403", "404", "409", "429", "502"):
        assert status in responses
