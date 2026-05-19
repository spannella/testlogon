from __future__ import annotations

from app.main import create_app


def test_openapi_includes_scope_annotations_for_integrated_routes() -> None:
    app = create_app()
    schema = app.openapi()

    tickets_get = schema["paths"]["/tickets"]["get"]
    assert tickets_get["x-api-key-scopes"] == ["tickets:read"]
    assert tickets_get["x-api-key-entitlement-required"] is True
    assert {"ApiKeyAuth": []} in tickets_get["security"]


def test_openapi_checkout_documents_idempotency_and_failure_examples() -> None:
    app = create_app()
    schema = app.openapi()

    checkout = schema["paths"]["/ui/shoppingcart/carts/{cart_id}/purchase"]["post"]
    header_names = {p["name"] for p in checkout.get("parameters", [])}
    assert "X-API-Key" in header_names
    assert "X-Idempotency-Key" in header_names

    examples = checkout["responses"]["403"]["content"]["application/json"]["examples"]
    assert "missing_scope" in examples
    assert "entitlement_denied" in examples
    assert "invalid_api_key" in checkout["responses"]["401"]["content"]["application/json"]["examples"]
    assert "api_rate_limited" in checkout["responses"]["429"]["content"]["application/json"]["examples"]
    assert "dual_credential_conflict" in checkout["responses"]["400"]["content"]["application/json"]["examples"]


def test_openapi_has_external_product_tag_grouping_and_auth_scheme() -> None:
    app = create_app()
    schema = app.openapi()

    groups = schema.get("x-tagGroups", [])
    assert groups
    assert groups[0]["name"] == "External Product APIs"
    assert "shoppingcart" in groups[0]["tags"]
    assert "messaging" in groups[0]["tags"]

    sec = schema["components"]["securitySchemes"]["ApiKeyAuth"]
    assert sec["type"] == "apiKey"
    assert sec["name"] == "X-API-Key"
