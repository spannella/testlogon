"""Regression test for GAP-0103: stylist app-auth credentials handled insecurely.

Offline / in-memory only: uses moto's in-memory DynamoDB (no real AWS, no
network). The ``agent_types`` table handle on ``app.core.tables.T`` is swapped
for a moto-backed table for the duration of the test, and ``ensure_tables`` is
neutralised so the service does not create tables against a different client.

Before the fix:
  * ``app_auth_credentials_secret_name`` was absent from ``_CONFIG_FIELDS`` and
    silently discarded by ``update_stylist_config``.
  * ``StylistConfigOut`` had no ``has_app_credentials`` indicator, so a caller
    could not tell whether live-app credentials were configured.
  * There was no credential-resolution code path at all.

After the fix:
  * The secret-name pointer is persisted (a name/ARN only, never the raw cred).
  * The config output exposes ``has_app_credentials: bool`` and NEVER the raw
    credential nor the raw secret pointer (StylistConfigOut drops the extra key).
  * ``_resolve_app_credentials`` resolves credentials via a dev/mock path
    offline (and Secrets Manager in prod, same entrypoint — SECOPS-007).
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

import app.core.tables as tables_mod
from app.core.settings import S
from app.core.tables import _FloatSafeTable
from app.models import StylistConfigOut
from app.services import agent_stylist as svc


@pytest.fixture
def agent_types_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="agent_types",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        # Mirror production: T.agent_types is a float-safe proxy (the stylist
        # config stores float scores like contrast_ratio_min that DynamoDB
        # rejects as raw floats).
        table = _FloatSafeTable(ddb.Table("agent_types"))
        # ensure_tables would target the real ddb client; the moto-backed handle
        # is wired in below, so make bootstrap a no-op.
        monkeypatch.setattr(svc, "ensure_tables", lambda: None)
        original = tables_mod.T.agent_types
        object.__setattr__(tables_mod.T, "agent_types", table)
        try:
            yield table
        finally:
            object.__setattr__(tables_mod.T, "agent_types", original)


SECRET_NAME = "arn:aws:secretsmanager:us-east-1:123456789012:secret:stylist-creds"


def test_secret_name_persisted_and_only_indicator_exposed(agent_types_table):
    """The secret-name pointer is stored, but the output exposes only the
    derived ``has_app_credentials`` boolean — never the raw secret or cred."""
    user_id = "u-gap0103"

    out = svc.update_stylist_config(
        user_id=user_id,
        fields={"app_auth_credentials_secret_name": SECRET_NAME},
    )

    # Service-level: the indicator is derived and true once configured.
    assert out["has_app_credentials"] is True

    # The persisted config keeps only the pointer (a name/ARN) — never any raw
    # username/password/token credential material.
    stored = svc.get_stylist_config(user_id=user_id)
    assert stored["app_auth_credentials_secret_name"] == SECRET_NAME
    assert stored["has_app_credentials"] is True
    for forbidden in ("password", "username", "token", "secret_string"):
        assert forbidden not in stored

    # API output model: exposes has_app_credentials but DROPS the raw secret
    # pointer (StylistConfigOut declares no such field; extra is ignored).
    model = StylistConfigOut(**stored)
    dumped = model.model_dump()
    assert dumped["has_app_credentials"] is True
    assert "app_auth_credentials_secret_name" not in dumped
    # And certainly no raw credential material leaks into the response.
    for forbidden in ("password", "username", "token", "secret_string"):
        assert forbidden not in dumped


def test_has_app_credentials_false_when_unset(agent_types_table):
    """Default / unconfigured config reports has_app_credentials = False."""
    user_id = "u-gap0103-empty"
    out = svc.update_stylist_config(user_id=user_id, fields={})
    assert out["has_app_credentials"] is False
    assert StylistConfigOut(**out).has_app_credentials is False


@pytest.fixture
def settings_override():
    """Toggle frozen Settings fields (and restore) — S is a frozen dataclass."""
    saved = {}

    def _set(name: str, value):
        if name not in saved:
            saved[name] = getattr(S, name)
        object.__setattr__(S, name, value)

    try:
        yield _set
    finally:
        for name, value in saved.items():
            object.__setattr__(S, name, value)


def test_resolve_app_credentials_uses_mock_path_offline(settings_override):
    """In dev mode, _resolve_app_credentials returns mock creds with no AWS /
    network call (would raise without a Secrets Manager mock otherwise)."""
    settings_override("dev_mode", True)
    creds = svc._resolve_app_credentials(user_id="any-user")
    assert creds is not None
    assert "username" in creds and "password" in creds


def test_trigger_review_blocked_without_creds_when_execute_enabled(
    agent_types_table, settings_override
):
    """When the execute gate is on and no credentials resolve, trigger_review
    refuses to run a live (unauthenticated) review."""
    settings_override("stylist_agent_execute_commands", True)
    settings_override("dev_mode", False)  # forces the Secrets Manager path
    user_id = "u-gap0103-noauth"
    # No secret configured -> _resolve_app_credentials returns None -> guard fires.
    with pytest.raises(ValueError, match="app_auth_credentials_not_configured"):
        svc.trigger_review(user_id=user_id, pages=["/billing"])
