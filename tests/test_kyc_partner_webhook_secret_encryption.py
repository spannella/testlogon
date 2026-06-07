"""Regression test for GAP-0025 — KYC partner webhook secret stored plaintext.

Before the fix, ``register_webhook()`` in ``app/services/kyc_partner_api.py``
wrote the caller-supplied webhook ``secret`` verbatim into the ``kyc_cases``
DynamoDB table (``"secret": str(secret)``). Anyone with table read access could
exfiltrate the HMAC signing key and forge KYC partner events.

After the fix, the secret is KMS-encrypted at rest (with a ``PLAIN:`` dev-mode
fallback) and a ``_decrypt_kyc_partner_secret()`` helper round-trips it.

Fully offline: real moto in-memory DynamoDB + moto's mock KMS. No real AWS,
no running dev stack, no mock-KMS-server process required.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws


_SECRET = "supersecret-hmac-key-value"


@pytest.fixture
def ddb_kms_env():
    """Wire a real-schema ``kyc_cases`` moto table + a moto KMS key.

    - Creates the ``kyc_cases`` table with the production ``pk``/``sk`` schema.
    - Creates a moto KMS key and points ``S.kms_key_id`` + the shared boto3 KMS
      client at it, so ``kms_encrypt`` exercises the real encrypt path (proving
      the stored value is genuine ciphertext, not just the PLAIN: fallback).

    ``T`` is a frozen dataclass; attributes are swapped via
    ``object.__setattr__`` and restored afterwards. Likewise for the KMS client
    in ``app.core.aws`` and ``S.kms_key_id``.
    """
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        kyc_cases = ddb.create_table(
            TableName="test-kyc-cases",
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
        kyc_cases.wait_until_exists()

        kms_client = boto3.client("kms", region_name="us-east-1")
        key = kms_client.create_key(Description="gap-0025 test key")
        key_id = key["KeyMetadata"]["KeyId"]

        from app.core import tables as tables_mod
        from app.core import aws as aws_mod
        from app.core import crypto as crypto_mod
        from app.core.settings import S

        orig_table = tables_mod.T.kyc_cases
        orig_kms_aws = aws_mod.kms
        orig_kms_crypto = crypto_mod.kms
        orig_key_id = S.kms_key_id

        object.__setattr__(tables_mod.T, "kyc_cases", kyc_cases)
        # crypto.kms is imported by-reference at module load (`from .aws import kms`);
        # swap that binding too so kms_encrypt/kms_decrypt use the moto client.
        aws_mod.kms = kms_client
        crypto_mod.kms = kms_client
        object.__setattr__(S, "kms_key_id", key_id)
        try:
            yield {"kyc_cases": kyc_cases, "kms_key_id": key_id}
        finally:
            object.__setattr__(tables_mod.T, "kyc_cases", orig_table)
            aws_mod.kms = orig_kms_aws
            crypto_mod.kms = orig_kms_crypto
            object.__setattr__(S, "kms_key_id", orig_key_id)


def _register(partner_id: str = "p_test", secret: str = _SECRET):
    from app.services import kyc_partner_api as svc

    principal = {"user_sub": partner_id, "api_key_id": "k1"}
    return svc.register_webhook(
        principal,
        url="https://example.com/kyc-hook",
        events=["status_changed"],
        secret=secret,
    )


def _stored_secret(partner_id: str = "p_test"):
    from app.core.tables import T
    from boto3.dynamodb.conditions import Key

    resp = T.kyc_cases.query(
        KeyConditionExpression=Key("pk").eq(f"PARTNER#{partner_id}")
        & Key("sk").begins_with("WH#"),
    )
    items = [i for i in resp["Items"] if i.get("entity_type") == "kyc_partner_webhook"]
    assert len(items) == 1, f"expected exactly one webhook item, got {len(items)}"
    return items[0]["secret"]


def test_register_webhook_does_not_store_plaintext_secret(ddb_kms_env):
    """The persisted DynamoDB item must not contain the raw plaintext secret.

    BEFORE fix: stored value == _SECRET (plaintext) -> FAILS.
    AFTER fix:  stored value is KMS ciphertext (or PLAIN: in dev) -> PASSES.
    """
    _register()
    stored = _stored_secret()

    assert stored != _SECRET, "Secret must not be stored in plaintext"
    assert _SECRET not in stored, "Plaintext secret must not appear in stored value"
    # With the moto KMS key wired, this is real base64 ciphertext (no PLAIN: prefix).
    assert not stored.startswith("PLAIN:"), (
        "Expected real KMS ciphertext when KMS is available, got PLAIN: fallback"
    )
    assert len(stored) > 30, "Encrypted ciphertext should be substantially longer"


def test_decrypt_helper_round_trips(ddb_kms_env):
    """_decrypt_kyc_partner_secret() must recover the original plaintext."""
    from app.services.kyc_partner_api import _decrypt_kyc_partner_secret

    _register(secret="round_trip_secret")
    stored = _stored_secret()
    assert stored != "round_trip_secret"
    assert _decrypt_kyc_partner_secret(stored) == "round_trip_secret"


def test_register_webhook_returns_plaintext_secret_once(ddb_kms_env):
    """Registration response returns the plaintext secret one time for the caller."""
    result = _register(secret="myhooksecret")
    assert result.get("secret") == "myhooksecret"


def test_list_webhooks_never_exposes_secret(ddb_kms_env):
    """list_webhooks() must never include the secret field (plaintext or cipher)."""
    from app.services import kyc_partner_api as svc

    _register(partner_id="p_list")
    principal = {"user_sub": "p_list", "api_key_id": "k1"}
    webhooks = svc.list_webhooks(principal)
    assert len(webhooks) == 1
    assert "secret" not in webhooks[0], "list_webhooks() must not return the secret"


def test_plain_fallback_when_kms_unavailable(ddb_kms_env):
    """When KMS raises (e.g. mock unavailable), fall back to PLAIN: prefix and
    still round-trip — no crash, dev/prod same code path."""
    from app.core import crypto as crypto_mod
    from app.services.kyc_partner_api import _decrypt_kyc_partner_secret

    class _BrokenKms:
        def encrypt(self, *a, **k):
            raise RuntimeError("kms down")

    orig = crypto_mod.kms
    crypto_mod.kms = _BrokenKms()
    try:
        _register(partner_id="p_fallback", secret="fallback_secret")
    finally:
        crypto_mod.kms = orig

    stored = _stored_secret("p_fallback")
    assert stored == "PLAIN:fallback_secret"
    assert _decrypt_kyc_partner_secret(stored) == "fallback_secret"
