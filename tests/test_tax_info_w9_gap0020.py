"""Regression test for GAP-0020 (FIN-008).

Before the fix:
  - No W-9 / TIN collection path existed (no ``submit_tax_info``, no
    ``tin_encrypted`` field, no endpoint).
  - ``app/services/tax_form_1099.py`` hardcoded the payer TIN to ``"0000"`` and
    printed no recipient TIN at all on every 1099-NEC.

After the fix:
  - Submitting a W-9 stores the TIN KMS-ENCRYPTED (stored value != plaintext).
  - The service layer NEVER returns the raw TIN nor the ciphertext — masked
    last-4 only.
  - The generated 1099 PDF uses the real recipient TIN last-4 (not "0000") and a
    real payer TIN derived from ``PLATFORM_EIN``.

Offline: in-memory moto DynamoDB + moto KMS (mock KMS, same code path as the dev
mock KMS server / prod AWS KMS). No real AWS.
"""

from __future__ import annotations

import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _env():
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    os.environ.setdefault("DDB_ENDPOINT_URL", "")
    os.environ.setdefault("DEV_MODE", "1")
    os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
    os.environ.setdefault("API_KEY_PEPPER", "test-pepper")


_RAW_TIN = "123-45-6789"
_TIN_DIGITS = "123456789"
_TIN_LAST4 = "6789"


@pytest.fixture
def env(monkeypatch):
    """Wire moto DDB tables (tax_info, tax_forms_1099, billing) + moto KMS."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        for name in ("tax_info", "tax_forms_1099", "billing"):
            ddb.create_table(
                TableName=name,
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

        # Real moto KMS key + wire crypto to use it (mock KMS, same path as prod).
        kms = boto3.client("kms", region_name="us-east-1")
        key_id = kms.create_key()["KeyMetadata"]["KeyId"]

        import app.core.crypto as crypto_mod
        import app.core.tables as tables_mod
        from app.core.settings import S

        monkeypatch.setattr(crypto_mod, "kms", kms)
        orig_kms_key = S.kms_key_id
        orig_ein = S.platform_ein
        object.__setattr__(S, "kms_key_id", key_id)

        orig_tax_info = tables_mod.T.tax_info
        orig_1099 = tables_mod.T.tax_forms_1099
        orig_billing = tables_mod.T.billing
        object.__setattr__(tables_mod.T, "tax_info", ddb.Table("tax_info"))
        object.__setattr__(tables_mod.T, "tax_forms_1099", ddb.Table("tax_forms_1099"))
        object.__setattr__(tables_mod.T, "billing", ddb.Table("billing"))
        try:
            yield {"ddb": ddb, "kms": kms, "S": S}
        finally:
            object.__setattr__(tables_mod.T, "tax_info", orig_tax_info)
            object.__setattr__(tables_mod.T, "tax_forms_1099", orig_1099)
            object.__setattr__(tables_mod.T, "billing", orig_billing)
            object.__setattr__(S, "kms_key_id", orig_kms_key)
            object.__setattr__(S, "platform_ein", orig_ein)


def _submit(user_sub: str = "alice"):
    from app.services import tax_info_w9

    return tax_info_w9.submit_tax_info(
        user_sub=user_sub,
        legal_name="Alice Test",
        tin=_RAW_TIN,
        tin_type="ssn",
        address_line1="123 Main St",
        city="Anytown",
        state="CA",
        zip_code="90210",
        certified=True,
    )


# ---------------------------------------------------------------------------
# Storage: TIN is KMS-encrypted, never plaintext.
# ---------------------------------------------------------------------------

def test_submit_stores_tin_encrypted_not_plaintext(env):
    """The stored DDB item holds ciphertext, never the raw TIN."""
    _submit()

    stored = env["ddb"].Table("tax_info").get_item(
        Key={"pk": "USER#alice", "sk": "TAX_INFO"}
    )["Item"]

    assert "tin_encrypted" in stored
    ct = stored["tin_encrypted"]
    # Encrypted blob must differ from the plaintext (both digit and dashed forms).
    assert ct != _TIN_DIGITS
    assert ct != _RAW_TIN
    assert _TIN_DIGITS not in ct
    assert _RAW_TIN not in ct
    # No plaintext TIN must be stored under any field.
    assert _TIN_DIGITS not in str({k: v for k, v in stored.items() if k != "tin_encrypted"})
    # Masked last-4 is stored for display.
    assert stored["tin_last4"] == _TIN_LAST4
    # And the ciphertext actually decrypts back to the original TIN.
    from app.services import tax_info_w9

    assert tax_info_w9.get_decrypted_tin("alice") == _TIN_DIGITS


# ---------------------------------------------------------------------------
# Service layer never returns the raw TIN or ciphertext.
# ---------------------------------------------------------------------------

def test_submit_returns_masked_only(env):
    result = _submit()
    assert "tin_encrypted" not in result
    assert "tin" not in result
    assert result["tin_last4"] == _TIN_LAST4
    assert result["certified"] is True
    # Raw TIN never echoed back, in any field.
    assert _RAW_TIN not in str(result)
    assert _TIN_DIGITS not in str(result)


def test_get_tax_info_omits_ciphertext(env):
    from app.services import tax_info_w9

    _submit()
    view = tax_info_w9.get_tax_info("alice")
    assert view is not None
    assert "tin_encrypted" not in view
    assert _TIN_DIGITS not in str(view)
    assert view["tin_last4"] == _TIN_LAST4


def test_invalid_tin_rejected(env):
    from app.services import tax_info_w9

    with pytest.raises(ValueError):
        tax_info_w9.submit_tax_info(
            user_sub="alice",
            legal_name="Alice",
            tin="12-34",  # too short
            tin_type="ssn",
            address_line1="1 St",
            city="X",
            state="CA",
            zip_code="90210",
            certified=True,
        )


# ---------------------------------------------------------------------------
# 1099 PDF uses the REAL recipient TIN last-4 (not "0000").
# ---------------------------------------------------------------------------

def test_1099_pdf_uses_real_recipient_tin(env, monkeypatch):
    import app.services.tax_form_1099 as svc

    monkeypatch.setattr(
        svc, "get_profile", lambda _sub: {"display_name": "Alice", "displayed_email": ""}
    )
    # Configure a real platform EIN so neither payer nor recipient TIN is "0000".
    object.__setattr__(env["S"], "platform_ein", "98-7654321")
    _submit()

    pdf = svc._render_1099_pdf(
        user_sub="alice", tax_year=2025, total_earnings_cents=70000, corrected=False
    )

    # Recipient TIN last-4 present; the bogus "0000" placeholder must not appear.
    assert b"***-**-6789" in pdf
    assert b"***-**-0000" not in pdf
    assert b"TIN NOT COLLECTED" not in pdf


def test_1099_payer_tin_from_platform_ein(env, monkeypatch):
    import app.services.tax_form_1099 as svc

    monkeypatch.setattr(
        svc, "get_profile", lambda _sub: {"display_name": "Alice", "displayed_email": ""}
    )
    object.__setattr__(env["S"], "platform_ein", "98-7654321")
    _submit()

    pdf = svc._render_1099_pdf(
        user_sub="alice", tax_year=2025, total_earnings_cents=70000, corrected=False
    )

    # Payer TIN last-4 derived from PLATFORM_EIN (98-7654321 -> 4321), not 0000.
    assert b"***-**-4321" in pdf
    assert b"***-**-0000" not in pdf


def test_1099_pdf_flags_missing_w9(env, monkeypatch):
    """Without a W-9 on file, the recipient TIN field must flag the form invalid."""
    import app.services.tax_form_1099 as svc

    monkeypatch.setattr(
        svc, "get_profile", lambda _sub: {"display_name": "Bob", "displayed_email": ""}
    )
    # No _submit() for bob.
    pdf = svc._render_1099_pdf(
        user_sub="bob", tax_year=2025, total_earnings_cents=70000, corrected=False
    )
    assert b"TIN NOT COLLECTED" in pdf
