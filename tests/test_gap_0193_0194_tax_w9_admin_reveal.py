"""Regression test for GAP-0193 + GAP-0194 (FIN-008).

Both gaps live in ``app/routers/tax_form_1099.py`` (W-9 / TIN handling):

  * GAP-0193 — W-9/TIN collection (creator submits a KMS-encrypted TIN, reads it
    back masked). This was already implemented under "GAP-0020"
    (``POST/GET /ui/tax-forms/w9`` + ``app.services.tax_info_w9.submit_tax_info``
    / ``get_tax_info``). We assert that round-trip here so the W-9 path stays
    covered and the masked view never leaks the raw TIN / ciphertext.

  * GAP-0194 — admin TIN reveal + IP-logged audit trail. NEW in this fix:
    ``GET /ui/tax-forms/admin/info/{target}`` returns the full decrypted TIN
    (``TaxInfoAdminOut.tin_full``) and writes a queryable ``TAX_AUDIT`` record
    (``action="tin_viewed"``, actor, target, ip, ts) to the ``tax_info`` table.
    Fails-before: the endpoint / ``get_tax_info_admin`` / ``write_tax_audit`` did
    not exist (AttributeError) and there was no persisted audit trail.

Fully offline AND hermetic. TestClient is broken in this repo, so we invoke the
router handler coroutine/function objects directly (pattern:
tests/test_gap_0142_call_missed_fanout.py).

Test-isolation (critical): we never rely on global moto/``@mock_aws``
interception of the app's pre-bound clients — that leaks to REAL AWS when another
test file imported the app first. Instead we monkeypatch the EXACT handles the
code path resolves at call time:
  - ``T.tax_info`` / ``T.profile`` on the frozen ``app.core.tables.T`` singleton
    via ``object.__setattr__`` (restored on teardown).
  - ``app.core.crypto.kms`` — a fake KMS client that round-trips Encrypt/Decrypt
    in-process, so no real KMS / network is touched.
  - ``S`` flags (``tax_form_1099_enabled``, ``kms_key_id``) via
    ``object.__setattr__`` since the Settings singleton is frozen.
"""
from __future__ import annotations

import base64
from typing import Any, Dict

import pytest


# --------------------------------------------------------------------------- #
# In-memory fakes (no AWS, no network)
# --------------------------------------------------------------------------- #

class _FakeTaxInfoTable:
    """Minimal DynamoDB Table stand-in for pk/sk single-table access."""

    def __init__(self) -> None:
        self.items: Dict[tuple, Dict[str, Any]] = {}

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def query(self, **kwargs):
        # KeyConditionExpression is a boto3 Key("pk").eq(<pk>) — pull the operand.
        cond = kwargs["KeyConditionExpression"]
        pk = cond._values[1]
        rows = [dict(v) for (p, _s), v in self.items.items() if p == pk]
        rows.sort(key=lambda r: r["sk"], reverse=not kwargs.get("ScanIndexForward", True))
        limit = int(kwargs.get("Limit") or len(rows))
        return {"Items": rows[:limit]}


class _FakeProfileTable:
    def __init__(self) -> None:
        self.items: Dict[str, Dict[str, Any]] = {}

    def put_item(self, *, Item):
        self.items[Item["user_sub"]] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(Key["user_sub"])
        return {"Item": dict(item)} if item else {}


class _FakeKms:
    """Reversible in-process KMS: ciphertext = b'CT:' + plaintext (base64'd)."""

    def encrypt(self, *, KeyId, Plaintext):
        return {"CiphertextBlob": b"CT:" + Plaintext}

    def decrypt(self, *, CiphertextBlob):
        assert CiphertextBlob.startswith(b"CT:")
        return {"Plaintext": CiphertextBlob[len(b"CT:"):]}


class _Admin:
    def __init__(self, sub: str) -> None:
        self.sub = sub


class _FakeRequest:
    class _Client:
        host = "203.0.113.7"

    client = _Client()


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def _wire(monkeypatch, request) -> Dict[str, Any]:
    from app.core import tables as tables_mod
    from app.core import crypto as crypto_mod
    from app.core.settings import S

    tax_table = _FakeTaxInfoTable()
    profile_table = _FakeProfileTable()

    # Enable the feature + KMS guard (S is frozen → object.__setattr__).
    _saved_s = {k: getattr(S, k) for k in ("tax_form_1099_enabled", "kms_key_id")}
    object.__setattr__(S, "tax_form_1099_enabled", True)
    object.__setattr__(S, "kms_key_id", "test-key")
    request.addfinalizer(
        lambda: [object.__setattr__(S, k, v) for k, v in _saved_s.items()]
    )

    # Reversible in-process KMS — crypto.kms_encrypt/decrypt resolve module-level
    # ``crypto.kms`` at call time.
    monkeypatch.setattr(crypto_mod, "kms", _FakeKms(), raising=True)

    # Swap the frozen global T entries the code path touches; restore on teardown.
    T = tables_mod.T
    overrides = {"tax_info": tax_table, "profile": profile_table}
    saved = {name: getattr(T, name) for name in overrides}

    def _restore():
        for name, original in saved.items():
            object.__setattr__(T, name, original)

    for name, value in overrides.items():
        object.__setattr__(T, name, value)
    request.addfinalizer(_restore)

    return {"tax_table": tax_table, "profile_table": profile_table}


# --------------------------------------------------------------------------- #
# GAP-0193: W-9 collection round-trip (already implemented; keep covered)
# --------------------------------------------------------------------------- #

def test_gap0193_submit_w9_encrypts_tin_and_masks_view(monkeypatch, request):
    ctx = _wire(monkeypatch, request)
    from app.services import tax_info_w9 as svc

    result = svc.submit_tax_info(
        user_sub="alice",
        legal_name="Alice Smith",
        tin="123-45-6789",
        tin_type="ssn",
        address_line1="100 Main St",
        city="Springfield",
        state="IL",
        zip_code="62701",
        certified=True,
    )
    # Masked view only.
    assert result["tin_last4"] == "6789"
    assert "tin_full" not in result
    assert "tin_encrypted" not in result

    # Raw TIN must NOT be stored in plaintext anywhere in the DDB item.
    item = ctx["tax_table"].items[("USER#alice", "TAX_INFO")]
    assert "123456789" not in str({k: v for k, v in item.items() if k != "tin_encrypted"})
    assert item["tin_encrypted"]  # ciphertext present
    # The stored value is base64 ciphertext (not the raw TIN).
    assert item["tin_encrypted"] != "123456789"
    base64.b64decode(item["tin_encrypted"])  # valid base64

    # get_tax_info returns masked view with no ciphertext.
    masked = svc.get_tax_info("alice")
    assert masked is not None and masked["tin_last4"] == "6789"
    assert "tin_encrypted" not in masked and "tin_full" not in masked


def test_gap0193_invalid_tin_rejected(monkeypatch, request):
    _wire(monkeypatch, request)
    from app.services import tax_info_w9 as svc

    with pytest.raises(ValueError, match="invalid_tin"):
        svc.submit_tax_info(
            user_sub="bob",
            legal_name="Bob",
            tin="12345",  # too short
            tin_type="ssn",
            address_line1="1 Oak",
            city="Chicago",
            state="IL",
            zip_code="60601",
            certified=True,
        )


# --------------------------------------------------------------------------- #
# GAP-0194: admin TIN reveal + audit trail
# --------------------------------------------------------------------------- #

def _seed_w9(svc, user_sub: str, tin: str) -> None:
    svc.submit_tax_info(
        user_sub=user_sub,
        legal_name="Carol Creator",
        tin=tin,
        tin_type="ssn",
        address_line1="2 Pine",
        city="Austin",
        state="TX",
        zip_code="73301",
        certified=True,
    )


def test_gap0194_admin_reveal_decrypts_and_audits(monkeypatch, request):
    ctx = _wire(monkeypatch, request)
    from app.services import tax_info_w9 as svc
    from app.routers import tax_form_1099 as router

    _seed_w9(svc, "carol", "987-65-4321")
    # Profile must exist (router calls _ensure_target_exists).
    ctx["profile_table"].put_item(Item={"user_sub": "carol", "display_name": "Carol"})

    out = router.admin_reveal_tin(
        target_user_sub="carol",
        request=_FakeRequest(),
        admin=_Admin("charlie_admin"),
    )
    # FAILS-BEFORE: endpoint/service did not exist.
    assert out.tin_full == "987654321"
    assert out.tin_last4 == "4321"

    # A queryable TAX_AUDIT record was written with actor/target/ip/action.
    audit = svc.list_tax_audit(target_user_sub="carol")
    viewed = [e for e in audit["entries"] if e.get("action") == "tin_viewed"]
    assert len(viewed) == 1
    assert viewed[0]["actor"] == "charlie_admin"
    assert viewed[0]["target"] == "carol"
    assert viewed[0]["ip"] == "203.0.113.7"
    assert int(viewed[0]["ts"]) > 0


def test_gap0194_reveal_404_when_no_w9(monkeypatch, request):
    ctx = _wire(monkeypatch, request)
    from fastapi import HTTPException
    from app.routers import tax_form_1099 as router

    # Target profile exists but no W-9 submitted.
    ctx["profile_table"].put_item(Item={"user_sub": "dave"})

    with pytest.raises(HTTPException) as ei:
        router.admin_reveal_tin(
            target_user_sub="dave",
            request=_FakeRequest(),
            admin=_Admin("charlie_admin"),
        )
    assert ei.value.status_code == 404
    assert ei.value.detail["code"] == "no_tax_info"


def test_gap0194_reveal_404_when_user_not_found(monkeypatch, request):
    _wire(monkeypatch, request)
    from fastapi import HTTPException
    from app.routers import tax_form_1099 as router

    with pytest.raises(HTTPException) as ei:
        router.admin_reveal_tin(
            target_user_sub="ghost",
            request=_FakeRequest(),
            admin=_Admin("charlie_admin"),
        )
    assert ei.value.status_code == 404
    assert ei.value.detail["code"] == "user_not_found"


def test_gap0194_audit_list_endpoint_returns_entries(monkeypatch, request):
    ctx = _wire(monkeypatch, request)
    from app.services import tax_info_w9 as svc
    from app.routers import tax_form_1099 as router

    _seed_w9(svc, "carol", "111-22-3333")
    ctx["profile_table"].put_item(Item={"user_sub": "carol"})

    # Two reveals → two audit entries.
    router.admin_reveal_tin(target_user_sub="carol", request=_FakeRequest(), admin=_Admin("a1"))
    router.admin_reveal_tin(target_user_sub="carol", request=_FakeRequest(), admin=_Admin("a2"))

    resp = router.admin_list_tin_audit(
        target_user_sub="carol", limit=50, admin=_Admin("a1")
    )
    assert resp["count"] == 2
    assert {e["actor"] for e in resp["entries"]} == {"a1", "a2"}
