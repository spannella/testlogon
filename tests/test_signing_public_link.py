"""Hermetic offline tests for the public signing link + inbox (SUX-002..007/014..016).

No real AWS, no network. moto in-memory tables are bound to the exact frozen
``T.signature_*`` handles via ``object.__setattr__`` (restored on teardown), and
the frozen ``S`` flags are toggled the same way. Async/sync route-handler
coroutines/functions are called directly (TestClient is broken in this env).
"""
from __future__ import annotations

import time

import boto3
import pytest
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T
from app.services import signature_packet_store as store
from app.services.signature_packet_domain import (
    SignatureFieldType,
    SignatureSignerStatus,
)

OWNER = "owner-1"
SIGNER = "signer-1"
OTHER = "signer-2"


def _make_table(ddb, name, hash_key, range_key=None, gsis=None):
    attr_defs = [{"AttributeName": hash_key, "AttributeType": "S"}]
    key_schema = [{"AttributeName": hash_key, "KeyType": "HASH"}]
    if range_key:
        attr_defs.append({"AttributeName": range_key, "AttributeType": "S"})
        key_schema.append({"AttributeName": range_key, "KeyType": "RANGE"})
    gsi_defs = []
    for g in gsis or []:
        for a in (g["partition_key"], g.get("sort_key")):
            if a and not any(d["AttributeName"] == a for d in attr_defs):
                attr_defs.append({"AttributeName": a, "AttributeType": "S"})
        ks = [{"AttributeName": g["partition_key"], "KeyType": "HASH"}]
        if g.get("sort_key"):
            ks.append({"AttributeName": g["sort_key"], "KeyType": "RANGE"})
        gsi_defs.append(
            {
                "IndexName": g["index_name"],
                "KeySchema": ks,
                "Projection": {"ProjectionType": "ALL"},
            }
        )
    kwargs = dict(
        TableName=name,
        KeySchema=key_schema,
        AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST",
    )
    if gsi_defs:
        kwargs["GlobalSecondaryIndexes"] = gsi_defs
    return ddb.create_table(**kwargs)


@pytest.fixture()
def env():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        packets = _make_table(
            ddb, "sp_packets", "packet_id",
            gsis=[{"index_name": "OWNER_CREATED_INDEX", "partition_key": "owner_user_id", "sort_key": "created_at"}],
        )
        signers = _make_table(
            ddb, "sp_signers", "packet_id", "signer_id",
            gsis=[{"index_name": "SIGNER_STATUS_INDEX", "partition_key": "signer_id", "sort_key": "status_key"}],
        )
        fields = _make_table(ddb, "sp_fields", "packet_id", "field_id")
        events = _make_table(ddb, "sp_events", "packet_id", "event_id")
        artifacts = _make_table(ddb, "sp_artifacts", "packet_id")
        sessions = _make_table(ddb, "sp_sessions", "user_sub", "session_id")

        saved = {
            "signature_packets": T.signature_packets,
            "signature_packet_signers": T.signature_packet_signers,
            "signature_packet_fields": T.signature_packet_fields,
            "signature_packet_events": T.signature_packet_events,
            "signature_packet_artifacts": T.signature_packet_artifacts,
            "sessions": T.sessions,
        }
        object.__setattr__(T, "signature_packets", packets)
        object.__setattr__(T, "signature_packet_signers", signers)
        object.__setattr__(T, "signature_packet_fields", fields)
        object.__setattr__(T, "signature_packet_events", events)
        object.__setattr__(T, "signature_packet_artifacts", artifacts)
        object.__setattr__(T, "sessions", sessions)

        s_saved = {
            "signature_pdf_enabled": S.signature_pdf_enabled,
            "signature_public_link_enabled": S.signature_public_link_enabled,
            "signature_packet_public_link_secret": S.signature_packet_public_link_secret,
        }
        object.__setattr__(S, "signature_pdf_enabled", True)
        object.__setattr__(S, "signature_public_link_enabled", True)
        object.__setattr__(S, "signature_packet_public_link_secret", "unit-test-secret")
        try:
            yield
        finally:
            for k, v in saved.items():
                object.__setattr__(T, k, v)
            for k, v in s_saved.items():
                object.__setattr__(S, k, v)


def _seed_sent_packet(*, with_signer=SIGNER):
    packet = store.create_draft_packet(
        owner_user_id=OWNER,
        source_path="/docs/contract.pdf",
        source_content_type="application/pdf",
        source_name="contract.pdf",
        origin_channel="file_manager",
    )
    pid = packet["packet_id"]
    store.add_packet_signer(packet_id=pid, signer_id=with_signer, required=True)
    store.upsert_packet_field(
        packet_id=pid,
        field_id="f1",
        page=1, x=0.1, y=0.1, width=0.2, height=0.05,
        field_type=SignatureFieldType.SIGNATURE,
        assigned_signer_id=with_signer,
        required=True,
    )
    store.mark_packet_sent(pid)
    return pid


# ─── SUX-002: mint / verify round-trip + rejection branches ──────────────────

def test_mint_verify_roundtrip(env):
    from app.services.signature_public_link import mint_signing_token, verify_signing_token

    tok = mint_signing_token("p1", "s1")
    payload = verify_signing_token(tok)
    assert payload is not None
    assert payload["packet_id"] == "p1"
    assert payload["signer_id"] == "s1"
    assert payload["scope"] == "sign"
    assert payload["jti"]
    # Secret is never embedded — only opaque ids in the decoded payload.
    assert "unit-test-secret" not in tok


def test_tampered_signature_rejected(env):
    from app.services.signature_public_link import mint_signing_token, verify_signing_token

    tok = mint_signing_token("p1", "s1")
    raw, sig = tok.split(".", 1)
    tampered = raw + "x." + sig
    assert verify_signing_token(tampered) is None


def test_expired_token_rejected(env):
    from app.services.signature_public_link import mint_signing_token, verify_signing_token

    tok = mint_signing_token("p1", "s1", ttl_days=0)  # exp == iat
    time.sleep(1.1)
    assert verify_signing_token(tok) is None


def test_wrong_scope_rejected(env):
    import json
    from app.core.crypto import b64url, b64url_decode
    from app.services.signature_public_link import _link_secret, verify_signing_token
    import hashlib, hmac

    payload = {"packet_id": "p", "signer_id": "s", "jti": "j", "scope": "evil", "iat": 1, "exp": 9999999999}
    raw = json.dumps(payload).encode()
    sig = hmac.new(_link_secret(), raw, hashlib.sha256).digest()
    tok = f"{b64url(raw)}.{b64url(sig)}"
    assert verify_signing_token(tok) is None


# ─── SUX-003: one-time-use + revocation store ────────────────────────────────

def test_consume_token_is_one_time(env):
    from app.services.signature_public_link import consume_token, is_token_consumed

    assert is_token_consumed("jti-abc") is False
    assert consume_token("jti-abc") is True
    assert is_token_consumed("jti-abc") is True
    # Second consume of the same jti fails (atomic conditional put).
    assert consume_token("jti-abc") is False


def test_revoke_token(env):
    from app.services.signature_public_link import revoke_token, is_token_revoked

    assert is_token_revoked("jti-rev") is False
    assert revoke_token("jti-rev") is True
    assert is_token_revoked("jti-rev") is True


# ─── SUX-004 + SUX-015: public signing happy path + rejections ───────────────

def test_public_sign_happy_path(env):
    from app.routers import signature_public as pub
    from app.services.signature_public_link import generate_signing_link
    from app.routers.signature_packets import SignaturePacketFieldFillIn

    class _Req:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    pid = _seed_sent_packet()
    link = generate_signing_link(pid, SIGNER)
    token = link["token"]

    # Open detail
    detail = pub.public_get_signing_detail(token, _Req())
    assert detail["packet_id"] == pid
    assert detail["role"] == "signer"
    # Legal notice required first → ack it
    pub.public_acknowledge_legal_notice(token, _Req())
    # Fill the assigned field
    fill_in = SignaturePacketFieldFillIn(value="Alice Q", input_mode="typed")
    res = pub.public_fill_field(token, "f1", fill_in, _Req())
    assert res["field_id"] == "f1"
    # Mark done → completes the packet (single required signer)
    done = pub.public_mark_done(token, _Req())
    assert done["signer_status"] == "completed"
    assert done["packet_status"] == "completed"

    # One-time-use: the same token cannot be reused after completion.
    with pytest.raises(Exception) as exc:
        pub.public_get_signing_detail(token, _Req())
    assert getattr(exc.value, "status_code", None) == 403


def test_cross_signer_token_rejected(env):
    from app.routers import signature_public as pub
    from app.services.signature_public_link import generate_signing_link

    class _Req:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    pid = _seed_sent_packet(with_signer=SIGNER)
    # Mint a link for a signer who is NOT assigned to this packet.
    link = generate_signing_link(pid, OTHER)
    with pytest.raises(Exception) as exc:
        pub.public_get_signing_detail(link["token"], _Req())
    assert getattr(exc.value, "status_code", None) == 403


def test_revoked_token_rejected(env):
    from app.routers import signature_public as pub
    from app.services.signature_public_link import generate_signing_link, revoke_token

    class _Req:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    pid = _seed_sent_packet()
    link = generate_signing_link(pid, SIGNER)
    revoke_token(link["jti"])
    with pytest.raises(Exception) as exc:
        pub.public_get_signing_detail(link["token"], _Req())
    assert getattr(exc.value, "status_code", None) == 403


def test_disabled_flag_returns_404(env):
    from app.routers import signature_public as pub

    class _Req:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    object.__setattr__(S, "signature_public_link_enabled", False)
    with pytest.raises(Exception) as exc:
        pub.public_get_signing_detail("anything", _Req())
    assert getattr(exc.value, "status_code", None) == 404


# ─── SUX-005: owner create-link + revoke (audit) ─────────────────────────────

def test_owner_create_and_revoke_link(env):
    from app.routers import signature_packets as sp

    pid = _seed_sent_packet()
    out = sp.create_signer_signing_link(pid, SIGNER, user_sub=OWNER)
    assert out["packet_id"] == pid
    assert "/ui/sign/" in out["url"]
    assert out["expires_at"] > 0

    # audit event recorded
    events = sp.list_packet_events(pid)
    assert any(e["event_type"] == "signing_link_created" for e in events)

    # Non-owner cannot mint
    with pytest.raises(Exception) as exc:
        sp.create_signer_signing_link(pid, SIGNER, user_sub=OTHER)
    assert getattr(exc.value, "status_code", None) == 403

    # Revoke
    from app.services.signature_public_link import mint_signing_token, verify_signing_token

    tok = mint_signing_token(pid, SIGNER)
    jti = verify_signing_token(tok)["jti"]
    rev = sp.revoke_signer_signing_link(pid, SIGNER, sp.RevokeSigningLinkIn(jti=jti), user_sub=OWNER)
    assert rev["revoked"] is True
    events = sp.list_packet_events(pid)
    assert any(e["event_type"] == "signing_link_revoked" for e in events)


# ─── SUX-007: inbox endpoints ────────────────────────────────────────────────

def test_awaiting_and_sent_inbox(env):
    from app.routers import signature_packets as sp

    pid = _seed_sent_packet()

    awaiting = sp.list_awaiting_my_signature(user_sub=SIGNER)
    assert awaiting["count"] == 1
    item = awaiting["items"][0]
    assert item["packet_id"] == pid
    assert item["status_chip"] == "awaiting_your_signature"
    assert item["source_name"] == "contract.pdf"

    # Owner's "sent" list shows the packet
    sent = sp.list_sent_by_me(user_sub=OWNER)
    assert any(i["packet_id"] == pid for i in sent["items"])

    # The owner is not awaiting their own packet
    owner_awaiting = sp.list_awaiting_my_signature(user_sub=OWNER)
    assert owner_awaiting["count"] == 0


def test_completed_for_me_after_signing(env):
    from app.routers import signature_packets as sp

    pid = _seed_sent_packet()
    # Complete via the store paths the public flow uses.
    store.mark_signer_notice_accepted(pid, SIGNER, S.signature_packet_legal_notice_version)
    store.fill_packet_field(
        packet_id=pid, field_id="f1", value="Alice", filled_by_signer_id=SIGNER,
        capture_mode="typed", render_payload={"kind": "typed_text", "text": "Alice"},
    )
    store.mark_signer_completed(pid, SIGNER, source_ip="1.1.1.1")

    completed = sp.list_completed_for_me(user_sub=SIGNER)
    assert any(i["packet_id"] == pid for i in completed["items"])
    # No longer awaiting
    awaiting = sp.list_awaiting_my_signature(user_sub=SIGNER)
    assert all(i["packet_id"] != pid for i in awaiting["items"])


# ─── SUX-014: origin_channel acceptance ──────────────────────────────────────

def test_new_origin_channels_accepted(env):
    from app.routers.signature_packets import CreateSignaturePacketIn

    for ch in ("share", "message", "file_manager", "kyc"):
        m = CreateSignaturePacketIn(source_path="/x.pdf", origin_channel=ch)
        assert m.origin_channel == ch
