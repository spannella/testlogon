"""GAP-0272 / GAP-0273 (KYC-011): admin-decision webhook-event dispatch.

GAP-0272: ``apply_admin_decision`` must emit ``kyc.case.approved`` /
``kyc.case.rejected`` after a successful DDB update.
GAP-0273: ``request_more_info`` must emit ``kyc.case.needs_info`` (with
``requested_items`` + ``note``) after a successful DDB update.

Hermetic / offline. The ``KycCaseStore`` takes an injected table handle, so
there is NO global moto/@mock_aws interception and NO real AWS reachability.
The webhook emit is spied by monkeypatching the module-level
``_emit_kyc_event_safe`` helper (mirrors tests/test_kyc_cases_store.py).
"""
from __future__ import annotations

import pytest

import app.services.kyc_cases as svc
from app.services.kyc_cases import KycCaseStore


class _FakeTable:
    """In-memory DynamoDB stand-in (copied from tests/test_kyc_cases_store.py)."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def update_item(
        self,
        *,
        Key,
        UpdateExpression,
        ExpressionAttributeValues,
        ExpressionAttributeNames=None,
        ConditionExpression=None,
    ):
        item = dict(self.items[(Key["pk"], Key["sk"])])
        if ConditionExpression and "version = :expected_version" in ConditionExpression:
            assert int(item.get("version") or 0) == int(
                ExpressionAttributeValues[":expected_version"]
            )

        set_part = UpdateExpression.replace("SET", "", 1).strip()
        remove_part = ""
        if " REMOVE " in set_part:
            set_part, _, remove_part = set_part.partition(" REMOVE ")
        for assignment in set_part.split(","):
            assignment = assignment.strip()
            if not assignment:
                continue
            left, right = assignment.split("=")
            field = left.strip()
            token = right.strip()
            if ExpressionAttributeNames and field in ExpressionAttributeNames:
                field = ExpressionAttributeNames[field]
            item[field] = ExpressionAttributeValues.get(token, token)
        if remove_part:
            for attr_alias in remove_part.split(","):
                attr_alias = attr_alias.strip()
                if not attr_alias:
                    continue
                attr = (ExpressionAttributeNames or {}).get(attr_alias, attr_alias)
                item.pop(attr, None)
        self.items[(Key["pk"], Key["sk"])] = item


def _spy_emit(monkeypatch) -> list[dict]:
    """Replace _emit_kyc_event_safe with a spy; return the captured-call list."""
    emitted: list[dict] = []

    def _fake(**kw):
        emitted.append(kw)

    monkeypatch.setattr(svc, "_emit_kyc_event_safe", _fake)
    return emitted


# --------------------------------------------------------------------------
# GAP-0272: apply_admin_decision emits approved / rejected
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "decision,expected_event,expected_status",
    [
        ("approve", "kyc.case.approved", "approved"),
        ("reject", "kyc.case.rejected", "rejected"),
    ],
)
def test_apply_admin_decision_emits_event(
    monkeypatch, decision, expected_event, expected_status
) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    emitted = _spy_emit(monkeypatch)

    out = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin_charlie",
        decision=decision,
        reason_codes=["identity_confirmed"],
        note="looks good",
        decision_hash="hash_abc",
    )

    assert out is not None
    assert out["status"] == expected_status
    # GAP-0272: exactly one event fired with the right type/payload.
    assert len(emitted) == 1, f"expected 1 event, got {len(emitted)}"
    ev = emitted[0]
    assert ev["event"] == expected_event
    assert ev["user_sub"] == "usr_alice"
    assert ev["case_id"] == created["kyc_case_id"]
    assert ev["decision"] == decision


def test_apply_admin_decision_idempotent_replay_emits_once(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    emitted = _spy_emit(monkeypatch)

    first = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin_charlie",
        decision="approve",
        reason_codes=["doc_ok"],
        note="ok",
        decision_hash="d1",
    )
    # Idempotent replay (same hash, terminal state) returns early — no DDB write.
    store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        admin_sub="admin_charlie",
        decision="approve",
        reason_codes=["doc_ok"],
        note="ok",
        decision_hash="d1",
    )

    assert len(emitted) == 1, "idempotent replay must not emit a second event"


# --------------------------------------------------------------------------
# GAP-0273: request_more_info emits needs_info
# --------------------------------------------------------------------------


def test_request_more_info_emits_needs_info(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    emitted = _spy_emit(monkeypatch)

    out = store.request_more_info(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin_charlie",
        requested_items=["proof_of_address", "selfie_retake"],
        note="Documents are unclear",
        request_hash="hashxyz",
    )

    assert out is not None
    assert out["status"] == "needs_more_info"
    assert len(emitted) == 1, f"expected 1 event, got {len(emitted)}"
    ev = emitted[0]
    assert ev["event"] == "kyc.case.needs_info"
    assert ev["user_sub"] == "usr_alice"
    assert ev["case_id"] == created["kyc_case_id"]
    assert ev["note"] == "Documents are unclear"
    assert ev["requested_items"] == ["proof_of_address", "selfie_retake"]


def test_request_more_info_idempotent_replay_emits_once(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    emitted = _spy_emit(monkeypatch)

    first = store.request_more_info(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin_charlie",
        requested_items=["selfie_retake"],
        note="Please retake selfie",
        request_hash="hash_repeat",
    )
    # Idempotent replay (same hash, already needs_more_info) returns early.
    store.request_more_info(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        admin_sub="admin_charlie",
        requested_items=["selfie_retake"],
        note="Please retake selfie",
        request_hash="hash_repeat",
    )

    assert len(emitted) == 1, "idempotent re-request must not emit a second event"
