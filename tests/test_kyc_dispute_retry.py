"""KYD-001..007 (KYC disputes & retry): hermetic offline tests.

Covers the service layer (dispute_case / reopen_case / apply_admin_decision
from disputed) plus the webhook-event emission, following the conventions in
CLAUDE.md and tests/test_gap_0272_0273_kyc_decision_events.py:

* The ``KycCaseStore`` takes an injected ``_table`` handle, so there is NO
  global moto/@mock_aws interception and NO real AWS reachability.
* The webhook emit is spied by monkeypatching the module-level
  ``_emit_kyc_event_safe`` helper.
* Frozen ``S`` flags are toggled via ``object.__setattr__`` and restored.

A router-level test (handlers called directly with stubbed deps) asserts 403
for non-owner, 409 for ``kyc_retry_limit_reached`` and feature-flag gating.
"""
from __future__ import annotations

import asyncio

import pytest

import app.services.kyc_cases as svc
from app.core.settings import S
from app.services.kyc_cases import (
    KycCaseConflictError,
    KycCaseStore,
    KycCaseValidationError,
)


class _FakeTable:
    """In-memory DynamoDB stand-in (copied from the GAP-0272/0273 test)."""

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
        # Honour the status guards on the conditional writes so a wrong-status
        # write is rejected like real DynamoDB would.
        if ConditionExpression and "#status = :rejected" in ConditionExpression:
            allowed = {ExpressionAttributeValues[":rejected"]}
            if ":expired" in ExpressionAttributeValues:
                allowed.add(ExpressionAttributeValues[":expired"])
            assert str(item.get("status") or "") in allowed

        set_part = UpdateExpression.replace("SET", "", 1).strip()
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
        self.items[(Key["pk"], Key["sk"])] = item


@pytest.fixture
def set_setting():
    """Set a frozen-dataclass S field and restore it on teardown."""
    saved: list[tuple[str, object]] = []

    def _set(name: str, value: object) -> None:
        saved.append((name, getattr(S, name)))
        object.__setattr__(S, name, value)

    yield _set
    for name, value in reversed(saved):
        object.__setattr__(S, name, value)


def _spy_emit(monkeypatch) -> list[dict]:
    emitted: list[dict] = []

    def _fake(**kw):
        emitted.append(kw)

    monkeypatch.setattr(svc, "_emit_kyc_event_safe", _fake)
    return emitted


def _rejected_case(store: KycCaseStore, *, user_sub: str = "usr_alice", decided_at: int | None = None) -> dict:
    """Create a case and drive it to rejected via the normal admin path."""
    created = store.create_case(user_sub=user_sub, status="under_review")
    out = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=created["version"],
        admin_sub="admin_charlie",
        decision="reject",
        reason_codes=["doc_unclear"],
        note="blurry id",
        decision_hash="rej1",
    )
    if decided_at is not None:
        # Backdate the decision to test the dispute window.
        review = dict(out["review"])
        review["decided_at"] = decided_at
        store._table.update_item(
            Key={"pk": svc._case_pk(out["kyc_case_id"]), "sk": "META"},
            UpdateExpression="SET review=:r",
            ExpressionAttributeValues={":r": review},
        )
        out = store.get_case(out["kyc_case_id"])
    return out


# ---------------------------------------------------------------------------
# KYD-002: dispute_case
# ---------------------------------------------------------------------------


def test_dispute_case_happy_path_emits_event(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    emitted = _spy_emit(monkeypatch)

    out = store.dispute_case(
        case_id=rejected["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=rejected["version"],
        reason="documents were valid",
        note="please re-check",
    )

    assert out is not None
    assert out["status"] == "disputed"
    assert out["version"] == rejected["version"] + 1
    dispute = out["review"]["dispute"]
    assert dispute["reason"] == "documents were valid"
    assert dispute["disputed_by"] == "usr_alice"
    assert dispute["dispute_count"] == 1
    assert out["gsi_status_pk"] == svc._status_pk("disputed")
    # Exactly one kyc.case.disputed event.
    assert len(emitted) == 1
    assert emitted[0]["event"] == "kyc.case.disputed"
    assert emitted[0]["user_sub"] == "usr_alice"


def test_dispute_case_idempotent_replay_emits_once(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    emitted = _spy_emit(monkeypatch)

    first = store.dispute_case(
        case_id=rejected["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=rejected["version"],
        reason="same reason",
        note="same note",
    )
    replay = store.dispute_case(
        case_id=rejected["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=first["version"],
        reason="same reason",
        note="same note",
    )
    assert replay["version"] == first["version"]  # no new write
    assert len(emitted) == 1


def test_dispute_case_wrong_status_raises(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    _spy_emit(monkeypatch)
    with pytest.raises(KycCaseValidationError) as exc:
        store.dispute_case(
            case_id=created["kyc_case_id"],
            owner_sub="usr_alice",
            expected_version=created["version"],
            reason="x",
        )
    assert str(exc.value) == "kyc_invalid_transition"


def test_dispute_case_window_expired_raises(monkeypatch, set_setting) -> None:
    store = KycCaseStore(_table=_FakeTable())
    set_setting("kyc_dispute_window_days", 30)
    # decided 1000 days ago -> way past the 30-day window.
    rejected = _rejected_case(store, decided_at=svc.now_ts() - 1000 * 24 * 3600)
    _spy_emit(monkeypatch)
    with pytest.raises(KycCaseValidationError) as exc:
        store.dispute_case(
            case_id=rejected["kyc_case_id"],
            owner_sub="usr_alice",
            expected_version=rejected["version"],
            reason="too late",
        )
    assert str(exc.value) == "kyc_dispute_window_expired"


def test_dispute_case_non_owner_raises() -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    with pytest.raises(KycCaseValidationError) as exc:
        store.dispute_case(
            case_id=rejected["kyc_case_id"],
            owner_sub="usr_bob",
            expected_version=rejected["version"],
            reason="x",
        )
    assert str(exc.value) == "kyc_access_forbidden"


def test_dispute_case_stale_version_conflict() -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    with pytest.raises(KycCaseConflictError):
        store.dispute_case(
            case_id=rejected["kyc_case_id"],
            owner_sub="usr_alice",
            expected_version=rejected["version"] + 5,
            reason="x",
        )


# ---------------------------------------------------------------------------
# KYD-003: reopen_case
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("from_status", ["rejected", "expired"])
def test_reopen_case_resets_and_preserves(monkeypatch, from_status, set_setting) -> None:
    store = KycCaseStore(_table=_FakeTable())
    set_setting("kyc_retry_max_attempts", 3)
    if from_status == "rejected":
        case = _rejected_case(store)
    else:
        created = store.create_case(user_sub="usr_alice", status="draft")
        case = store.update_case_status(
            case_id=created["kyc_case_id"],
            expected_version=created["version"],
            new_status="expired",
            actor_sub="system",
        )
    # Attach a file + questionnaire to verify preservation.
    files = [{"path": "/kyc/id.png", "type": "id_front"}]
    qref = {"questionnaire_id": "q1", "version_id": "v1", "response_session_id": "s1", "response_pdf_ref": None}
    case = store.update_case_links(
        case_id=case["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=case["version"],
        files=files,
        questionnaire=qref,
    )

    emitted = _spy_emit(monkeypatch)
    out = store.reopen_case(
        case_id=case["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=case["version"],
    )
    assert out["status"] == "draft"
    assert out["version"] == case["version"] + 1
    assert out["review"]["attempt_count"] == 1
    assert "decision" not in out["review"]
    assert out["review"]["reason_codes"] == []
    # submission cleared, files + questionnaire preserved.
    assert out["submission"]["submitted_at"] is None
    assert out["files"] == files
    assert out["questionnaire"]["questionnaire_id"] == "q1"
    # No user webhook (kyc.case.reopened is internal-only).
    assert len(emitted) == 1
    assert emitted[0]["event"] == "kyc.case.reopened"


def test_reopen_case_attempt_limit_exhausted(monkeypatch, set_setting) -> None:
    store = KycCaseStore(_table=_FakeTable())
    set_setting("kyc_retry_max_attempts", 2)
    case = _rejected_case(store)
    # Pre-set attempt_count to the max.
    review = dict(case["review"])
    review["attempt_count"] = 2
    store._table.update_item(
        Key={"pk": svc._case_pk(case["kyc_case_id"]), "sk": "META"},
        UpdateExpression="SET review=:r",
        ExpressionAttributeValues={":r": review},
    )
    case = store.get_case(case["kyc_case_id"])
    with pytest.raises(KycCaseValidationError) as exc:
        store.reopen_case(
            case_id=case["kyc_case_id"],
            owner_sub="usr_alice",
            expected_version=case["version"],
        )
    assert str(exc.value) == "kyc_retry_limit_reached"
    # Unchanged.
    assert store.get_case(case["kyc_case_id"])["status"] == "rejected"


def test_reopen_case_wrong_status_raises() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="under_review")
    with pytest.raises(KycCaseValidationError) as exc:
        store.reopen_case(
            case_id=created["kyc_case_id"],
            owner_sub="usr_alice",
            expected_version=created["version"],
        )
    assert str(exc.value) == "kyc_invalid_transition"


# ---------------------------------------------------------------------------
# KYD-004: admin decision from disputed
# ---------------------------------------------------------------------------


def test_admin_decision_from_disputed_records_resolution(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    original_decided_at = rejected["review"]["decided_at"]
    disputed = store.dispute_case(
        case_id=rejected["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=rejected["version"],
        reason="appeal",
    )
    emitted = _spy_emit(monkeypatch)
    out = store.apply_admin_decision(
        case_id=disputed["kyc_case_id"],
        expected_version=disputed["version"],
        admin_sub="admin_charlie",
        decision="approve",
        reason_codes=["appeal_upheld"],
        note="ok on appeal",
        decision_hash="appeal_decision",
    )
    assert out["status"] == "approved"
    # Original rejection preserved.
    assert out["review"]["decision"] == "reject"
    assert out["review"]["decided_at"] == original_decided_at
    # Appeal outcome recorded separately.
    res = out["review"]["dispute_resolution"]
    assert res["outcome"] == "approved"
    assert res["resolved_by"] == "admin_charlie"
    assert len(emitted) == 1
    assert emitted[0]["event"] == "kyc.case.approved"


# ---------------------------------------------------------------------------
# KYD-007: resubmit event on retry
# ---------------------------------------------------------------------------


def test_resubmit_emits_resubmitted_event(monkeypatch, set_setting) -> None:
    store = KycCaseStore(_table=_FakeTable())
    set_setting("kyc_retry_max_attempts", 3)
    rejected = _rejected_case(store)
    reopened = store.reopen_case(
        case_id=rejected["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=rejected["version"],
    )
    emitted = _spy_emit(monkeypatch)
    out = store.submit_case(
        case_id=reopened["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=reopened["version"],
        evidence_snapshot={"q": "snapshot"},
    )
    assert out["status"] == "submitted"
    assert len(emitted) == 1
    assert emitted[0]["event"] == "kyc.case.resubmitted"
    assert emitted[0]["attempt_count"] == 1


def test_first_submit_emits_submitted_event(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="usr_alice", status="draft")
    emitted = _spy_emit(monkeypatch)
    out = store.submit_case(
        case_id=created["kyc_case_id"],
        owner_sub="usr_alice",
        expected_version=created["version"],
        evidence_snapshot={"q": "snapshot"},
    )
    assert out["status"] == "submitted"
    assert len(emitted) == 1
    assert emitted[0]["event"] == "kyc.case.submitted"


# ---------------------------------------------------------------------------
# KYD-005: router-level gating / ownership / retry-limit
# ---------------------------------------------------------------------------

import app.routers.kyc_cases as router_mod
from fastapi import HTTPException


class _User:
    def __init__(self, sub: str, role: str = "user") -> None:
        self.sub = sub
        self.role = role


class _Req:
    headers: dict[str, str] = {}


def _call(coro_or_fn, **kw):
    res = coro_or_fn(**kw)
    if asyncio.iscoroutine(res):
        return asyncio.get_event_loop().run_until_complete(res)
    return res


@pytest.fixture(autouse=True)
def _stub_router_side_effects(monkeypatch):
    """Stub out audit/metric/event side-effects so router handlers stay offline."""
    monkeypatch.setattr(router_mod, "audit_event", lambda *a, **k: None)
    monkeypatch.setattr(router_mod, "_audit_state_transition", lambda *a, **k: None)
    monkeypatch.setattr(router_mod, "_emit_kyc_metric", lambda *a, **k: None)
    yield


def test_dispute_endpoint_feature_disabled(monkeypatch, set_setting) -> None:
    set_setting("kyc_dispute_enabled", False)
    body = router_mod.KycDisputeRequest(expected_version=1, reason="x")
    with pytest.raises(HTTPException) as exc:
        router_mod.dispute_kyc_case(
            case_id="kyc_x", body=body, request=_Req(), _ctx={}, user=_User("usr_alice")
        )
    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["code"] == "kyc_feature_disabled"


def test_dispute_endpoint_non_owner_403(monkeypatch, set_setting) -> None:
    set_setting("kyc_dispute_enabled", True)
    store = KycCaseStore(_table=_FakeTable())
    rejected = _rejected_case(store)
    monkeypatch.setattr(router_mod, "STORE", store)
    body = router_mod.KycDisputeRequest(expected_version=rejected["version"], reason="x")
    with pytest.raises(HTTPException) as exc:
        router_mod.dispute_kyc_case(
            case_id=rejected["kyc_case_id"], body=body, request=_Req(), _ctx={}, user=_User("usr_bob")
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["error"]["code"] == "kyc_access_forbidden"


def test_reopen_endpoint_retry_limit_409(monkeypatch, set_setting) -> None:
    set_setting("kyc_retry_enabled", True)
    set_setting("kyc_retry_max_attempts", 1)
    store = KycCaseStore(_table=_FakeTable())
    case = _rejected_case(store)
    review = dict(case["review"])
    review["attempt_count"] = 1
    store._table.update_item(
        Key={"pk": svc._case_pk(case["kyc_case_id"]), "sk": "META"},
        UpdateExpression="SET review=:r",
        ExpressionAttributeValues={":r": review},
    )
    case = store.get_case(case["kyc_case_id"])
    monkeypatch.setattr(router_mod, "STORE", store)
    body = router_mod.KycReopenRequest(expected_version=case["version"])
    with pytest.raises(HTTPException) as exc:
        router_mod.reopen_kyc_case(
            case_id=case["kyc_case_id"], body=body, request=_Req(), _ctx={}, user=_User("usr_alice")
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["code"] == "kyc_retry_limit_reached"


def test_reopen_endpoint_happy_path(monkeypatch, set_setting) -> None:
    set_setting("kyc_retry_enabled", True)
    set_setting("kyc_retry_max_attempts", 3)
    store = KycCaseStore(_table=_FakeTable())
    case = _rejected_case(store)
    monkeypatch.setattr(router_mod, "STORE", store)
    body = router_mod.KycReopenRequest(expected_version=case["version"])
    out = router_mod.reopen_kyc_case(
        case_id=case["kyc_case_id"], body=body, request=_Req(), _ctx={}, user=_User("usr_alice")
    )
    assert out.case.status == "draft"
