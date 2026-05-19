from __future__ import annotations

import pytest

from app.services.kyc_cases import KycCaseConflictError, KycCaseStore, KycCaseValidationError


class _FakeTable:
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
            assert int(item.get("version") or 0) == int(ExpressionAttributeValues[":expected_version"])
        if ConditionExpression and "#status = :draft OR #status = :needs_more_info" in ConditionExpression:
            assert str(item.get("status") or "") in {"draft", "needs_more_info"}

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

    def query(self, **kwargs):
        index_name = kwargs.get("IndexName", "")
        pk = kwargs.get("ExpressionAttributeValues", {}).get(":pk")
        out: list[dict] = []
        for item in self.items.values():
            if item.get("entity_type") != "kyc_case":
                continue
            if index_name.endswith("owner-updated-index") and item.get("gsi_owner_pk") == pk:
                out.append(dict(item))
            if index_name.endswith("status-updated-index") and item.get("gsi_status_pk") == pk:
                out.append(dict(item))
        return {"Items": out[: kwargs.get("Limit", 25)]}


def test_create_and_get_case() -> None:
    store = KycCaseStore(_table=_FakeTable())

    created = store.create_case(user_sub="user_1")
    assert created["status"] == "draft"
    assert created["version"] == 1

    got = store.get_case(created["kyc_case_id"])
    assert got is not None
    assert got["user_sub"] == "user_1"
    assert got["questionnaire"]["questionnaire_id"] is None
    assert got["signature"]["packet_id"] is None
    assert got["review"]["ticket_id"] is None


def test_list_by_owner_and_status() -> None:
    store = KycCaseStore(_table=_FakeTable())

    case1 = store.create_case(user_sub="owner_a", status="draft")
    store.create_case(user_sub="owner_a", status="submitted")
    store.create_case(user_sub="owner_b", status="submitted")

    owner_rows = store.list_cases_by_owner(user_sub="owner_a")
    assert len(owner_rows) == 2
    assert {row["user_sub"] for row in owner_rows} == {"owner_a"}

    submitted = store.list_cases_by_status(status="submitted")
    assert len(submitted) == 2
    assert {row["status"] for row in submitted} == {"submitted"}
    assert case1["kyc_case_id"] not in {row["kyc_case_id"] for row in submitted}


def test_status_update_increments_version_and_sets_review_metadata() -> None:
    store = KycCaseStore(_table=_FakeTable())

    created = store.create_case(user_sub="user_1")
    updated = store.update_case_status(
        case_id=created["kyc_case_id"],
        expected_version=1,
        new_status="under_review",
        actor_sub="admin_1",
        reason_codes=["manual_review"],
        decision_note="Escalated",
    )

    assert updated is not None
    assert updated["status"] == "under_review"
    assert updated["version"] == 2
    assert updated["review"]["last_actor_sub"] == "admin_1"
    assert updated["review"]["reason_codes"] == ["manual_review"]


def test_update_case_links_updates_cross_system_references() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1")

    updated = store.update_case_links(
        case_id=created["kyc_case_id"],
        owner_sub="user_1",
        expected_version=1,
        questionnaire={
            "questionnaire_id": "q_1",
            "version_id": "v_1",
            "response_session_id": "resp_1",
            "response_pdf_ref": "s3://bucket/a.pdf",
        },
        files=[{"path": "/kyc/id-front.jpg", "type": "id_front"}],
        signature={"packet_id": "pkt_1", "status": "completed", "final_pdf_ref": "s3://bucket/signed.pdf"},
        review_ticket_id="tkt_1",
    )
    assert updated is not None
    assert updated["version"] == 2
    assert updated["questionnaire"]["response_session_id"] == "resp_1"
    assert updated["files"][0]["path"] == "/kyc/id-front.jpg"
    assert updated["signature"]["packet_id"] == "pkt_1"
    assert updated["review"]["ticket_id"] == "tkt_1"


def test_status_update_with_stale_version_raises_conflict() -> None:
    store = KycCaseStore(_table=_FakeTable())

    created = store.create_case(user_sub="user_1")
    with pytest.raises(KycCaseConflictError):
        store.update_case_status(
            case_id=created["kyc_case_id"],
            expected_version=999,
            new_status="submitted",
            actor_sub="user_1",
        )


def test_invalid_status_raises_validation_error() -> None:
    store = KycCaseStore(_table=_FakeTable())

    with pytest.raises(KycCaseValidationError):
        store.create_case(user_sub="user_1", status="nope")


def test_submit_case_transitions_and_persists_evidence_manifest() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1")

    submitted = store.submit_case(
        case_id=created["kyc_case_id"],
        owner_sub="user_1",
        expected_version=1,
        evidence_snapshot={
            "questionnaire": {"response_session_id": "resp_1", "response_pdf_ref": "QNR#q_1#PDF#RESP#resp_1"},
            "files": {"present_types": ["selfie", "id_front", "id_back"]},
            "signature": {"packet_id": "pkt_1", "final_pdf_ref": "packet:pkt_1:final-pdf"},
        },
    )

    assert submitted is not None
    assert submitted["status"] == "submitted"
    assert submitted["version"] == 2
    assert submitted["submission"]["submitted_at"] is not None
    assert submitted["submission"]["evidence_hash"]
    assert submitted["submission"]["evidence_snapshot"]["signature"]["packet_id"] == "pkt_1"


def test_submit_case_rejects_invalid_transition() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="under_review")

    with pytest.raises(KycCaseValidationError):
        store.submit_case(
            case_id=created["kyc_case_id"],
            owner_sub="user_1",
            expected_version=1,
            evidence_snapshot={"questionnaire": {}, "files": {}, "signature": {}},
        )


def test_submit_case_idempotent_retry_ignores_expected_version_after_submitted() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="draft")

    first = store.submit_case(
        case_id=created["kyc_case_id"],
        owner_sub="user_1",
        expected_version=1,
        evidence_snapshot={"questionnaire": {"response_session_id": "r1"}, "files": {"present_types": ["id_front", "selfie"]}, "signature": {"packet_id": "pkt_1"}},
    )
    assert first is not None
    assert first["status"] == "submitted"

    replay = store.submit_case(
        case_id=created["kyc_case_id"],
        owner_sub="user_1",
        expected_version=0,
        evidence_snapshot={"questionnaire": {"response_session_id": "r1"}, "files": {"present_types": ["id_front", "selfie"]}, "signature": {"packet_id": "pkt_1"}},
    )
    assert replay is not None
    assert replay["status"] == "submitted"
    assert replay["version"] == first["version"]


def test_submit_case_replay_with_mismatched_evidence_hash_conflicts() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="draft")
    first = store.submit_case(
        case_id=created["kyc_case_id"],
        owner_sub="user_1",
        expected_version=1,
        evidence_snapshot={"questionnaire": {"response_session_id": "r1"}, "files": {"present_types": ["selfie"]}, "signature": {"packet_id": "pkt_1"}},
    )
    assert first is not None
    with pytest.raises(KycCaseConflictError):
        store.submit_case(
            case_id=created["kyc_case_id"],
            owner_sub="user_1",
            expected_version=0,
            evidence_snapshot={"questionnaire": {"response_session_id": "r2"}, "files": {"present_types": ["selfie", "id_front"]}, "signature": {"packet_id": "pkt_2"}},
        )


def test_sync_from_ticket_event_updates_review_assignment_and_status() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="submitted")

    updated = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=1,
        ticket_id="tkt_kyc_case",
        sync_event_id="assigned:t1:2",
        ticket_status="in_progress",
        assigned_admin_sub="admin-1",
    )
    assert updated is not None
    assert updated["status"] == "under_review"
    assert updated["review"]["assigned_admin_sub"] == "admin-1"
    assert updated["review"]["last_ticket_sync_event_id"] == "assigned:t1:2"


def test_sync_from_ticket_event_is_idempotent_for_same_event_id() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="submitted")
    first = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=1,
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:3",
        ticket_status="waiting_on_user",
    )
    assert first is not None
    second = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:3",
        ticket_status="waiting_on_user",
    )
    assert second is not None
    assert second["version"] == first["version"]
    assert second["status"] == "needs_more_info"


def test_sync_from_ticket_event_ignores_out_of_order_ticket_versions() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="submitted")

    newest = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=1,
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:10:1000",
        ticket_status="in_progress",
        ticket_version=10,
        ticket_updated_at=1000,
        assigned_admin_sub="admin-1",
    )
    assert newest is not None
    assert newest["status"] == "under_review"
    assert newest["review"]["last_ticket_version"] == 10
    assert newest["review"]["last_ticket_updated_at"] == 1000

    stale = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=newest["version"],
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:9:900",
        ticket_status="waiting_on_user",
        ticket_version=9,
        ticket_updated_at=900,
        assigned_admin_sub="admin-2",
    )
    assert stale is not None
    assert stale["version"] == newest["version"]
    assert stale["status"] == "under_review"
    assert stale["review"]["assigned_admin_sub"] == "admin-1"


def test_sync_from_ticket_event_ignores_same_version_older_timestamp() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="submitted")
    first = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=1,
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:5:100",
        ticket_status="in_progress",
        ticket_version=5,
        ticket_updated_at=100,
    )
    assert first is not None
    replay_stale = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        ticket_id="tkt_kyc_case",
        sync_event_id="status:t1:5:99",
        ticket_status="waiting_on_user",
        ticket_version=5,
        ticket_updated_at=99,
    )
    assert replay_stale is not None
    assert replay_stale["version"] == first["version"]
    assert replay_stale["status"] == "under_review"


def test_sync_from_ticket_event_rejects_mismatched_ticket_id() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="user_1", status="submitted")
    linked = store.sync_from_ticket_event(
        case_id=created["kyc_case_id"],
        expected_version=1,
        ticket_id="tkt_kyc_1",
        sync_event_id="assigned:tkt_kyc_1:1",
        ticket_status="in_progress",
        assigned_admin_sub="admin-1",
    )
    assert linked is not None
    assert linked["review"]["ticket_id"] == "tkt_kyc_1"

    with pytest.raises(KycCaseValidationError):
        store.sync_from_ticket_event(
            case_id=created["kyc_case_id"],
            expected_version=2,
            ticket_id="tkt_other",
            sync_event_id="assigned:tkt_other:1",
            ticket_status="in_progress",
            assigned_admin_sub="admin-2",
        )


def test_list_admin_queue_filters_and_cursor() -> None:
    store = KycCaseStore(_table=_FakeTable())
    a = store.create_case(user_sub="u1", status="submitted", intake_profile="enhanced")
    b = store.create_case(user_sub="u2", status="under_review", intake_profile="standard")

    row_a = store.get_case(a["kyc_case_id"])
    row_b = store.get_case(b["kyc_case_id"])
    assert row_a and row_b
    row_a["review"]["assigned_admin_sub"] = "admin-1"
    row_b["review"]["assigned_admin_sub"] = "admin-1"
    store._table.put_item(Item=row_a)
    store._table.put_item(Item=row_b)

    page1 = store.list_admin_queue(statuses=["submitted", "under_review"], assignee_sub="admin-1", limit=1)
    assert len(page1["items"]) == 1
    assert page1["next_cursor"]

    page2 = store.list_admin_queue(
        statuses=["submitted", "under_review"],
        assignee_sub="admin-1",
        limit=1,
        cursor=page1["next_cursor"],
    )
    assert len(page2["items"]) == 1
    assert page1["items"][0]["kyc_case_id"] != page2["items"][0]["kyc_case_id"]


def test_request_more_info_transitions_and_is_idempotent() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="u1", status="under_review")

    first = store.request_more_info(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin-1",
        requested_items=["id_back"],
        note="Upload clearer id back",
        request_hash="h1",
    )
    assert first is not None
    assert first["status"] == "needs_more_info"
    assert first["review"]["requested_items"] == ["id_back"]

    second = store.request_more_info(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        admin_sub="admin-1",
        requested_items=["id_back"],
        note="Upload clearer id back",
        request_hash="h1",
    )
    assert second is not None
    assert second["version"] == first["version"]


def test_apply_admin_decision_is_terminal_and_idempotent() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="u1", status="under_review")

    first = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin-1",
        decision="approve",
        reason_codes=["doc_ok"],
        note="All checks passed",
        decision_hash="d1",
    )
    assert first is not None
    assert first["status"] == "approved"
    assert first["review"]["decision"] == "approve"

    replay = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=first["version"],
        admin_sub="admin-1",
        decision="approve",
        reason_codes=["doc_ok"],
        note="All checks passed",
        decision_hash="d1",
    )
    assert replay is not None
    assert replay["version"] == first["version"]


def test_apply_admin_decision_conflicting_second_decision_is_blocked() -> None:
    store = KycCaseStore(_table=_FakeTable())
    created = store.create_case(user_sub="u1", status="under_review")

    approved = store.apply_admin_decision(
        case_id=created["kyc_case_id"],
        expected_version=1,
        admin_sub="admin-1",
        decision="approve",
        reason_codes=["doc_ok"],
        note="ok",
        decision_hash="h-approve",
    )
    assert approved is not None
    assert approved["status"] == "approved"

    with pytest.raises(KycCaseValidationError):
        store.apply_admin_decision(
            case_id=created["kyc_case_id"],
            expected_version=1,
            admin_sub="admin-2",
            decision="reject",
            reason_codes=["fraud"],
            note="no",
            decision_hash="h-reject",
        )


def test_metrics_snapshot_includes_funnel_and_latency() -> None:
    store = KycCaseStore(_table=_FakeTable())
    row = store.create_case(user_sub="u1", status="approved")
    row["submission"] = {"submitted_at": 10}
    row["review"]["decided_at"] = 20
    store._table.put_item(Item=row)

    snapshot = store.get_metrics_snapshot(stale_after_seconds=60)
    assert "funnel_counts" in snapshot
    assert snapshot["funnel_counts"]["approved"] >= 1
    assert snapshot["review_latency_seconds"]["p50"] is not None


def test_run_retention_purge_redacts_expired_and_rejected_cases() -> None:
    store = KycCaseStore(_table=_FakeTable())
    rejected = store.create_case(user_sub="u1", status="rejected")
    expired = store.create_case(user_sub="u2", status="expired")
    rrow = store.get_case(rejected["kyc_case_id"])
    erow = store.get_case(expired["kyc_case_id"])
    assert rrow and erow
    rrow["updated_at"] = 1
    rrow["review"]["decided_at"] = 1
    rrow["questionnaire"]["response_session_id"] = "resp_1"
    rrow["files"] = [{"path": "/a.jpg", "type": "selfie"}]
    rrow["signature"]["packet_id"] = "pkt_1"
    erow["updated_at"] = 1
    store._table.put_item(Item=rrow)
    store._table.put_item(Item=erow)

    result = store.run_retention_purge(dry_run=False, now_epoch=10**9)
    assert result["purged_count"] >= 2

    r_after = store.get_case(rejected["kyc_case_id"])
    assert r_after is not None
    assert r_after["status"] == "expired"
    assert r_after["files"] == []
    assert r_after["review"]["purged_at"] is not None
