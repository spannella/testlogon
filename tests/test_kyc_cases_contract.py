from __future__ import annotations

from app.contracts.kyc_cases_contract import (
    KYC_CONTRACT_VERSION,
    KycAdminDecisionRequest,
    KycAdminQueueEnvelope,
    KycAdminQueueItem,
    KycAdminCaseDetailEnvelope,
    KycAdminCaseDetailOut,
    KycAdminTimelineEvent,
    KycMetricsSummaryEnvelope,
    KycMetricsSummaryOut,
    KycPurgeRunEnvelope,
    KycPurgeRunOut,
    KycAdminRequestInfoRequest,
    KycCaseEnvelope,
    KycFileAttachmentRequest,
    KycFileValidationEnvelope,
    KycFileValidationOut,
    KycLinkSignaturePacketRequest,
    KycSignatureStatusEnvelope,
    KycSignatureStatusOut,
    KycCaseOut,
    KycErrorEnvelope,
    KycQuestionnaireStatusEnvelope,
    KycQuestionnaireStatusOut,
    KycStartQuestionnaireRequest,
    KycReadinessEnvelope,
    KycReadinessOut,
    KycSubmitCaseRequest,
    kyc_validation_error_envelope,
    kyc_error_envelope,
    kyc_error_http_status,
)
from pydantic import ValidationError


def test_case_out_uses_contract_version_and_defaults() -> None:
    case = KycCaseOut(
        kyc_case_id="kyc_123",
        user_sub="user_1",
        status="draft",
        created_at=1,
        updated_at=1,
        version=1,
    )

    assert case.contract_version == KYC_CONTRACT_VERSION
    assert case.questionnaire.response_session_id is None
    assert case.files == []
    assert case.missing_requirements == []


def test_case_envelope_validation() -> None:
    payload = {
        "case": {
            "kyc_case_id": "kyc_123",
            "user_sub": "user_1",
            "status": "draft",
            "created_at": 1,
            "updated_at": 1,
            "version": 1,
            "questionnaire": {},
            "files": [],
            "signature": {},
            "review": {},
            "missing_requirements": [],
        }
    }

    env = KycCaseEnvelope.model_validate(payload)
    assert env.case.kyc_case_id == "kyc_123"


def test_error_envelope_and_http_status_mapping() -> None:
    err = kyc_error_envelope("kyc_case_update_conflict", details={"kyc_case_id": "kyc_123"})
    parsed = KycErrorEnvelope.model_validate(err)

    assert parsed.error.code == "kyc_case_update_conflict"
    assert "refresh and retry" in parsed.error.message
    assert parsed.error.details == {"kyc_case_id": "kyc_123"}
    assert kyc_error_http_status("kyc_case_update_conflict") == 409
    assert kyc_error_http_status("kyc_case_not_found") == 404


def test_admin_and_readiness_contracts_validate() -> None:
    readiness = KycReadinessEnvelope(
        readiness=KycReadinessOut(
            kyc_case_id="kyc_123",
            status="draft",
            ready_to_submit=False,
            missing_requirements=["questionnaire_submitted"],
            missing_hints=["Submit the linked questionnaire to continue."],
            checks={"questionnaire_submitted": False},
            requirements=[
                {
                    "key": "questionnaire_submitted",
                    "ready": False,
                    "missing": ["questionnaire_submission"],
                    "hint": "Submit the linked questionnaire to continue.",
                    "refs": {"questionnaire_id": "q_1", "response_session_id": "resp_1", "response_pdf_ref": None},
                }
            ],
        )
    )
    assert readiness.readiness.ready_to_submit is False

    queue = KycAdminQueueEnvelope(
        items=[
            KycAdminQueueItem(
                kyc_case_id="kyc_1",
                user_sub="user_1",
                status="submitted",
                created_at=1,
                updated_at=2,
            )
        ]
    )
    assert queue.items[0].status == "submitted"

    detail = KycAdminCaseDetailEnvelope(
        case=KycAdminCaseDetailOut(
            kyc_case_id="kyc_123",
            user_sub="user_1",
            status="under_review",
            questionnaire_ref={"response_session_id": "resp_1", "response_pdf_ref": "QNR#q#PDF#resp"},
            files_ref=[{"type": "selfie", "path": "/kyc/selfie.jpg"}],
            signature_ref={"packet_id": "pkt_1", "final_pdf_ref": "packet:pkt_1:final-pdf"},
            ticket_ref={"ticket_id": "tkt_kyc_kyc_123", "status": "in_progress"},
            decision_state={"decision": None, "reason_codes": []},
            timeline=[KycAdminTimelineEvent(event_type="ticket_opened", source="ticket", created_at=1, actor_sub="user_1")],
        )
    )
    assert detail.case.ticket_ref["ticket_id"] == "tkt_kyc_kyc_123"

    metrics = KycMetricsSummaryEnvelope(
        metrics=KycMetricsSummaryOut(
            funnel_counts={"draft": 1},
            review_latency_seconds={"p50": 10.0},
            stale_queue_count=0,
            submit_guard_failures_by_reason={"signature_completed": 2},
        )
    )
    assert metrics.metrics.submit_guard_failures_by_reason["signature_completed"] == 2

    purge = KycPurgeRunEnvelope(
        purge=KycPurgeRunOut(scanned_statuses=["rejected"], purged_case_ids=["kyc_1"], purged_count=1, dry_run=False)
    )
    assert purge.purge.purged_count == 1

    req_info = KycAdminRequestInfoRequest(expected_version=1, requested_items=["id_back"], note="Upload clearer image")
    assert req_info.requested_items == ["id_back"]

    decision = KycAdminDecisionRequest(expected_version=2, decision="approve", note="Looks good")
    assert decision.decision == "approve"

    start_req = KycStartQuestionnaireRequest(published_slug="kyc-basic")
    assert start_req.published_slug == "kyc-basic"

    qstatus = KycQuestionnaireStatusEnvelope(
        questionnaire=KycQuestionnaireStatusOut(
            kyc_case_id="kyc_123",
            questionnaire_bound=True,
            questionnaire_id="q_1",
            version_id="v_1",
            response_session_id="resp_1",
            submitted=True,
            response_pdf_ref="QNR#q_1#PDF#RESP#resp_1",
            ready_for_submit_gate=True,
        )
    )
    assert qstatus.questionnaire.ready_for_submit_gate is True

    attach = KycFileAttachmentRequest(expected_version=1, file_type="selfie", path="/kyc/selfie.jpg")
    assert attach.file_type == "selfie"

    fstatus = KycFileValidationEnvelope(
        files=KycFileValidationOut(
            kyc_case_id="kyc_123",
            required_types=["selfie", "id_front", "id_back"],
            present_types=["selfie"],
            missing_types=["id_front", "id_back"],
            invalid_attachments=[],
            ready_for_submit_gate=False,
        )
    )
    assert fstatus.files.missing_types == ["id_front", "id_back"]

    sig_link = KycLinkSignaturePacketRequest(expected_version=2, source_path="/policies/kyc-consent.pdf", origin_channel="share")
    assert sig_link.source_path.endswith(".pdf")

    sig_status = KycSignatureStatusEnvelope(
        signature=KycSignatureStatusOut(
            kyc_case_id="kyc_123",
            packet_id="pkt_1",
            packet_status="completed",
            completed=True,
            final_pdf_ready=True,
            final_pdf_ref="packet:pkt_1:final-pdf",
            legal_notice_version="2026-01",
            legal_notice_accepted=True,
            ready_for_submit_gate=True,
        )
    )
    assert sig_status.signature.ready_for_submit_gate is True

    submit_req = KycSubmitCaseRequest(expected_version=3)
    assert submit_req.expected_version == 3


def test_validation_errors_return_deterministic_kyc_invalid_request_envelope() -> None:
    try:
        KycAdminDecisionRequest(expected_version=0, decision="unknown", note="")
        raise AssertionError("expected validation error")
    except ValidationError as exc:
        envelope = kyc_validation_error_envelope(exc)

    parsed = KycErrorEnvelope.model_validate(envelope)
    assert parsed.error.code == "kyc_invalid_request"
    assert isinstance(parsed.error.details, dict)
    assert "errors" in parsed.error.details
