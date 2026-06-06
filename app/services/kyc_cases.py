from __future__ import annotations

from dataclasses import dataclass, field
import base64
import hashlib
import json
import logging
import uuid
from typing import Any

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _emit_kyc_event_safe(*, event: str, user_sub: str, **kw: Any) -> None:
    """Emit a KYC webhook/notification event (KYC-011), lazy-import-safe.

    Never raises — a notification failure must not break a case transition.
    """
    try:
        from app.services.kyc_webhooks import emit_kyc_event

        emit_kyc_event(event=event, user_sub=user_sub, **kw)
    except Exception:  # pragma: no cover - defensive
        pass


_ALLOWED_STATUSES = {
    "draft",
    "submitted",
    "under_review",
    "needs_more_info",
    "approved",
    "rejected",
    "expired",
}


class KycCaseConflictError(ValueError):
    """Raised when optimistic concurrency version checks fail."""


class KycCaseValidationError(ValueError):
    """Raised when invalid KYC case inputs are provided."""


def _case_pk(case_id: str) -> str:
    return f"KYC#{case_id}"


def _updated_sk(ts: int, case_id: str) -> str:
    return f"UPDATED#{ts:013d}#KYC#{case_id}"


def _owner_pk(user_sub: str) -> str:
    return f"OWNER#{user_sub}"


def _status_pk(status: str) -> str:
    return f"STATUS#{status}"


def _empty_questionnaire_ref() -> dict[str, Any]:
    return {
        "questionnaire_id": None,
        "version_id": None,
        "response_session_id": None,
        "response_pdf_ref": None,
    }


def _empty_signature_ref() -> dict[str, Any]:
    return {
        "packet_id": None,
        "status": None,
        "final_pdf_ref": None,
    }


def _empty_review_ref() -> dict[str, Any]:
    return {
        "ticket_id": None,
        "assigned_admin_sub": None,
        "decision": None,
        "decided_at": None,
        "reason_codes": [],
        "last_ticket_version": None,
        "last_ticket_updated_at": None,
    }


def _empty_submission_ref() -> dict[str, Any]:
    return {
        "submitted_at": None,
        "evidence_snapshot": {},
        "evidence_hash": None,
    }


def _is_conditional_conflict(exc: ClientError) -> bool:
    return str(exc.response.get("Error", {}).get("Code", "")) == "ConditionalCheckFailedException"


@dataclass
class KycCaseStore:
    _table: Any = field(default=T.kyc_cases)

    def create_case(
        self,
        *,
        user_sub: str,
        status: str = "draft",
        intake_profile: str | None = None,
        questionnaire: dict[str, Any] | None = None,
        files: list[dict[str, Any]] | None = None,
        signature: dict[str, Any] | None = None,
        review: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_status = str(status or "draft").strip()
        if normalized_status not in _ALLOWED_STATUSES:
            raise KycCaseValidationError("invalid_kyc_case_status")

        ts = now_ts()
        case_id = f"kyc_{uuid.uuid4().hex[:12]}"
        item = {
            "pk": _case_pk(case_id),
            "sk": "META",
            "entity_type": "kyc_case",
            "kyc_case_id": case_id,
            "user_sub": user_sub,
            "status": normalized_status,
            "intake_profile": (intake_profile or "").strip() or None,
            "questionnaire": questionnaire or _empty_questionnaire_ref(),
            "files": files or [],
            "signature": signature or _empty_signature_ref(),
            "submission": _empty_submission_ref(),
            "review": review or _empty_review_ref(),
            "created_at": ts,
            "updated_at": ts,
            "version": 1,
            "gsi_owner_pk": _owner_pk(user_sub),
            "gsi_owner_sk": _updated_sk(ts, case_id),
            "gsi_status_pk": _status_pk(normalized_status),
            "gsi_status_sk": _updated_sk(ts, case_id),
        }
        self._table.put_item(Item=item)
        return item

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": _case_pk(case_id), "sk": "META"}).get("Item")

    def update_case_status(
        self,
        *,
        case_id: str,
        expected_version: int,
        new_status: str,
        actor_sub: str,
        reason_codes: list[str] | None = None,
        decision_note: str | None = None,
    ) -> dict[str, Any] | None:
        normalized_status = str(new_status or "").strip()
        if normalized_status not in _ALLOWED_STATUSES:
            raise KycCaseValidationError("invalid_kyc_case_status")

        existing = self.get_case(case_id)
        if not existing:
            return None

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        review = dict(existing.get("review") or {})
        review["last_actor_sub"] = actor_sub
        review["last_action_at"] = ts
        if reason_codes is not None:
            review["reason_codes"] = [str(code) for code in reason_codes]
        if decision_note is not None:
            review["decision_note"] = str(decision_note)

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, updated_at=:updated_at, version=:version, "
                    "gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk, "
                    "gsi_owner_sk=:gsi_owner_sk, review=:review"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": normalized_status,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_status_pk": _status_pk(normalized_status),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":review": review,
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    def update_draft(
        self,
        *,
        case_id: str,
        owner_sub: str,
        expected_version: int,
        intake_profile: str | None = None,
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None
        if str(existing.get("user_sub") or "") != owner_sub:
            raise KycCaseValidationError("kyc_access_forbidden")
        if str(existing.get("status") or "") != "draft":
            raise KycCaseValidationError("kyc_invalid_transition")

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET intake_profile=:intake_profile, updated_at=:updated_at, version=:version, "
                    "gsi_owner_sk=:gsi_owner_sk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeValues={
                    ":intake_profile": (intake_profile or "").strip() or None,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    def set_encrypted_pii(
        self,
        *,
        case_id: str,
        encrypted_pii: dict[str, Any],
        pii_hints: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Persist KYC-023 encrypted PII + masking hints onto a case META item.

        Merges with any previously-encrypted fields so repeated writes (e.g.
        adding tax_id after document_number) accumulate rather than replace.
        Does not bump the optimistic ``version`` — PII writes are out-of-band
        from the case state machine.
        """
        existing = self.get_case(case_id)
        if not existing:
            return None
        merged_pii = dict(existing.get("encrypted_pii") or {})
        merged_pii.update(encrypted_pii or {})
        merged_hints = dict(existing.get("pii_hints") or {})
        merged_hints.update(pii_hints or {})
        ts = now_ts()
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": "META"},
            UpdateExpression="SET encrypted_pii=:e, pii_hints=:h, updated_at=:u",
            ExpressionAttributeValues={
                ":e": merged_pii,
                ":h": merged_hints,
                ":u": ts,
            },
        )
        return self.get_case(case_id)

    def update_case_links(
        self,
        *,
        case_id: str,
        owner_sub: str,
        expected_version: int,
        questionnaire: dict[str, Any] | None = None,
        files: list[dict[str, Any]] | None = None,
        signature: dict[str, Any] | None = None,
        review_ticket_id: str | None = None,
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None
        if str(existing.get("user_sub") or "") != owner_sub:
            raise KycCaseValidationError("kyc_access_forbidden")

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        review = dict(existing.get("review") or _empty_review_ref())
        if review_ticket_id is not None:
            review["ticket_id"] = review_ticket_id

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET questionnaire=:questionnaire, files=:files, signature=:signature, review=:review, "
                    "updated_at=:updated_at, version=:version, gsi_owner_sk=:gsi_owner_sk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeValues={
                    ":questionnaire": questionnaire or dict(existing.get("questionnaire") or _empty_questionnaire_ref()),
                    ":files": files if files is not None else list(existing.get("files") or []),
                    ":signature": signature or dict(existing.get("signature") or _empty_signature_ref()),
                    ":review": review,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    def submit_case(
        self,
        *,
        case_id: str,
        owner_sub: str,
        expected_version: int,
        evidence_snapshot: dict[str, Any],
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None
        if str(existing.get("user_sub") or "") != owner_sub:
            raise KycCaseValidationError("kyc_access_forbidden")

        current_status = str(existing.get("status") or "")
        canonical_evidence = json.dumps(evidence_snapshot, sort_keys=True, separators=(",", ":"))
        evidence_hash = hashlib.sha256(canonical_evidence.encode("utf-8")).hexdigest()
        if current_status == "submitted":
            previous_hash = str(((existing.get("submission") or {}).get("evidence_hash") or "")).strip()
            if previous_hash and previous_hash != evidence_hash:
                raise KycCaseConflictError("kyc_case_update_conflict")
            return existing
        if current_status not in {"draft", "needs_more_info"}:
            raise KycCaseValidationError("kyc_invalid_transition")

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        submission = {
            "submitted_at": ts,
            "evidence_snapshot": evidence_snapshot,
            "evidence_hash": evidence_hash,
        }

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, submission=:submission, missing_requirements=:missing_requirements, "
                    "updated_at=:updated_at, version=:version, gsi_owner_sk=:gsi_owner_sk, "
                    "gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": "submitted",
                    ":submission": submission,
                    ":missing_requirements": [],
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_pk": _status_pk("submitted"),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                    ":draft": "draft",
                    ":needs_more_info": "needs_more_info",
                },
                ConditionExpression="version = :expected_version AND (#status = :draft OR #status = :needs_more_info)",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                latest = self.get_case(case_id)
                if latest and str(latest.get("status") or "") == "submitted":
                    return latest
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        _emit_kyc_event_safe(
            event="kyc.case.submitted",
            user_sub=owner_sub,
            case_id=case_id,
            submitted_at=ts,
        )
        return self.get_case(case_id)

    def sync_from_ticket_event(
        self,
        *,
        case_id: str,
        expected_version: int,
        ticket_id: str,
        sync_event_id: str,
        ticket_status: str | None = None,
        ticket_version: int | None = None,
        ticket_updated_at: int | None = None,
        assigned_admin_sub: str | None = None,
        request_info: bool = False,
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        review = dict(existing.get("review") or _empty_review_ref())
        if str(review.get("ticket_id") or "").strip() and str(review.get("ticket_id") or "").strip() != ticket_id:
            raise KycCaseValidationError("kyc_invalid_request")
        if str(review.get("last_ticket_sync_event_id") or "").strip() == sync_event_id:
            return existing
        prior_ticket_version = review.get("last_ticket_version")
        prior_ticket_updated_at = review.get("last_ticket_updated_at")
        try:
            prior_ticket_version_int = int(prior_ticket_version) if prior_ticket_version is not None else None
        except (TypeError, ValueError):
            prior_ticket_version_int = None
        try:
            prior_ticket_updated_at_int = int(prior_ticket_updated_at) if prior_ticket_updated_at is not None else None
        except (TypeError, ValueError):
            prior_ticket_updated_at_int = None

        if ticket_version is not None and prior_ticket_version_int is not None:
            if int(ticket_version) < prior_ticket_version_int:
                return existing
            if int(ticket_version) == prior_ticket_version_int:
                if ticket_updated_at is None:
                    return existing
                if prior_ticket_updated_at_int is not None and int(ticket_updated_at) <= prior_ticket_updated_at_int:
                    return existing
        elif (
            ticket_version is None
            and ticket_updated_at is not None
            and prior_ticket_version_int is None
            and prior_ticket_updated_at_int is not None
            and int(ticket_updated_at) <= prior_ticket_updated_at_int
        ):
            return existing

        status_now = str(existing.get("status") or "")
        next_status = status_now
        normalized_ticket_status = str(ticket_status or "").strip().lower()
        if request_info or normalized_ticket_status == "waiting_on_user":
            next_status = "needs_more_info"
        elif normalized_ticket_status in {"open", "in_progress"} and status_now in {"submitted", "needs_more_info"}:
            next_status = "under_review"

        ts = now_ts()
        next_version = current_version + 1
        review["ticket_id"] = ticket_id
        if assigned_admin_sub is not None:
            review["assigned_admin_sub"] = assigned_admin_sub
        if normalized_ticket_status:
            review["last_ticket_status"] = normalized_ticket_status
        if ticket_version is not None:
            review["last_ticket_version"] = int(ticket_version)
        if ticket_updated_at is not None:
            review["last_ticket_updated_at"] = int(ticket_updated_at)
        review["last_ticket_sync_event_id"] = sync_event_id
        review["last_ticket_sync_at"] = ts
        if request_info:
            review["last_requested_info_at"] = ts

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, review=:review, updated_at=:updated_at, version=:version, "
                    "gsi_owner_sk=:gsi_owner_sk, gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": next_status,
                    ":review": review,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_pk": _status_pk(next_status),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    def request_more_info(
        self,
        *,
        case_id: str,
        expected_version: int,
        admin_sub: str,
        requested_items: list[str],
        note: str,
        request_hash: str,
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None

        review = dict(existing.get("review") or _empty_review_ref())
        if (
            str(existing.get("status") or "") == "needs_more_info"
            and str(review.get("last_request_info_hash") or "") == request_hash
        ):
            return existing
        if str(existing.get("status") or "") != "under_review":
            raise KycCaseValidationError("kyc_invalid_transition")

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        review["last_actor_sub"] = admin_sub
        review["last_action_at"] = ts
        review["requested_items"] = [str(item) for item in requested_items]
        review["last_request_info_note"] = str(note)
        review["last_request_info_hash"] = request_hash
        review["last_request_info_at"] = ts

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, review=:review, updated_at=:updated_at, version=:version, "
                    "gsi_owner_sk=:gsi_owner_sk, gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": "needs_more_info",
                    ":review": review,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_pk": _status_pk("needs_more_info"),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        # GAP-0273 (KYC-011): notify the applicant that more info is needed.
        # Best-effort — never blocks the transition (helper swallows failures).
        _emit_kyc_event_safe(
            event="kyc.case.needs_info",
            user_sub=str(existing.get("user_sub") or ""),
            case_id=case_id,
            requested_items=review.get("requested_items"),
            note=note,
            requested_by=admin_sub,
            requested_at=ts,
        )
        return self.get_case(case_id)

    def apply_admin_decision(
        self,
        *,
        case_id: str,
        expected_version: int,
        admin_sub: str,
        decision: str,
        reason_codes: list[str],
        note: str,
        decision_hash: str,
    ) -> dict[str, Any] | None:
        existing = self.get_case(case_id)
        if not existing:
            return None

        normalized = str(decision or "").strip().lower()
        if normalized not in {"approve", "reject"}:
            raise KycCaseValidationError("kyc_invalid_request")
        target_status = "approved" if normalized == "approve" else "rejected"

        review = dict(existing.get("review") or _empty_review_ref())
        current_status = str(existing.get("status") or "")
        if current_status in {"approved", "rejected"}:
            if (
                str(review.get("decision") or "") == normalized
                and str(review.get("decision_hash") or "") == decision_hash
            ):
                return existing
            raise KycCaseValidationError("kyc_invalid_transition")
        if current_status != "under_review":
            raise KycCaseValidationError("kyc_invalid_transition")

        current_version = int(existing.get("version") or 0)
        if current_version != int(expected_version):
            raise KycCaseConflictError("kyc_case_update_conflict")

        ts = now_ts()
        next_version = current_version + 1
        review["decision"] = normalized
        review["decided_at"] = ts
        review["reason_codes"] = [str(code) for code in reason_codes]
        review["decision_note"] = str(note)
        review["decision_actor_sub"] = admin_sub
        review["decision_hash"] = decision_hash
        review["last_actor_sub"] = admin_sub
        review["last_action_at"] = ts

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, review=:review, updated_at=:updated_at, version=:version, "
                    "gsi_owner_sk=:gsi_owner_sk, gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": target_status,
                    ":review": review,
                    ":updated_at": ts,
                    ":version": next_version,
                    ":gsi_owner_sk": _updated_sk(ts, case_id),
                    ":gsi_status_pk": _status_pk(target_status),
                    ":gsi_status_sk": _updated_sk(ts, case_id),
                    ":expected_version": current_version,
                },
                ConditionExpression="version = :expected_version",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KycCaseConflictError("kyc_case_update_conflict") from exc
            raise
        # GAP-0272 (KYC-011): notify the applicant of the final decision.
        # Best-effort — never blocks the transition (helper swallows failures).
        _emit_kyc_event_safe(
            event="kyc.case.approved" if target_status == "approved" else "kyc.case.rejected",
            user_sub=str(existing.get("user_sub") or ""),
            case_id=case_id,
            decision=normalized,
            reason_codes=reason_codes,
            note=note,
            decided_at=ts,
            admin_sub=admin_sub,
        )
        return self.get_case(case_id)

    def escalate_case(
        self,
        *,
        case_id: str,
        score: int,
        reason: str,
        actor_sub: str = "system_auto_escalate",
    ) -> dict[str, Any] | None:
        """Flag a case as escalated for senior review (GAP-0265 / KYC-008).

        Writes ``review.escalated``, ``review.escalation_reason``,
        ``review.escalated_at`` and ``review.escalated_by`` to the case META
        item. Does not change case status and does not bump ``version`` — the
        escalation flag is an administrative annotation, not a user-visible
        state transition, so it must not invalidate concurrent draft edits or
        the optimistic-concurrency checks used by user-facing mutations.

        No-op (returns the existing case unchanged) when the case is already in
        a terminal decision state (``approved`` / ``rejected``). Returns
        ``None`` when the case does not exist.
        """
        existing = self.get_case(case_id)
        if not existing:
            return None

        current_status = str(existing.get("status") or "")
        if current_status not in {"submitted", "under_review", "needs_more_info"}:
            # Terminal or pre-submission state — nothing to escalate.
            return existing

        ts = now_ts()
        review = dict(existing.get("review") or _empty_review_ref())
        review["escalated"] = True
        review["escalation_reason"] = str(reason)
        review["escalated_at"] = ts
        review["escalated_by"] = actor_sub

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression="SET review=:review, updated_at=:updated_at",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":review": review,
                    ":updated_at": ts,
                    ":submitted": "submitted",
                    ":under_review": "under_review",
                    ":needs_more_info": "needs_more_info",
                },
                ConditionExpression=(
                    "attribute_exists(pk) AND "
                    "(#status = :submitted OR #status = :under_review OR #status = :needs_more_info)"
                ),
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                # Status changed concurrently (e.g. decided just now); accept gracefully.
                logger.warning(
                    "kyc.escalate_case: condition failed for case %s (status changed?)",
                    case_id,
                )
                return self.get_case(case_id)
            raise
        return self.get_case(case_id)

    def list_cases_by_owner(self, *, user_sub: str, limit: int = 25) -> list[dict[str, Any]]:
        response = self._table.query(
            IndexName=S.kyc_cases_owner_index_name,
            KeyConditionExpression="gsi_owner_pk = :pk",
            ExpressionAttributeValues={":pk": _owner_pk(user_sub)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit or 25), 100)),
        )
        return [row for row in response.get("Items", []) if row.get("entity_type") == "kyc_case"]

    def list_cases_by_status(self, *, status: str, limit: int = 25) -> list[dict[str, Any]]:
        normalized_status = str(status or "").strip()
        if normalized_status not in _ALLOWED_STATUSES:
            raise KycCaseValidationError("invalid_kyc_case_status")
        response = self._table.query(
            IndexName=S.kyc_cases_status_index_name,
            KeyConditionExpression="gsi_status_pk = :pk",
            ExpressionAttributeValues={":pk": _status_pk(normalized_status)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit or 25), 100)),
        )
        return [row for row in response.get("Items", []) if row.get("entity_type") == "kyc_case"]

    def _encode_cursor(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8")

    def _decode_cursor(self, cursor: str | None) -> dict[str, Any]:
        if not cursor:
            return {}
        try:
            data = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
            parsed = json.loads(data)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
        return {}

    def list_admin_queue(
        self,
        *,
        statuses: list[str],
        assignee_sub: str | None = None,
        min_waiting_seconds: int | None = None,
        risk_tier: str | None = None,
        limit: int = 25,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        normalized_statuses = [str(s or "").strip() for s in statuses if str(s or "").strip() in _ALLOWED_STATUSES]
        if not normalized_statuses:
            normalized_statuses = ["submitted", "under_review", "needs_more_info"]
        now = now_ts()
        collected: list[dict[str, Any]] = []
        for status in normalized_statuses:
            collected.extend(self.list_cases_by_status(status=status, limit=200))

        def _risk(case: dict[str, Any]) -> str:
            intake = str(case.get("intake_profile") or "").strip().lower()
            if intake in {"enhanced", "high_risk"}:
                return "high"
            if intake in {"standard", "medium_risk"}:
                return "medium"
            return "low"

        filtered: list[dict[str, Any]] = []
        for item in collected:
            review = item.get("review") or {}
            assigned = str(review.get("assigned_admin_sub") or "").strip() or None
            if assignee_sub and assigned != assignee_sub:
                continue
            waiting_seconds = max(0, now - int(item.get("updated_at") or now))
            if min_waiting_seconds is not None and waiting_seconds < int(min_waiting_seconds):
                continue
            tier = _risk(item)
            if risk_tier and tier != risk_tier:
                continue
            filtered.append(
                {
                    **item,
                    "waiting_seconds": waiting_seconds,
                    "risk_tier": tier,
                }
            )

        filtered.sort(key=lambda row: (-int(row.get("updated_at") or 0), str(row.get("kyc_case_id") or "")))
        start = int(self._decode_cursor(cursor).get("offset") or 0)
        page_size = max(1, min(int(limit or 25), 100))
        page = filtered[start : start + page_size]
        next_cursor = None
        if start + page_size < len(filtered):
            next_cursor = self._encode_cursor({"offset": start + page_size})
        return {"items": page, "next_cursor": next_cursor}

    def get_metrics_snapshot(self, *, stale_after_seconds: int = 48 * 3600) -> dict[str, Any]:
        statuses = ["draft", "submitted", "under_review", "needs_more_info", "approved", "rejected"]
        funnel_counts: dict[str, int] = {}
        all_rows: list[dict[str, Any]] = []
        for status in statuses:
            rows = self.list_cases_by_status(status=status, limit=200)
            funnel_counts[status] = len(rows)
            all_rows.extend(rows)

        now = now_ts()
        stale_cutoff = now - max(1, int(stale_after_seconds))
        stale_queue_count = sum(
            1
            for row in all_rows
            if str(row.get("status") or "") in {"submitted", "under_review", "needs_more_info"}
            and int(row.get("updated_at") or 0) < stale_cutoff
        )

        latencies: list[int] = []
        for row in all_rows:
            if str(row.get("status") or "") not in {"approved", "rejected"}:
                continue
            submission = dict(row.get("submission") or {})
            submitted_at = int(submission.get("submitted_at") or 0)
            decided_at = int((row.get("review") or {}).get("decided_at") or 0)
            if submitted_at > 0 and decided_at >= submitted_at:
                latencies.append(decided_at - submitted_at)
        latencies.sort()

        def _pct(values: list[int], q: float) -> float | None:
            if not values:
                return None
            idx = int(round((len(values) - 1) * q))
            idx = max(0, min(idx, len(values) - 1))
            return float(values[idx])

        return {
            "funnel_counts": funnel_counts,
            "review_latency_seconds": {
                "p50": _pct(latencies, 0.50),
                "p90": _pct(latencies, 0.90),
                "p99": _pct(latencies, 0.99),
            },
            "stale_queue_count": stale_queue_count,
        }

    def run_retention_purge(self, *, dry_run: bool = False, now_epoch: int | None = None) -> dict[str, Any]:
        now = int(now_epoch or now_ts())
        rejected_cutoff = now - max(1, int(S.kyc_retention_rejected_days)) * 24 * 3600
        expired_cutoff = now - max(1, int(S.kyc_retention_expired_days)) * 24 * 3600
        scanned_statuses = ["rejected", "expired"]
        purged_case_ids: list[str] = []

        candidates: list[dict[str, Any]] = []
        for status in scanned_statuses:
            candidates.extend(self.list_cases_by_status(status=status, limit=200))

        for case in candidates:
            review = dict(case.get("review") or {})
            if review.get("purged_at"):
                continue
            status = str(case.get("status") or "")
            decided_at = int(review.get("decided_at") or 0)
            updated_at = int(case.get("updated_at") or 0)
            eligible = False
            if status == "rejected":
                anchor = decided_at or updated_at
                eligible = anchor > 0 and anchor <= rejected_cutoff
            elif status == "expired":
                eligible = updated_at > 0 and updated_at <= expired_cutoff
            if not eligible:
                continue
            purged_case_ids.append(str(case.get("kyc_case_id") or ""))
            if dry_run:
                continue

            case_id = str(case.get("kyc_case_id") or "")
            current_version = int(case.get("version") or 0)
            ts = now
            next_version = current_version + 1
            review["purged_at"] = ts
            review["purge_reason"] = "retention_window_elapsed"
            review["ticket_id"] = None
            submission = dict(case.get("submission") or _empty_submission_ref())
            submission["evidence_snapshot"] = {}
            submission["evidence_hash"] = None
            submission["purged_at"] = ts
            submission["purge_reason"] = "retention_window_elapsed"

            try:
                self._table.update_item(
                    Key={"pk": _case_pk(case_id), "sk": "META"},
                    UpdateExpression=(
                        "SET #status=:status, questionnaire=:questionnaire, files=:files, signature=:signature, submission=:submission, "
                        "review=:review, updated_at=:updated_at, version=:version, gsi_owner_sk=:gsi_owner_sk, "
                        "gsi_status_pk=:gsi_status_pk, gsi_status_sk=:gsi_status_sk"
                    ),
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":status": "expired",
                        ":questionnaire": _empty_questionnaire_ref(),
                        ":files": [],
                        ":signature": _empty_signature_ref(),
                        ":submission": submission,
                        ":review": review,
                        ":updated_at": ts,
                        ":version": next_version,
                        ":gsi_owner_sk": _updated_sk(ts, case_id),
                        ":gsi_status_pk": _status_pk("expired"),
                        ":gsi_status_sk": _updated_sk(ts, case_id),
                        ":expected_version": current_version,
                    },
                    ConditionExpression="version = :expected_version",
                )
            except ClientError as exc:
                if _is_conditional_conflict(exc):
                    continue
                raise

        return {
            "scanned_statuses": scanned_statuses,
            "purged_case_ids": purged_case_ids,
            "purged_count": len(purged_case_ids),
            "dry_run": bool(dry_run),
        }


STORE = KycCaseStore()
