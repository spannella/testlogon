"""KYC-002: Identity Document Verification service.

Standalone document-verification feature that builds on top of the existing KYC
case feature (see ``app/services/kyc_cases.py``) without modifying it.

A user uploads an identity document image (id_front / id_back). The document is
stored in S3 (mocked in dev) and a record is written to the ``kyc_documents``
DynamoDB table. An extraction/verification pipeline then runs:

    pending  -> extracted  (fields extracted + matched against profile)
             -> failed     (extraction provider error / unreadable document)

Reviewers list pending/failed documents via the ``ByStatus`` GSI and
approve / reject them.

In dev (and E2E), a deterministic mock OCR provider is used: extraction results
are derived from filename patterns so tests are predictable. A "real" provider
is gated behind ``S.kyc_documents_real_extraction_enabled`` (default off) and is
intentionally not wired in dev.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _emit_kyc_event_safe(*, event: str, user_sub: str, **kw) -> None:
    """Emit a KYC webhook/notification event (KYC-011), lazy-import-safe."""
    if not user_sub:
        return
    try:
        from app.services.kyc_webhooks import emit_kyc_event

        emit_kyc_event(event=event, user_sub=user_sub, **kw)
    except Exception:  # pragma: no cover - defensive
        pass

# --- constants -------------------------------------------------------------

ALLOWED_DOCUMENT_TYPES = {"id_front", "id_back"}

STATUS_PENDING = "pending"
STATUS_EXTRACTED = "extracted"
STATUS_FAILED = "failed"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"

_ALL_STATUSES = {
    STATUS_PENDING,
    STATUS_EXTRACTED,
    STATUS_FAILED,
    STATUS_APPROVED,
    STATUS_REJECTED,
}

# statuses that can be listed via the ByStatus GSI for background / admin work
LISTABLE_STATUSES = {
    STATUS_PENDING,
    STATUS_EXTRACTED,
    STATUS_FAILED,
    STATUS_APPROVED,
    STATUS_REJECTED,
}

MATCH = "match"
MISMATCH = "mismatch"
PARTIAL = "partial"
NOT_AVAILABLE = "not_available"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_FAILED = "failed"


# --- errors ----------------------------------------------------------------


class KycDocumentValidationError(ValueError):
    """Invalid input supplied for a KYC document operation."""


class KycDocumentNotFoundError(LookupError):
    """A referenced KYC document does not exist."""


class KycDocumentStateError(RuntimeError):
    """A document is in a state that does not permit the requested operation."""


# --- helpers ---------------------------------------------------------------


def _new_document_id() -> str:
    return f"kycdoc_{uuid.uuid4().hex[:16]}"


def _new_extraction_id() -> str:
    return f"ext_{uuid.uuid4().hex[:12]}"


def _normalize_name(value: str | None) -> str:
    if not value:
        return ""
    collapsed = re.sub(r"\s+", " ", str(value).strip())
    return collapsed.upper()


def _name_similarity(a: str, b: str) -> float:
    na, nb = _normalize_name(a), _normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def _shift_dob_year(dob: str, delta: int) -> str:
    m = re.match(r"^(\d{4})(-\d{2}-\d{2})$", str(dob or ""))
    if not m:
        return str(dob or "")
    return f"{int(m.group(1)) + delta:04d}{m.group(2)}"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# --- service ---------------------------------------------------------------


@dataclass
class KycDocumentVerificationStore:
    """Persistence + verification pipeline for KYC identity documents."""

    _table: Any = field(default=T.kyc_documents)

    # -- profile access ----------------------------------------------------

    def _load_profile_identity(self, user_sub: str) -> dict[str, str | None]:
        """Return the profile fields used for matching (name, dob)."""
        try:
            from app.services.profile import get_profile

            profile = get_profile(user_sub)
        except Exception:  # pragma: no cover - defensive
            profile = {}
        display_name = profile.get("display_name")
        if not display_name:
            parts = [profile.get("first_name"), profile.get("last_name")]
            display_name = " ".join(p for p in parts if p) or None
        return {
            "full_name": display_name,
            "date_of_birth": profile.get("birthday"),
        }

    # -- S3 upload ---------------------------------------------------------

    def _store_image(self, *, document_id: str, file_name: str, content_b64: str | None) -> dict[str, Any]:
        """Store the uploaded document image in S3 (mocked in dev).

        Returns a dict with ``s3_key``, ``bucket`` and (dev) ``url``.
        """
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", file_name or "document.jpg")
        bucket = S.kyc_documents_bucket or "local-uploads"
        s3_key = f"{S.kyc_documents_s3_prefix}{document_id}/{safe_name}"

        body: bytes | None = None
        if content_b64:
            try:
                body = base64.b64decode(content_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise KycDocumentValidationError("invalid_document_image") from exc

        if body is not None:
            try:
                from app.core.aws_clients import s3_client

                s3_client().put_object(
                    Bucket=bucket, Key=s3_key, Body=body, ContentType="image/jpeg"
                )
            except Exception:  # pragma: no cover - dev mock best effort
                logger.warning("kyc.document.s3_put_failed key=%s", s3_key)

        out: dict[str, Any] = {"s3_key": s3_key, "bucket": bucket}
        if S.dev_mode:
            out["url"] = f"/mock/s3/{bucket}/{s3_key}"
        return out

    # -- public API --------------------------------------------------------

    def upload_document(
        self,
        *,
        user_sub: str,
        document_type: str,
        file_name: str,
        case_id: str | None = None,
        content_b64: str | None = None,
    ) -> dict[str, Any]:
        """Upload a document image and create a ``pending`` record."""
        doc_type = str(document_type or "").strip()
        if doc_type not in ALLOWED_DOCUMENT_TYPES:
            raise KycDocumentValidationError("invalid_document_type")
        if not str(file_name or "").strip():
            raise KycDocumentValidationError("missing_file_name")

        document_id = _new_document_id()
        ts = now_ts()
        storage = self._store_image(
            document_id=document_id, file_name=file_name, content_b64=content_b64
        )

        item: dict[str, Any] = {
            "document_id": document_id,
            "user_sub": user_sub,
            "case_id": case_id or "_none",
            "document_type": doc_type,
            "file_name": file_name,
            "status": STATUS_PENDING,
            "provider": S.kyc_documents_provider,
            "s3_key": storage["s3_key"],
            "bucket": storage["bucket"],
            "image_url": storage.get("url"),
            "extraction_id": None,
            "extracted_fields": {},
            "match_results": {},
            "overall_confidence": None,
            "review": {"decision": None, "reviewer_sub": None, "decided_at": None, "note": None},
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        logger.info("kyc.document.uploaded document_id=%s type=%s", document_id, doc_type)
        return item

    def get_document(self, document_id: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"document_id": document_id})
        return resp.get("Item")

    def list_documents_for_owner(self, user_sub: str) -> list[dict[str, Any]]:
        try:
            resp = self._table.query(
                IndexName="ByOwner",
                KeyConditionExpression=Key("user_sub").eq(user_sub),
                ScanIndexForward=False,
            )
            return list(resp.get("Items", []))
        except Exception:
            # GSI not available (e.g. older table) -> fall back to scan + filter
            resp = self._table.scan()
            items = [i for i in resp.get("Items", []) if i.get("user_sub") == user_sub]
            items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
            return items

    def list_documents_for_case(self, case_id: str) -> list[dict[str, Any]]:
        try:
            resp = self._table.query(
                IndexName="ByCase",
                KeyConditionExpression=Key("case_id").eq(case_id),
                ScanIndexForward=False,
            )
            return list(resp.get("Items", []))
        except Exception:
            resp = self._table.scan()
            items = [i for i in resp.get("Items", []) if i.get("case_id") == case_id]
            items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
            return items

    def list_by_status(
        self,
        status: str,
        *,
        limit: int = 100,
        case_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List documents by status using the ByStatus GSI (PK=status, SK=created_at).

        When ``case_id`` is provided, a DynamoDB ``FilterExpression`` is applied so
        only that case's documents (in the given status) are returned. The
        ``FilterExpression`` is evaluated server-side *after* the 1 MB page read, so
        it does not reduce read cost; the pagination loop below continues fetching
        until ``limit`` matching items are collected (or the partition is exhausted).
        Documents uploaded without a case are stored with the ``"_none"`` sentinel
        (see ``upload_document``); a real ``case_id`` filter never matches that
        sentinel, so case-less documents are correctly excluded.
        """
        st = str(status or "").strip()
        if st not in LISTABLE_STATUSES:
            raise KycDocumentValidationError("invalid_status")
        case = str(case_id).strip() if case_id else None
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_documents_status_index_name,
                "KeyConditionExpression": Key("status").eq(st),
                "ScanIndexForward": False,
                "Limit": min(limit, 500),
            }
            if case:
                kwargs["FilterExpression"] = Attr("case_id").eq(case)
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(items) >= limit:
                break
        return items[:limit]

    def run_extraction(self, document_id: str) -> dict[str, Any]:
        """Run (or re-run) the extraction/verification pipeline for a document.

        Idempotent: updates the existing record in place. Transitions
        ``pending`` -> ``extracted`` (or ``failed``).
        """
        item = self.get_document(document_id)
        if not item:
            raise KycDocumentNotFoundError(document_id)

        ts = now_ts()
        extraction_id = _new_extraction_id()
        provider_result = self._run_provider(
            file_name=str(item.get("file_name") or ""),
            document_type=str(item.get("document_type") or ""),
        )

        if provider_result["status"] == STATUS_FAILED:
            update = {
                "status": STATUS_FAILED,
                "extraction_id": extraction_id,
                "extracted_fields": {},
                "match_results": {},
                "overall_confidence": CONFIDENCE_FAILED,
                "provider": provider_result["provider"],
                "raw_response": provider_result["raw_response"],
                "updated_at": ts,
            }
            self._apply_update(document_id, update)
            logger.error("kyc.document.extraction_failed document_id=%s", document_id)
            return {**item, **update}

        extracted = provider_result["extracted_fields"]
        identity = self._load_profile_identity(str(item.get("user_sub") or ""))
        match_results = self._match_against_profile(extracted=extracted, identity=identity)
        confidence = self._compute_confidence(match_results)

        update = {
            "status": STATUS_EXTRACTED,
            "extraction_id": extraction_id,
            "extracted_fields": extracted,
            "match_results": match_results,
            "overall_confidence": confidence,
            "provider": provider_result["provider"],
            "raw_response": provider_result["raw_response"],
            "updated_at": ts,
        }
        self._apply_update(document_id, update)
        logger.info(
            "kyc.document.extracted document_id=%s confidence=%s", document_id, confidence
        )
        return {**item, **update}

    def review_document(
        self,
        *,
        document_id: str,
        decision: str,
        reviewer_sub: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Approve or reject a document (reviewer action)."""
        dec = str(decision or "").strip().lower()
        if dec not in ("approve", "reject"):
            raise KycDocumentValidationError("invalid_decision")
        item = self.get_document(document_id)
        if not item:
            raise KycDocumentNotFoundError(document_id)
        if str(item.get("status")) == STATUS_PENDING:
            raise KycDocumentStateError("document_not_extracted")

        new_status = STATUS_APPROVED if dec == "approve" else STATUS_REJECTED
        ts = now_ts()
        update = {
            "status": new_status,
            "review": {
                "decision": dec,
                "reviewer_sub": reviewer_sub,
                "decided_at": ts,
                "note": note,
            },
            "updated_at": ts,
        }
        self._apply_update(document_id, update)
        logger.info(
            "kyc.document.reviewed document_id=%s decision=%s reviewer=%s",
            document_id,
            dec,
            reviewer_sub,
        )
        _emit_kyc_event_safe(
            event="kyc.document.verified" if dec == "approve" else "kyc.document.rejected",
            user_sub=str(item.get("user_sub") or ""),
            case_id=str(item.get("case_id") or "") or None,
            document_id=document_id,
            decision=dec,
        )
        return {**item, **update}

    # -- internals ---------------------------------------------------------

    def _apply_update(self, document_id: str, update: dict[str, Any]) -> None:
        expr_names: dict[str, str] = {}
        expr_values: dict[str, Any] = {}
        sets: list[str] = []
        for i, (k, v) in enumerate(update.items()):
            nk = f"#k{i}"
            vk = f":v{i}"
            expr_names[nk] = k
            expr_values[vk] = v
            sets.append(f"{nk} = {vk}")
        self._table.update_item(
            Key={"document_id": document_id},
            UpdateExpression="SET " + ", ".join(sets),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

    def _run_provider(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        if S.kyc_documents_real_extraction_enabled:
            return self._run_real_extraction(file_name=file_name, document_type=document_type)
        return self._run_mock_extraction(file_name=file_name, document_type=document_type)

    def _run_real_extraction(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        """Placeholder for a real OCR provider integration.

        Intentionally not wired in dev / E2E. Falls back to the mock provider so
        the pipeline remains functional even if the flag is flipped on without a
        provider configured.
        """
        logger.warning("kyc.document.real_provider_not_configured falling back to mock")
        return self._run_mock_extraction(file_name=file_name, document_type=document_type)

    def _run_mock_extraction(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        """Deterministic mock OCR. Behaviour keyed off filename patterns.

        See KYC-002 spec section 8.3.
        """
        provider = "mock_ocr"
        lower = (file_name or "").lower()

        base_name = "ALICE SMITH"
        base_dob = "1990-05-15"

        if "_fail_" in lower or lower.endswith("_fail"):
            return {
                "status": STATUS_FAILED,
                "provider": provider,
                "extracted_fields": {},
                "raw_response": json.dumps({"provider": provider, "error": "unreadable_document"}),
            }

        full_name = base_name
        dob = base_dob
        expiry = "2030-12-31"

        if "_mismatch_" in lower:
            full_name = f"WRONG {base_name}"
            dob = _shift_dob_year(base_dob, 1)
        elif "_partial_" in lower:
            full_name = base_name.replace(" ", "  ")  # minor spacing typo
        elif "_expired_" in lower:
            expiry = "2010-01-01"

        extracted = {
            "full_name": full_name,
            "date_of_birth": dob,
            "document_number": "X12345678",
            "expiry_date": expiry,
            "issuing_country": "US",
        }
        return {
            "status": STATUS_EXTRACTED,
            "provider": provider,
            "extracted_fields": extracted,
            "raw_response": json.dumps({"provider": provider, "raw": {}}),
        }

    def _match_against_profile(
        self, *, extracted: dict[str, Any], identity: dict[str, str | None]
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}

        # full_name
        profile_name = identity.get("full_name")
        extracted_name = extracted.get("full_name")
        if not profile_name:
            results["full_name"] = {
                "status": NOT_AVAILABLE,
                "profile_value": None,
                "extracted_value": extracted_name,
                "similarity": None,
            }
        else:
            sim = _name_similarity(profile_name, extracted_name or "")
            if _normalize_name(profile_name) == _normalize_name(extracted_name):
                name_status = MATCH
            elif sim >= S.kyc_documents_name_match_threshold:
                name_status = PARTIAL
            else:
                name_status = MISMATCH
            results["full_name"] = {
                "status": name_status,
                "profile_value": profile_name,
                "extracted_value": extracted_name,
                "similarity": round(sim, 4),
            }

        # date_of_birth (exact ISO comparison)
        profile_dob = identity.get("date_of_birth")
        extracted_dob = extracted.get("date_of_birth")
        if not profile_dob:
            results["date_of_birth"] = {
                "status": NOT_AVAILABLE,
                "profile_value": None,
                "extracted_value": extracted_dob,
                "similarity": None,
            }
        else:
            dob_match = str(profile_dob).strip() == str(extracted_dob or "").strip()
            results["date_of_birth"] = {
                "status": MATCH if dob_match else MISMATCH,
                "profile_value": profile_dob,
                "extracted_value": extracted_dob,
                "similarity": 1.0 if dob_match else 0.0,
            }

        return results

    def _compute_confidence(self, match_results: dict[str, Any]) -> str:
        statuses = [
            str(r.get("status"))
            for r in match_results.values()
            if str(r.get("status")) != NOT_AVAILABLE
        ]
        if not statuses:
            return CONFIDENCE_MEDIUM
        if any(s == MISMATCH for s in statuses):
            return CONFIDENCE_LOW
        if any(s == PARTIAL for s in statuses):
            return CONFIDENCE_MEDIUM
        return CONFIDENCE_HIGH


STORE = KycDocumentVerificationStore()


def public_document_view(item: dict[str, Any], *, include_match: bool = True) -> dict[str, Any]:
    """Shape a stored item into the API response model fields."""
    review = item.get("review") or {}
    out: dict[str, Any] = {
        "document_id": item.get("document_id"),
        "case_id": None if item.get("case_id") == "_none" else item.get("case_id"),
        "user_sub": item.get("user_sub"),
        "document_type": item.get("document_type"),
        "file_name": item.get("file_name"),
        "status": item.get("status"),
        "provider": item.get("provider"),
        "image_url": item.get("image_url"),
        "extraction_id": item.get("extraction_id"),
        "extracted_fields": item.get("extracted_fields") or {},
        "overall_confidence": item.get("overall_confidence"),
        "review_decision": review.get("decision"),
        "review_note": review.get("note"),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }
    if include_match:
        out["match_results"] = item.get("match_results") or {}
    return out
