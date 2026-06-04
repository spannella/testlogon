"""KYB (Know Your Business) case management service (KYC-015).

Business-entity KYC, parallel to the individual KYC system in
``app/services/kyc_cases.py``. Manages the business-case lifecycle
(create / submit / review / approve / reject), UBO and director
management, corporate documents, address verification, and mock
deterministic company-registration / address verification.

On approval a business case grants Tier 4 (Institutional) eligibility via
``app/services/kyc_tiers.py`` (KYC-009) and screens the company plus its
UBOs/directors against the sanctions watchlist (KYC-006).

DynamoDB single-table layout (table ``kyc_business_cases``):

    pk                | sk                | meaning
    ------------------+-------------------+--------------------------------
    BIZ#{case_id}     | META              | company info + status + summary
    BIZ#{case_id}     | UBO#{ubo_id}      | ultimate beneficial owner
    BIZ#{case_id}     | DIR#{dir_id}      | director / officer
    BIZ#{case_id}     | DOC#{doc_id}      | corporate document
    BIZ#{case_id}     | ADDR#{addr_type}  | registered / trading address

GSIs: owner (gsi_owner_pk/sk), status (gsi_status_pk/sk), org (gsi_org_pk/sk).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import zlib
import uuid
from typing import Any

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# --- domain constants ------------------------------------------------------

ALLOWED_STATUSES = {
    "draft",
    "submitted",
    "under_review",
    "needs_more_info",
    "approved",
    "rejected",
    "expired",
}
ALLOWED_COMPANY_TYPES = {"llc", "corp", "partnership", "sole_prop", "nonprofit", "cooperative", "trust"}
ALLOWED_DIRECTOR_ROLES = {"director", "secretary", "ceo", "cfo", "coo", "treasurer"}
ALLOWED_DOCUMENT_TYPES = {
    "certificate_of_incorporation",
    "articles_of_association",
    "shareholder_register",
    "financial_statements",
    "board_resolution",
    "proof_of_address_registered",
    "proof_of_address_trading",
}
REQUIRED_DOCUMENT_TYPES = {
    "certificate_of_incorporation",
    "articles_of_association",
    "shareholder_register",
}
ALLOWED_ADDRESS_TYPES = {"registered", "trading"}

# An individual must own strictly more than this share to count as a UBO.
UBO_OWNERSHIP_THRESHOLD = 25.0
# Minimum total identified ownership required before a case can be submitted.
MIN_TOTAL_OWNERSHIP_FOR_SUBMIT = 75.0


# --- errors ----------------------------------------------------------------


class KybConflictError(ValueError):
    """Raised when optimistic concurrency version checks fail."""


class KybValidationError(ValueError):
    """Raised when invalid KYB inputs are provided."""


class KybNotFoundError(LookupError):
    """Raised when a referenced KYB case / sub-entity does not exist."""


# --- key helpers -----------------------------------------------------------


def _case_pk(case_id: str) -> str:
    return f"BIZ#{case_id}"


def _updated_sk(ts: int, case_id: str) -> str:
    return f"UPDATED#{ts:013d}#BIZ#{case_id}"


def _owner_pk(user_sub: str) -> str:
    return f"OWNER#{user_sub}"


def _status_pk(status: str) -> str:
    return f"STATUS#{status}"


def _is_conditional_conflict(exc: ClientError) -> bool:
    return str(exc.response.get("Error", {}).get("Code", "")) == "ConditionalCheckFailedException"


def _denumber(value: Any) -> Any:
    """Recursively coerce DynamoDB ``Decimal`` values to native int/float.

    DynamoDB returns all numbers as ``Decimal``. FastAPI's JSON encoder
    serializes ``Decimal`` inside untyped (``Any``) response fields as
    *strings* (e.g. ``Decimal("2") -> "2"``), which breaks numeric API
    assertions. Coerce integral decimals to ``int`` and the rest to ``float``.
    """
    from decimal import Decimal

    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _denumber(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_denumber(v) for v in value]
    return value


def _normalize_company(data: dict[str, Any]) -> dict[str, Any]:
    company_type = str(data.get("company_type") or "llc").strip().lower()
    if company_type not in ALLOWED_COMPANY_TYPES:
        raise KybValidationError("invalid_company_type")
    return {
        "legal_name": str(data.get("legal_name", "")).strip(),
        "trading_name": str(data.get("trading_name", "")).strip() or None,
        "registration_number": str(data.get("registration_number", "")).strip(),
        "jurisdiction": str(data.get("jurisdiction", "")).strip().upper(),
        "incorporation_date": str(data.get("incorporation_date", "")).strip() or None,
        "company_type": company_type,
        "tax_id": str(data.get("tax_id", "")).strip() or None,
        "website": str(data.get("website", "")).strip() or None,
        "industry": str(data.get("industry", "")).strip() or None,
    }


def _deterministic_score(*parts: str | None) -> int:
    """Deterministic 0-99 score derived from input (NOT builtin ``hash``)."""
    seed = "|".join(str(p or "") for p in parts)
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return (zlib.crc32(seed.encode("utf-8")) ^ int(digest[:8], 16)) % 100


# --- mock verification -----------------------------------------------------


def verify_company_registration(company: dict[str, Any]) -> dict[str, Any]:
    """Mock deterministic verification of a company's registration.

    Pass/fail is derived from the legal name + registration number +
    jurisdiction via crc32/sha256 — fully reproducible. A registration
    number containing the marker ``FAIL`` always fails (handy for tests).
    """
    legal_name = str(company.get("legal_name") or "")
    reg_no = str(company.get("registration_number") or "")
    jurisdiction = str(company.get("jurisdiction") or "")
    if not legal_name or not reg_no:
        return {"verified": False, "score": 0, "reason": "missing_company_details"}
    if "FAIL" in reg_no.upper():
        return {"verified": False, "score": 0, "reason": "registry_no_match"}
    if "PASS" in reg_no.upper():
        return {
            "verified": True,
            "score": 99,
            "reason": "registry_match",
            "matched_registry": f"{jurisdiction or 'XX'}-REGISTRY",
        }
    score = _deterministic_score(legal_name, reg_no, jurisdiction)
    verified = score >= 30
    return {
        "verified": verified,
        "score": score,
        "reason": "registry_match" if verified else "registry_low_confidence",
        "matched_registry": f"{jurisdiction or 'XX'}-REGISTRY",
    }


def verify_company_address(address: dict[str, Any]) -> dict[str, Any]:
    """Mock deterministic verification of a company address."""
    line1 = str(address.get("line1") or "")
    postal = str(address.get("postal_code") or "")
    country = str(address.get("country") or "")
    if not line1 or not postal:
        return {"verified": False, "score": 0, "reason": "missing_address_details"}
    if "FAIL" in line1.upper():
        return {"verified": False, "score": 0, "reason": "address_not_found"}
    score = _deterministic_score(line1, postal, country)
    verified = score >= 30
    return {
        "verified": verified,
        "score": score,
        "reason": "address_match" if verified else "address_low_confidence",
    }


def _screen_entity_safe(*, case_id: str, user_sub: str, name: str) -> list[dict[str, Any]]:
    """Screen a single entity name against the sanctions watchlist (KYC-006).

    Reuses ``kyc_sanctions_screening``. Never raises — screening failure must
    not break the review flow.
    """
    try:
        from app.services.kyc_sanctions_screening import STORE as SANCTIONS_STORE, TRIGGER_MANUAL

        return SANCTIONS_STORE.screen_case(
            case_id=case_id,
            user_sub=user_sub,
            trigger=TRIGGER_MANUAL,
            name=name,
        )
    except Exception:  # pragma: no cover - defensive
        return []


# --- store -----------------------------------------------------------------


@dataclass
class KybCaseStore:
    _table: Any = field(default=T.kyc_business_cases)

    # -- case lifecycle ----------------------------------------------------

    def create_case(
        self,
        *,
        user_sub: str,
        company: dict[str, Any],
        org_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize_company(company)
        if not normalized["legal_name"]:
            raise KybValidationError("missing_legal_name")
        ts = now_ts()
        case_id = f"kyb_{uuid.uuid4().hex[:12]}"
        item: dict[str, Any] = {
            "pk": _case_pk(case_id),
            "sk": "META",
            "entity_type": "kyb_case",
            "kyb_case_id": case_id,
            "user_sub": user_sub,
            "status": "draft",
            "company": normalized,
            "ubo_summary": {
                "total_ubos": 0,
                "all_kyc_approved": False,
                "total_ownership_pct": 0,
            },
            "director_count": 0,
            "document_count": 0,
            "registration_verification": {},
            "submission": {},
            "review": {},
            "org_id": org_id,
            "created_at": ts,
            "updated_at": ts,
            "version": 1,
            "gsi_owner_pk": _owner_pk(user_sub),
            "gsi_owner_sk": _updated_sk(ts, case_id),
            "gsi_status_pk": _status_pk("draft"),
            "gsi_status_sk": _updated_sk(ts, case_id),
        }
        if org_id:
            item["gsi_org_pk"] = f"ORG#{org_id}"
            item["gsi_org_sk"] = _case_pk(case_id)
        self._table.put_item(Item=item)
        return item

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        item = self._table.get_item(Key={"pk": _case_pk(case_id), "sk": "META"}).get("Item")
        return _denumber(item) if item is not None else None

    def _require_owned_draft(self, *, case_id: str, owner_sub: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        if not case:
            raise KybNotFoundError("kyb_case_not_found")
        if str(case.get("user_sub") or "") != owner_sub:
            raise KybValidationError("kyb_access_forbidden")
        if str(case.get("status") or "") != "draft":
            raise KybValidationError("kyb_invalid_transition")
        return case

    def update_company(
        self,
        *,
        case_id: str,
        owner_sub: str,
        expected_version: int,
        company_patch: dict[str, Any],
    ) -> dict[str, Any] | None:
        case = self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        current_version = int(case.get("version") or 0)
        if current_version != int(expected_version):
            raise KybConflictError("kyb_case_update_conflict")
        merged = dict(case.get("company") or {})
        for key, value in company_patch.items():
            if value is not None:
                merged[key] = value
        normalized = _normalize_company(merged)
        ts = now_ts()
        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET company=:company, updated_at=:ts, version=:next, "
                    "gsi_owner_sk=:osk, gsi_status_sk=:ssk"
                ),
                ExpressionAttributeValues={
                    ":company": normalized,
                    ":ts": ts,
                    ":next": current_version + 1,
                    ":osk": _updated_sk(ts, case_id),
                    ":ssk": _updated_sk(ts, case_id),
                    ":expected": current_version,
                },
                ConditionExpression="version = :expected",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KybConflictError("kyb_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    # -- UBOs --------------------------------------------------------------

    def add_ubo(self, *, case_id: str, owner_sub: str, ubo_data: dict[str, Any]) -> dict[str, Any]:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        pct = float(ubo_data.get("ownership_percentage") or 0)
        if pct <= UBO_OWNERSHIP_THRESHOLD:
            raise KybValidationError("ubo_ownership_below_threshold")
        ubo_id = f"ubo_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": _case_pk(case_id),
            "sk": f"UBO#{ubo_id}",
            "entity_type": "kyb_ubo",
            "ubo_id": ubo_id,
            "full_name": str(ubo_data["full_name"]).strip(),
            "date_of_birth": ubo_data.get("date_of_birth"),
            "nationality": ubo_data.get("nationality"),
            "ownership_percentage": pct,
            "personal_kyc_case_id": ubo_data.get("personal_kyc_case_id"),
            "personal_kyc_status": None,
            "added_at": ts,
            "added_by": owner_sub,
        }
        # If linked to a personal KYC case, snapshot its current status.
        if item["personal_kyc_case_id"]:
            item["personal_kyc_status"] = self._lookup_personal_kyc_status(item["personal_kyc_case_id"])
        self._table.put_item(Item=item)
        self._refresh_ubo_summary(case_id)
        return item

    def link_ubo_personal_kyc(
        self,
        *,
        case_id: str,
        owner_sub: str,
        ubo_id: str,
        personal_kyc_case_id: str,
    ) -> dict[str, Any]:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        existing = self._table.get_item(
            Key={"pk": _case_pk(case_id), "sk": f"UBO#{ubo_id}"}
        ).get("Item")
        if not existing:
            raise KybNotFoundError("ubo_not_found")
        status = self._lookup_personal_kyc_status(personal_kyc_case_id)
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": f"UBO#{ubo_id}"},
            UpdateExpression="SET personal_kyc_case_id=:cid, personal_kyc_status=:st",
            ExpressionAttributeValues={":cid": personal_kyc_case_id, ":st": status},
        )
        self._refresh_ubo_summary(case_id)
        return self._table.get_item(
            Key={"pk": _case_pk(case_id), "sk": f"UBO#{ubo_id}"}
        ).get("Item")

    def _lookup_personal_kyc_status(self, personal_kyc_case_id: str) -> str | None:
        """Snapshot the linked personal KYC case status (link + track, no recursion)."""
        try:
            from app.services.kyc_cases import STORE as KYC_STORE

            personal = KYC_STORE.get_case(personal_kyc_case_id)
            if personal:
                return str(personal.get("status") or "") or None
        except Exception:  # pragma: no cover - defensive
            pass
        return None

    def remove_ubo(self, *, case_id: str, owner_sub: str, ubo_id: str) -> bool:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        self._table.delete_item(Key={"pk": _case_pk(case_id), "sk": f"UBO#{ubo_id}"})
        self._refresh_ubo_summary(case_id)
        return True

    def list_ubos(self, case_id: str) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("UBO#"),
        )
        return resp.get("Items", [])

    def _refresh_ubo_summary(self, case_id: str) -> None:
        ubos = self.list_ubos(case_id)
        total_pct = sum(float(u.get("ownership_percentage", 0)) for u in ubos)
        all_approved = bool(ubos) and all(u.get("personal_kyc_status") == "approved" for u in ubos)
        ts = now_ts()
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": "META"},
            UpdateExpression="SET ubo_summary=:s, updated_at=:ts",
            ExpressionAttributeValues={
                ":s": {
                    "total_ubos": len(ubos),
                    "all_kyc_approved": all_approved,
                    "total_ownership_pct": total_pct,
                },
                ":ts": ts,
            },
        )

    # -- directors ---------------------------------------------------------

    def add_director(self, *, case_id: str, owner_sub: str, director_data: dict[str, Any]) -> dict[str, Any]:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        role = str(director_data.get("role") or "director").strip().lower()
        if role not in ALLOWED_DIRECTOR_ROLES:
            raise KybValidationError("invalid_director_role")
        director_id = f"dir_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": _case_pk(case_id),
            "sk": f"DIR#{director_id}",
            "entity_type": "kyb_director",
            "director_id": director_id,
            "full_name": str(director_data["full_name"]).strip(),
            "role": role,
            "date_of_birth": director_data.get("date_of_birth"),
            "nationality": director_data.get("nationality"),
            "personal_kyc_case_id": director_data.get("personal_kyc_case_id"),
            "added_at": ts,
            "added_by": owner_sub,
        }
        self._table.put_item(Item=item)
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": "META"},
            UpdateExpression="SET director_count = if_not_exists(director_count, :zero) + :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":zero": 0, ":ts": ts},
        )
        return item

    def remove_director(self, *, case_id: str, owner_sub: str, director_id: str) -> bool:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        self._table.delete_item(Key={"pk": _case_pk(case_id), "sk": f"DIR#{director_id}"})
        ts = now_ts()
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": "META"},
            UpdateExpression="SET director_count = if_not_exists(director_count, :zero) - :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":zero": 0, ":ts": ts},
        )
        return True

    def list_directors(self, case_id: str) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("DIR#"),
        )
        return resp.get("Items", [])

    # -- documents ---------------------------------------------------------

    def add_document(self, *, case_id: str, owner_sub: str, doc_data: dict[str, Any]) -> dict[str, Any]:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        doc_type = str(doc_data.get("document_type") or "").strip()
        if doc_type not in ALLOWED_DOCUMENT_TYPES:
            raise KybValidationError("invalid_document_type")
        doc_id = f"doc_{uuid.uuid4().hex[:8]}"
        ts = now_ts()
        item = {
            "pk": _case_pk(case_id),
            "sk": f"DOC#{doc_id}",
            "entity_type": "kyb_document",
            "doc_id": doc_id,
            "document_type": doc_type,
            "file_node_id": str(doc_data.get("file_node_id") or ""),
            "file_name": str(doc_data.get("file_name") or ""),
            "uploaded_at": ts,
            "uploaded_by": owner_sub,
        }
        self._table.put_item(Item=item)
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": "META"},
            UpdateExpression="SET document_count = if_not_exists(document_count, :zero) + :one, updated_at = :ts",
            ExpressionAttributeValues={":one": 1, ":zero": 0, ":ts": ts},
        )
        return item

    def list_documents(self, case_id: str) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("DOC#"),
        )
        return resp.get("Items", [])

    # -- addresses ---------------------------------------------------------

    def set_address(self, *, case_id: str, owner_sub: str, address_type: str, address: dict[str, Any]) -> dict[str, Any]:
        self._require_owned_draft(case_id=case_id, owner_sub=owner_sub)
        if address_type not in ALLOWED_ADDRESS_TYPES:
            raise KybValidationError("invalid_address_type")
        ts = now_ts()
        verification = verify_company_address(address)
        item = {
            "pk": _case_pk(case_id),
            "sk": f"ADDR#{address_type}",
            "entity_type": "kyb_address",
            "address_type": address_type,
            "line1": str(address.get("line1") or ""),
            "line2": str(address.get("line2") or "") or None,
            "city": str(address.get("city") or ""),
            "state": str(address.get("state") or "") or None,
            "postal_code": str(address.get("postal_code") or ""),
            "country": str(address.get("country") or "").upper(),
            "verified": bool(verification.get("verified")),
            "verification": verification,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def list_addresses(self, case_id: str) -> list[dict[str, Any]]:
        from boto3.dynamodb.conditions import Key

        resp = self._table.query(
            KeyConditionExpression=Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("ADDR#"),
        )
        return resp.get("Items", [])

    # -- submit ------------------------------------------------------------

    def validate_submit_requirements(self, case_id: str, case: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        company = case.get("company") or {}
        if not company.get("legal_name"):
            errors.append("missing_legal_name")
        if not company.get("registration_number"):
            errors.append("missing_registration_number")

        ubos = self.list_ubos(case_id)
        if not ubos:
            errors.append("no_ubos_added")
        total_pct = sum(float(u.get("ownership_percentage", 0)) for u in ubos)
        if ubos and total_pct < MIN_TOTAL_OWNERSHIP_FOR_SUBMIT:
            errors.append("ubo_ownership_below_75_percent")
        if total_pct > 100.0:
            errors.append("ubo_ownership_exceeds_100_percent")

        doc_types = {d.get("document_type") for d in self.list_documents(case_id)}
        missing = REQUIRED_DOCUMENT_TYPES - doc_types
        if missing:
            errors.append("missing_documents:" + ",".join(sorted(missing)))
        return errors

    def submit_case(self, *, case_id: str, owner_sub: str, expected_version: int) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if not case:
            raise KybNotFoundError("kyb_case_not_found")
        if str(case.get("user_sub") or "") != owner_sub:
            raise KybValidationError("kyb_access_forbidden")
        current_status = str(case.get("status") or "")
        if current_status == "submitted":
            return case
        if current_status not in {"draft", "needs_more_info"}:
            raise KybValidationError("kyb_invalid_transition")

        current_version = int(case.get("version") or 0)
        if current_version != int(expected_version):
            raise KybConflictError("kyb_case_update_conflict")

        errors = self.validate_submit_requirements(case_id, case)
        if errors:
            raise KybValidationError("kyb_submit_prereq_failed:" + ",".join(errors))

        # Mock-verify the company registration at submission time.
        reg_verification = verify_company_registration(case.get("company") or {})
        ts = now_ts()
        submission = {
            "submitted_at": ts,
            "registration_verification": reg_verification,
        }
        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, submission=:submission, registration_verification=:rv, "
                    "updated_at=:ts, version=:next, gsi_owner_sk=:osk, "
                    "gsi_status_pk=:spk, gsi_status_sk=:ssk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": "submitted",
                    ":submission": submission,
                    ":rv": reg_verification,
                    ":ts": ts,
                    ":next": current_version + 1,
                    ":osk": _updated_sk(ts, case_id),
                    ":spk": _status_pk("submitted"),
                    ":ssk": _updated_sk(ts, case_id),
                    ":expected": current_version,
                },
                ConditionExpression="version = :expected",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KybConflictError("kyb_case_update_conflict") from exc
            raise
        return self.get_case(case_id)

    # -- admin review ------------------------------------------------------

    def screen_business(self, *, case_id: str) -> dict[str, Any]:
        """Screen the company name + all UBOs + directors against sanctions."""
        case = self.get_case(case_id)
        if not case:
            raise KybNotFoundError("kyb_case_not_found")
        user_sub = str(case.get("user_sub") or "")
        company_name = str((case.get("company") or {}).get("legal_name") or "")
        screened: list[dict[str, Any]] = []
        company_results = _screen_entity_safe(case_id=case_id, user_sub=user_sub, name=company_name)
        screened.append({"subject": "company", "name": company_name, "results": company_results})
        for ubo in self.list_ubos(case_id):
            name = str(ubo.get("full_name") or "")
            screened.append(
                {
                    "subject": "ubo",
                    "ubo_id": ubo.get("ubo_id"),
                    "name": name,
                    "results": _screen_entity_safe(case_id=case_id, user_sub=user_sub, name=name),
                }
            )
        for director in self.list_directors(case_id):
            name = str(director.get("full_name") or "")
            screened.append(
                {
                    "subject": "director",
                    "director_id": director.get("director_id"),
                    "name": name,
                    "results": _screen_entity_safe(case_id=case_id, user_sub=user_sub, name=name),
                }
            )

        def _has_hit(entry: dict[str, Any]) -> bool:
            return any(str(r.get("result") or "clear") != "clear" for r in entry.get("results") or [])

        any_hit = any(_has_hit(e) for e in screened)
        return {"case_id": case_id, "any_hit": any_hit, "screened": screened}

    def apply_admin_decision(
        self,
        *,
        case_id: str,
        expected_version: int,
        admin_sub: str,
        decision: str,
        reason_codes: list[str] | None = None,
        note: str | None = None,
        request: Any = None,
    ) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if not case:
            raise KybNotFoundError("kyb_case_not_found")
        normalized = str(decision or "").strip().lower()
        if normalized not in {"approve", "reject"}:
            raise KybValidationError("kyb_invalid_decision")
        target_status = "approved" if normalized == "approve" else "rejected"

        current_status = str(case.get("status") or "")
        review = dict(case.get("review") or {})
        if current_status in {"approved", "rejected"}:
            if str(review.get("decision") or "") == normalized:
                return case
            raise KybValidationError("kyb_invalid_transition")
        if current_status not in {"submitted", "under_review"}:
            raise KybValidationError("kyb_invalid_transition")

        current_version = int(case.get("version") or 0)
        if current_version != int(expected_version):
            raise KybConflictError("kyb_case_update_conflict")

        ts = now_ts()
        review["decision"] = normalized
        review["decided_at"] = ts
        review["reason_codes"] = [str(c) for c in (reason_codes or [])]
        review["decision_note"] = str(note or "")
        review["decision_actor_sub"] = admin_sub

        try:
            self._table.update_item(
                Key={"pk": _case_pk(case_id), "sk": "META"},
                UpdateExpression=(
                    "SET #status=:status, review=:review, updated_at=:ts, version=:next, "
                    "gsi_owner_sk=:osk, gsi_status_pk=:spk, gsi_status_sk=:ssk"
                ),
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": target_status,
                    ":review": review,
                    ":ts": ts,
                    ":next": current_version + 1,
                    ":osk": _updated_sk(ts, case_id),
                    ":spk": _status_pk(target_status),
                    ":ssk": _updated_sk(ts, case_id),
                    ":expected": current_version,
                },
                ConditionExpression="version = :expected",
            )
        except ClientError as exc:
            if _is_conditional_conflict(exc):
                raise KybConflictError("kyb_case_update_conflict") from exc
            raise

        if target_status == "approved":
            self._grant_tier4(case=case, admin_sub=admin_sub, request=request)
        return self.get_case(case_id)

    def _grant_tier4(self, *, case: dict[str, Any], admin_sub: str, request: Any = None) -> None:
        """On business-KYC approval, upgrade the owner to Tier 4 (KYC-009)."""
        try:
            from app.services.kyc_tiers import upgrade_tier, get_user_kyc_tier, KYC_TIER_MAX

            user_sub = str(case.get("user_sub") or "")
            if not user_sub:
                return
            current = get_user_kyc_tier(user_sub)
            if current >= KYC_TIER_MAX:
                return
            upgrade_tier(
                user_sub=user_sub,
                new_tier=KYC_TIER_MAX,
                reason="business_kyc_approved",
                actor_sub=admin_sub,
                case_id=str(case.get("kyb_case_id") or ""),
                request=request,
            )
        except Exception:  # pragma: no cover - defensive
            pass

    # -- listing -----------------------------------------------------------

    def list_cases_by_owner(self, *, user_sub: str, limit: int = 25) -> list[dict[str, Any]]:
        resp = self._table.query(
            IndexName=S.kyc_business_cases_owner_index_name,
            KeyConditionExpression="gsi_owner_pk = :pk",
            ExpressionAttributeValues={":pk": _owner_pk(user_sub)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit or 25), 100)),
        )
        return [_denumber(r) for r in resp.get("Items", []) if r.get("entity_type") == "kyb_case"]

    def list_cases_by_status(self, *, status: str, limit: int = 50) -> list[dict[str, Any]]:
        normalized = str(status or "").strip()
        if normalized not in ALLOWED_STATUSES:
            raise KybValidationError("invalid_kyb_status")
        resp = self._table.query(
            IndexName=S.kyc_business_cases_status_index_name,
            KeyConditionExpression="gsi_status_pk = :pk",
            ExpressionAttributeValues={":pk": _status_pk(normalized)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit or 50), 200)),
        )
        return [_denumber(r) for r in resp.get("Items", []) if r.get("entity_type") == "kyb_case"]

    def list_admin_queue(self, *, statuses: list[str] | None = None, limit: int = 50) -> list[dict[str, Any]]:
        review_statuses = statuses or ["submitted", "under_review", "needs_more_info"]
        collected: list[dict[str, Any]] = []
        for status in review_statuses:
            if status in ALLOWED_STATUSES:
                collected.extend(self.list_cases_by_status(status=status, limit=limit))
        collected.sort(key=lambda r: -int(r.get("updated_at") or 0))
        return collected


STORE = KybCaseStore()
