"""KYC-010: Passport / National-ID Scanner service.

NET-NEW scanner feature that is invoked explicitly via the scanner router
(see ``app/routers/kyc_id_scanner.py``). It is independent of the existing KYC
case file-attachment flow (see ``app/routers/kyc_cases.py``): removing it has no
impact on the KYC case lifecycle.

A user submits an uploaded passport / national-ID image (referenced via the dev
S3 mock) for a KYC case. The scanner:

    * extracts the MRZ (machine-readable zone) / document fields
      (doc number, name, DOB, expiry, nationality, issuing country),
    * validates the ICAO 9303 MRZ check digits (the TD3 / TD1 check-digit
      algorithm is implemented for real on the mock MRZ string),
    * checks document expiry (expired / expiring_soon / valid),
    * cross-checks the extracted data against the KYC case / user profile,
    * records a scan result with a status:

          matched   -> all check digits pass, not expired, profile cross-check OK
          flagged   -> parsed but a check digit failed / profile mismatch / expiring
          rejected  -> document is expired (or hard validation failure)

Reviewers list scans by status via the ``ByStatus`` GSI and adjudicate them.

In dev (and E2E) a deterministic mock extraction is used (gated behind
``S.kyc_id_scanner_real_ocr_enabled``, default off): MRZ lines may be supplied
directly in the request, otherwise deterministic mock MRZ strings are derived
from the document type. The result feeds the KYC risk-scoring engine via a
lazy import so this module stays import-safe.
"""

from __future__ import annotations

import datetime
import difflib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

ALLOWED_DOCUMENT_TYPES = {"passport", "national_id_card", "driving_license", "residence_permit"}
ALLOWED_FILE_TYPES = {"id_front", "id_back"}

# scan result statuses
STATUS_MATCHED = "matched"
STATUS_FLAGGED = "flagged"
STATUS_REJECTED = "rejected"
STATUS_APPROVED = "approved"
STATUS_DECLINED = "declined"

_ALL_STATUSES = {
    STATUS_MATCHED,
    STATUS_FLAGGED,
    STATUS_REJECTED,
    STATUS_APPROVED,
    STATUS_DECLINED,
}

# statuses that can be listed via the ByStatus GSI for reviewer / admin work
LISTABLE_STATUSES = {
    STATUS_MATCHED,
    STATUS_FLAGGED,
    STATUS_REJECTED,
    STATUS_APPROVED,
    STATUS_DECLINED,
}

EXPIRY_WARNING_DAYS = 90

DOCUMENT_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "passport": {"sides_required": ["front"], "has_mrz": True, "mrz_format": "TD3"},
    "national_id_card": {"sides_required": ["front", "back"], "has_mrz": True, "mrz_format": "TD1"},
    "driving_license": {"sides_required": ["front", "back"], "has_mrz": False, "mrz_format": None},
    "residence_permit": {"sides_required": ["front", "back"], "has_mrz": True, "mrz_format": "TD1"},
}


# --- errors ----------------------------------------------------------------


class KycIdScannerValidationError(ValueError):
    """Invalid input supplied for a KYC ID-scanner operation."""


class KycIdScannerNotFoundError(LookupError):
    """A referenced KYC scan does not exist."""


class KycIdScannerStateError(RuntimeError):
    """A scan is in a state that does not permit the requested operation."""


# --- ids -------------------------------------------------------------------


def _new_scan_id() -> str:
    return f"kycscan_{uuid.uuid4().hex[:16]}"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# --- MRZ parsing + check-digit validation (ICAO 9303) ----------------------

_MRZ_WEIGHTS = [7, 3, 1]


def mrz_check_digit(data: str) -> int:
    """Compute the ICAO 9303 check digit for an MRZ field."""
    total = 0
    for i, ch in enumerate(data):
        if ch == "<":
            val = 0
        elif ch.isdigit():
            val = int(ch)
        elif ch.isalpha():
            val = ord(ch.upper()) - ord("A") + 10
        else:
            val = 0
        total += val * _MRZ_WEIGHTS[i % 3]
    return total % 10


def validate_mrz_checksum(data: str, expected: str) -> bool:
    """Validate a single MRZ check digit field against its computed value."""
    return str(mrz_check_digit(data)) == str(expected).strip()


def _mrz_date_to_iso(raw: str) -> str | None:
    """Convert YYMMDD to YYYY-MM-DD. Century pivot: 00-29 = 2000s, 30-99 = 1900s.

    Used for dates that are expected to be in the past (e.g. date of birth).
    """
    if len(raw) != 6 or not raw.isdigit():
        return None
    yy = int(raw[0:2])
    mm = raw[2:4]
    dd = raw[4:6]
    century = 2000 if yy <= 29 else 1900
    return f"{century + yy}-{mm}-{dd}"


def _mrz_expiry_to_iso(raw: str, *, now: datetime.date | None = None) -> str | None:
    """Convert a YYMMDD MRZ *expiry* date to YYYY-MM-DD.

    Expiry dates are forward-looking, so the fixed 1900s pivot used for date of
    birth (``_mrz_date_to_iso``) wrongly maps e.g. ``36`` -> 1936 for a passport
    that expires in 2036. Pick the century whose resulting year is not already
    deep in the past: if the 1900s interpretation predates the current year, roll
    forward to the 2000s.
    """
    if len(raw) != 6 or not raw.isdigit():
        return None
    yy = int(raw[0:2])
    mm = raw[2:4]
    dd = raw[4:6]
    today = now or datetime.date.today()
    candidate = 1900 + yy if yy >= 30 else 2000 + yy
    if candidate < today.year:
        candidate += 100
    return f"{candidate}-{mm}-{dd}"


def _sex_human(code: str) -> str:
    return {"M": "male", "F": "female", "<": "unspecified"}.get(code, code)


def parse_td3_mrz(line1: str, line2: str) -> dict[str, Any]:
    """Parse TD3 (passport) MRZ -- 2 lines of 44 chars."""
    if len(line1) != 44 or len(line2) != 44:
        return {"valid": False, "error": "invalid_mrz_length", "format": "TD3"}

    doc_type = line1[0:2].replace("<", "")
    issuing_state = line1[2:5].replace("<", "")
    names_raw = line1[5:44]
    parts = names_raw.split("<<", 1)
    surname = parts[0].replace("<", " ").strip()
    given_names = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    doc_check = line2[9]
    dob_raw = line2[13:19]
    dob_check = line2[19]
    sex = line2[20]
    expiry_raw = line2[21:27]
    expiry_check = line2[27]
    optional_check = line2[42]
    composite_check = line2[43]

    checksums = {
        "document_number": validate_mrz_checksum(line2[0:9], doc_check),
        "date_of_birth": validate_mrz_checksum(line2[13:19], dob_check),
        "expiry_date": validate_mrz_checksum(line2[21:27], expiry_check),
        "optional_data": validate_mrz_checksum(line2[28:42], optional_check),
        "composite": validate_mrz_checksum(
            line2[0:10] + line2[13:20] + line2[21:43], composite_check
        ),
    }

    return {
        "valid": all(checksums.values()),
        "format": "TD3",
        "document_type": doc_type,
        "issuing_state": issuing_state,
        "surname": surname,
        "given_names": given_names,
        "document_number": line2[0:9].replace("<", ""),
        "nationality": line2[10:13].replace("<", ""),
        "date_of_birth": _mrz_date_to_iso(dob_raw),
        "sex": _sex_human(sex),
        "expiry_date": _mrz_expiry_to_iso(expiry_raw),
        "checksums": checksums,
    }


def parse_td1_mrz(line1: str, line2: str, line3: str) -> dict[str, Any]:
    """Parse TD1 (ID card / residence permit) MRZ -- 3 lines of 30 chars."""
    if len(line1) != 30 or len(line2) != 30 or len(line3) != 30:
        return {"valid": False, "error": "invalid_mrz_length", "format": "TD1"}

    doc_type = line1[0:2].replace("<", "")
    issuing_state = line1[2:5].replace("<", "")
    doc_check = line1[14]

    dob_raw = line2[0:6]
    dob_check = line2[6]
    sex = line2[7]
    expiry_raw = line2[8:14]
    expiry_check = line2[14]
    composite_check = line2[29]

    names_raw = line3[0:30]
    parts = names_raw.split("<<", 1)
    surname = parts[0].replace("<", " ").strip()
    given_names = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    checksums = {
        "document_number": validate_mrz_checksum(line1[5:14], doc_check),
        "date_of_birth": validate_mrz_checksum(line2[0:6], dob_check),
        "expiry_date": validate_mrz_checksum(line2[8:14], expiry_check),
        "composite": validate_mrz_checksum(
            line1[5:30] + line2[0:7] + line2[8:15] + line2[18:29], composite_check
        ),
    }

    return {
        "valid": all(checksums.values()),
        "format": "TD1",
        "document_type": doc_type,
        "issuing_state": issuing_state,
        "surname": surname,
        "given_names": given_names,
        "document_number": line1[5:14].replace("<", ""),
        "nationality": line2[15:18].replace("<", ""),
        "date_of_birth": _mrz_date_to_iso(dob_raw),
        "sex": _sex_human(sex),
        "expiry_date": _mrz_expiry_to_iso(expiry_raw),
        "checksums": checksums,
    }


def parse_mrz_lines(mrz_lines: list[str], mrz_format: str | None) -> dict[str, Any]:
    """Dispatch MRZ lines to the appropriate parser by format."""
    lines = [str(x) for x in (mrz_lines or [])]
    if mrz_format == "TD3":
        if len(lines) != 2:
            return {"valid": False, "error": "invalid_mrz_lines", "format": "TD3"}
        return parse_td3_mrz(lines[0], lines[1])
    if mrz_format == "TD1":
        if len(lines) != 3:
            return {"valid": False, "error": "invalid_mrz_lines", "format": "TD1"}
        return parse_td1_mrz(lines[0], lines[1], lines[2])
    # no MRZ for this document type (e.g. driving_license)
    return {"valid": None, "format": None, "error": None}


# --- expiry ----------------------------------------------------------------


def check_document_expiry(expiry_date_iso: str | None, *, now: datetime.date | None = None) -> dict[str, Any]:
    """Check whether a document is expired / expiring_soon / valid.

    ``now`` is injectable so expiry status is deterministic in tests.
    """
    if not expiry_date_iso:
        return {"status": "unknown", "message": "No expiry date available", "expiry_date": None, "days_until_expiry": None}
    try:
        expiry = datetime.date.fromisoformat(str(expiry_date_iso))
    except ValueError:
        return {"status": "unknown", "message": f"Invalid date format: {expiry_date_iso}", "expiry_date": None, "days_until_expiry": None}

    today = now or datetime.date.today()
    days = (expiry - today).days
    if days < 0:
        return {"status": "expired", "message": f"Document expired {abs(days)} days ago", "expiry_date": expiry_date_iso, "days_until_expiry": days}
    if days <= EXPIRY_WARNING_DAYS:
        return {"status": "expiring_soon", "message": f"Document expires in {days} days", "expiry_date": expiry_date_iso, "days_until_expiry": days}
    return {"status": "valid", "message": "Document is valid", "expiry_date": expiry_date_iso, "days_until_expiry": days}


# --- name / cross-reference helpers ----------------------------------------


def _normalize_name(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value).strip()).upper()


def _name_similarity(a: str, b: str) -> float:
    na, nb = _normalize_name(a), _normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


def cross_reference_profile(extraction: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Compare extracted document data against user-profile / case fields."""
    matches: dict[str, Any] = {}
    mismatches: dict[str, Any] = {}
    score = 0.0
    total = 0

    extracted_name = f"{extraction.get('given_names', '')} {extraction.get('surname', '')}".strip()
    profile_name = f"{profile.get('first_name', '')} {profile.get('last_name', '')}".strip()
    if extracted_name and profile_name:
        total += 1
        if _normalize_name(extracted_name) == _normalize_name(profile_name):
            matches["name"] = {"extracted": extracted_name, "profile": profile_name}
            score += 1
        elif _normalize_name(extraction.get("surname", "")) == _normalize_name(profile.get("last_name", "")):
            matches["surname"] = {"extracted": extraction.get("surname", ""), "profile": profile.get("last_name", "")}
            score += 0.5
        else:
            mismatches["name"] = {"extracted": extracted_name, "profile": profile_name}

    extracted_dob = extraction.get("date_of_birth")
    profile_dob = profile.get("date_of_birth")
    if extracted_dob and profile_dob:
        total += 1
        if str(extracted_dob).strip() == str(profile_dob).strip():
            matches["date_of_birth"] = {"extracted": extracted_dob, "profile": profile_dob}
            score += 1
        else:
            mismatches["date_of_birth"] = {"extracted": extracted_dob, "profile": profile_dob}

    extracted_nat = _normalize_name(extraction.get("nationality", ""))
    profile_nat = _normalize_name(profile.get("nationality", ""))
    if extracted_nat and profile_nat:
        total += 1
        if extracted_nat == profile_nat:
            matches["nationality"] = {"extracted": extracted_nat, "profile": profile_nat}
            score += 1
        else:
            mismatches["nationality"] = {"extracted": extracted_nat, "profile": profile_nat}

    return {
        "match_score": round(score / max(total, 1) * 100),
        "total_fields_checked": total,
        "fields_matched": len(matches),
        "matches": matches,
        "mismatches": mismatches,
    }


# --- deterministic mock MRZ ------------------------------------------------

# Deterministic mock MRZ strings whose check digits are all valid.
#
# GAP-0271: the expiry field is "361231" (YYMMDD = 2036-12-31), an unambiguous
# far-future date. The earlier example used "120415" (2012-04-15); although the
# century roll-forward in ``_mrz_expiry_to_iso`` masked that at runtime (it maps
# 2012 -> 2112), the raw value read as expired and a naive constant edit or a
# clock-stubbed test could re-introduce ``status="rejected"``. The expiry and
# all dependent check digits (expiry check + composite for TD3; expiry check +
# composite for TD1) were recomputed with ``mrz_check_digit`` -- see
# tests/test_gap_0271_kyc_id_scanner.py which pins them as valid for the next
# decade. Do NOT change the expiry field without recomputing those check digits.
_MOCK_MRZ: dict[str, dict[str, list[str]]] = {
    "passport": {
        "lines": [
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            "L898902C36UTO7408122F3612314ZE184226B<<<<<18",
        ],
    },
    "national_id_card": {
        "lines": [
            "I<UTOD231458907<<<<<<<<<<<<<<<",
            "7408122F3612314UTO<<<<<<<<<<<4",
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
        ],
    },
    "residence_permit": {
        "lines": [
            "I<UTOD231458907<<<<<<<<<<<<<<<",
            "7408122F3612314UTO<<<<<<<<<<<4",
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
        ],
    },
}


def _mock_mrz_lines(document_type: str) -> list[str]:
    return list(_MOCK_MRZ.get(document_type, {}).get("lines", []))


# --- service ---------------------------------------------------------------


@dataclass
class KycIdScannerStore:
    """Persistence + scan pipeline for KYC passport / national-ID documents."""

    _table: Any = field(default=T.kyc_id_scans)

    # -- case / profile access --------------------------------------------

    def _load_case(self, case_id: str) -> dict[str, Any] | None:
        try:
            from app.services.kyc_cases import STORE as CASE_STORE

            return CASE_STORE.get_case(case_id)
        except Exception:  # pragma: no cover - defensive
            return None

    def _load_crosscheck_profile(self, user_sub: str, case: dict[str, Any] | None) -> dict[str, Any]:
        """Build the dict used for cross-checking (profile + case overrides)."""
        out: dict[str, Any] = {}
        try:
            from app.services.profile import get_profile

            profile = get_profile(user_sub) or {}
        except Exception:  # pragma: no cover - defensive
            profile = {}
        out["first_name"] = profile.get("first_name") or ""
        out["last_name"] = profile.get("last_name") or ""
        # GAP-0270: if structured name fields are absent, derive them from display_name.
        # Users who registered with only a full_name (stored as display_name) would
        # otherwise produce an empty profile_name, skipping the name comparison and
        # yielding match_score=0 -> every such scan is falsely flagged.
        if not out["first_name"] and not out["last_name"]:
            display_name = str(profile.get("display_name") or "").strip()
            if display_name:
                parts = display_name.split(None, 1)  # split on first whitespace, max 2 parts
                out["first_name"] = parts[0] if parts else ""
                out["last_name"] = parts[1] if len(parts) > 1 else ""
                logger.debug(
                    "kyc.id_scanner.crosscheck.display_name_fallback user_sub=%s "
                    "derived first_name=%r last_name=%r",
                    user_sub,
                    out["first_name"],
                    out["last_name"],
                )
        out["date_of_birth"] = profile.get("birthday") or profile.get("date_of_birth") or ""
        out["nationality"] = profile.get("nationality") or profile.get("country") or ""
        # case META may carry overriding identity fields
        if case:
            ident = case.get("identity") or {}
            if isinstance(ident, dict):
                out["first_name"] = ident.get("first_name") or out["first_name"]
                out["last_name"] = ident.get("last_name") or out["last_name"]
                out["date_of_birth"] = ident.get("date_of_birth") or out["date_of_birth"]
                out["nationality"] = ident.get("nationality") or out["nationality"]
        return out

    # -- mock / real extraction -------------------------------------------

    def _run_extraction(
        self, *, document_type: str, mrz_lines: list[str] | None
    ) -> dict[str, Any]:
        if S.kyc_id_scanner_real_ocr_enabled:
            return self._run_real_extraction(document_type=document_type, mrz_lines=mrz_lines)
        return self._run_mock_extraction(document_type=document_type, mrz_lines=mrz_lines)

    def _run_real_extraction(self, *, document_type: str, mrz_lines: list[str] | None) -> dict[str, Any]:
        """Placeholder for a real OCR/MRZ provider (not wired in dev/E2E)."""
        logger.warning("kyc.id_scanner.real_provider_not_configured falling back to mock")
        return self._run_mock_extraction(document_type=document_type, mrz_lines=mrz_lines)

    def _run_mock_extraction(self, *, document_type: str, mrz_lines: list[str] | None) -> dict[str, Any]:
        """Deterministic mock extraction.

        If ``mrz_lines`` are supplied they are parsed directly (so E2E can drive
        predictable / expired / bad-check-digit cases). Otherwise deterministic
        mock MRZ lines are used for the document type.
        """
        req = DOCUMENT_REQUIREMENTS.get(document_type, {})
        mrz_format = req.get("mrz_format")
        if not req.get("has_mrz"):
            # No MRZ (e.g. driving license) -- basic extraction only.
            return {"valid": None, "format": None, "error": None, "document_type": document_type}
        lines = list(mrz_lines) if mrz_lines else _mock_mrz_lines(document_type)
        return parse_mrz_lines(lines, mrz_format)

    # -- public API --------------------------------------------------------

    def scan_document(
        self,
        *,
        user_sub: str,
        case_id: str,
        document_type: str,
        file_type: str = "id_front",
        mrz_lines: list[str] | None = None,
        image_ref: str | None = None,
        now: datetime.date | None = None,
    ) -> dict[str, Any]:
        """Scan an uploaded passport / national-ID image and record the result."""
        doc_type = str(document_type or "").strip()
        if doc_type not in ALLOWED_DOCUMENT_TYPES:
            raise KycIdScannerValidationError("invalid_document_type")
        ft = str(file_type or "id_front").strip()
        if ft not in ALLOWED_FILE_TYPES:
            raise KycIdScannerValidationError("invalid_file_type")

        case = self._load_case(case_id)
        if not case:
            raise KycIdScannerNotFoundError("kyc_case_not_found")
        if str(case.get("user_sub") or "") != str(user_sub):
            raise KycIdScannerStateError("kyc_access_forbidden")
        if str(case.get("status") or "") in ("approved", "rejected"):
            raise KycIdScannerStateError("kyc_case_finalized")

        req = DOCUMENT_REQUIREMENTS[doc_type]
        # MRZ line-count validation up front (hard error for wrong count).
        if req.get("has_mrz") and mrz_lines is not None:
            fmt = req.get("mrz_format")
            if fmt == "TD3" and len(mrz_lines) != 2:
                raise KycIdScannerValidationError("kyc_mrz_invalid_lines")
            if fmt == "TD1" and len(mrz_lines) != 3:
                raise KycIdScannerValidationError("kyc_mrz_invalid_lines")

        extraction = self._run_extraction(document_type=doc_type, mrz_lines=mrz_lines)
        mrz_valid = bool(extraction.get("valid")) if extraction.get("valid") is not None else False
        has_extraction_error = bool(extraction.get("error"))

        expiry_check = check_document_expiry(extraction.get("expiry_date"), now=now)

        cross_reference: dict[str, Any] | None = None
        # Only cross-reference a successfully-parsed extraction.
        if extraction.get("valid") is True:
            profile = self._load_crosscheck_profile(user_sub, case)
            cross_reference = cross_reference_profile(extraction, profile)

        status = self._derive_status(
            extraction=extraction,
            expiry_check=expiry_check,
            cross_reference=cross_reference,
            has_mrz=bool(req.get("has_mrz")),
        )

        scan_id = _new_scan_id()
        ts = now_ts()
        image_url = None
        if S.dev_mode:
            ref = image_ref or f"{S.kyc_id_scanner_s3_prefix}{case_id}/{ft}.jpg"
            bucket = S.kyc_id_scanner_bucket or "local-uploads"
            image_url = f"/mock/s3/{bucket}/{ref}" if not str(ref).startswith("/mock/s3/") else ref

        item: dict[str, Any] = {
            "scan_id": scan_id,
            "case_id": case_id,
            "user_sub": user_sub,
            "document_type": doc_type,
            "file_type": ft,
            "status": status,
            "mrz_valid": mrz_valid,
            "extraction": extraction,
            "expiry_check": expiry_check,
            "cross_reference": cross_reference or {},
            "image_url": image_url,
            "review": {"decision": None, "reviewer_sub": None, "decided_at": None, "note": None},
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        logger.info(
            "kyc.id_scanner.scanned scan_id=%s case_id=%s type=%s status=%s mrz_valid=%s",
            scan_id, case_id, doc_type, status, mrz_valid,
        )
        if has_extraction_error:
            logger.warning("kyc.id_scanner.extraction_error case_id=%s error=%s", case_id, extraction.get("error"))

        # Feed the KYC risk-scoring engine (lazy import keeps module import-safe).
        self._feed_risk_scoring(case_id=case_id, user_sub=user_sub)
        return item

    def _derive_status(
        self,
        *,
        extraction: dict[str, Any],
        expiry_check: dict[str, Any],
        cross_reference: dict[str, Any] | None,
        has_mrz: bool,
    ) -> str:
        # Expired documents are rejected outright.
        if expiry_check.get("status") == "expired":
            return STATUS_REJECTED
        if has_mrz:
            if extraction.get("error"):
                return STATUS_FLAGGED
            if extraction.get("valid") is not True:
                # A failed check digit flags the scan for manual review.
                return STATUS_FLAGGED
        if expiry_check.get("status") == "expiring_soon":
            return STATUS_FLAGGED
        if cross_reference is not None and int(cross_reference.get("match_score", 0)) < 50:
            return STATUS_FLAGGED
        return STATUS_MATCHED

    def _feed_risk_scoring(self, *, case_id: str, user_sub: str) -> None:
        try:
            from app.services.kyc_risk_scoring import KycRiskScoringService

            KycRiskScoringService().compute_score(
                case_id=case_id, user_sub=user_sub, trigger="id_scan"
            )
        except Exception:  # pragma: no cover - best effort
            logger.warning("kyc.id_scanner.risk_rescore_failed case_id=%s", case_id)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"scan_id": scan_id})
        return resp.get("Item")

    def list_scans_for_case(self, case_id: str) -> list[dict[str, Any]]:
        try:
            resp = self._table.query(
                IndexName="ByCase",
                KeyConditionExpression=Key("case_id").eq(case_id),
                ScanIndexForward=False,
            )
            return list(resp.get("Items", []))
        except Exception:
            # Fail closed: never fall back to a full table scan, which would load
            # every user's scan records into memory (cross-user PII exposure).
            logger.exception(
                "kyc_id_scanner.list_scans_for_case: ByCase GSI query failed for case_id=%s",
                case_id,
            )
            return []

    def list_by_status(self, status: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List scans by status via the ByStatus GSI (PK=status, SK=created_at)."""
        st = str(status or "").strip()
        if st not in LISTABLE_STATUSES:
            raise KycIdScannerValidationError("invalid_status")
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_id_scanner_status_index_name,
                "KeyConditionExpression": Key("status").eq(st),
                "ScanIndexForward": False,
                "Limit": min(limit, 500),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(items) >= limit:
                break
        return items[:limit]

    def adjudicate(
        self,
        *,
        scan_id: str,
        decision: str,
        reviewer_sub: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Reviewer approve/decline a scan result."""
        dec = str(decision or "").strip().lower()
        if dec not in ("approve", "decline"):
            raise KycIdScannerValidationError("invalid_decision")
        item = self.get_scan(scan_id)
        if not item:
            raise KycIdScannerNotFoundError(scan_id)

        new_status = STATUS_APPROVED if dec == "approve" else STATUS_DECLINED
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
        self._apply_update(scan_id, update)
        logger.info(
            "kyc.id_scanner.adjudicated scan_id=%s decision=%s reviewer=%s",
            scan_id, dec, reviewer_sub,
        )
        return {**item, **update}

    def validate_requirements(self, *, document_type: str, case_id: str | None = None) -> dict[str, Any]:
        """Return document-type requirements + which sides are present for a case."""
        doc_type = str(document_type or "").strip()
        if doc_type not in DOCUMENT_REQUIREMENTS:
            raise KycIdScannerValidationError("invalid_document_type")
        req = DOCUMENT_REQUIREMENTS[doc_type]
        sides_present: list[str] = []
        if case_id:
            scans = self.list_scans_for_case(case_id)
            present = set()
            for s in scans:
                if str(s.get("document_type")) != doc_type:
                    continue
                ft = str(s.get("file_type") or "")
                if ft == "id_front":
                    present.add("front")
                elif ft == "id_back":
                    present.add("back")
            sides_present = [s for s in ("front", "back") if s in present]
        all_present = all(side in sides_present for side in req["sides_required"])
        return {
            "document_type": doc_type,
            "sides_required": list(req["sides_required"]),
            "has_mrz": bool(req["has_mrz"]),
            "mrz_format": req["mrz_format"],
            "sides_present": sides_present,
            "all_sides_present": all_present,
        }

    # -- internals ---------------------------------------------------------

    def _apply_update(self, scan_id: str, update: dict[str, Any]) -> None:
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
            Key={"scan_id": scan_id},
            UpdateExpression="SET " + ", ".join(sets),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )


STORE = KycIdScannerStore()


def _extraction_view(extraction: dict[str, Any]) -> dict[str, Any]:
    checksums = extraction.get("checksums")
    return {
        "valid": extraction.get("valid"),
        "format": extraction.get("format"),
        "error": extraction.get("error"),
        "document_type": extraction.get("document_type"),
        "issuing_state": extraction.get("issuing_state"),
        "surname": extraction.get("surname"),
        "given_names": extraction.get("given_names"),
        "document_number": extraction.get("document_number"),
        "nationality": extraction.get("nationality"),
        "date_of_birth": extraction.get("date_of_birth"),
        "sex": extraction.get("sex"),
        "expiry_date": extraction.get("expiry_date"),
        "checksums": dict(checksums) if isinstance(checksums, dict) else None,
    }


def public_scan_view(item: dict[str, Any], *, include_cross_reference: bool = True) -> dict[str, Any]:
    """Shape a stored scan item into the API response model fields."""
    review = item.get("review") or {}
    extraction = item.get("extraction") or {}
    cross_reference = item.get("cross_reference") or None
    out: dict[str, Any] = {
        "scan_id": item.get("scan_id"),
        "case_id": item.get("case_id"),
        "user_sub": item.get("user_sub"),
        "document_type": item.get("document_type"),
        "file_type": item.get("file_type"),
        "status": item.get("status"),
        "mrz_valid": bool(item.get("mrz_valid")),
        "extraction": _extraction_view(extraction),
        "expiry_check": item.get("expiry_check") or {"status": "unknown", "message": "No expiry date available", "expiry_date": None, "days_until_expiry": None},
        "image_url": item.get("image_url"),
        "review_decision": review.get("decision"),
        "review_note": review.get("note"),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }
    if include_cross_reference:
        out["cross_reference"] = dict(cross_reference) if isinstance(cross_reference, dict) and cross_reference else None
    else:
        out["cross_reference"] = None
    return out


def scan_summary_view(item: dict[str, Any]) -> dict[str, Any]:
    """Compact summary for list endpoints."""
    expiry = item.get("expiry_check") or {}
    cross = item.get("cross_reference") or {}
    return {
        "scan_id": item.get("scan_id"),
        "case_id": item.get("case_id"),
        "document_type": item.get("document_type"),
        "file_type": item.get("file_type"),
        "status": item.get("status"),
        "mrz_valid": bool(item.get("mrz_valid")),
        "expiry_status": expiry.get("status"),
        "match_score": int(cross.get("match_score")) if isinstance(cross, dict) and cross.get("match_score") is not None else None,
        "created_at": _coerce_int(item.get("created_at")),
    }
