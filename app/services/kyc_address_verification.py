"""KYC-018: Address Verification Service.

Standalone address-verification feature that builds alongside the existing KYC
case feature (``app/services/kyc_cases.py``) and the KYC-004 proof-of-residency
feature (``app/services/kyc_residency.py``) WITHOUT modifying them.

The KYC system accepts proof-of-residency documents (KYC-004) but has no
mechanism to independently VERIFY an address: that it exists, that it matches
the submitted document, and that it conforms to the official postal format for
the user's country. This service adds that capability:

    * normalize + validate an address against a country's postal format,
    * check existence against a MOCK postal database (deterministic in dev),
    * compare the profile address vs the proof-of-residency document address and
      flag discrepancies,
    * compute a verification result (verified / needs_review / failed) plus a
      confidence score,
    * persist verification records and expose get-latest / list-attempts.

Determinism: all mock provider outcomes are derived from the input via
``zlib.crc32`` / ``hashlib`` (NEVER the builtin ``hash()`` which is salted per
process). A few seeded "known" addresses pass, malformed / unknown addresses
fail, and a mismatch between the profile address and the document address flags
a discrepancy.

Storage: verification records are stored on the EXISTING ``kyc_cases`` table as
sub-records of the case item using a distinct sort key
``ADDRVERIFY#{ts:013d}#{id}`` (mirroring how other KYC sub-record features hang
off the case partition). No new table is introduced. ``get-latest`` reads the
highest-ordered sub-record; ``list-attempts`` scans the case partition. Scans
loop via ``LastEvaluatedKey``.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from decimal import Decimal


def _floats_to_decimal(obj):
    """Recursively convert float values to Decimal so DynamoDB accepts the item."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_floats_to_decimal(v) for v in obj]
    return obj
import zlib
from dataclasses import dataclass, field
from typing import Any, Literal

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Reuse the KYC-004 address normalization + matching helpers (do NOT duplicate).
from app.services.kyc_residency import (
    _normalize_city,
    _normalize_country,
    _normalize_line,
    _normalize_postal,
    _normalize_state,
    match_addresses,
)

logger = logging.getLogger(__name__)

# --- result / decision buckets ---------------------------------------------

STATUS_VERIFIED = "verified"
STATUS_PARTIAL = "partial_match"
STATUS_UNVERIFIABLE = "unverifiable"
STATUS_PENDING = "pending"
STATUS_ERROR = "error"

# Decision buckets (independent of the provider status, derived from confidence).
DECISION_VERIFIED = "verified"
DECISION_NEEDS_REVIEW = "needs_review"
DECISION_FAILED = "failed"

# Cross-reference discrepancy markers
_FIELD_DISCREPANCY = {
    "line1": "line_1_differs",
    "city": "city_differs",
    "state": "state_format_differs",
    "postal_code": "postal_code_differs",
    "country": "country_differs",
}


# --- errors ----------------------------------------------------------------


class KycAddressValidationError(ValueError):
    """Invalid input supplied for an address-verification operation."""


class KycAddressNotFoundError(LookupError):
    """A referenced KYC case (or verification record) does not exist."""


class KycAddressFeatureDisabledError(RuntimeError):
    """Address verification is disabled via the feature flag."""


# --- country-specific postal format rules ----------------------------------
#
# Each entry: (compiled regex, human-readable hint). The regex is applied to the
# postal code after stripping surrounding whitespace and uppercasing. Countries
# not present here fall back to a generic non-empty check.

_POSTAL_RULES: dict[str, tuple[re.Pattern[str], str]] = {
    "US": (
        re.compile(r"^\d{5}(-\d{4})?$"),
        "US ZIP code must be 5 digits, optionally followed by a hyphen and 4 "
        "digits (e.g., 10001 or 10001-1234)",
    ),
    "GB": (
        re.compile(
            r"^(?:GIR 0AA|[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2})$"
        ),
        "UK postcode must look like 'SW1A 1AA' (outward code, space, inward "
        "code)",
    ),
    "DE": (
        re.compile(r"^\d{5}$"),
        "German PLZ must be exactly 5 digits (e.g., 10115)",
    ),
    "FR": (
        re.compile(r"^\d{5}$"),
        "French code postal must be exactly 5 digits (e.g., 75001)",
    ),
    "CA": (
        re.compile(r"^[A-Z]\d[A-Z] \d[A-Z]\d$"),
        "Canadian postal code must look like 'K1A 0B1' (A9A 9A9)",
    ),
    "AU": (
        re.compile(r"^\d{4}$"),
        "Australian postcode must be exactly 4 digits (e.g., 2000)",
    ),
    "JP": (
        re.compile(r"^\d{3}-\d{4}$"),
        "Japanese postal code must look like '100-0001' (999-9999)",
    ),
}

# Countries recognized for "supported postal format" purposes (a superset is
# allowed but only these have specific rules above).
_KNOWN_COUNTRIES = set(_POSTAL_RULES.keys()) | {
    "US", "GB", "DE", "FR", "CA", "AU", "JP",
}


def _normalize_postal_raw(postal_code: str) -> str:
    """Collapse internal whitespace and uppercase a postal code for matching."""
    return re.sub(r"\s+", " ", str(postal_code or "").strip()).upper()


def validate_postal_code(*, postal_code: str, country: str) -> dict[str, Any]:
    """Country-specific postal code format validation.

    Returns ``{"valid": bool, "format_hint": str, "normalized": str}``.
    Unknown countries use a generic "non-empty" rule.
    """
    cc = str(country or "").strip().upper()
    raw = _normalize_postal_raw(postal_code)
    rule = _POSTAL_RULES.get(cc)
    if rule is None:
        # Generic: any non-empty postal code is accepted.
        valid = bool(raw)
        hint = (
            "" if valid else "A non-empty postal code is required for this country"
        )
        return {"valid": valid, "format_hint": hint, "normalized": raw if valid else ""}

    pattern, hint = rule
    if pattern.match(raw):
        return {"valid": True, "format_hint": "", "normalized": raw}
    return {"valid": False, "format_hint": hint, "normalized": ""}


# --- mock postal "database" / provider -------------------------------------


def _address_fingerprint(address: dict[str, Any]) -> str:
    """Stable, normalized string fingerprint of an address (order-independent)."""
    parts = [
        _normalize_line(address.get("line_1") or address.get("line1")),
        _normalize_line(address.get("line_2") or address.get("line2")),
        _normalize_city(address.get("city")),
        _normalize_state(address.get("state")),
        _normalize_postal(address.get("postal_code")),
        _normalize_country(address.get("country")),
    ]
    return "|".join(parts)


def _crc(value: str) -> int:
    """Deterministic 32-bit checksum (NOT the salted builtin ``hash()``)."""
    return zlib.crc32(value.encode("utf-8")) & 0xFFFFFFFF


def _geocode(address: dict[str, Any]) -> dict[str, float] | None:
    """Deterministic mock geocoding derived from a SHA-256 of the fingerprint.

    Returns lat in [-90, 90], lng in [-180, 180]. ``None`` when geocoding is
    disabled via the feature flag.
    """
    if not S.kyc_address_geocoding_enabled:
        return None
    fp = _address_fingerprint(address)
    digest = hashlib.sha256(fp.encode("utf-8")).digest()
    lat_raw = int.from_bytes(digest[0:4], "big")
    lng_raw = int.from_bytes(digest[4:8], "big")
    lat = round((lat_raw % 180_000_000) / 1_000_000.0 - 90.0, 6)
    lng = round((lng_raw % 360_000_000) / 1_000_000.0 - 180.0, 6)
    return {"lat": lat, "lng": lng}


def _standardize(address: dict[str, Any], country: str) -> dict[str, str]:
    """Return the address in (mock) official postal format: uppercased fields,
    line_2 folded into line_1, postal code standardized to a +4 form for US."""
    line1 = str(address.get("line_1") or address.get("line1") or "").strip()
    line2 = str(address.get("line_2") or address.get("line2") or "").strip()
    merged = (f"{line1} {line2}".strip() if line2 else line1).upper()
    cc = str(country or "").strip().upper()
    postal = _normalize_postal_raw(address.get("postal_code"))
    if cc == "US" and re.match(r"^\d{5}$", postal):
        # Append a deterministic +4 extension so standardized differs visibly.
        ext = _crc(_address_fingerprint(address)) % 10000
        postal = f"{postal}-{ext:04d}"
    return {
        "line_1": merged,
        "line_2": "",
        "city": str(address.get("city") or "").strip().upper(),
        "state": str(address.get("state") or "").strip().upper(),
        "postal_code": postal,
        "country": cc,
    }


@dataclass
class MockAddressProvider:
    """Deterministic mock postal provider for dev / test.

    Seeded "known" markers (matched against the normalized line_1):

      * "123 Main St"        -> verified,      confidence 1.0
      * "456 Oak"            -> partial_match,  confidence 0.75
      * "999 Nonexistent"    -> unverifiable,   confidence 0.0

    Everything else verifies with a deterministic confidence derived from
    ``zlib.crc32`` of the address fingerprint, biased high (0.85 - 0.99) so
    ordinary valid addresses pass while remaining stable across runs. Malformed
    addresses (empty street / city) are unverifiable.
    """

    def lookup(self, *, address: dict[str, Any], country: str) -> dict[str, Any]:
        line1_norm = _normalize_line(address.get("line_1") or address.get("line1"))
        city_norm = _normalize_city(address.get("city"))

        # Malformed: missing required street or city -> unverifiable.
        if not line1_norm or not city_norm:
            return {
                "status": STATUS_UNVERIFIABLE,
                "confidence_score": 0.0,
                "discrepancies": ["missing_required_fields"],
            }

        if "999 nonexistent" in line1_norm:
            return {
                "status": STATUS_UNVERIFIABLE,
                "confidence_score": 0.0,
                "discrepancies": ["address_not_found"],
            }
        if line1_norm.startswith("456 oak"):
            return {
                "status": STATUS_PARTIAL,
                "confidence_score": 0.75,
                "discrepancies": ["line_1_abbreviation_differs"],
            }
        if line1_norm.startswith("123 main street"):
            return {
                "status": STATUS_VERIFIED,
                "confidence_score": 1.0,
                "discrepancies": [],
            }

        # Generic deterministic confidence in [0.85, 0.99].
        fp = _address_fingerprint(address)
        conf = 0.85 + (_crc(fp) % 15) / 100.0
        return {
            "status": STATUS_VERIFIED,
            "confidence_score": round(conf, 2),
            "discrepancies": [],
        }


# --- helpers ---------------------------------------------------------------


def _case_pk(case_id: str) -> str:
    # Mirror app.services.kyc_cases._case_pk WITHOUT importing/mutating it.
    return f"KYC#{case_id}"


def _now_ms() -> int:
    """Millisecond epoch timestamp.

    Used for the verification sub-record sort key so two attempts that land
    within the same wall-clock second still sort deterministically by recency
    (the SK is the only "latest wins" signal; a same-second collision would
    otherwise be broken by the random verify_id, making get_latest flaky).
    The 13-digit SK width already accommodates ms precision.
    """
    return int(time.time() * 1000)


def _verify_sk(ts_ms: int, verify_id: str) -> str:
    return f"ADDRVERIFY#{ts_ms:013d}#{verify_id}"


def _new_verify_id() -> str:
    return f"addrv_{uuid.uuid4().hex[:16]}"


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _decision_for_confidence(confidence: float) -> str:
    if confidence >= S.kyc_address_verified_threshold:
        return DECISION_VERIFIED
    if confidence >= S.kyc_address_review_threshold:
        return DECISION_NEEDS_REVIEW
    return DECISION_FAILED


def _address_to_match_shape(address: dict[str, Any]) -> dict[str, Any]:
    """Map the AddressInput shape (line_1/line_2) onto the kyc_residency
    match_addresses shape (line1/line2)."""
    return {
        "line1": address.get("line_1") or address.get("line1"),
        "line2": address.get("line_2") or address.get("line2"),
        "city": address.get("city"),
        "state": address.get("state"),
        "postal_code": address.get("postal_code"),
        "country": address.get("country"),
    }


# --- service ---------------------------------------------------------------


@dataclass
class KycAddressVerificationStore:
    """Persistence + verification pipeline for KYC-018 address verification."""

    _table: Any = field(default=T.kyc_cases)
    _provider: MockAddressProvider = field(default_factory=MockAddressProvider)

    # -- case access -------------------------------------------------------

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return self._table.get_item(
            Key={"pk": _case_pk(case_id), "sk": "META"}
        ).get("Item")

    def require_case(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        if not case:
            raise KycAddressNotFoundError(case_id)
        return case

    # -- postal validation -------------------------------------------------

    def validate_postal_code(self, *, postal_code: str, country: str) -> dict[str, Any]:
        return validate_postal_code(postal_code=postal_code, country=country)

    # -- verification ------------------------------------------------------

    def verify_address(
        self,
        *,
        case_id: str,
        address: dict[str, Any],
        triggered_by: str,
    ) -> dict[str, Any]:
        """Validate + normalize + existence-check an address for a case and
        persist a verification sub-record. Overwrites/supersedes prior attempts
        (latest wins) but keeps the full attempt history.
        """
        if not S.kyc_address_verification_enabled:
            raise KycAddressFeatureDisabledError("feature_disabled")
        case = self.require_case(case_id)

        country = str(address.get("country") or "").strip().upper()
        if not country:
            raise KycAddressValidationError("missing_country")

        # 1. postal format validation
        postal_result = validate_postal_code(
            postal_code=str(address.get("postal_code") or ""), country=country
        )
        country_format_valid = bool(postal_result["valid"])

        # 2. existence check via provider (mock in dev)
        lookup = self._provider.lookup(address=address, country=country)
        status = str(lookup["status"])
        confidence = _coerce_float(lookup["confidence_score"])
        discrepancies = list(lookup.get("discrepancies") or [])

        if not country_format_valid and status != STATUS_UNVERIFIABLE:
            # A bad postal format caps confidence and downgrades the result.
            discrepancies.append("postal_format_invalid")
            confidence = min(confidence, 0.6)
            if status == STATUS_VERIFIED:
                status = STATUS_PARTIAL

        # 3. standardize + geocode
        standardized = (
            _standardize(address, country)
            if status in (STATUS_VERIFIED, STATUS_PARTIAL)
            else None
        )
        geocoding = (
            _geocode(address) if status in (STATUS_VERIFIED, STATUS_PARTIAL) else None
        )

        decision = _decision_for_confidence(confidence)
        ts = now_ts()
        ts_ms = _now_ms()
        verify_id = _new_verify_id()

        record: dict[str, Any] = {
            "pk": _case_pk(case_id),
            "sk": _verify_sk(ts_ms, verify_id),
            "entity_type": "kyc_address_verification",
            "kyc_case_id": case_id,
            "verification_id": verify_id,
            "user_sub": str(case.get("user_sub") or ""),
            "status": status,
            "decision": decision,
            "confidence_score": confidence,
            "country": country,
            "country_format_valid": country_format_valid,
            "postal_format_hint": postal_result.get("format_hint") or "",
            "input_address": self._clean_address(address),
            "standardized_address": standardized,
            "geocoding": geocoding,
            "discrepancies": discrepancies,
            "cross_reference": None,
            "override": None,
            "provider": S.kyc_address_provider,
            "verified_at": ts if status in (STATUS_VERIFIED, STATUS_PARTIAL) else None,
            "triggered_by": triggered_by,
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=_floats_to_decimal(record))
        logger.info(
            "kyc.address.verified case_id=%s status=%s decision=%s confidence=%s",
            case_id,
            status,
            decision,
            confidence,
        )
        return record

    def cross_reference_document(
        self,
        *,
        case_id: str,
        document_address: dict[str, Any],
        actor_sub: str,
    ) -> dict[str, Any]:
        """Compare the latest verified profile address against an address
        extracted from a proof-of-residency document and flag discrepancies.
        Stores the cross-reference on the latest verification record.
        """
        if not S.kyc_address_verification_enabled:
            raise KycAddressFeatureDisabledError("feature_disabled")
        self.require_case(case_id)
        latest = self.get_latest(case_id)
        if latest is None:
            raise KycAddressValidationError("no_verification_to_cross_reference")

        profile_addr = latest.get("input_address") or {}
        comparison = self._compare_addresses(profile_addr, document_address)

        cross_ref = {
            "match_score": comparison["match_score"],
            "discrepancies": comparison["discrepancies"],
            "field_comparisons": comparison["field_comparisons"],
            "document_address": self._clean_address(document_address),
            "actor_sub": actor_sub,
            "compared_at": now_ts(),
        }
        ts = now_ts()
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": latest["sk"]},
            UpdateExpression="SET cross_reference = :cr, updated_at = :ts",
            ExpressionAttributeValues={":cr": _floats_to_decimal(cross_ref), ":ts": ts},
        )
        logger.info(
            "kyc.address.cross_reference case_id=%s match_score=%s actor=%s",
            case_id,
            comparison["match_score"],
            actor_sub,
        )
        out = dict(latest)
        out["cross_reference"] = cross_ref
        out["updated_at"] = ts
        return out

    def override_decision(
        self,
        *,
        case_id: str,
        decision: str,
        reviewer_sub: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Admin override of the latest verification decision."""
        if not S.kyc_address_verification_enabled:
            raise KycAddressFeatureDisabledError("feature_disabled")
        dec = str(decision or "").strip().lower()
        if dec not in (DECISION_VERIFIED, DECISION_NEEDS_REVIEW, DECISION_FAILED):
            raise KycAddressValidationError("invalid_decision")
        self.require_case(case_id)
        latest = self.get_latest(case_id)
        if latest is None:
            raise KycAddressValidationError("no_verification_to_override")

        ts = now_ts()
        override = {
            "decision": dec,
            "reviewer_sub": reviewer_sub,
            "note": note,
            "decided_at": ts,
        }
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": latest["sk"]},
            UpdateExpression="SET #d = :d, #o = :ov, updated_at = :ts",
            ExpressionAttributeNames={"#d": "decision", "#o": "override"},
            ExpressionAttributeValues={":d": dec, ":ov": _floats_to_decimal(override), ":ts": ts},
        )
        logger.info(
            "kyc.address.override case_id=%s decision=%s reviewer=%s",
            case_id,
            dec,
            reviewer_sub,
        )
        out = dict(latest)
        out["decision"] = dec
        out["override"] = override
        out["updated_at"] = ts
        return out

    def invalidate_verification(self, *, case_id: str, reason: str = "address_changed") -> None:
        """Reset the latest verification to pending (called on address change)."""
        latest = self.get_latest(case_id)
        if latest is None:
            return
        ts = now_ts()
        self._table.update_item(
            Key={"pk": _case_pk(case_id), "sk": latest["sk"]},
            UpdateExpression="SET #s = :s, decision = :d, updated_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": STATUS_PENDING,
                ":d": DECISION_NEEDS_REVIEW,
                ":ts": ts,
            },
        )
        logger.info("kyc.address.invalidated case_id=%s reason=%s", case_id, reason)

    # -- reads -------------------------------------------------------------

    def list_attempts(self, case_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List all verification attempts for a case (newest first). Loops
        LastEvaluatedKey defensively."""
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(_case_pk(case_id))
                & Key("sk").begins_with("ADDRVERIFY#"),
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
        items.sort(key=lambda i: str(i.get("sk") or ""), reverse=True)
        return items[:limit]

    def get_latest(self, case_id: str) -> dict[str, Any] | None:
        attempts = self.list_attempts(case_id, limit=1)
        return attempts[0] if attempts else None

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _clean_address(address: dict[str, Any]) -> dict[str, Any]:
        return {
            "line_1": str(address.get("line_1") or address.get("line1") or "").strip(),
            "line_2": str(address.get("line_2") or address.get("line2") or "").strip(),
            "city": str(address.get("city") or "").strip(),
            "state": str(address.get("state") or "").strip(),
            "postal_code": str(address.get("postal_code") or "").strip(),
            "country": str(address.get("country") or "").strip().upper(),
        }

    def _compare_addresses(
        self, profile: dict[str, Any], document: dict[str, Any]
    ) -> dict[str, Any]:
        """Field-by-field comparison reusing KYC-004 match_addresses, plus a
        normalized match score + per-field comparison table."""
        match = match_addresses(
            _address_to_match_shape(document), _address_to_match_shape(profile)
        )
        field_matches: dict[str, str] = match.get("field_matches") or {}

        field_comparisons: list[dict[str, Any]] = []
        discrepancies: list[str] = []
        matched = 0
        total = 0
        for field_name, profile_key in (
            ("line1", "line_1"),
            ("city", "city"),
            ("state", "state"),
            ("postal_code", "postal_code"),
            ("country", "country"),
        ):
            if field_name not in field_matches:
                continue
            total += 1
            is_match = field_matches[field_name] == "match"
            if is_match:
                matched += 1
            else:
                marker = _FIELD_DISCREPANCY.get(field_name)
                if marker:
                    discrepancies.append(marker)
            field_comparisons.append(
                {
                    "field": profile_key,
                    "profile": str(profile.get(profile_key) or ""),
                    "document": str(document.get(profile_key) or ""),
                    "match": is_match,
                }
            )

        match_score = round(matched / total, 2) if total else 0.0
        return {
            "match_score": match_score,
            "discrepancies": discrepancies,
            "field_comparisons": field_comparisons,
        }


STORE = KycAddressVerificationStore()


# --- response shaping ------------------------------------------------------


def public_verification_view(record: dict[str, Any] | None) -> dict[str, Any]:
    """Shape a stored verification sub-record into the API response fields."""
    if not record:
        return {
            "status": STATUS_PENDING,
            "decision": DECISION_NEEDS_REVIEW,
            "confidence_score": 0.0,
            "country_format_valid": False,
            "discrepancies": [],
        }
    cr = record.get("cross_reference")
    cross_reference = None
    if cr:
        cross_reference = {
            "match_score": _coerce_float(cr.get("match_score")),
            "discrepancies": list(cr.get("discrepancies") or []),
            "field_comparisons": list(cr.get("field_comparisons") or []),
        }
    return {
        "verification_id": record.get("verification_id"),
        "kyc_case_id": record.get("kyc_case_id"),
        "status": record.get("status") or STATUS_PENDING,
        "decision": record.get("decision") or DECISION_NEEDS_REVIEW,
        "confidence_score": _coerce_float(record.get("confidence_score")),
        "country": record.get("country"),
        "country_format_valid": bool(record.get("country_format_valid")),
        "postal_format_hint": record.get("postal_format_hint") or "",
        "input_address": record.get("input_address") or None,
        "standardized_address": record.get("standardized_address") or None,
        "geocoding": record.get("geocoding") or None,
        "discrepancies": list(record.get("discrepancies") or []),
        "cross_reference": cross_reference,
        "override": record.get("override") or None,
        "provider": record.get("provider"),
        "verified_at": _coerce_int(record.get("verified_at"))
        if record.get("verified_at") is not None
        else None,
        "created_at": _coerce_int(record.get("created_at")),
        "updated_at": _coerce_int(record.get("updated_at")),
    }
