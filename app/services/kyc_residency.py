"""KYC-004: Proof of Residency Verification service.

Standalone proof-of-residency feature that builds alongside the existing KYC
case feature (``app/services/kyc_cases.py``) and the KYC-002 identity-document
feature (``app/services/kyc_document_verification.py``) WITHOUT modifying them.

A user uploads a residency document (utility bill / bank statement / lease /
government letter / tax document). The document is stored in S3 (mocked in dev)
and a record is written to the ``kyc_residency_documents`` DynamoDB table. An
extraction/verification pipeline then runs:

    pending  -> verified  (recent + extracted address matches the profile)
             -> rejected  (too old OR address mismatch)
             -> expired   (document date older than the recency window)

Reviewers list documents by status via the ``ByStatus`` GSI and approve / reject
them.

In dev (and E2E) a deterministic mock extraction provider is used: extraction
results are derived from filename patterns so tests are predictable. A "real"
extraction provider is gated behind
``S.kyc_residency_real_extraction_enabled`` (default off) and is intentionally
not wired in dev.

The recency check accepts an injectable ``now`` value for deterministic tests.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

ALLOWED_DOCUMENT_TYPES = {
    "utility_bill",
    "bank_statement",
    "government_letter",
    "tax_document",
    "lease_agreement",
}

# Document lifecycle / status values
STATUS_PENDING = "pending"
STATUS_VERIFIED = "verified"
STATUS_REJECTED = "rejected"
STATUS_EXPIRED = "expired"

_ALL_STATUSES = {STATUS_PENDING, STATUS_VERIFIED, STATUS_REJECTED, STATUS_EXPIRED}

# statuses that can be listed via the ByStatus GSI for admin / reviewer work
LISTABLE_STATUSES = {STATUS_PENDING, STATUS_VERIFIED, STATUS_REJECTED, STATUS_EXPIRED}

# address-match result statuses
MATCH = "match"
PARTIAL = "partial"
MISMATCH = "mismatch"
NOT_AVAILABLE = "not_available"

# Street suffix / unit abbreviation normalization map (KYC-004 spec 8.2).
_STREET_ABBREVIATIONS = {
    "st": "street",
    "ave": "avenue",
    "av": "avenue",
    "blvd": "boulevard",
    "dr": "drive",
    "ln": "lane",
    "rd": "road",
    "ct": "court",
    "pl": "place",
    "cir": "circle",
    "pkwy": "parkway",
    "hwy": "highway",
    "apt": "apartment",
    "ste": "suite",
    "fl": "floor",
    "n": "north",
    "s": "south",
    "e": "east",
    "w": "west",
}

# US state abbreviation <-> full name (subset sufficient for matching / tests).
_US_STATES = {
    "al": "alabama", "ak": "alaska", "az": "arizona", "ar": "arkansas",
    "ca": "california", "co": "colorado", "ct": "connecticut", "de": "delaware",
    "fl": "florida", "ga": "georgia", "hi": "hawaii", "id": "idaho",
    "il": "illinois", "in": "indiana", "ia": "iowa", "ks": "kansas",
    "ky": "kentucky", "la": "louisiana", "me": "maine", "md": "maryland",
    "ma": "massachusetts", "mi": "michigan", "mn": "minnesota", "ms": "mississippi",
    "mo": "missouri", "mt": "montana", "ne": "nebraska", "nv": "nevada",
    "nh": "new hampshire", "nj": "new jersey", "nm": "new mexico", "ny": "new york",
    "nc": "north carolina", "nd": "north dakota", "oh": "ohio", "ok": "oklahoma",
    "or": "oregon", "pa": "pennsylvania", "ri": "rhode island", "sc": "south carolina",
    "sd": "south dakota", "tn": "tennessee", "tx": "texas", "ut": "utah",
    "vt": "vermont", "va": "virginia", "wa": "washington", "wv": "west virginia",
    "wi": "wisconsin", "wy": "wyoming",
}

_COUNTRY_ALIASES = {
    "us": "united states",
    "usa": "united states",
    "united states of america": "united states",
    "united states": "united states",
    "uk": "united kingdom",
    "gb": "united kingdom",
    "united kingdom": "united kingdom",
    "ca": "canada",
    "can": "canada",
    "canada": "canada",
}


# --- errors ----------------------------------------------------------------


class KycResidencyValidationError(ValueError):
    """Invalid input supplied for a KYC residency operation."""


class KycResidencyNotFoundError(LookupError):
    """A referenced KYC residency document does not exist."""


class KycResidencyStateError(RuntimeError):
    """A document is in a state that does not permit the requested operation."""


# --- helpers ---------------------------------------------------------------


def _new_document_id() -> str:
    return f"kycres_{uuid.uuid4().hex[:16]}"


def _new_extraction_id() -> str:
    return f"rext_{uuid.uuid4().hex[:12]}"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", str(value).strip())
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _today(now: Any = None) -> date:
    """Return the reference "today" for recency checks.

    ``now`` may be a ``datetime``, ``date``, or an integer Unix timestamp. When
    omitted, the current UTC date is used. Injectable for deterministic tests.
    """
    if now is None:
        return datetime.now(timezone.utc).date()
    if isinstance(now, date) and not isinstance(now, datetime):
        return now
    if isinstance(now, datetime):
        return now.date()
    if isinstance(now, (int, float)):
        return datetime.fromtimestamp(int(now), tz=timezone.utc).date()
    return datetime.now(timezone.utc).date()


# --- address normalization + matching --------------------------------------


def _norm_token(token: str) -> str:
    """Lowercase a token, strip punctuation, expand known abbreviations."""
    t = re.sub(r"[^a-z0-9]", "", token.lower())
    return _STREET_ABBREVIATIONS.get(t, t)


def _normalize_line(value: str | None) -> str:
    if not value:
        return ""
    tokens = re.split(r"\s+", str(value).strip())
    return " ".join(_norm_token(tok) for tok in tokens if _norm_token(tok))


def _normalize_city(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value).strip()).lower()


def _normalize_state(value: str | None) -> str:
    if not value:
        return ""
    v = re.sub(r"\s+", " ", str(value).strip()).lower()
    # canonicalize to full name when an abbreviation is given
    if v in _US_STATES:
        return _US_STATES[v]
    return v


def _normalize_postal(value: str | None) -> str:
    if not value:
        return ""
    digits = re.sub(r"\D", "", str(value))
    return digits[:5]


def _normalize_country(value: str | None) -> str:
    if not value:
        return ""
    v = re.sub(r"\s+", " ", str(value).strip()).lower()
    return _COUNTRY_ALIASES.get(v, v)


def _field_status(extracted: str | None, profile: str | None, normalizer) -> str | None:
    """Compare a single field. Returns ``match`` / ``mismatch`` or ``None`` when
    neither side has a value to compare."""
    pe = normalizer(extracted)
    pp = normalizer(profile)
    if not pe and not pp:
        return None
    if not pe or not pp:
        return MISMATCH
    return MATCH if pe == pp else MISMATCH


def match_addresses(extracted: dict | None, profile: dict | None, *, line2_field: bool = True) -> dict:
    """Compare an extracted address against the profile address field-by-field.

    Returns a dict shaped for ``AddressMatchResult``:
        { status, profile_address, field_matches: {line1, city, state, postal_code, country} }

    Overall status rules (KYC-004 spec 8.1):
      - all comparable fields match            -> ``match``
      - city + postal_code match, line1 differs -> ``partial``
      - city or postal_code mismatch            -> ``mismatch``
      - no profile address at all               -> ``not_available``
    """
    extracted = extracted or {}
    profile = profile or {}

    if not any((profile.get(k) for k in ("line1", "city", "state", "postal_code", "country"))):
        return {
            "status": NOT_AVAILABLE,
            "profile_address": {},
            "field_matches": {},
        }

    field_matches: dict[str, str] = {}
    line1 = _field_status(extracted.get("line1"), profile.get("line1"), _normalize_line)
    if line1 is not None:
        field_matches["line1"] = line1
    city = _field_status(extracted.get("city"), profile.get("city"), _normalize_city)
    if city is not None:
        field_matches["city"] = city
    state = _field_status(extracted.get("state"), profile.get("state"), _normalize_state)
    if state is not None:
        field_matches["state"] = state
    postal = _field_status(extracted.get("postal_code"), profile.get("postal_code"), _normalize_postal)
    if postal is not None:
        field_matches["postal_code"] = postal
    country = _field_status(extracted.get("country"), profile.get("country"), _normalize_country)
    if country is not None:
        field_matches["country"] = country

    # overall status
    city_ok = field_matches.get("city") == MATCH
    postal_ok = field_matches.get("postal_code") == MATCH
    all_present = list(field_matches.values())
    all_match = bool(all_present) and all(s == MATCH for s in all_present)

    if all_match:
        status = MATCH
    elif city_ok and postal_ok:
        # locality is correct but a finer field (e.g. line1) differs
        status = PARTIAL
    else:
        status = MISMATCH

    return {
        "status": status,
        "profile_address": {
            k: profile.get(k)
            for k in ("line1", "line2", "city", "state", "postal_code", "country")
            if profile.get(k) is not None
        },
        "field_matches": field_matches,
    }


# --- service ---------------------------------------------------------------


@dataclass
class KycResidencyStore:
    """Persistence + verification pipeline for KYC proof-of-residency documents."""

    _table: Any = field(default=T.kyc_residency_documents)

    # -- profile access ----------------------------------------------------

    def _load_profile_address(self, user_sub: str) -> dict[str, Any]:
        """Return the mailing_address dict from the user's profile (or {})."""
        try:
            from app.services.profile import get_profile

            profile = get_profile(user_sub)
        except Exception:  # pragma: no cover - defensive
            return {}
        addr = profile.get("mailing_address") or {}
        if not isinstance(addr, dict):
            return {}
        return addr

    # -- S3 upload ---------------------------------------------------------

    def _store_document(self, *, document_id: str, file_name: str, content_b64: str | None) -> dict[str, Any]:
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", file_name or "residency.pdf")
        bucket = S.kyc_residency_bucket or "local-uploads"
        s3_key = f"{S.kyc_residency_s3_prefix}{document_id}/{safe_name}"

        body: bytes | None = None
        if content_b64:
            try:
                body = base64.b64decode(content_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise KycResidencyValidationError("invalid_document_file") from exc

        if body is not None:
            try:
                from app.core.aws_clients import s3_client

                s3_client().put_object(
                    Bucket=bucket, Key=s3_key, Body=body, ContentType="application/octet-stream"
                )
            except Exception:  # pragma: no cover - dev mock best effort
                logger.warning("kyc.residency.s3_put_failed key=%s", s3_key)

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
        issuing_entity: str,
        document_date: str,
        file_name: str,
        case_id: str | None = None,
        content_b64: str | None = None,
    ) -> dict[str, Any]:
        """Upload a residency document and create a ``pending`` record."""
        doc_type = str(document_type or "").strip()
        if doc_type not in ALLOWED_DOCUMENT_TYPES:
            raise KycResidencyValidationError("invalid_document_type")
        if not str(file_name or "").strip():
            raise KycResidencyValidationError("missing_file_name")
        if not str(issuing_entity or "").strip():
            raise KycResidencyValidationError("missing_issuing_entity")
        if _parse_iso_date(document_date) is None:
            raise KycResidencyValidationError("invalid_document_date")

        document_id = _new_document_id()
        ts = now_ts()
        storage = self._store_document(
            document_id=document_id, file_name=file_name, content_b64=content_b64
        )

        item: dict[str, Any] = {
            "document_id": document_id,
            "user_sub": user_sub,
            "case_id": case_id or "_none",
            "document_type": doc_type,
            "issuing_entity": str(issuing_entity).strip(),
            "document_date": str(document_date).strip(),
            "file_name": file_name,
            "status": STATUS_PENDING,
            "provider": S.kyc_residency_provider,
            "s3_key": storage["s3_key"],
            "bucket": storage["bucket"],
            "document_url": storage.get("url"),
            "extraction_id": None,
            "extracted_address": {},
            "recency_valid": False,
            "recency_days": 0,
            "address_match": {},
            "review": {"decision": None, "reviewer_sub": None, "decided_at": None, "note": None},
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        logger.info("kyc.residency.uploaded document_id=%s type=%s", document_id, doc_type)
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

    def get_verified_docs_for_case(self, case_id: str) -> list[dict[str, Any]]:
        """Return all residency documents with status=verified for the given case.

        Queries the ByCase GSI (O(docs per case), typically 1-3 items) and
        filters in Python for status=verified. This is intentionally NOT
        implemented via the ByStatus GSI + FilterExpression, which would scan
        the entire 'verified' partition (potentially tens of thousands of items)
        to find the one or two documents for a specific case.
        """
        docs = self.list_documents_for_case(case_id)
        return [d for d in docs if str(d.get("status") or "") == STATUS_VERIFIED]

    def list_by_status(self, status: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List documents by status via the ByStatus GSI (PK=status, SK=created_at)."""
        st = str(status or "").strip()
        if st not in LISTABLE_STATUSES:
            raise KycResidencyValidationError("invalid_status")
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_residency_documents_status_index_name,
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

    def run_extraction(self, document_id: str, *, now: Any = None) -> dict[str, Any]:
        """Run (or re-run) the extraction/verification pipeline for a document.

        Idempotent: updates the existing record in place. Transitions
        ``pending`` -> ``verified`` / ``rejected`` / ``expired``.
        """
        item = self.get_document(document_id)
        if not item:
            raise KycResidencyNotFoundError(document_id)

        ts = now_ts()
        extraction_id = _new_extraction_id()

        # 1. recency check (deterministic, injectable now)
        recency_valid, recency_days = self._check_recency(
            str(item.get("document_date") or ""), now=now
        )

        # 2. extraction (mock by filename; address used for matching)
        extracted_address = self._run_provider(
            file_name=str(item.get("file_name") or ""),
            document_type=str(item.get("document_type") or ""),
        )

        # 3. address matching against the profile mailing_address
        profile_addr = self._load_profile_address(str(item.get("user_sub") or ""))
        address_match = match_addresses(extracted_address, profile_addr)

        # 4. status lifecycle
        status = self._decide_status(
            recency_valid=recency_valid, address_match=address_match
        )

        update = {
            "status": status,
            "extraction_id": extraction_id,
            "extracted_address": extracted_address,
            "recency_valid": recency_valid,
            "recency_days": recency_days,
            "address_match": address_match,
            "provider": S.kyc_residency_provider,
            "updated_at": ts,
        }
        self._apply_update(document_id, update)
        logger.info(
            "kyc.residency.extracted document_id=%s status=%s recency_valid=%s match=%s",
            document_id,
            status,
            recency_valid,
            address_match.get("status"),
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
        """Approve (verify) or reject a residency document (reviewer action)."""
        dec = str(decision or "").strip().lower()
        if dec not in ("approve", "reject"):
            raise KycResidencyValidationError("invalid_decision")
        item = self.get_document(document_id)
        if not item:
            raise KycResidencyNotFoundError(document_id)
        if str(item.get("status")) == STATUS_PENDING:
            raise KycResidencyStateError("document_not_extracted")

        new_status = STATUS_VERIFIED if dec == "approve" else STATUS_REJECTED
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
            "kyc.residency.reviewed document_id=%s decision=%s reviewer=%s",
            document_id,
            dec,
            reviewer_sub,
        )
        return {**item, **update}

    def expire_stale_submissions(
        self, *, now: Any = None, limit: int = 500
    ) -> list[str]:
        """Expire verified residency documents whose ``document_date`` has aged
        out of the recency window (KYC-005 / GAP-0255).

        Iterates the ByStatus GSI ``verified`` partition (paginated internally
        via ``list_by_status`` -> ``LastEvaluatedKey``) and re-applies the
        recency check. Any document that is no longer recent is transitioned to
        :data:`STATUS_EXPIRED` so it stops satisfying readiness gates forever.

        ``now`` is injectable for deterministic tests. Processes at most
        ``limit`` verified documents per invocation. Returns the list of
        expired ``document_id`` values.
        """
        expired_ids: list[str] = []
        items = self.list_by_status(STATUS_VERIFIED, limit=limit)
        ts = now_ts()
        for item in items:
            recency_valid, _ = self._check_recency(
                str(item.get("document_date") or ""), now=now
            )
            if recency_valid:
                continue
            document_id = str(item.get("document_id") or "")
            if not document_id:
                continue
            self._apply_update(
                document_id,
                {
                    "status": STATUS_EXPIRED,
                    "updated_at": ts,
                },
            )
            logger.info(
                "kyc.residency.expired document_id=%s document_date=%s",
                document_id,
                item.get("document_date"),
            )
            expired_ids.append(document_id)
        return expired_ids

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

    def _check_recency(self, document_date: str, *, now: Any = None) -> tuple[bool, int]:
        """Return (recency_valid, recency_days). A document dated more than
        ``kyc_residency_recency_days`` ago is not recent. The boundary day
        (exactly N days) is inclusive (still valid)."""
        d = _parse_iso_date(document_date)
        if d is None:
            return (False, 0)
        today = _today(now)
        days = (today - d).days
        if days < 0:
            # future-dated document; treat age as 0
            days = 0
        valid = days <= S.kyc_residency_recency_days
        return (valid, days)

    def _decide_status(self, *, recency_valid: bool, address_match: dict) -> str:
        if not recency_valid:
            return STATUS_EXPIRED
        match_status = str((address_match or {}).get("status") or "")
        if match_status == MISMATCH:
            return STATUS_REJECTED
        # match / partial / not_available -> awaiting/eligible: verified
        return STATUS_VERIFIED

    def _run_provider(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        if S.kyc_residency_real_extraction_enabled:
            return self._run_real_extraction(file_name=file_name, document_type=document_type)
        return self._run_mock_extraction(file_name=file_name, document_type=document_type)

    def _run_real_extraction(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        """Placeholder for a real extraction provider. Not wired in dev / E2E."""
        logger.warning("kyc.residency.real_provider_not_configured falling back to mock")
        return self._run_mock_extraction(file_name=file_name, document_type=document_type)

    def _run_mock_extraction(self, *, file_name: str, document_type: str) -> dict[str, Any]:
        """Deterministic mock address extraction keyed off the filename.

        Default extraction yields the canonical "matching" address. Filename
        markers select variant addresses so E2E tests are predictable:

          _mismatchcity_  -> different city  (drives status=mismatch/rejected)
          _partial_       -> different line1  (drives status=partial/verified)
          _abbrev_        -> abbreviated line1 ("123 Main St", "Ste 200")
          _statecode_     -> state given as abbreviation ("CA")
          _zipplus4_      -> postal code with +4 extension
          _country_       -> country as ISO code ("US")
        """
        lower = (file_name or "").lower()

        addr: dict[str, Any] = {
            "line1": "123 Main Street",
            "line2": "Apartment 4B",
            "city": "San Francisco",
            "state": "California",
            "postal_code": "94105",
            "country": "United States",
        }

        if "_mismatchcity_" in lower:
            addr["city"] = "Los Angeles"
        if "_partial_" in lower:
            addr["line1"] = "456 Oak Avenue"
        if "_abbrev_" in lower:
            addr["line1"] = "123 Main St"
            addr["line2"] = "Ste 200"
        if "_statecode_" in lower:
            addr["state"] = "CA"
        if "_zipplus4_" in lower:
            addr["postal_code"] = "94105-1234"
        if "_country_" in lower:
            addr["country"] = "US"

        return addr


STORE = KycResidencyStore()


def public_document_view(item: dict[str, Any], *, include_match: bool = True) -> dict[str, Any]:
    """Shape a stored item into the API response model fields."""
    review = item.get("review") or {}
    out: dict[str, Any] = {
        "document_id": item.get("document_id"),
        "case_id": None if item.get("case_id") == "_none" else item.get("case_id"),
        "user_sub": item.get("user_sub"),
        "document_type": item.get("document_type"),
        "issuing_entity": item.get("issuing_entity"),
        "document_date": item.get("document_date"),
        "file_name": item.get("file_name"),
        "status": item.get("status"),
        "provider": item.get("provider"),
        "document_url": item.get("document_url"),
        "extraction_id": item.get("extraction_id"),
        "recency_valid": bool(item.get("recency_valid")),
        "recency_days": _coerce_int(item.get("recency_days")),
        "review_decision": review.get("decision"),
        "review_note": review.get("note"),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }
    if include_match:
        out["extracted_address"] = item.get("extracted_address") or {}
        am = item.get("address_match") or {}
        out["address_match"] = am if am else None
    return out


# -- background expiry task (GAP-0255 / KYC-005) ---------------------------

_RESIDENCY_EXPIRY_INTERVAL_SECONDS = 6 * 3600  # run every 6 hours


async def kyc_residency_expiry_loop(
    interval_seconds: int = _RESIDENCY_EXPIRY_INTERVAL_SECONDS,
) -> None:
    """Every ``interval_seconds``: expire verified residency documents whose
    ``document_date`` has aged out of the recency window so a stale submission
    stops satisfying readiness gates forever (and the ByStatus ``verified``
    partition stays pruned). Never raises out of the loop."""
    import asyncio

    while True:
        try:
            expired = STORE.expire_stale_submissions()
            if expired:
                logger.info(
                    "kyc.residency.expiry_loop.expired count=%d document_ids=%s",
                    len(expired),
                    expired[:10],
                )
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.residency.expiry_loop.error")
        await asyncio.sleep(max(5, int(interval_seconds)))


def start_kyc_residency_expiry_task() -> None:
    """Register the KYC residency submission-expiry background task at startup."""
    import asyncio

    if S.kyc_residency_enabled and S.kyc_residency_expiry_enabled:
        asyncio.ensure_future(kyc_residency_expiry_loop())
        logger.info("KYC residency submission-expiry task started")
