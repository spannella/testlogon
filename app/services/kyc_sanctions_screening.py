"""KYC-006: Sanctions / PEP Screening service.

Standalone sanctions + politically-exposed-persons (PEP) screening feature that
builds alongside the existing KYC features (``kyc_cases``, ``kyc_document_verification``,
``kyc_residency``, ``kyc_proof_of_funds``, ``kyc_liveness_call``, ``kyc_risk_scoring``)
WITHOUT modifying their core logic.

A user (subject) is screened, by name / DOB / country, against a sanctions and
PEP watchlist. Each run produces one result per ``screen_type``:

    sanctions_ofac, sanctions_eu, sanctions_un, pep_check, adverse_media

Each result carries a ``result`` status:

    clear            -> no watchlist hit
    potential_match  -> name match above the threshold (needs review)
    confirmed_match  -> exact/strong match on a designated entity

Results are written to the ``kyc_screening_results`` DynamoDB table
(PK=case_id, SK=screen_key="{screen_type}#{iso_ts}"). Reviewers list unreviewed
``potential_match`` / ``confirmed_match`` results via the ByStatus GSI (PK=result)
and adjudicate each one (``clear`` / ``confirm`` / ``escalate``). Re-reviewing an
already-reviewed result raises :class:`KycScreeningAlreadyReviewedError` (-> 409).

Screening feeds the KYC risk engine: a per-case ``screening`` summary is written
onto the KYC case META item so ``kyc_risk_scoring._compute_screening_result``
can consume it. That write is best-effort and import-safe (lazy import).

In dev (and E2E) a deterministic MOCK watchlist (the module constant
``MOCK_WATCHLIST``) is used so screening is fully reproducible. A "real" provider
is gated behind ``S.kyc_screening_real_provider_enabled`` (default off) and is
intentionally not wired in dev. Matching uses normalized-name fuzzy comparison
(case + diacritics insensitive) with DOB / country corroboration and an injectable
threshold; all inputs are injectable for deterministic tests.
"""

from __future__ import annotations

import difflib
import logging
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any

from boto3.dynamodb.conditions import Key

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

SCREEN_TYPES = [
    "sanctions_ofac",
    "sanctions_eu",
    "sanctions_un",
    "pep_check",
    "adverse_media",
]
_SCREEN_TYPE_SET = set(SCREEN_TYPES)

# result statuses
RESULT_CLEAR = "clear"
RESULT_POTENTIAL = "potential_match"
RESULT_CONFIRMED = "confirmed_match"
_ALL_RESULTS = {RESULT_CLEAR, RESULT_POTENTIAL, RESULT_CONFIRMED}
# results that can be listed via the ByStatus GSI for reviewer work
LISTABLE_RESULTS = {RESULT_POTENTIAL, RESULT_CONFIRMED}

# reviewer adjudication decisions
DECISION_CLEAR = "clear"
DECISION_CONFIRM = "confirm"
DECISION_ESCALATE = "escalate"
_ALL_DECISIONS = {DECISION_CLEAR, DECISION_CONFIRM, DECISION_ESCALATE}

# triggers
TRIGGER_SUBMISSION = "submission"
TRIGGER_PROFILE_CHANGE = "profile_change"
TRIGGER_CONTINUOUS = "continuous_monitoring"
TRIGGER_MANUAL = "manual"

# --- mock watchlist --------------------------------------------------------
# Deterministic, seeded watchlist used in dev / E2E so screening is reproducible.
# Each entry lists the screen types it appears on and the outcome it produces
# when a subject's name matches the entry name above the threshold. The entries
# are intentionally small and stable; tests rely on these names.
MOCK_WATCHLIST: list[dict[str, Any]] = [
    {
        "entity_id": "OFAC-SDN-1001",
        "name": "OFAC Test Person",
        "dob": "1990-01-15",
        "country": "US",
        "entity_type": "individual",
        "list_name": "OFAC SDN",
        "listed_since": "2020-01-01",
        "screen_types": ["sanctions_ofac"],
        "result": RESULT_POTENTIAL,
        "match_score": 0.92,
    },
    {
        "entity_id": "SAN-GLOBAL-2002",
        "name": "Sanctioned Person",
        "dob": "1980-06-30",
        "country": "RU",
        "entity_type": "individual",
        "list_name": "Global Sanctions",
        "listed_since": "2018-03-01",
        # appears on ALL sanctions lists with a confirmed match
        "screen_types": ["sanctions_ofac", "sanctions_eu", "sanctions_un"],
        "result": RESULT_CONFIRMED,
        "match_score": 1.0,
    },
    {
        "entity_id": "PEP-3003",
        "name": "PEP Official",
        "dob": "1975-11-02",
        "country": "GB",
        "entity_type": "individual",
        "list_name": "PEP Register",
        "listed_since": "2015-09-12",
        "screen_types": ["pep_check"],
        "result": RESULT_POTENTIAL,
        "match_score": 0.88,
    },
    {
        "entity_id": "MEDIA-4004",
        "name": "Media Flagged",
        "dob": None,
        "country": None,
        "entity_type": "individual",
        "list_name": "Adverse Media",
        "listed_since": "2022-05-20",
        "screen_types": ["adverse_media"],
        "result": RESULT_POTENTIAL,
        "match_score": 0.75,
    },
]

_MOCK_SOURCE_URL = "https://mock-screening.example.com/"


# --- errors ----------------------------------------------------------------


class KycScreeningValidationError(ValueError):
    """Invalid input supplied for a KYC screening operation."""


class KycScreeningNotFoundError(LookupError):
    """A referenced KYC screening result does not exist."""


class KycScreeningAlreadyReviewedError(RuntimeError):
    """The screening result has already been reviewed (409)."""


# --- helpers ---------------------------------------------------------------


def _new_screening_id() -> str:
    return f"scr_{uuid.uuid4().hex[:12]}"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _iso_ts(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strip_diacritics(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _normalize_name(value: str | None) -> str:
    """Case + diacritics insensitive name normalization for fuzzy matching."""
    if not value:
        return ""
    folded = _strip_diacritics(str(value)).lower()
    collapsed = re.sub(r"[^a-z0-9 ]", " ", folded)
    return re.sub(r"\s+", " ", collapsed).strip()


def _subject_matches_watchlist(subject: str | None, watch: str | None) -> float:
    """Return a similarity score (0.0-1.0) of how strongly a screened subject
    name matches a watchlist entry name.

    The watchlist entries use short discriminating "patterns" (e.g. ``OFAC Test
    Person``); a subject name matches when the watchlist's core pattern appears
    within it. We support three signals:

      * exact normalized equality                  -> 1.0
      * watchlist name is a contiguous substring of the subject (glob ``*name*``)
        -> strong match (>= 0.9)
      * watchlist name's leading tokens (dropping a trailing generic surname like
        "Person") appear contiguously in the subject -> strong match
      * fallback: fuzzy ``SequenceMatcher`` ratio
    """
    ns, nw = _normalize_name(subject), _normalize_name(watch)
    if not ns or not nw:
        return 0.0
    if ns == nw:
        return 1.0

    ratio = difflib.SequenceMatcher(None, ns, nw).ratio()

    # contiguous substring containment (matches the ticket's ``*pattern*`` globs)
    s_tokens = ns.split()
    w_tokens = nw.split()
    # try the full watchlist token sequence, then progressively drop the last
    # (often generic) token so e.g. "OFAC Test Person" still matches "OFAC Test".
    for end in range(len(w_tokens), 0, -1):
        pattern = w_tokens[:end]
        if len(pattern) < 2:
            break
        for i in range(0, len(s_tokens) - len(pattern) + 1):
            if s_tokens[i : i + len(pattern)] == pattern:
                return max(0.9, ratio)
    return ratio


def _name_similarity(a: str | None, b: str | None) -> float:
    return _subject_matches_watchlist(a, b)


# --- service ---------------------------------------------------------------


@dataclass
class KycSanctionsScreeningStore:
    """Persistence + screening pipeline for KYC sanctions / PEP screening."""

    _table: Any = field(default=T.kyc_screening_results)

    # -- subject identity --------------------------------------------------

    def _load_subject_identity(self, user_sub: str) -> dict[str, str | None]:
        """Return the screened name / DOB / country for a user.

        Pulls from the user profile (display_name / first+last, birthday) and
        the users table (country / nationality). Best-effort; returns blanks on
        any failure so screening still produces deterministic results.
        """
        name: str | None = None
        dob: str | None = None
        country: str | None = None
        try:
            from app.services.profile import get_profile

            profile = get_profile(user_sub)
            name = profile.get("display_name")
            if not name:
                parts = [profile.get("first_name"), profile.get("last_name")]
                name = " ".join(p for p in parts if p) or None
            dob = profile.get("birthday")
        except Exception:  # pragma: no cover - defensive
            pass
        try:
            resp = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
            country = (
                str(resp.get("country") or resp.get("nationality") or "").strip() or None
            )
        except Exception:  # pragma: no cover - defensive
            pass
        return {"name": name, "dob": dob, "country": country}

    # -- public API --------------------------------------------------------

    def screen_case(
        self,
        *,
        case_id: str,
        user_sub: str,
        trigger: str = TRIGGER_SUBMISSION,
        name: str | None = None,
        dob: str | None = None,
        country: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run all screen types for a case. Returns one result per screen type.

        ``name`` / ``dob`` / ``country`` are injectable for deterministic tests;
        when omitted they are resolved from the subject's profile.
        """
        identity = {"name": name, "dob": dob, "country": country}
        if not identity["name"]:
            identity = self._load_subject_identity(user_sub)
        logger.info(
            "kyc.screening.run_started case_id=%s user_sub=%s trigger=%s",
            case_id,
            user_sub,
            trigger,
        )
        results: list[dict[str, Any]] = []
        # share one base timestamp; offset per type so screen_key SKs are unique
        base_ts = now_ts()
        for offset, screen_type in enumerate(SCREEN_TYPES):
            results.append(
                self._store_result(
                    case_id=case_id,
                    user_sub=user_sub,
                    screen_type=screen_type,
                    trigger=trigger,
                    identity=identity,
                    ts=base_ts + offset,
                )
            )
        matches = sum(1 for r in results if r["result"] != RESULT_CLEAR)
        if matches:
            logger.warning(
                "kyc.screening.match_found case_id=%s matches=%s", case_id, matches
            )
            _emit_kyc_event_safe(
                event="kyc.sanctions.match",
                user_sub=user_sub,
                case_id=case_id,
                match_count=matches,
                trigger=trigger,
            )
        else:
            logger.info("kyc.screening.all_clear case_id=%s trigger=%s", case_id, trigger)
            _emit_kyc_event_safe(
                event="kyc.sanctions.clear",
                user_sub=user_sub,
                case_id=case_id,
                trigger=trigger,
            )
        self._write_case_screening_summary(case_id=case_id, results=results)
        return results

    def _store_result(
        self,
        *,
        case_id: str,
        user_sub: str,
        screen_type: str,
        trigger: str,
        identity: dict[str, str | None],
        ts: int,
    ) -> dict[str, Any]:
        provider_out = self._run_provider(
            screen_type=screen_type,
            name=identity.get("name"),
            dob=identity.get("dob"),
            country=identity.get("country"),
        )
        screening_id = _new_screening_id()
        screen_key = f"{screen_type}#{_iso_ts(ts)}"
        item: dict[str, Any] = {
            "case_id": case_id,
            "screen_key": screen_key,
            "screening_id": screening_id,
            "screen_type": screen_type,
            "user_sub": user_sub,
            "screened_name": identity.get("name") or "",
            "screened_dob": identity.get("dob") or "",
            "screened_nationality": identity.get("country") or "",
            "result": provider_out["result"],
            "match_details": provider_out["match_details"],
            "reviewed_by": None,
            "review_decision": None,
            "review_note": None,
            "reviewed_at": None,
            "provider": S.kyc_screening_provider,
            "trigger": trigger,
            "created_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def get_results_for_case(self, *, case_id: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression=Key("case_id").eq(case_id),
            ScanIndexForward=False,
        )
        items = list(resp.get("Items", []))
        items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
        return items

    def get_result(self, *, case_id: str, screen_key: str) -> dict[str, Any] | None:
        return self._table.get_item(
            Key={"case_id": case_id, "screen_key": screen_key}
        ).get("Item")

    def get_results_for_user(
        self, *, user_sub: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Screening history for a user across all cases (ByUserSub GSI, desc)."""
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_screening_user_index_name,
                "KeyConditionExpression": Key("user_sub").eq(user_sub),
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
        items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
        return items[:limit]

    def get_pending_reviews(
        self, *, result: str = RESULT_POTENTIAL, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List unreviewed results of a given status via the ByStatus GSI."""
        st = str(result or "").strip()
        if st not in LISTABLE_RESULTS:
            raise KycScreeningValidationError("kyc_invalid_screening_result")
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_screening_status_index_name,
                "KeyConditionExpression": Key("result").eq(st),
                "ScanIndexForward": False,
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kwargs)
            for it in resp.get("Items", []):
                if it.get("reviewed_by") in (None, ""):
                    items.append(it)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(items) >= limit:
                break
        items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
        return items[:limit]

    def review_match(
        self,
        *,
        case_id: str,
        screen_key: str,
        reviewer_sub: str,
        decision: str,
        note: str,
    ) -> dict[str, Any]:
        """Adjudicate a screening result (clear / confirm / escalate).

        Raises :class:`KycScreeningAlreadyReviewedError` (409) if it was already
        reviewed; :class:`KycScreeningNotFoundError` (404) if it does not exist;
        :class:`KycScreeningValidationError` (422) for a bad decision / note.
        """
        dec = str(decision or "").strip().lower()
        if dec not in _ALL_DECISIONS:
            raise KycScreeningValidationError("kyc_invalid_screening_decision")
        clean_note = str(note or "").strip()
        if not (1 <= len(clean_note) <= 2000):
            raise KycScreeningValidationError("kyc_invalid_screening_note")

        item = self.get_result(case_id=case_id, screen_key=screen_key)
        if not item:
            raise KycScreeningNotFoundError(screen_key)
        if item.get("reviewed_by") not in (None, ""):
            raise KycScreeningAlreadyReviewedError(screen_key)

        ts = now_ts()
        update = {
            "reviewed_by": reviewer_sub,
            "review_decision": dec,
            "review_note": clean_note,
            "reviewed_at": ts,
        }
        try:
            self._table.update_item(
                Key={"case_id": case_id, "screen_key": screen_key},
                UpdateExpression=(
                    "SET reviewed_by = :rb, review_decision = :rd, "
                    "review_note = :rn, reviewed_at = :ra"
                ),
                ConditionExpression="attribute_exists(case_id) AND "
                "(attribute_not_exists(reviewed_by) OR reviewed_by = :null)",
                ExpressionAttributeValues={
                    ":rb": reviewer_sub,
                    ":rd": dec,
                    ":rn": clean_note,
                    ":ra": ts,
                    ":null": None,
                },
            )
        except Exception as exc:  # ConditionalCheckFailed -> already reviewed
            if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                raise KycScreeningAlreadyReviewedError(screen_key) from exc
            raise
        logger.info(
            "kyc.screening.reviewed case_id=%s screen_key=%s decision=%s reviewer=%s",
            case_id,
            screen_key,
            dec,
            reviewer_sub,
        )
        merged = {**item, **update}
        self._write_case_screening_summary(case_id=case_id)
        return merged

    def rescreen_user(
        self,
        *,
        case_id: str,
        user_sub: str,
        trigger: str = TRIGGER_MANUAL,
        name: str | None = None,
        dob: str | None = None,
        country: str | None = None,
    ) -> list[dict[str, Any]]:
        """Re-screen a subject (append-only; new results with fresh timestamps)."""
        logger.info(
            "kyc.screening.rescreen_triggered case_id=%s user_sub=%s trigger=%s",
            case_id,
            user_sub,
            trigger,
        )
        return self.screen_case(
            case_id=case_id,
            user_sub=user_sub,
            trigger=trigger,
            name=name,
            dob=dob,
            country=country,
        )

    # -- risk integration --------------------------------------------------

    def _write_case_screening_summary(
        self, *, case_id: str, results: list[dict[str, Any]] | None = None
    ) -> None:
        """Write a ``screening`` summary onto the KYC case META item so the risk
        engine (``kyc_risk_scoring._compute_screening_result``) can consume it.

        Best-effort + import-safe: failures (e.g. the case row does not use the
        expected single-table layout, or the case does not exist) are swallowed.
        """
        try:
            items = results if results is not None else self.get_results_for_case(
                case_id=case_id
            )
            if not items:
                return
            # Use the latest screening run (by created_at) for the summary.
            latest_ts = max(_coerce_int(i.get("created_at")) for i in items)
            latest = [i for i in items if _coerce_int(i.get("created_at")) == latest_ts] or items

            def _effective(i: dict[str, Any]) -> str:
                """Status after considering reviewer adjudication."""
                if str(i.get("review_decision") or "") == DECISION_CLEAR:
                    return RESULT_CLEAR
                return str(i.get("result") or RESULT_CLEAR)

            statuses = [_effective(i) for i in latest]
            if RESULT_CONFIRMED in statuses:
                overall = RESULT_CONFIRMED
            elif RESULT_POTENTIAL in statuses:
                overall = RESULT_POTENTIAL
            else:
                overall = RESULT_CLEAR

            reviewed_fp = any(
                str(i.get("review_decision") or "") == DECISION_CLEAR for i in latest
            )
            summary = {
                "status": overall,
                "reviewed_as_false_positive": reviewed_fp,
                "match_count": sum(1 for s in statuses if s != RESULT_CLEAR),
                "provider": S.kyc_screening_provider,
                "updated_at": now_ts(),
            }
            from app.core.tables import T as _T

            _T.kyc_cases.update_item(
                Key={"pk": f"KYC#{case_id}", "sk": "META"},
                UpdateExpression="SET screening = :s",
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={":s": summary},
            )
        except Exception:  # pragma: no cover - best effort
            logger.debug("kyc.screening.summary_write_skipped case_id=%s", case_id)

    # -- provider ----------------------------------------------------------

    def _run_provider(
        self,
        *,
        screen_type: str,
        name: str | None,
        dob: str | None,
        country: str | None,
    ) -> dict[str, Any]:
        if S.kyc_screening_real_provider_enabled:
            return self._run_real_provider(
                screen_type=screen_type, name=name, dob=dob, country=country
            )
        return self._run_mock_screening(
            screen_type=screen_type, name=name, dob=dob, country=country
        )

    def _run_real_provider(
        self,
        *,
        screen_type: str,
        name: str | None,
        dob: str | None,
        country: str | None,
    ) -> dict[str, Any]:
        """Placeholder for a real screening provider. Not wired in dev / E2E."""
        logger.warning("kyc.screening.real_provider_not_configured falling back to mock")
        return self._run_mock_screening(
            screen_type=screen_type, name=name, dob=dob, country=country
        )

    def _run_mock_screening(
        self,
        *,
        screen_type: str,
        name: str | None,
        dob: str | None,
        country: str | None,
    ) -> dict[str, Any]:
        """Deterministic mock screening against ``MOCK_WATCHLIST``.

        For the requested ``screen_type``, find the watchlist entry that (a) lists
        on that screen type and (b) has a normalized-name similarity at or above
        the threshold. DOB / country corroboration nudges the score up. Returns
        the strongest match, or ``clear`` if none.
        """
        threshold = float(S.kyc_screening_match_threshold)
        best: dict[str, Any] | None = None
        best_score = 0.0
        for entry in MOCK_WATCHLIST:
            if screen_type not in entry.get("screen_types", []):
                continue
            sim = _name_similarity(name, entry.get("name"))
            if sim < threshold:
                continue
            score = float(entry.get("match_score") or sim)
            # corroboration: bump score (capped) when DOB / country agree
            if dob and entry.get("dob") and str(dob) == str(entry["dob"]):
                score = min(1.0, score + 0.03)
            if country and entry.get("country") and str(country).upper() == str(
                entry["country"]
            ).upper():
                score = min(1.0, score + 0.02)
            if score > best_score:
                best_score = score
                best = entry

        if best is None:
            return {"result": RESULT_CLEAR, "match_details": []}

        match_detail = {
            "list_name": best.get("list_name") or f"Mock {screen_type.upper()} List",
            "matched_name": best.get("name") or (name or ""),
            "matched_dob": best.get("dob"),
            # DynamoDB rejects native floats; store the score as Decimal.
            "match_score": Decimal(str(round(best_score, 4))),
            "entity_id": best.get("entity_id") or f"MOCK-{uuid.uuid4().hex[:8]}",
            "entity_type": best.get("entity_type") or "individual",
            "listed_since": best.get("listed_since"),
            "source_url": _MOCK_SOURCE_URL,
        }
        return {"result": best.get("result", RESULT_POTENTIAL), "match_details": [match_detail]}


STORE = KycSanctionsScreeningStore()


# --- view shaping ----------------------------------------------------------


def public_screening_view(item: dict[str, Any], *, include_match: bool = True) -> dict[str, Any]:
    """Shape a stored item into the API response model fields.

    When ``include_match`` is False (non-admin owner view) the match details are
    redacted to an empty list and reviewer fields are hidden.
    """
    raw_matches = item.get("match_details") or []
    match_details: list[dict[str, Any]] = []
    if include_match:
        for m in raw_matches:
            if not isinstance(m, dict):
                continue
            match_details.append(
                {
                    "list_name": m.get("list_name") or "",
                    "matched_name": m.get("matched_name") or "",
                    "matched_dob": m.get("matched_dob"),
                    "match_score": _coerce_float(m.get("match_score")),
                    "entity_id": m.get("entity_id") or "",
                    "entity_type": m.get("entity_type") or "individual",
                    "listed_since": m.get("listed_since"),
                    "source_url": m.get("source_url"),
                }
            )
    out: dict[str, Any] = {
        "screening_id": item.get("screening_id"),
        "case_id": item.get("case_id"),
        "screen_key": item.get("screen_key"),
        "screen_type": item.get("screen_type"),
        "user_sub": item.get("user_sub"),
        "result": item.get("result"),
        "match_details": match_details,
        "reviewed_by": item.get("reviewed_by") if include_match else None,
        "review_decision": item.get("review_decision") if include_match else None,
        "review_note": item.get("review_note") if include_match else None,
        "reviewed_at": _coerce_int(item.get("reviewed_at")) if item.get("reviewed_at") else None,
        "trigger": item.get("trigger"),
        "provider": item.get("provider") or S.kyc_screening_provider,
        "created_at": _coerce_int(item.get("created_at")),
    }
    return out
