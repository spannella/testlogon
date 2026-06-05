"""KYC Risk Scoring Engine (KYC-008).

Computes a weighted risk score (0-100) for users based on 8 factors,
assigns risk tiers, and optionally auto-approves or auto-escalates cases.
"""
from __future__ import annotations

import logging
import threading
import time
from decimal import Decimal
from typing import Any
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# The kyc_risk_scores table uses (user_sub, timestamp) as its key. Multiple
# scores written for the same user within the same wall-clock second would
# collide on the sort key and silently overwrite each other (losing history).
# Use a process-monotonic microsecond value as the sort key so every write is
# distinct while preserving chronological ordering.
_sort_key_lock = threading.Lock()
_last_sort_key = 0


def _unique_sort_key() -> int:
    """Return a strictly-increasing integer suitable for the timestamp sort key."""
    global _last_sort_key
    with _sort_key_lock:
        candidate = time.time_ns() // 1000  # microseconds
        if candidate <= _last_sort_key:
            candidate = _last_sort_key + 1
        _last_sort_key = candidate
        return candidate

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk tiers
# ---------------------------------------------------------------------------

RISK_TIERS = {
    "low": (0, 30),
    "medium": (31, 60),
    "high": (61, 80),
    "critical": (81, 100),
}

# ---------------------------------------------------------------------------
# Default factor weights (must sum to 1.0)
# ---------------------------------------------------------------------------

DEFAULT_FACTOR_WEIGHTS: dict[str, float] = {
    "country_risk": 0.15,
    "document_quality": 0.15,
    "screening_result": 0.25,
    "source_of_funds": 0.15,
    "verification_call": 0.10,
    "profile_completeness": 0.05,
    "account_age": 0.05,
    "address_match": 0.10,
}

# ---------------------------------------------------------------------------
# Country risk lists
# ---------------------------------------------------------------------------

_LOW_RISK_COUNTRIES = {
    "US", "GB", "CA", "AU", "NZ", "DE", "FR", "NL", "SE", "NO", "DK",
    "FI", "IE", "AT", "BE", "LU", "CH", "IT", "ES", "PT", "JP", "SG",
}

_HIGH_RISK_COUNTRIES = {
    "KP", "IR", "SY", "CU", "VE", "MM", "SD", "SO", "YE", "LY", "AF",
}


def _determine_tier(total_score: int) -> str:
    """Map numeric score to risk tier."""
    for tier, (lo, hi) in RISK_TIERS.items():
        if lo <= total_score <= hi:
            return tier
    return "critical"  # > 100 edge case


class KycRiskScoringService:
    """Stateless risk scoring engine.  All state is in DynamoDB."""

    def __init__(self, *, table=None, weights: dict[str, float] | None = None):
        self._table = table or T.kyc_risk_scores
        self._weights = weights or DEFAULT_FACTOR_WEIGHTS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_score(
        self,
        *,
        case_id: str,
        user_sub: str,
        trigger: str = "submission",
    ) -> dict:
        """Compute risk score, store in DDB, return the full record."""
        factors = self._compute_all_factors(case_id=case_id, user_sub=user_sub)

        weighted_total = sum(
            f["score"] * f["weight"] for f in factors.values()
        )
        total_score = max(0, min(100, int(round(weighted_total))))

        tier = _determine_tier(total_score)

        # Fetch previous score
        prev = self.get_latest_score(user_sub=user_sub)
        previous_score = int(prev["total_score"]) if prev else None
        previous_tier = prev["risk_tier"] if prev else None

        # Determine auto-action
        all_checks_passed = self._all_checks_passed(factors)
        auto_action = self._apply_auto_action(
            case_id=case_id,
            score=total_score,
            tier=tier,
            all_checks_passed=all_checks_passed,
        )

        ts = now_ts()
        sort_ts = _unique_sort_key()
        score_id = f"rs_{uuid4().hex[:12]}"

        # Convert factor values for DDB (Decimal)
        factors_ddb: dict[str, Any] = {}
        for fname, fdata in factors.items():
            factors_ddb[fname] = {
                "score": Decimal(str(fdata["score"])),
                "weight": Decimal(str(fdata["weight"])),
                "weighted_score": Decimal(str(round(fdata["score"] * fdata["weight"], 4))),
                "raw_value": str(fdata["raw_value"]),
                "description": fdata["description"],
            }

        item: dict[str, Any] = {
            "user_sub": user_sub,
            "timestamp": sort_ts,
            "score_id": score_id,
            "case_id": case_id,
            "total_score": total_score,
            "risk_tier": tier,
            "factors": factors_ddb,
            "trigger": trigger,
            "auto_action_taken": auto_action,
            "model_version": S.kyc_risk_scoring_model_version,
            "created_at": ts,
        }
        if previous_score is not None:
            item["previous_score"] = previous_score
            item["previous_tier"] = previous_tier

        self._table.put_item(Item=item)
        logger.info(
            "kyc.risk.scored case_id=%s user_sub=%s total_score=%s tier=%s trigger=%s",
            case_id, user_sub, total_score, tier, trigger,
        )

        return self._to_output(item)

    def get_latest_score(self, *, user_sub: str) -> dict | None:
        """Most recent score for a user (ScanIndexForward=False, Limit=1)."""
        resp = self._table.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub),
            ScanIndexForward=False,
            Limit=1,
        )
        items = resp.get("Items", [])
        return self._to_output(items[0]) if items else None

    def get_score_history(self, *, user_sub: str, limit: int = 25) -> list[dict]:
        """Score history for a user, newest first."""
        resp = self._table.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub),
            ScanIndexForward=False,
            Limit=min(limit, 100),
        )
        return [self._to_output(i) for i in resp.get("Items", [])]

    def get_scores_for_case(self, *, case_id: str) -> list[dict]:
        """All scores for a specific case via GSI."""
        resp = self._table.query(
            IndexName="case-timestamp-index",
            KeyConditionExpression=Key("case_id").eq(case_id),
            ScanIndexForward=False,
        )
        return [self._to_output(i) for i in resp.get("Items", [])]

    def get_tier_distribution(self) -> dict:
        """Count of users in each risk tier.

        For each tier we do a Select=COUNT query on the ByTier GSI.
        We also count auto_approved and auto_escalated actions.
        """
        dist: dict[str, int] = {}
        total = 0
        for tier in RISK_TIERS:
            resp = self._table.query(
                IndexName="tier-timestamp-index",
                KeyConditionExpression=Key("risk_tier").eq(tier),
                Select="COUNT",
            )
            count = resp.get("Count", 0)
            dist[tier] = count
            total += count

        # Count auto-actions (scan a small set - acceptable for dev)
        auto_approved = 0
        auto_escalated = 0
        scan_params: dict[str, Any] = {}
        while True:
            resp = self._table.scan(**scan_params)
            for item in resp.get("Items", []):
                aa = str(item.get("auto_action_taken", "none"))
                if aa == "auto_approved":
                    auto_approved += 1
                elif aa == "auto_escalated":
                    auto_escalated += 1
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            scan_params["ExclusiveStartKey"] = lek

        return {
            "distribution": dist,
            "total_scored": total,
            "auto_approve_rate": round(auto_approved / total, 2) if total else 0,
            "auto_escalate_rate": round(auto_escalated / total, 2) if total else 0,
        }

    def list_users_by_tier(self, *, tier: str, limit: int = 50) -> list[dict]:
        """List score records in a given tier."""
        resp = self._table.query(
            IndexName="tier-timestamp-index",
            KeyConditionExpression=Key("risk_tier").eq(tier),
            ScanIndexForward=False,
            Limit=min(limit, 200),
        )
        return [self._to_output(i) for i in resp.get("Items", [])]

    def admin_override_risk_score(
        self,
        *,
        admin_id: str,
        user_sub: str,
        score: int,
        reason: str,
    ) -> dict:
        """Admin manually overrides the risk score for a user."""
        prev = self.get_latest_score(user_sub=user_sub)
        previous_score = int(prev["total_score"]) if prev else None
        previous_tier = prev["risk_tier"] if prev else None

        tier = _determine_tier(score)
        ts = now_ts()
        sort_ts = _unique_sort_key()
        score_id = f"rs_{uuid4().hex[:12]}"

        item: dict[str, Any] = {
            "user_sub": user_sub,
            "timestamp": sort_ts,
            "score_id": score_id,
            "case_id": "override",
            "total_score": score,
            "risk_tier": tier,
            "factors": {
                "admin_override": {
                    "score": Decimal(str(score)),
                    "weight": Decimal("1"),
                    "weighted_score": Decimal(str(score)),
                    "raw_value": f"override_by_{admin_id}",
                    "description": reason,
                }
            },
            "trigger": "manual",
            "auto_action_taken": "none",
            "model_version": S.kyc_risk_scoring_model_version,
            "created_at": ts,
        }
        if previous_score is not None:
            item["previous_score"] = previous_score
            item["previous_tier"] = previous_tier

        self._table.put_item(Item=item)
        logger.info(
            "kyc.risk.admin_override user_sub=%s score=%s tier=%s admin=%s reason=%s",
            user_sub, score, tier, admin_id, reason,
        )
        return self._to_output(item)

    # ------------------------------------------------------------------
    # Factor computation
    # ------------------------------------------------------------------

    def _compute_all_factors(self, *, case_id: str, user_sub: str) -> dict[str, dict]:
        """Compute all 8 risk factors.  Each returns {score, weight, raw_value, description}."""
        factors = {}
        for name in self._weights:
            method = getattr(self, f"_compute_{name}", None)
            if method:
                try:
                    result = method(case_id=case_id, user_sub=user_sub)
                except Exception:
                    logger.exception("Factor %s computation failed for case=%s", name, case_id)
                    result = {
                        "score": 50,
                        "raw_value": "error",
                        "description": f"Error computing {name}",
                    }
            else:
                result = {
                    "score": 0,
                    "raw_value": "unknown",
                    "description": f"Factor {name} not implemented",
                }
            result["weight"] = self._weights[name]
            factors[name] = result
        return factors

    def _compute_country_risk(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on user's country."""
        try:
            # country / nationality live at the top level of the users table item
            # (written by external KYC processes, e.g. kyc_sanctions_screening),
            # keyed by the simple "user_sub" partition key.
            resp = T.users.get_item(Key={"user_sub": user_sub})
            profile = resp.get("Item", {}) or {}
            country = str(profile.get("country", "") or profile.get("nationality", "") or "").upper().strip()
        except Exception:
            country = ""

        if not country:
            return {"score": 30, "raw_value": "unknown", "description": "Country not specified"}
        if country in _LOW_RISK_COUNTRIES:
            return {"score": 0, "raw_value": country, "description": f"Low-risk country: {country}"}
        if country in _HIGH_RISK_COUNTRIES:
            return {"score": 100, "raw_value": country, "description": f"High-risk country: {country}"}
        return {"score": 50, "raw_value": country, "description": f"Medium-risk country: {country}"}

    def _compute_document_quality(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on document extraction confidence."""
        # Dependencies KYC-002 may not be implemented; return safe default
        try:
            resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
            case = resp.get("Item", {})
            files = case.get("files", [])
            if not files:
                return {"score": 40, "raw_value": "no_documents", "description": "No documents uploaded"}
            # Check verification states
            states = [str(f.get("verification_state", "pending")).lower() for f in files if isinstance(f, dict)]
            if all(s == "verified" for s in states):
                return {"score": 0, "raw_value": "all_verified", "description": "All documents verified"}
            if any(s == "rejected" for s in states):
                return {"score": 80, "raw_value": "rejected", "description": "One or more documents rejected"}
            return {"score": 30, "raw_value": "pending", "description": "Documents pending verification"}
        except Exception:
            return {"score": 40, "raw_value": "unavailable", "description": "Document quality check unavailable"}

    def _compute_screening_result(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on screening results."""
        try:
            resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
            case = resp.get("Item", {})
            screening = case.get("screening", {})
            if not screening:
                return {"score": 40, "raw_value": "not_conducted", "description": "Screening not conducted"}
            status = str(screening.get("status", "")).lower()
            if status == "clear" or status == "all_clear":
                return {"score": 0, "raw_value": "all_clear", "description": "All screening checks clear"}
            if status == "confirmed_match":
                return {"score": 100, "raw_value": "confirmed_match", "description": "Confirmed screening match"}
            if status == "potential_match":
                reviewed = screening.get("reviewed_as_false_positive", False)
                if reviewed:
                    return {"score": 50, "raw_value": "false_positive", "description": "Potential match reviewed as false positive"}
                return {"score": 80, "raw_value": "potential_match", "description": "Unreviewed potential screening match"}
            return {"score": 20, "raw_value": status, "description": f"Screening status: {status}"}
        except Exception:
            return {"score": 40, "raw_value": "unavailable", "description": "Screening check unavailable"}

    def _compute_source_of_funds(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on source of funds risk flags."""
        try:
            resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
            case = resp.get("Item", {})
            sof = case.get("source_of_funds", {})
            if not sof:
                # KYC-005: fall back to standalone proof-of-funds submissions.
                pof = self._proof_of_funds_factor(user_sub)
                if pof is not None:
                    return pof
                return {"score": 30, "raw_value": "not_provided", "description": "Source of funds not provided"}
            risk_flags = sof.get("risk_flags", [])
            if not risk_flags:
                return {"score": 0, "raw_value": "no_flags", "description": "No SOF risk flags"}
            # Sum risk flag weights (20 each, capped at 100)
            flag_score = min(100, len(risk_flags) * 20)
            return {"score": flag_score, "raw_value": f"{len(risk_flags)}_flags", "description": f"{len(risk_flags)} SOF risk flag(s)"}
        except Exception:
            return {"score": 30, "raw_value": "unavailable", "description": "SOF check unavailable"}

    def _compute_verification_call(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on verification call result."""
        try:
            resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
            case = resp.get("Item", {})
            call = case.get("verification_call", {})
            if not call:
                return {"score": 40, "raw_value": "not_conducted", "description": "Verification call not conducted"}
            result = str(call.get("result", "")).lower()
            if result == "passed":
                return {"score": 0, "raw_value": "passed", "description": "Verification call passed"}
            if result == "inconclusive":
                return {"score": 60, "raw_value": "inconclusive", "description": "Verification call inconclusive"}
            if result == "failed":
                return {"score": 100, "raw_value": "failed", "description": "Verification call failed"}
            return {"score": 40, "raw_value": result or "unknown", "description": f"Verification call: {result or 'unknown'}"}
        except Exception:
            return {"score": 40, "raw_value": "unavailable", "description": "Verification call check unavailable"}

    def _compute_profile_completeness(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on how many critical profile fields are populated."""
        # first_name / last_name / birthday live in the profile table (nested under
        # the "profile" sub-document); email lives at the top level of the users
        # table. The profile table stores the date of birth as "birthday", not
        # "date_of_birth".
        critical_fields = ["first_name", "last_name", "birthday", "email"]
        try:
            from app.services.profile import get_profile

            profile = dict(get_profile(user_sub) or {})
            users_item = T.users.get_item(Key={"user_sub": user_sub}).get("Item", {}) or {}
            if not profile.get("email"):
                profile["email"] = users_item.get("email")
            missing = 0
            for field in critical_fields:
                val = profile.get(field)
                if not val or (isinstance(val, str) and not val.strip()):
                    missing += 1
            score = min(100, missing * 20)
            if score == 0:
                return {"score": 0, "raw_value": "complete", "description": "All profile fields populated"}
            return {"score": score, "raw_value": f"{missing}_missing", "description": f"{missing} critical profile field(s) missing"}
        except Exception:
            return {"score": 40, "raw_value": "unavailable", "description": "Profile check unavailable"}

    def _compute_account_age(self, *, case_id: str, user_sub: str) -> dict:
        """Score: newer accounts are higher risk."""
        try:
            # created_at is written by registration.py at the top level of the
            # users table item, keyed by the simple "user_sub" partition key.
            resp = T.users.get_item(Key={"user_sub": user_sub})
            profile = resp.get("Item", {}) or {}
            created_at = profile.get("created_at")
            if not created_at:
                return {"score": 60, "raw_value": "unknown", "description": "Account creation date unknown"}
            age_days = (now_ts() - int(created_at)) // 86400
            if age_days > 180:
                return {"score": 0, "raw_value": f"{age_days}_days", "description": f"Account {age_days} days old (>180 days)"}
            if age_days >= 30:
                return {"score": 30, "raw_value": f"{age_days}_days", "description": f"Account {age_days} days old (30-180 days)"}
            if age_days >= 7:
                return {"score": 60, "raw_value": f"{age_days}_days", "description": f"Account {age_days} days old (7-30 days)"}
            return {"score": 100, "raw_value": f"{age_days}_days", "description": f"Account {age_days} days old (<7 days)"}
        except Exception:
            return {"score": 60, "raw_value": "unavailable", "description": "Account age check unavailable"}

    def _compute_address_match(self, *, case_id: str, user_sub: str) -> dict:
        """Score based on residency address match."""
        try:
            resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
            case = resp.get("Item", {})
            residency = case.get("residency_meta", {})
            if not residency:
                return {"score": 100, "raw_value": "no_residency_doc", "description": "No residency document provided"}
            match_info = residency.get("address_match", {})
            status = str(match_info.get("status", "") if isinstance(match_info, dict) else match_info).lower()
            if status == "match":
                return {"score": 0, "raw_value": "match", "description": "Address fully matched"}
            if status == "partial":
                return {"score": 40, "raw_value": "partial", "description": "Address partially matched"}
            if status == "mismatch":
                return {"score": 80, "raw_value": "mismatch", "description": "Address mismatch"}
            return {"score": 60, "raw_value": status or "unknown", "description": f"Address match: {status or 'unknown'}"}
        except Exception:
            return {"score": 60, "raw_value": "unavailable", "description": "Address match check unavailable"}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _proof_of_funds_factor(user_sub: str) -> dict | None:
        """KYC-005 integration: derive a source-of-funds factor from standalone
        proof-of-funds submissions when the case has no embedded SOF data.

        Returns None when no proof-of-funds submissions exist (so the caller can
        fall back to its default), otherwise a factor dict {score, raw_value,
        description}.
        """
        try:
            from app.services.kyc_proof_of_funds import summarize_proof_of_funds

            summary = summarize_proof_of_funds(user_sub)
        except Exception:
            return None
        if not summary or int(summary.get("count") or 0) == 0:
            return None
        verified = int(summary.get("verified_count") or 0)
        contribution = int(summary.get("active_risk_contribution") or 0)
        if verified > 0:
            return {
                "score": max(0, min(100, contribution)),
                "raw_value": f"{verified}_verified",
                "description": f"{verified} verified proof-of-funds submission(s)",
            }
        # Submissions exist but none verified -> elevated risk from contribution.
        return {
            "score": max(0, min(100, 30 + contribution)),
            "raw_value": "unverified_proof_of_funds",
            "description": "Proof-of-funds submitted but not yet verified",
        }

    @staticmethod
    def _all_checks_passed(factors: dict[str, dict]) -> bool:
        """True if all factor scores are 0 (all clear)."""
        return all(f["score"] == 0 for f in factors.values())

    def _apply_auto_action(
        self,
        *,
        case_id: str,
        score: int,
        tier: str,
        all_checks_passed: bool,
    ) -> str:
        """Apply auto-approve or auto-escalate based on score and tier."""
        if (
            S.kyc_risk_auto_approve_enabled
            and tier == "low"
            and all_checks_passed
            and score <= S.kyc_risk_auto_approve_max_score
        ):
            # Auto-approve
            try:
                from app.services.kyc_cases import STORE
                case_resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
                case = case_resp.get("Item", {})
                if case and case.get("status") in ("submitted", "under_review"):
                    STORE.apply_admin_decision(
                        case_id=case_id,
                        owner_sub=case.get("user_sub", ""),
                        expected_version=int(case.get("version", 1)),
                        decision="approve",
                        actor_sub="system_auto_approve",
                        reason_codes=["auto_approved_low_risk"],
                        decision_note=f"Auto-approved: risk score {score} (tier: low), all checks passed",
                    )
                    logger.info("kyc.risk.auto_approved case_id=%s score=%s", case_id, score)
                    return "auto_approved"
            except Exception:
                logger.exception("Auto-approve failed for case %s", case_id)
            return "none"

        if tier == "critical" and score >= S.kyc_risk_auto_escalate_min_score:
            # Auto-escalate
            try:
                logger.warning("kyc.risk.auto_escalated case_id=%s score=%s tier=%s", case_id, score, tier)
                return "auto_escalated"
            except Exception:
                logger.exception("Auto-escalate failed for case %s", case_id)
            return "none"

        return "none"

    @staticmethod
    def _to_output(item: dict) -> dict:
        """Convert DDB item to JSON-safe output dict."""
        out: dict[str, Any] = {}
        for k, v in item.items():
            if isinstance(v, Decimal):
                out[k] = int(v) if v == int(v) else float(v)
            elif isinstance(v, dict):
                converted = {}
                for mk, mv in v.items():
                    if isinstance(mv, dict):
                        inner = {}
                        for ik, iv in mv.items():
                            inner[ik] = int(iv) if isinstance(iv, Decimal) and iv == int(iv) else (float(iv) if isinstance(iv, Decimal) else iv)
                        converted[mk] = inner
                    elif isinstance(mv, Decimal):
                        converted[mk] = int(mv) if mv == int(mv) else float(mv)
                    else:
                        converted[mk] = mv
                out[k] = converted
            else:
                out[k] = v
        return out
