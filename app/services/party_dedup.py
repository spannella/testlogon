"""
CCT-004 — Duplicate contact detection.

Scores candidate party pairs for likely duplication using:
1. Exact contact-mech match (EMAIL → 0.90, PHONE → 0.80)
2. Fuzzy name match via difflib.SequenceMatcher (ratio ≥ 0.85 → score = ratio × 0.70)

The scoring threshold is configurable via S.party_dedup_match_threshold (default 0.70).

Both service functions are flag-gated on S.party_crm_enabled.
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.cursor import decode_cursor, encode_cursor


def _normalize_name(name: str) -> str:
    """Lowercase, strip diacritics, collapse non-alphanumeric to spaces.
    Mirrors the pattern in app/services/kyc_sanctions_screening.py."""
    s = name.lower()
    # Strip diacritics (NFD normalization + remove combining chars)
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    # Collapse non-alphanumeric to spaces
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    return s


def _score_pair(
    party_a: Dict[str, Any],
    party_b: Dict[str, Any],
    mech_a: List[Dict[str, Any]],
    mech_b: List[Dict[str, Any]],
) -> Tuple[float, List[str]]:
    """Compute duplicate score and list of match signals."""
    signals: List[str] = []
    score = 0.0

    # Build lookup sets for party_b mechs
    email_vals_b = {
        m.get("mech_value", "").lower()
        for m in mech_b
        if m.get("mech_type") == "EMAIL"
    }
    phone_vals_b = {
        m.get("mech_value", "")
        for m in mech_b
        if m.get("mech_type") == "PHONE"
    }

    for m in mech_a:
        mtype = m.get("mech_type", "")
        val = m.get("mech_value", "")
        if mtype == "EMAIL" and val.lower() in email_vals_b:
            score = max(score, 0.90)
            signals.append("email_exact")
        elif mtype == "PHONE" and val in phone_vals_b:
            score = max(score, 0.80)
            signals.append("phone_exact")

    # Fuzzy name match
    name_a = _normalize_name(party_a.get("name", ""))
    name_b = _normalize_name(party_b.get("name", ""))
    if name_a and name_b:
        ratio = difflib.SequenceMatcher(None, name_a, name_b).ratio()
        if ratio >= 0.85:
            name_score = ratio * 0.70
            if name_score > score:
                score = name_score
            signals.append(f"name_similarity:{ratio:.2f}")

    return min(score, 1.0), signals


def _list_mechs_for_party(party_id: str) -> List[Dict[str, Any]]:
    """Return all MECH# rows for a party."""
    resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(party_id) & Key("sk").begins_with("MECH#"),
    )
    return resp.get("Items", [])


def _find_parties_sharing_mech(
    mech_type: str,
    mech_value: str,
) -> List[str]:
    """Return party_ids that share an exact contact mech value via GSI_MECH_VALUE."""
    resp = T.party.query(
        IndexName="GSI_MECH_VALUE",
        KeyConditionExpression=Key("mech_value").eq(mech_value),
        FilterExpression=Attr("mech_type").eq(mech_type),
    )
    return [item.get("party_id", "") for item in resp.get("Items", []) if item.get("party_id")]


def find_duplicates_for_party(
    party_id: str,
    *,
    actor_sub: str,
) -> List[Dict[str, Any]]:
    """Find duplicate candidates for a given party.

    Returns a list of CctDuplicateCandidateOut dicts with score >= threshold.
    """
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    threshold = getattr(S, "party_dedup_match_threshold", 0.70)

    party_meta = T.party.get_item(Key={"party_id": party_id, "sk": "META"}).get("Item")
    if not party_meta:
        raise HTTPException(404, "party_not_found")

    mechs_a = _list_mechs_for_party(party_id)

    # Gather candidate party_ids via shared mechs
    candidate_ids: set = set()
    for m in mechs_a:
        mtype = m.get("mech_type", "")
        val = m.get("mech_value", "")
        if mtype in ("EMAIL", "PHONE") and val:
            for pid in _find_parties_sharing_mech(mtype, val):
                if pid != party_id:
                    candidate_ids.add(pid)

    # Also gather candidates by name prefix (scan up to 200 via GSI_CREATED)
    owner_sub = party_meta.get("owner_user_sub", "")
    if owner_sub:
        name_resp = T.party.query(
            IndexName="GSI_CREATED",
            KeyConditionExpression=Key("owner_user_sub").eq(owner_sub),
            Limit=200,
        )
        for item in name_resp.get("Items", []):
            pid = item.get("party_id", "")
            if pid and pid != party_id:
                candidate_ids.add(pid)

    results: List[Dict[str, Any]] = []
    for cand_id in candidate_ids:
        cand_meta = T.party.get_item(Key={"party_id": cand_id, "sk": "META"}).get("Item")
        if not cand_meta:
            continue
        mechs_b = _list_mechs_for_party(cand_id)
        score, signals = _score_pair(party_meta, cand_meta, mechs_a, mechs_b)
        if score >= threshold:
            results.append({
                "party_a_id": party_id,
                "party_b_id": cand_id,
                "score": score,
                "match_signals": signals,
            })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def list_all_duplicate_candidates(
    actor_sub: str,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Admin sweep: page through all parties and return duplicate pairs.

    Returns (items, next_cursor).
    """
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    try:
        from app.services.alerts import audit_event
        audit_event("party.duplicate_scan", actor_sub)
    except Exception:
        pass

    threshold = getattr(S, "party_dedup_match_threshold", 0.70)
    exclusive_start = decode_cursor(cursor)

    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "sk = :meta AND (party_type = :pg OR party_type = :ps)",
        "ExpressionAttributeValues": {
            ":meta": "META",
            ":pg": "PARTY_GROUP",
            ":ps": "PERSON",
        },
        "Limit": 50,
    }
    if exclusive_start:
        scan_kwargs["ExclusiveStartKey"] = exclusive_start

    resp = T.party.scan(**scan_kwargs)
    parties = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    results: List[Dict[str, Any]] = []
    # For each party pair found, score them
    seen_pairs: set = set()
    for i, party_a in enumerate(parties):
        pid_a = party_a.get("party_id", "")
        if not pid_a:
            continue
        mechs_a = _list_mechs_for_party(pid_a)

        # Find candidates via shared mechs
        candidate_ids: set = set()
        for m in mechs_a:
            mtype = m.get("mech_type", "")
            val = m.get("mech_value", "")
            if mtype in ("EMAIL", "PHONE") and val:
                for pid in _find_parties_sharing_mech(mtype, val):
                    if pid != pid_a:
                        candidate_ids.add(pid)

        for cand_id in candidate_ids:
            pair_key = tuple(sorted([pid_a, cand_id]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            cand_meta = T.party.get_item(Key={"party_id": cand_id, "sk": "META"}).get("Item")
            if not cand_meta:
                continue
            mechs_b = _list_mechs_for_party(cand_id)
            score, signals = _score_pair(party_a, cand_meta, mechs_a, mechs_b)
            if score >= threshold:
                results.append({
                    "party_a_id": pid_a,
                    "party_b_id": cand_id,
                    "score": score,
                    "match_signals": signals,
                })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results, next_cursor
