"""
CCT-004 — Duplicate contact detection.

Scores candidate party pairs for likely duplication using:
1. Exact contact-mech match (EMAIL → 0.90, PHONE → 0.80)
2. Fuzzy name match via difflib.SequenceMatcher (ratio ≥ 0.85 → score = ratio × 0.70)

The scoring threshold is configurable via S.party_dedup_match_threshold (default 0.70).

Storage is the SAME ``party`` table owned by app.services.party. This module uses
that table's REAL key schema (PK/SK) and GSIs:
  * GSI2 (GSI2PK/GSI2SK) — contact-mech value lookup, keyed on the normalized
    EMAIL#.. / PHONE#.. value; used to find parties sharing an exact mech.
  * GSI3 (GSI3PK/GSI3SK) — owner listing, keyed on OWNER#{user_sub}; used to
    gather same-owner candidates for fuzzy-name scoring.
Contact-mech values are stored under the ``value`` attribute (not ``mech_value``).

Both service functions are flag-gated on S.party_crm_enabled.
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.cursor import decode_cursor, encode_cursor


def _pk(party_id: str) -> str:
    return f"PARTY#{party_id}"


def _mech_value(item: Dict[str, Any]) -> str:
    """Read a contact-mech value, tolerating both the real (`value`) and the
    legacy (`mech_value`) attribute names."""
    v = item.get("value")
    if v in (None, ""):
        v = item.get("mech_value", "")
    return v if isinstance(v, str) else ""


def _normalize_name(name: str) -> str:
    """Lowercase, strip diacritics, collapse non-alphanumeric to spaces."""
    s = name.lower()
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
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

    email_vals_b = {
        _mech_value(m).lower()
        for m in mech_b
        if m.get("mech_type") == "EMAIL"
    }
    phone_vals_b = {
        _mech_value(m)
        for m in mech_b
        if m.get("mech_type") == "PHONE"
    }

    for m in mech_a:
        mtype = m.get("mech_type", "")
        val = _mech_value(m)
        if mtype == "EMAIL" and val.lower() in email_vals_b:
            score = max(score, 0.90)
            signals.append("email_exact")
        elif mtype == "PHONE" and val in phone_vals_b:
            score = max(score, 0.80)
            signals.append("phone_exact")

    name_a = _normalize_name(party_a.get("name", "") or party_a.get("display_name", ""))
    name_b = _normalize_name(party_b.get("name", "") or party_b.get("display_name", ""))
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
        KeyConditionExpression=Key("PK").eq(_pk(party_id))
        & Key("SK").begins_with("MECH#"),
    )
    return resp.get("Items", [])


def _get_meta(party_id: str) -> Optional[Dict[str, Any]]:
    return T.party.get_item(Key={"PK": _pk(party_id), "SK": "META"}).get("Item")


def _find_parties_sharing_mech(mech_type: str, mech_value: str) -> List[str]:
    """Return party_ids that share an exact contact mech value via GSI2.

    GSI2PK is the normalized value key (EMAIL#{norm} / PHONE#{norm}).
    """
    if mech_type == "EMAIL":
        gsi2_pk = f"EMAIL#{mech_value.lower()}"
    elif mech_type == "PHONE":
        gsi2_pk = f"PHONE#{mech_value}"
    else:
        return []
    resp = T.party.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(gsi2_pk),
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

    party_meta = _get_meta(party_id)
    if not party_meta:
        raise HTTPException(404, "party_not_found")

    mechs_a = _list_mechs_for_party(party_id)

    # Gather candidate party_ids via shared mechs (GSI2).
    candidate_ids: set = set()
    for m in mechs_a:
        mtype = m.get("mech_type", "")
        val = _mech_value(m)
        if mtype in ("EMAIL", "PHONE") and val:
            for pid in _find_parties_sharing_mech(mtype, val):
                if pid != party_id:
                    candidate_ids.add(pid)

    # Also gather same-owner candidates for fuzzy-name scoring (GSI3 owner index).
    owner_sub = party_meta.get("owner_user_sub") or party_meta.get("user_sub", "")
    if owner_sub:
        name_resp = T.party.query(
            IndexName="GSI3",
            KeyConditionExpression=Key("GSI3PK").eq(f"OWNER#{owner_sub}"),
            Limit=200,
        )
        for item in name_resp.get("Items", []):
            if item.get("SK") != "META":
                continue
            pid = item.get("party_id", "")
            if pid and pid != party_id:
                candidate_ids.add(pid)

    results: List[Dict[str, Any]] = []
    for cand_id in candidate_ids:
        cand_meta = _get_meta(cand_id)
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
        "FilterExpression": "SK = :meta AND (party_type = :pg OR party_type = :ps)",
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
    seen_pairs: set = set()
    for party_a in parties:
        pid_a = party_a.get("party_id", "")
        if not pid_a:
            continue
        mechs_a = _list_mechs_for_party(pid_a)

        candidate_ids: set = set()
        for m in mechs_a:
            mtype = m.get("mech_type", "")
            val = _mech_value(m)
            if mtype in ("EMAIL", "PHONE") and val:
                for pid in _find_parties_sharing_mech(mtype, val):
                    if pid != pid_a:
                        candidate_ids.add(pid)

        for cand_id in candidate_ids:
            pair_key = tuple(sorted([pid_a, cand_id]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            cand_meta = _get_meta(cand_id)
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
