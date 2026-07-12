"""RSK-003 — Full-text résumé keyword-search token index.

Inverted-token index over extracted_text, stored on the candidates table
under RESUME_TOKEN# prefix. Adapts the KB-009 pattern.

Token row shape:
  pk = "RESUME_TOKEN#{token}"
  sk = "CANDIDATE#{candidate_id}"
  { candidate_id, name_snippet, owner_sub, updated_at }

All functions are synchronous; async routers call them directly (fast) or
via asyncio.to_thread (migration helper).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Module-level constants (not env-driven; changing requires index rebuild)
_RESUME_SEARCH_MAX_PREFIX_LEN: int = 8   # must match query-side prefix cap
_RESUME_SEARCH_MIN_TOKEN_LEN: int = 3   # skip words shorter than 3 chars
_RESUME_SEARCH_MAX_TOKENS: int = 400    # cap on distinct tokens per résumé


# ─────────────────────────────────────────────────────────────────────────────
# Token generation
# ─────────────────────────────────────────────────────────────────────────────

def _build_resume_tokens(text: str) -> list[str]:
    """Build inverted index tokens from résumé text.

    Generates prefix strings of length 3..min(len(word), 8) for each word
    with len >= 3. Deduplicates and caps at _RESUME_SEARCH_MAX_TOKENS.
    """
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    out: list[str] = []
    for word in words:
        if len(word) < _RESUME_SEARCH_MIN_TOKEN_LEN:
            continue
        for length in range(
            _RESUME_SEARCH_MIN_TOKEN_LEN,
            min(len(word), _RESUME_SEARCH_MAX_PREFIX_LEN) + 1,
        ):
            out.append(word[:length])
    # Deduplicate while preserving order
    return list(dict.fromkeys(out))[: _RESUME_SEARCH_MAX_TOKENS]


# ─────────────────────────────────────────────────────────────────────────────
# Index write/delete
# ─────────────────────────────────────────────────────────────────────────────

def _write_resume_index(
    candidate_id: str,
    name: str,
    owner_sub: str,
    text: str,
) -> None:
    """Write token index rows for a candidate's résumé text.

    Uses T.candidates.batch_writer() — mirrors _write_tag_index at
    newsfeed.py:444. Best-effort: caller wraps in try/except.
    """
    tokens = _build_resume_tokens(text)
    if not tokens:
        return

    name_snippet = (name or "")[:80]
    ts = now_ts()

    with T.candidates.batch_writer() as batch:  # type: ignore[attr-defined]
        for token in tokens:
            batch.put_item(
                Item={
                    "pk": f"RESUME_TOKEN#{token}",
                    "sk": f"CANDIDATE#{candidate_id}",
                    "candidate_id": candidate_id,
                    "name_snippet": name_snippet,
                    "owner_sub": owner_sub,
                    "updated_at": ts,
                }
            )


def _delete_resume_index(candidate_id: str, text: str) -> None:
    """Delete all token index rows for a candidate's résumé text.

    Best-effort: caller wraps in try/except.
    """
    tokens = _build_resume_tokens(text)
    if not tokens:
        return

    with T.candidates.batch_writer() as batch:  # type: ignore[attr-defined]
        for token in tokens:
            batch.delete_item(
                Key={
                    "pk": f"RESUME_TOKEN#{token}",
                    "sk": f"CANDIDATE#{candidate_id}",
                }
            )


# ─────────────────────────────────────────────────────────────────────────────
# Search
# ─────────────────────────────────────────────────────────────────────────────

def search_resumes(
    q: str,
    *,
    owner_sub: Optional[str] = None,
    limit: int = 25,
) -> list[dict]:
    """Search résumés by keyword query (AND semantics, up to 3 tokens).

    Returns list of dicts compatible with ResumeSearchResultItem.
    """
    # Tokenize query — same rules as index time but cap at 3 tokens
    query_words = re.findall(r"[a-z0-9]+", (q or "").lower())
    query_tokens = [
        w[:_RESUME_SEARCH_MAX_PREFIX_LEN]
        for w in query_words
        if len(w) >= _RESUME_SEARCH_MIN_TOKEN_LEN
    ][:3]

    if not query_tokens:
        return []

    # Fetch per-token candidate sets
    token_sets: list[dict[str, dict]] = []  # each is {candidate_id: row_data}
    for token in query_tokens:
        candidate_map: dict[str, dict] = {}
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": (
                    "pk = :pk"
                ),
                "ExpressionAttributeValues": {":pk": f"RESUME_TOKEN#{token}"},
                "Limit": 200,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.candidates.query(**kwargs)  # type: ignore[attr-defined]
            for item in resp.get("Items", []):
                sk = item.get("sk", "")
                if sk.startswith("CANDIDATE#"):
                    cid = sk[len("CANDIDATE#"):]
                    candidate_map[cid] = {
                        "candidate_id": cid,
                        "name_snippet": item.get("name_snippet", ""),
                        "owner_sub": item.get("owner_sub", ""),
                        "updated_at": int(item.get("updated_at", 0)),
                    }
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        token_sets.append(candidate_map)

    # AND-intersect: must appear in all token sets
    if not token_sets:
        return []
    intersected_ids = set(token_sets[0].keys())
    for ts_map in token_sets[1:]:
        intersected_ids &= set(ts_map.keys())

    if not intersected_ids:
        return []

    # Collect result data (from first token set — all have same row data)
    results = []
    primary = token_sets[0]
    for cid in intersected_ids:
        row = primary.get(cid, {})
        if not row:
            # Fall back to any token set that has this candidate
            for ts_map in token_sets:
                if cid in ts_map:
                    row = ts_map[cid]
                    break
        if owner_sub and row.get("owner_sub") != owner_sub:
            continue
        results.append(row)

    # Sort by updated_at desc
    results.sort(key=lambda r: r.get("updated_at", 0), reverse=True)
    return results[:limit]


# ─────────────────────────────────────────────────────────────────────────────
# Migration helper (CLI-only, not exposed as HTTP endpoint)
# ─────────────────────────────────────────────────────────────────────────────

def rebuild_resume_index() -> int:
    """Scan all ATTACHMENT# rows and rebuild the token index.

    Not exposed as an HTTP endpoint — invoked via scripts/rootctl or a one-off
    admin script. Returns count of résumés reindexed.
    """
    count = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "FilterExpression": "begins_with(sk, :prefix)",
            "ExpressionAttributeValues": {":prefix": "ATTACHMENT#"},
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.candidates.scan(**kwargs)  # type: ignore[attr-defined]
        for item in resp.get("Items", []):
            if item.get("extraction_status") != "ok":
                continue
            text = item.get("extracted_text", "")
            if not text:
                continue
            pk = item.get("pk", "")
            candidate_id = pk.removeprefix("CANDIDATE#")
            # Fetch candidate META for name/owner_sub
            try:
                meta_resp = T.candidates.get_item(  # type: ignore[attr-defined]
                    Key={"pk": pk, "sk": "META"}
                )
                meta = meta_resp.get("Item", {})
                name = (
                    f"{meta.get('first_name', '')} {meta.get('last_name', '')}".strip()
                    or meta.get("name", "")
                )
                owner_sub = meta.get("owner_sub", "")
            except Exception:
                name = ""
                owner_sub = ""
            try:
                _write_resume_index(candidate_id, name, owner_sub, text)
                count += 1
            except Exception:
                logger.debug("rebuild_resume_index: failed for %s", candidate_id, exc_info=True)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return count
