from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.tables import T
from app.services.profile import get_profile_identity
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/contacts", tags=["contacts"])


# ── Models ─────────────────────────────────────────────────────────────────

class AddContactIn(BaseModel):
    user_id: str


class UpdateContactIn(BaseModel):
    is_favorite: Optional[bool] = None
    is_blocked: Optional[bool] = None


class ContactEntry(BaseModel):
    owner_id: str
    contact_id: str
    display_name: str
    profile_photo_url: Optional[str] = None
    is_favorite: bool
    is_blocked: bool
    added_at: str


# ── Helpers ────────────────────────────────────────────────────────────────

def _item_to_contact(item: Dict[str, Any]) -> ContactEntry:
    return ContactEntry(
        owner_id=item["owner_id"],
        contact_id=item["contact_id"],
        display_name=item.get("display_name") or item["contact_id"],
        profile_photo_url=item.get("profile_photo_url") or None,
        is_favorite=bool(item.get("is_favorite", False)),
        is_blocked=bool(item.get("is_blocked", False)),
        added_at=item.get("added_at", ""),
    )


def _sort_contacts(contacts: List[ContactEntry]) -> List[ContactEntry]:
    """Favorites first, then alphabetical by display_name (case-insensitive)."""
    return sorted(
        contacts,
        key=lambda c: (not c.is_favorite, c.display_name.lower()),
    )


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.get("", response_model=Dict[str, List[ContactEntry]])
def list_contacts(ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("owner_id").eq(user_sub),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.contacts.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    contacts = _sort_contacts([_item_to_contact(i) for i in items])
    return {"contacts": contacts}


@router.post("", response_model=ContactEntry, status_code=201)
def add_contact(inp: AddContactIn, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]

    if inp.user_id == user_sub:
        raise HTTPException(400, "Cannot add yourself as a contact")

    # Load display name + photo from profile
    try:
        identity = get_profile_identity(inp.user_id)
        display_name = identity.get("display_name") or inp.user_id
        profile_photo_url = identity.get("profile_photo_url") or None
    except Exception:
        display_name = inp.user_id
        profile_photo_url = None

    now = datetime.now(timezone.utc).isoformat()
    item: Dict[str, Any] = {
        "owner_id": user_sub,
        "contact_id": inp.user_id,
        "display_name": display_name,
        "profile_photo_url": profile_photo_url,
        "is_favorite": False,
        "is_blocked": False,
        "added_at": now,
    }
    T.contacts.put_item(Item=item)

    # PTY-009 forward hook — best-effort, flag-gated (lazy import to avoid
    # pulling the party graph into the import path when the flag is off).
    from app.core.settings import S as _S

    if _S.party_crm_contacts_migration_enabled:
        try:
            from app.services.party_contacts_migration import maybe_project_new_contact

            maybe_project_new_contact(user_sub, inp.user_id, item)
        except Exception:
            pass

    return _item_to_contact(item)
    contact_out = _item_to_contact(item)
    try:
        from app.services.workflow_hooks import fire_on_save_hook
        fire_on_save_hook(module="contact", record=item, event="create")
    except Exception:
        pass
    return contact_out


@router.delete("/{contact_id}", status_code=204)
def remove_contact(contact_id: str, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    T.contacts.delete_item(Key={"owner_id": user_sub, "contact_id": contact_id})


@router.patch("/{contact_id}", response_model=ContactEntry)
def update_contact(contact_id: str, inp: UpdateContactIn, ctx: Dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]

    if inp.is_favorite is None and inp.is_blocked is None:
        raise HTTPException(400, "Nothing to update")

    # Build update expression
    set_parts: List[str] = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {}

    if inp.is_favorite is not None:
        set_parts.append("#fav = :fav")
        expr_names["#fav"] = "is_favorite"
        expr_values[":fav"] = inp.is_favorite

    if inp.is_blocked is not None:
        set_parts.append("#blk = :blk")
        expr_names["#blk"] = "is_blocked"
        expr_values[":blk"] = inp.is_blocked

    update_expr = "SET " + ", ".join(set_parts)

    try:
        resp = T.contacts.update_item(
            Key={"owner_id": user_sub, "contact_id": contact_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ConditionExpression="attribute_exists(owner_id)",
            ReturnValues="ALL_NEW",
        )
    except T.contacts.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(404, "Contact not found")

    raw = resp["Attributes"]
    contact_out = _item_to_contact(raw)
    try:
        from app.services.workflow_hooks import fire_on_save_hook
        fire_on_save_hook(module="contact", record=raw, event="update")
    except Exception:
        pass
    return contact_out


# ── People-you-may-know suggestions ─────────────────────────────────────────

class SuggestionCard(BaseModel):
    user_id: str
    display_name: str
    profile_photo_url: Optional[str] = None
    # Relationship hint for the UI, e.g. "Follows you", "You follow", "Mutual",
    # "Recent chat", "2 mutual connections".
    hint: str
    mutual_count: int = 0
    source: str  # one of: mutual | follower | following | dm_peer


def _load_saved_contact_ids(owner_id: str) -> set:
    saved: set = set()
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("owner_id").eq(owner_id),
            "ProjectionExpression": "contact_id",
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.contacts.query(**kwargs)
        for it in resp.get("Items", []):
            cid = it.get("contact_id")
            if cid:
                saved.add(cid)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return saved


def _recent_dm_peer_ids(user_sub: str, *, limit: int = 40) -> List[str]:
    """Best-effort: recent 1:1 DM peers, most-recent-first, de-duplicated.

    Reuses the messaging Participants/Conversations tables. Isolated so a
    messaging-side change or missing table never breaks the contacts hub.
    """
    peers: List[str] = []
    seen: set = set()
    try:
        from boto3.dynamodb.conditions import Key as _Key
        from app.routers.messaging import (
            tbl_parts as _tbl_parts,
            tbl_convos as _tbl_convos,
        )

        parts: List[Dict[str, Any]] = []
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": _Key("user_id").eq(user_sub),
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = _tbl_parts.query(**kwargs)
            parts.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(parts) >= 2000:
                break

        cids = [p.get("conversation_id") for p in parts if p.get("conversation_id")]

        # Enrich conversations for recency + type; cap the fan-out.
        convo_map: Dict[str, Dict[str, Any]] = {}
        for cid in cids:
            try:
                convo = _tbl_convos.get_item(Key={"conversation_id": cid}).get("Item")
                if convo:
                    convo_map[cid] = convo
            except Exception:
                continue

        def _recency(cid: str) -> int:
            c = convo_map.get(cid, {})
            return int(c.get("last_message_at", 0) or c.get("created_at", 0) or 0)

        for cid in sorted(cids, key=_recency, reverse=True):
            convo = convo_map.get(cid, {})
            ctype = str(convo.get("type") or "").lower()
            if ctype and ctype != "dm":
                continue
            try:
                other = _tbl_parts.query(
                    IndexName="GSI1",
                    KeyConditionExpression=_Key("GSI1PK").eq(cid),
                    Limit=10,
                ).get("Items", [])
            except Exception:
                other = []
            for op in other:
                pid = op.get("user_id")
                if pid and pid != user_sub and pid not in seen:
                    seen.add(pid)
                    peers.append(pid)
            if len(peers) >= limit:
                break
    except Exception:
        return peers
    return peers[:limit]


@router.get("/suggestions", response_model=Dict[str, List[SuggestionCard]])
def contact_suggestions(ctx: Dict = Depends(require_ui_session)):
    """People-you-may-know: mutuals + follow graph + recent DM peers, minus
    self, already-saved contacts, and blocked/blocking users. Read-only."""
    from app.services import social as _social
    from app.services import blocking as _blocking

    user_sub = ctx["user_sub"]

    saved = _load_saved_contact_ids(user_sub)
    try:
        blocked = _blocking.get_blocked_set(user_sub)
    except Exception:
        blocked = set()
    try:
        blocked_by = _blocking.get_blocked_by_set(user_sub)
    except Exception:
        blocked_by = set()

    excluded = set(saved) | set(blocked) | set(blocked_by) | {user_sub}

    # candidate_id -> {source, mutual_count}
    candidates: Dict[str, Dict[str, Any]] = {}
    rank = {"mutual": 0, "follower": 1, "following": 2, "dm_peer": 3}

    def _consider(cid: str, source: str, mutual_count: int = 0) -> None:
        if not cid or cid in excluded:
            return
        cur = candidates.get(cid)
        # Priority: mutual > follower(follows-you) > following > dm_peer.
        if cur is None or rank.get(source, 9) < rank.get(cur["source"], 9):
            candidates[cid] = {"source": source, "mutual_count": mutual_count}
        elif source == cur["source"] and mutual_count > cur["mutual_count"]:
            cur["mutual_count"] = mutual_count

    # 1) People who follow me but I haven't saved -> "Follows you" (strong signal)
    try:
        followers, _ = _social.get_followers(user_sub, limit=100)
        for it in followers:
            _consider(it.get("user_id", ""), "follower")
    except Exception:
        pass

    # 2) People I follow -> "You follow"
    try:
        following, _ = _social.get_following(user_sub, limit=100)
        for it in following:
            _consider(it.get("target_user_id", "") or it.get("user_id", ""), "following")
    except Exception:
        pass

    # 3) Mutual connections: friends-of-friends. For each person I follow, pull
    #    who THEY follow and surface non-excluded ones with a mutual count.
    try:
        following2, _ = _social.get_following(user_sub, limit=50)
        fof_counts: Dict[str, int] = {}
        for it in following2:
            fid = it.get("target_user_id", "") or it.get("user_id", "")
            if not fid:
                continue
            try:
                their_following, _ = _social.get_following(fid, limit=50)
            except Exception:
                continue
            for jt in their_following:
                cand = jt.get("target_user_id", "") or jt.get("user_id", "")
                if cand and cand not in excluded:
                    fof_counts[cand] = fof_counts.get(cand, 0) + 1
        for cand, cnt in fof_counts.items():
            _consider(cand, "mutual", mutual_count=cnt)
    except Exception:
        pass

    # 4) Recent DM peers I haven't saved.
    try:
        for pid in _recent_dm_peer_ids(user_sub, limit=40):
            _consider(pid, "dm_peer")
    except Exception:
        pass

    # Rank: mutual (by count desc) first, then follower, following, dm_peer.
    ordered = sorted(
        candidates.items(),
        key=lambda kv: (rank.get(kv[1]["source"], 9), -kv[1]["mutual_count"]),
    )[:50]

    cards: List[SuggestionCard] = []
    for cid, meta in ordered:
        try:
            identity = get_profile_identity(cid)
            display_name = identity.get("display_name") or cid
            photo = identity.get("profile_photo_url") or None
        except Exception:
            display_name, photo = cid, None

        source = meta["source"]
        mc = int(meta["mutual_count"])
        if source == "mutual":
            hint = f"{mc} mutual connection{'s' if mc != 1 else ''}" if mc else "Mutual connection"
        elif source == "follower":
            hint = "Follows you"
        elif source == "following":
            hint = "You follow"
        else:
            hint = "Recent chat"

        cards.append(SuggestionCard(
            user_id=cid,
            display_name=display_name,
            profile_photo_url=photo,
            hint=hint,
            mutual_count=mc,
            source=source,
        ))

    return {"suggestions": cards}
