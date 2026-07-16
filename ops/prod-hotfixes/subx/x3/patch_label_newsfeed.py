import ast

# ---- append tier_label_for_level helper to subscription_access.py ----
pa = "app/services/subscription_access.py"
sa = open(pa, encoding="utf-8").read()
if "def tier_label_for_level" not in sa:
    helper = '''

def tier_label_for_level(creator_id: str, required_level: int) -> Optional[str]:
    """SUBX-31 app upsell: the display NAME of the cheapest active plan whose
    tier level is >= ``required_level`` - i.e. the tier a locked-out viewer must
    buy to unlock. None when no such plan / no requirement."""
    if not creator_id or not required_level or required_level < 1:
        return None
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_creator(creator_id)) & Key("sk").begins_with("PLAN#"),
        )
        plans = [p for p in resp.get("Items", []) if (p.get("status") or "active") == "active"]
    except Exception:
        return None
    best_name = None
    best_price = None
    for p in plans:
        lvl = get_plan_level(creator_id, str(p.get("plan_id") or ""))
        if lvl < required_level:
            continue
        price = _monthly_equiv_cents(p.get("price_cents"), p.get("interval"))
        if best_price is None or price < best_price:
            best_price = price
            best_name = p.get("name")
    return best_name
'''
    sa = sa.rstrip("\n") + "\n" + helper
    open(pa, "w", encoding="utf-8").write(sa)
    ast.parse(sa)
    print("APPENDED tier_label_for_level")
else:
    print("tier_label_for_level already present")

# ---- newsfeed.py: create request + persist + emit required tier ----
pn = "app/routers/newsfeed.py"
s = open(pn, encoding="utf-8").read()
orig = s

def rep(old, new):
    global s
    assert s.count(old) >= 1, f"NF ANCHOR NOT FOUND: {old[:70]!r}"
    s = s.replace(old, new, 1)

# CreatePostRequest: add required_tier_level
rep(
    '    subscriber_only: bool = False  # SUB-E3: per-post subscriber-only gate\n',
    '    subscriber_only: bool = False  # SUB-E3: per-post subscriber-only gate\n    # SUBX-31: minimum tier level required to unlock this subscriber-only post\n    # (0/None = any active subscriber unlocks - the pre-tier binary default).\n    required_tier_level: Optional[int] = Field(default=None, ge=1, le=100)\n',
)

# persist on create
rep(
    '        "subscriber_only": bool(getattr(req, "subscriber_only", False)),\n        "locked": locked,',
    '        "subscriber_only": bool(getattr(req, "subscriber_only", False)),\n        "required_tier_level": int(getattr(req, "required_tier_level", 0) or 0),  # SUBX-31\n        "locked": locked,',
)

# emit required tier level + name in _post_to_dict
rep(
    '        "subscriber_only": bool(post.get("subscriber_only")),\n        "subscriber_locked": _sub_locked,\n        "creator_id": _sub_author,',
    '        "subscriber_only": bool(post.get("subscriber_only")),\n        "subscriber_locked": _sub_locked,\n        # SUBX-31: the tier the locked-out viewer must buy (level + display name)\n        # so the app SubscriberLockCard can name the required tier + upsell to it.\n        "required_tier_level": int(post.get("required_tier_level") or 0),\n        "required_tier_name": (_subx_tier_label(_sub_author, int(post.get("required_tier_level") or 0)) if _sub_locked else None),\n        "creator_id": _sub_author,',
)

# add the _subx_tier_label helper near _subscriber_locked_post
rep(
    'def _subscriber_locked_post(post: Dict[str, Any], viewer_id) -> bool:',
    'def _subx_tier_label(creator_id, required_level) -> Optional[str]:\n    """SUBX-31: best-effort display name of the required tier for the lock card."""\n    try:\n        from app.services.subscription_access import tier_label_for_level\n        return tier_label_for_level(str(creator_id or ""), int(required_level or 0))\n    except Exception:\n        return None\n\n\ndef _subscriber_locked_post(post: Dict[str, Any], viewer_id) -> bool:',
)

open(pn, "w", encoding="utf-8").write(s)
ast.parse(s)
print(f"PATCHED newsfeed.py; delta {len(s)-len(orig)}")
