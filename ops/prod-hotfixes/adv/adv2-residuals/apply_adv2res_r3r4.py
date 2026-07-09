#!/usr/bin/env python3
"""ADV2 residuals R3 (self-promo moderation) + R4 (F6 subscriber enumeration).
Anchored + idempotent. ROOT env var selects the repo root (default cwd)."""
import os, sys, re

ROOT = os.environ.get("ROOT") or os.getcwd()

def read(p):
    with open(p) as f: return f.read()
def write(p, s):
    with open(p, "w") as f: f.write(s)

results = []

# ─────────────────────────── R3: ad_serving.py ───────────────────────────
p = os.path.join(ROOT, "app/services/ad_serving.py")
s = read(p)
OLD_R3 = (
    '            sp_creatives = list_approved_creatives(campaign["campaign_id"])\n'
    '            if not sp_creatives:\n'
    '                # ADV2-304: a free own-content promo may auto-serve unmoderated\n'
    '                # creatives -- fall back to all creatives when none are approved.\n'
    '                from app.services.ad_creatives import list_creatives as _list_all_creatives\n'
    '                sp_creatives = _list_all_creatives(campaign["campaign_id"])\n'
    '            if not sp_creatives:\n'
    '                continue\n'
)
NEW_R3 = (
    '            # ADV2 R3: a self-promo serves ONLY approved (moderated) creatives\n'
    '            # -- same moderation/fraud gate as a paid ad. If the creator has no\n'
    '            # approved self-promo creative there is simply no self-promo fill; we\n'
    '            # NEVER auto-serve an unmoderated/rejected creative.\n'
    '            sp_creatives = list_approved_creatives(campaign["campaign_id"])\n'
    '            if not sp_creatives:\n'
    '                continue\n'
)
if "ADV2 R3: a self-promo serves ONLY approved" in s:
    results.append("R3 ad_serving.py SKIP_ALREADY")
elif OLD_R3 in s:
    write(p, s.replace(OLD_R3, NEW_R3, 1))
    results.append("R3 ad_serving.py APPLIED")
else:
    results.append("R3 ad_serving.py ANCHOR_MISS")

# ─────────────────── R4a: subscription_access.py helper ───────────────────
p = os.path.join(ROOT, "app/services/subscription_access.py")
s = read(p)
ANCHOR_R4A = "def can_access_creator(subscriber_id: str, creator_id: str) -> bool:"
HELPER = (
    'def list_active_subscriber_ids(creator_id: str) -> List[str]:\n'
    '    """ADV2 R4: enumerate the user_ids of users with an ACTIVE subscription to\n'
    '    ``creator_id``. Reads the creator-index partition (``CREATOR#{creator_id}``,\n'
    '    ``SUB#`` items) written by ``subscription_server.save_subscription`` -- the\n'
    '    same index ``count_active_subscribers`` trusts -- so NO GSI/backfill is\n'
    '    required. Deduped, active/trialing/past_due only. Best-effort (returns what\n'
    '    it has on error)."""\n'
    '    subs: List[str] = []\n'
    '    seen: set = set()\n'
    '    last = None\n'
    '    try:\n'
    '        while True:\n'
    '            kwargs: Dict[str, Any] = {\n'
    '                "KeyConditionExpression": Key("pk").eq(_pk_creator(creator_id))\n'
    '                & Key("sk").begins_with("SUB#"),\n'
    '            }\n'
    '            if last:\n'
    '                kwargs["ExclusiveStartKey"] = last\n'
    '            resp = T.subscriptions.query(**kwargs)\n'
    '            for it in resp.get("Items", []):\n'
    '                status = (it.get("status") or "").lower()\n'
    '                if status not in {"active", "trialing", "past_due"}:\n'
    '                    continue\n'
    '                sub = str(it.get("subscriber_id") or "")\n'
    '                if sub and sub not in seen:\n'
    '                    seen.add(sub)\n'
    '                    subs.append(sub)\n'
    '            last = resp.get("LastEvaluatedKey")\n'
    '            if not last:\n'
    '                break\n'
    '    except Exception:\n'
    '        return subs\n'
    '    return subs\n'
    '\n'
    '\n'
)
if "def list_active_subscriber_ids(" in s:
    results.append("R4a subscription_access.py SKIP_ALREADY")
elif ANCHOR_R4A in s:
    write(p, s.replace(ANCHOR_R4A, HELPER + ANCHOR_R4A, 1))
    results.append("R4a subscription_access.py APPLIED")
else:
    results.append("R4a subscription_access.py ANCHOR_MISS")

# ─────────────────── R4b: ad_dm_audience.py wire-in ───────────────────
p = os.path.join(ROOT, "app/services/ad_dm_audience.py")
s = read(p)
ANCHOR_R4B = (
    '    if capped:\n'
    '        logger.info("ad_dm_audience_capped advertiser=%s cap=%s", advertiser_sub, max_recipients)\n'
)
SUBBLOCK = (
    '    # ADV2 R4: subscriber enumeration -- UNION active SUBSCRIBERS of the\n'
    '    # advertiser (who may NOT follow) into the audience. Reads the CREATOR#\n'
    '    # index partition (no GSI needed). Each is re-verified via _has_relationship\n'
    '    # (which accepts an active subscription) + opt-out filtered + deduped against\n'
    '    # followers, honoring the same cap. The send-time re-gate still applies.\n'
    '    subscribers_added = 0\n'
    '    if not capped:\n'
    '        try:\n'
    '            from app.services import subscription_access as _subacc\n'
    '            _sub_ids = _subacc.list_active_subscriber_ids(advertiser_sub)\n'
    '        except Exception:\n'
    '            _sub_ids = []\n'
    '        for sub in _sub_ids:\n'
    '            sub = str(sub or "")\n'
    '            if not sub or sub == advertiser_sub or sub in seen:\n'
    '                continue\n'
    '            seen.add(sub)\n'
    '            if not _has_relationship(advertiser_sub, sub):\n'
    '                excluded_non_relationship.append(sub)\n'
    '                continue\n'
    '            if not _admsg.user_accepts_ad_messages(sub):\n'
    '                excluded_optout.append(sub)\n'
    '                continue\n'
    '            recipients.append(sub)\n'
    '            subscribers_added += 1\n'
    '            if len(recipients) >= max_recipients:\n'
    '                capped = True\n'
    '                break\n'
    + ANCHOR_R4B
)
if "ADV2 R4: subscriber enumeration" in s:
    results.append("R4b ad_dm_audience.py SKIP_ALREADY")
elif ANCHOR_R4B in s:
    s = s.replace(ANCHOR_R4B, SUBBLOCK, 1)
    # update the return-dict marker field
    s = s.replace(
        '        "subscriber_enumeration": "deferred_dec2_followers_only",\n',
        '        "subscriber_enumeration": "creator_index_partition",\n'
        '        "subscribers_added": subscribers_added,\n',
        1,
    )
    write(p, s)
    results.append("R4b ad_dm_audience.py APPLIED")
else:
    results.append("R4b ad_dm_audience.py ANCHOR_MISS")

print("\n".join(results))

# ─────────────── R4c: refresh the now-stale module docstring ───────────────
p = os.path.join(ROOT, "app/services/ad_dm_audience.py")
s = read(p)
OLD_DOC = (
    'Subscriber enumeration: ``subscriptions`` has no ByCreator GSI (DEC-2) so a\n'
    'pure-subscriber (subscribes but does not follow) cannot be ENUMERATED into the\n'
    'audience yet; followers are fully enumerable via GSI5. Per the plan note we pick\n'
    'the simplest reliable path -- enumerate FOLLOWERS (each RE-VERIFIED as a live\n'
    'relationship + non-opted-out) and log the cap; the subscriber-only slice is\n'
    'deferred to the DEC-2 GSI/snapshot decision. NOTE: a subscriber who is ALSO a\n'
    'follower is still reached, and the send-time gate ``is_recipient_eligible``\n'
    'already accepts an active subscription, so once enumeration lands no billing\n'
    'change is needed.\n'
)
NEW_DOC = (
    'Subscriber enumeration (ADV2 R4): the audience is followers UNION active\n'
    'SUBSCRIBERS of the advertiser (a pure-subscriber who does NOT follow is now\n'
    'reached too), MINUS the per-user ad opt-outs. Followers enumerate via GSI5;\n'
    'subscribers enumerate via the existing ``CREATOR#{advertiser}`` index partition\n'
    '(SUB# items -- the same index ``count_active_subscribers`` reads), so NO new\n'
    'GSI/backfill was required. Every candidate is RE-VERIFIED as a live relationship\n'
    '(``_has_relationship`` accepts a follow OR an active subscription) and the\n'
    'send-time re-gate (ADV2-606) still drops any edge/opt-out change before dispatch.\n'
)
if "Subscriber enumeration (ADV2 R4)" in s:
    results2 = "R4c docstring SKIP_ALREADY"
elif OLD_DOC in s:
    write(p, s.replace(OLD_DOC, NEW_DOC, 1))
    results2 = "R4c docstring APPLIED"
else:
    results2 = "R4c docstring ANCHOR_MISS"
print(results2)
