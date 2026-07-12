#!/usr/bin/env python3
"""Idempotent anchored patch for the 3 backend features."""
import io, os, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/dev/testlogon")

def read(p):
    with io.open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
        return f.read()

def write(p, s):
    with io.open(os.path.join(ROOT, p), "w", encoding="utf-8") as f:
        f.write(s)

def patch(path, edits):
    src = read(path)
    for name, old, new in edits:
        if new in src:
            print("  SKIP (already applied):", name); continue
        n = src.count(old)
        if n != 1:
            print("  FAIL:", name, "anchor count=", n); sys.exit(3)
        src = src.replace(old, new, 1)
        print("  OK:", name)
    write(path, src)

patch("app/services/broadcast_ads.py", [
 ("serve_ad-content-owner",
  "        result = serve_ad(\n"
  "            surface=surface,\n"
  "            content_type=\"broadcast\",\n"
  "            creator_id=creator_id,\n"
  "            content_id=content_id,\n"
  "            slot_type=slot_type,\n"
  "            user_id=user_id,\n"
  "        )",
  "        result = serve_ad(\n"
  "            surface=surface,\n"
  "            content_type=\"broadcast\",\n"
  "            creator_id=creator_id,\n"
  "            content_id=content_id,\n"
  "            slot_type=slot_type,\n"
  "            user_id=user_id,\n"
  "            content_owner_id=creator_id,\n"
  "        )"),
 ("build_pre_roll-surface",
  "    ad = serve_broadcast_ad(\n"
  "        surface=\"broadcast\",\n"
  "        creator_id=session.created_by,",
  "    ad = serve_broadcast_ad(\n"
  "        surface=\"broadcast_preroll\",\n"
  "        creator_id=session.created_by,"),
 ("pre_roll-ad_click_id",
  "        \"skip_after_seconds\": PRE_ROLL_SKIP_AFTER_SECONDS,\n",
  "        \"skip_after_seconds\": PRE_ROLL_SKIP_AFTER_SECONDS,\n"
  "        \"ad_click_id\": ad.get(\"ad_click_id\", \"\"),\n"),
 ("record_ad_event-signature",
  "    account_id: str = \"\",\n"
  "    campaign_id: str = \"\",\n"
  "    creator_id: str = \"\",\n"
  "    bid_cpm_cents: int = 0,",
  "    account_id: str = \"\",\n"
  "    campaign_id: str = \"\",\n"
  "    creator_id: str = \"\",\n"
  "    bid_cpm_cents: int = 0,\n"
  "    ad_click_id: str = \"\","),
 ("billing-block",
  "    # ── Billing (impression charges, gated by flag, never for fraud) ───\n"
  "    charge_id = None\n"
  "    if (\n"
  "        S.broadcast_ads_billing_enabled\n"
  "        and not fraud_flagged\n"
  "        and event_type == \"impression\"\n"
  "        and account_id\n"
  "        and campaign_id\n"
  "        and bid_cpm_cents > 0\n"
  "    ):\n"
  "        try:\n"
  "            from app.services.ad_billing import charge_impression\n"
  "\n"
  "            charge_result = charge_impression(\n"
  "                account_id=account_id,\n"
  "                campaign_id=campaign_id,\n"
  "                creative_id=creative_id,\n"
  "                creator_id=creator_id,\n"
  "                content_id=session_id,\n"
  "                bid_cpm_cents=bid_cpm_cents,\n"
  "            )\n"
  "            charge_id = charge_result.get(\"entry_id\")\n"
  "        except Exception:  # pragma: no cover - billing must never break playback\n"
  "            pass",
  "    # Billing (broadcast pre-roll charge, gated by flag, never for fraud).\n"
  "    # GAP-0071/0072: charge the ADVERTISER + credit the BROADCASTER 70/30 from\n"
  "    # the authoritative AdClicks row (surface=broadcast_preroll,\n"
  "    # content_owner_sub=broadcaster). Funds-guarded + idempotent per\n"
  "    # ad_click_id so impression AND complete never double-charge.\n"
  "    charge_id = None\n"
  "    if (\n"
  "        S.broadcast_ads_billing_enabled\n"
  "        and not fraud_flagged\n"
  "        and event_type in (\"impression\", \"complete\")\n"
  "        and ad_click_id\n"
  "    ):\n"
  "        try:\n"
  "            _res = _charge_broadcast_preroll_completion(\n"
  "                ad_click_id=ad_click_id, session_id=session_id\n"
  "            )\n"
  "            if _res and _res.get(\"ok\"):\n"
  "                charge_id = _res.get(\"entry_id\")\n"
  "        except Exception:  # pragma: no cover - billing must never break playback\n"
  "            pass"),
 ("charge-helper-fn",
  "_VALID_EVENTS = {\"impression\", \"skip\", \"complete\", \"click\"}\n",
  "_VALID_EVENTS = {\"impression\", \"skip\", \"complete\", \"click\"}\n"
  "\n"
  "\n"
  "def _charge_broadcast_preroll_completion(*, ad_click_id, session_id):\n"
  "    # Charge advertiser for a completed broadcast pre-roll + credit the\n"
  "    # BROADCASTER 70/30 via ad_billing._process_charge. Reads the AdClicks row\n"
  "    # minted at serve time (content_owner_sub=broadcaster). Funds-guarded +\n"
  "    # idempotent per ad_click_id. Returns the charge result or None.\n"
  "    if not ad_click_id:\n"
  "        return None\n"
  "    try:\n"
  "        row = T.ad_clicks.get_item(Key={\"ad_click_id\": ad_click_id}).get(\"Item\")\n"
  "    except Exception:\n"
  "        return None\n"
  "    if not row:\n"
  "        return None\n"
  "    account_id = row.get(\"account_id\", \"\")\n"
  "    campaign_id = row.get(\"campaign_id\", \"\")\n"
  "    if not account_id or not campaign_id:\n"
  "        return None\n"
  "    creative_id = row.get(\"creative_id\", \"\")\n"
  "    content_owner = row.get(\"content_owner_sub\", \"\")\n"
  "    charge_cents = int(row.get(\"effective_price_cents\", 0) or 0)\n"
  "    if charge_cents <= 0:\n"
  "        charge_cents = int(getattr(S, \"vod_ad_cpm_cents\", 500) or 500)\n"
  "    from app.services.ad_billing import _process_charge\n"
  "    result = _process_charge(\n"
  "        account_id=account_id,\n"
  "        campaign_id=campaign_id,\n"
  "        entry_type=\"impression_charge\",\n"
  "        charge_cents=charge_cents,\n"
  "        creator_id=content_owner,\n"
  "        reason=\"Broadcast pre-roll impression\",\n"
  "        meta={\n"
  "            \"creative_id\": creative_id,\n"
  "            \"content_id\": session_id,\n"
  "            \"model\": \"cpm\",\n"
  "            \"surface\": \"broadcast_preroll\",\n"
  "            \"ad_click_id\": ad_click_id,\n"
  "        },\n"
  "        idempotency_key=\"broadcast_preroll:%s\" % ad_click_id,\n"
  "    )\n"
  "    try:\n"
  "        T.ad_clicks.update_item(\n"
  "            Key={\"ad_click_id\": ad_click_id},\n"
  "            UpdateExpression=\"SET #s = :s, charged_cents = :c, completed_at = :t\",\n"
  "            ExpressionAttributeNames={\"#s\": \"status\"},\n"
  "            ExpressionAttributeValues={\n"
  "                \":s\": \"completed\",\n"
  "                \":c\": int(result.get(\"charge_cents\", 0)) if result.get(\"ok\") else 0,\n"
  "                \":t\": now_ts(),\n"
  "            },\n"
  "        )\n"
  "    except Exception:\n"
  "        pass\n"
  "    return result\n"),
])

patch("app/routers/broadcast_ads.py", [
 ("PreRollOut-ad_click_id",
  "    skip_after_seconds: int = 5\n"
  "    impression_url: str",
  "    skip_after_seconds: int = 5\n"
  "    ad_click_id: str = \"\"\n"
  "    impression_url: str"),
 ("track-route-param",
  "    creator_id: str = Query(default=\"\"),\n"
  "    bid_cpm_cents: int = Query(default=0),\n"
  "    view_time_ms: int = Query(default=0),",
  "    creator_id: str = Query(default=\"\"),\n"
  "    bid_cpm_cents: int = Query(default=0),\n"
  "    ad_click_id: str = Query(default=\"\"),\n"
  "    view_time_ms: int = Query(default=0),"),
 ("track-call-arg",
  "        creator_id=creator_id,\n"
  "        bid_cpm_cents=bid_cpm_cents,\n"
  "        view_time_ms=view_time_ms,",
  "        creator_id=creator_id,\n"
  "        bid_cpm_cents=bid_cpm_cents,\n"
  "        ad_click_id=ad_click_id,\n"
  "        view_time_ms=view_time_ms,"),
])

patch("app/routers/newsfeed.py", [
 ("tip_post-reject-sponsored",
  "    post = ddb_get_item({\"pk\": pk_post(post_id), \"sk\": sk_post()})\n"
  "    if not post:\n"
  "        raise HTTPException(status_code=404, detail=\"Post not found\")\n"
  "    if post.get(\"user_id\") == user_id:\n"
  "        raise HTTPException(status_code=400, detail=\"Cannot tip your own post\")",
  "    post = ddb_get_item({\"pk\": pk_post(post_id), \"sk\": sk_post()})\n"
  "    if not post:\n"
  "        raise HTTPException(status_code=404, detail=\"Post not found\")\n"
  "    if post.get(\"is_sponsored\"):\n"
  "        raise HTTPException(status_code=400, detail={\"code\": \"tip_not_allowed_on_ad\", \"message\": \"Tipping is not available on sponsored posts.\"})\n"
  "    if post.get(\"user_id\") == user_id:\n"
  "        raise HTTPException(status_code=400, detail=\"Cannot tip your own post\")"),
 ("tip_react-reject-sponsored",
  "    author = post.get(\"user_id\")\n"
  "    if not author:\n"
  "        raise HTTPException(status_code=400, detail=\"Post has no author to tip\")\n"
  "    if author == user_id:\n"
  "        raise HTTPException(status_code=400, detail=\"Cannot tip your own post\")",
  "    if post.get(\"is_sponsored\"):\n"
  "        raise HTTPException(status_code=400, detail={\"code\": \"tip_not_allowed_on_ad\", \"message\": \"Tipping is not available on sponsored posts.\"})\n"
  "    author = post.get(\"user_id\")\n"
  "    if not author:\n"
  "        raise HTTPException(status_code=400, detail=\"Post has no author to tip\")\n"
  "    if author == user_id:\n"
  "        raise HTTPException(status_code=400, detail=\"Cannot tip your own post\")"),
])

patch("app/services/group_feed.py", [
 ("group-inject",
  "    return {\n"
  "        \"posts\": sorted_posts,\n"
  "        \"cursor\": next_cursor,\n"
  "        \"has_more\": has_more,\n"
  "    }",
  "    if viewer_id:\n"
  "        try:\n"
  "            from app.services.sponsored_feed import inject_sponsored\n"
  "            sorted_posts = inject_sponsored(\n"
  "                sorted_posts, viewer_id, surface=\"group_feed\",\n"
  "                content_prefix=\"group_%s\" % group_id,\n"
  "            )\n"
  "        except Exception:\n"
  "            pass\n"
  "    return {\n"
  "        \"posts\": sorted_posts,\n"
  "        \"cursor\": next_cursor,\n"
  "        \"has_more\": has_more,\n"
  "    }"),
])

patch("app/services/syndicate_feed.py", [
 ("syndicate-inject",
  "    return {\n"
  "        \"posts\": posts,\n"
  "        \"next_cursor\": next_cursor,\n"
  "        \"is_member\": is_member,\n"
  "    }",
  "    if viewer_sub:\n"
  "        try:\n"
  "            from app.services.sponsored_feed import inject_sponsored_syndicate\n"
  "            posts = inject_sponsored_syndicate(\n"
  "                posts, viewer_sub, syndicate_id=syndicate_id\n"
  "            )\n"
  "        except Exception:\n"
  "            pass\n"
  "    return {\n"
  "        \"posts\": posts,\n"
  "        \"next_cursor\": next_cursor,\n"
  "        \"is_member\": is_member,\n"
  "    }"),
])

patch("app/models.py", [
 ("SyndicatePostOut-sponsored-fields",
  "class SyndicatePostOut(BaseModel):\n"
  "    post_id: str\n"
  "    author_id: str\n"
  "    author_name: str = \"\"\n"
  "    author_avatar: str = \"\"\n"
  "    text: str = \"\"\n"
  "    image_url: str = \"\"\n"
  "    syndicate_id: str\n"
  "    visibility: str = \"public\"\n"
  "    created_at: int = 0\n"
  "    comment_count: int = 0\n"
  "    reaction_counts: Dict[str, int] = Field(default_factory=dict)\n"
  "    tip_total_cents: int = 0\n",
  "class SyndicatePostOut(BaseModel):\n"
  "    post_id: str\n"
  "    author_id: str\n"
  "    author_name: str = \"\"\n"
  "    author_avatar: str = \"\"\n"
  "    text: str = \"\"\n"
  "    image_url: str = \"\"\n"
  "    syndicate_id: str\n"
  "    visibility: str = \"public\"\n"
  "    created_at: int = 0\n"
  "    comment_count: int = 0\n"
  "    reaction_counts: Dict[str, int] = Field(default_factory=dict)\n"
  "    tip_total_cents: int = 0\n"
  "    # ADV syndicate-feed ads: optional sponsored-unit fields so an injected\n"
  "    # standalone sponsored unit serializes through this response model.\n"
  "    is_sponsored: bool = False\n"
  "    sponsor_label: str = \"\"\n"
  "    headline: Optional[str] = None\n"
  "    body: str = \"\"\n"
  "    cta_text: Optional[str] = None\n"
  "    cta_url: Optional[str] = None\n"
  "    image_urls: List[str] = Field(default_factory=list)\n"
  "    impression_url: Optional[str] = None\n"
  "    click_url: Optional[str] = None\n"
  "    creative_id: str = \"\"\n"
  "    campaign_id: str = \"\"\n"
  "    account_id: str = \"\"\n"
  "    ad_click_id: str = \"\"\n"
  "    content_owner_id: str = \"\"\n"),
])

patch("app/core/settings.py", [
 ("enable-broadcast-ads-billing",
  "    broadcast_ads_billing_enabled: bool = os.environ.get(\"BROADCAST_ADS_BILLING_ENABLED\", \"0\") not in (\"0\", \"false\", \"False\")",
  "    broadcast_ads_billing_enabled: bool = os.environ.get(\"BROADCAST_ADS_BILLING_ENABLED\", \"1\") not in (\"0\", \"false\", \"False\")"),
])

print("PATCH_DONE")
