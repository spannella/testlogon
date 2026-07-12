#!/usr/bin/env python3
"""ADV2-E2 (F2) backend hotfix: structured click-through CTA targets.

Idempotent, anchor-matched (not line-number) so it runs on the divergent dev
clone AND prod. Adds:
  - CtaActionIn / CtaClickIn models + `ctas` on CreativeCreate/Update, VodAdBreak,
    AdServeResponseOut, SyndicatePostOut.
  - create_creative persists `ctas`.
  - serve_ad carries `ctas`; new record_cta_click() charges CPC (except tip),
    idempotent per (ad_click_id, cta_type), records the tap for attribution.
  - POST /ui/ads/cta-click endpoint.
  - `ctas` carried through broadcast pre/mid-roll, VOD schedule, sponsored feed
    (newsfeed + group/syndicate).

Usage: ROOT=/home/ubuntu/testlogon python3 apply_adv2e2.py
"""
import os
import sys

ROOT = os.environ.get("ROOT", "/home/ubuntu/testlogon")

CTA_CLASSES = '''class CtaActionIn(BaseModel):
    """ADV2-201: one structured click-through CTA target on an ad creative.

    cta_type routes the in-app destination; target_id names the product /
    creator / account; label is the button text. buy_product / view_product need
    a product target; subscribe_other needs an account/creator target; tip and
    subscribe (this creator) may omit target_id (resolved to the placement
    content owner at tap time).
    """
    cta_type: str = Field(
        ..., pattern="^(buy_product|view_product|tip|subscribe|subscribe_other)$"
    )
    target_id: str = Field(default="", max_length=200)
    label: str = Field(..., min_length=1, max_length=40)


class CtaClickIn(BaseModel):
    """ADV2-201: body for POST /ui/ads/cta-click (a CTA tap)."""
    ad_click_id: str = Field(..., min_length=1)
    cta_type: str = Field(
        ..., pattern="^(buy_product|view_product|tip|subscribe|subscribe_other)$"
    )
    target_id: str = Field(default="", max_length=200)


'''

RECORD_CTA = '''# --- ADV2-201/E2: structured CTA click-through targets ----------------------
# A CTA tap charges CPC to the advertiser (funds-guarded, idempotent per
# ad_click_id + cta_type) via ad_billing.charge_click and records the tap on the
# AdClicks row for last-click attribution. A resulting purchase/subscribe then
# fires CPA through the existing ad_attribution path (which reads the same row).
# TIP is NOT an advertiser conversion: a tip CTA deep-links to the creator tip
# flow and fires NO advertiser charge (the viewer tips the creator as normal
# creator earnings). Placement split is unchanged (content_owner present ->
# creator share; standalone -> platform).
CTA_TYPES = frozenset({"buy_product", "view_product", "tip", "subscribe", "subscribe_other"})
CTA_NO_ADVERTISER_CHARGE = frozenset({"tip"})


def record_cta_click(
    *,
    ad_click_id: str,
    cta_type: str,
    viewer_sub: str = "",
    target_id: str = "",
    ip_address: str = "",
    user_agent: str = "",
) -> Dict[str, Any]:
    """Record a CTA tap and charge CPC (except tip). Idempotent per
    (ad_click_id, cta_type)."""
    if cta_type not in CTA_TYPES:
        return {"ok": False, "reason": "invalid_cta_type", "cta_type": cta_type}
    if not ad_click_id:
        return {"ok": False, "reason": "missing_ad_click_id"}

    try:
        row = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id}).get("Item") or {}
    except Exception:
        row = {}
    if not row:
        return {"ok": False, "reason": "unknown_click", "ad_click_id": ad_click_id}

    content_owner_sub = str(row.get("content_owner_sub", "") or "")

    # Record the tap on the click row (best-effort) for attribution/analytics.
    try:
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression=(
                "SET last_cta_type = :ct, last_cta_target = :tg, cta_clicked_at = :ts"
            ),
            ExpressionAttributeValues={
                ":ct": cta_type, ":tg": target_id or "", ":ts": now_ts(),
            },
        )
    except Exception:
        logger.warning("cta_click_record_failed click=%s", ad_click_id)

    charged = False
    charge_cents = 0
    reason = ""
    if cta_type in CTA_NO_ADVERTISER_CHARGE:
        # Tip CTA: NO advertiser charge. The tip credits the creator only.
        reason = "tip_no_advertiser_charge"
    else:
        try:
            from app.services import ad_billing
            from app.services.ad_campaigns import get_campaign
            account_id = str(row.get("account_id", "") or "")
            campaign_id = str(row.get("campaign_id", "") or "")
            cpc = row.get("bid_cpc_cents")
            if cpc is None:
                cpc = (get_campaign(account_id, campaign_id) or {}).get("bid_cpc_cents", 50)
            res = ad_billing.charge_click(
                account_id=account_id, campaign_id=campaign_id,
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpc_cents=int(cpc or 50),
                idempotency_key="%s#cta#%s" % (ad_click_id, cta_type),
            )
            charged = bool(res.get("ok"))
            charge_cents = int(res.get("charge_cents", 0) or 0)
            reason = str(res.get("reason", "") or "")
        except Exception:
            logger.warning("cta_click_charge_failed click=%s cta=%s", ad_click_id, cta_type)
            reason = "charge_error"

    return {
        "ok": True,
        "ad_click_id": ad_click_id,
        "cta_type": cta_type,
        "target_id": target_id or "",
        "content_owner_sub": content_owner_sub,
        "campaign_id": str(row.get("campaign_id", "") or ""),
        "charged": charged,
        "charge_cents": charge_cents,
        "reason": reason,
    }


'''

CTA_ENDPOINT = '''@router.post("/cta-click")
async def cta_click_endpoint(body: CtaClickIn, request: Request, ctx=Depends(require_ui_session)):
    """ADV2-201/E2: a structured CTA tap. Charges CPC to the advertiser
    (funds-guarded, idempotent per ad_click_id+cta_type) EXCEPT tip (no
    advertiser charge; a tip credits the creator only). Records the tap for
    last-click attribution so a resulting purchase/subscribe fires CPA via the
    existing conversion path."""
    ip_address = request.client.host if request.client else ""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        ip_address = fwd.split(",")[0].strip()
    return record_cta_click(
        ad_click_id=body.ad_click_id,
        cta_type=body.cta_type,
        target_id=body.target_id,
        viewer_sub=ctx["user_sub"],
        ip_address=ip_address,
        user_agent=request.headers.get("user-agent", ""),
    )


'''

# Each edit: (relpath, old, new). Applied once if `new` not already present.
EDITS = [
    # ---- app/models.py ----
    ("app/models.py",
     "class CreativeCreateIn(BaseModel):\n",
     CTA_CLASSES + "class CreativeCreateIn(BaseModel):\n"),
    ("app/models.py",
     "    rotation_weight: int = Field(default=50, ge=0, le=100)\n"
     "    promo_code_id: Optional[str] = None\n"
     "    affiliate_link_id: Optional[str] = None\n\n"
     "    @field_validator(\"cta_url\")",
     "    rotation_weight: int = Field(default=50, ge=0, le=100)\n"
     "    promo_code_id: Optional[str] = None\n"
     "    affiliate_link_id: Optional[str] = None\n"
     "    ctas: Optional[List[CtaActionIn]] = Field(default=None, max_length=8)\n\n"
     "    @field_validator(\"cta_url\")"),
    ("app/models.py",
     "    skip_after_seconds: Optional[int] = Field(default=None, ge=0, le=30)\n"
     "    promo_code_id: Optional[str] = None\n"
     "    affiliate_link_id: Optional[str] = None\n\n"
     "    @field_validator(\"cta_url\")",
     "    skip_after_seconds: Optional[int] = Field(default=None, ge=0, le=30)\n"
     "    promo_code_id: Optional[str] = None\n"
     "    affiliate_link_id: Optional[str] = None\n"
     "    ctas: Optional[List[CtaActionIn]] = Field(default=None, max_length=8)\n\n"
     "    @field_validator(\"cta_url\")"),
    ("app/models.py",
     "    creative_type: str  # \"video\" | \"image\"\n"
     "    skip_after_seconds: int\n"
     "    slot_index: int\n"
     "    completed: bool = False",
     "    creative_type: str  # \"video\" | \"image\"\n"
     "    skip_after_seconds: int\n"
     "    slot_index: int\n"
     "    ad_click_id: str = \"\"\n"
     "    ctas: List[Dict[str, Any]] = Field(default_factory=list)\n"
     "    completed: bool = False"),
    ("app/models.py",
     "    cta_text: Optional[str] = None\n"
     "    cta_url: Optional[str] = None\n"
     "    image_url: Optional[str] = None\n"
     "    video_url: Optional[str] = None\n"
     "    thumbnail_url: Optional[str] = None\n"
     "    alt_text: Optional[str] = None",
     "    cta_text: Optional[str] = None\n"
     "    cta_url: Optional[str] = None\n"
     "    ctas: List[Dict[str, Any]] = Field(default_factory=list)\n"
     "    image_url: Optional[str] = None\n"
     "    video_url: Optional[str] = None\n"
     "    thumbnail_url: Optional[str] = None\n"
     "    alt_text: Optional[str] = None"),
    ("app/models.py",
     "    cta_text: Optional[str] = None\n"
     "    cta_url: Optional[str] = None\n"
     "    image_urls: List[str] = Field(default_factory=list)",
     "    cta_text: Optional[str] = None\n"
     "    cta_url: Optional[str] = None\n"
     "    ctas: List[Dict[str, Any]] = Field(default_factory=list)\n"
     "    image_urls: List[str] = Field(default_factory=list)"),
    # ---- app/services/ad_creatives.py ----
    ("app/services/ad_creatives.py",
     "    T.ad_creatives.put_item(Item=item)\n",
     "    if getattr(data, \"ctas\", None):\n"
     "        item[\"ctas\"] = [c.model_dump() for c in data.ctas]\n"
     "    T.ad_creatives.put_item(Item=item)\n"),
    # ---- app/services/ad_serving.py ----
    ("app/services/ad_serving.py",
     "        \"cta_text\": creative.get(\"cta_text\"),\n"
     "        \"cta_url\": creative.get(\"cta_url\"),\n",
     "        \"cta_text\": creative.get(\"cta_text\"),\n"
     "        \"cta_url\": creative.get(\"cta_url\"),\n"
     "        \"ctas\": creative.get(\"ctas\") or [],\n"),
    ("app/services/ad_serving.py",
     "def track_ad_event(\n    *,\n    event: str,",
     RECORD_CTA + "def track_ad_event(\n    *,\n    event: str,"),
    # ---- app/routers/ads.py ----
    ("app/routers/ads.py",
     "    AdServeRequestIn,\n    AdTrackEventIn,\n",
     "    AdServeRequestIn,\n    AdTrackEventIn,\n    CtaClickIn,\n"),
    ("app/routers/ads.py",
     "from app.services.ad_serving import serve_ad, track_ad_event, get_serving_stats\n",
     "from app.services.ad_serving import serve_ad, track_ad_event, get_serving_stats, record_cta_click\n"),
    ("app/routers/ads.py",
     "@router.get(\"/stats/{campaign_id}\")",
     CTA_ENDPOINT + "@router.get(\"/stats/{campaign_id}\")"),
    # ---- app/services/broadcast_ads.py (pre_roll + mid_roll dicts) ----
    ("app/services/broadcast_ads.py",
     "        \"ad_click_id\": ad.get(\"ad_click_id\", \"\"),\n",
     "        \"ad_click_id\": ad.get(\"ad_click_id\", \"\"),\n"
     "        \"ctas\": ad.get(\"ctas\") or [],\n"),
    # ---- app/routers/broadcast_ads.py (PreRollOut + MidRollOut) ----
    ("app/routers/broadcast_ads.py",
     "    ad_click_id: str = \"\"\n    impression_url: str",
     "    ad_click_id: str = \"\"\n    ctas: list = []\n    impression_url: str"),
    # ---- app/services/vod_ad_supported.py ----
    ("app/services/vod_ad_supported.py",
     "        ad_click_id = \"\"\n",
     "        ad_click_id = \"\"\n        ctas: List[Dict[str, Any]] = []\n"),
    ("app/services/vod_ad_supported.py",
     "                    ad_click_id = served.get(\"ad_click_id\", \"\") or \"\"\n",
     "                    ad_click_id = served.get(\"ad_click_id\", \"\") or \"\"\n"
     "                    ctas = served.get(\"ctas\") or []\n"),
    ("app/services/vod_ad_supported.py",
     "                \"ad_click_id\": ad_click_id,\n                \"completed\": False,",
     "                \"ad_click_id\": ad_click_id,\n                \"ctas\": ctas,\n                \"completed\": False,"),
    ("app/services/vod_ad_supported.py",
     "                \"slot_index\": int(b.get(\"slot_index\", 0)),\n"
     "                \"completed\": bool(b.get(\"completed\", False)),",
     "                \"slot_index\": int(b.get(\"slot_index\", 0)),\n"
     "                \"ad_click_id\": b.get(\"ad_click_id\", \"\") or \"\",\n"
     "                \"ctas\": b.get(\"ctas\", []) or [],\n"
     "                \"completed\": bool(b.get(\"completed\", False)),"),
    # ---- app/services/sponsored_feed.py (build_sponsored_unit + syndicate shape) ----
    ("app/services/sponsored_feed.py",
     "            \"cta_text\": ad.get(\"cta_text\"),\n"
     "            \"cta_url\": ad.get(\"cta_url\"),\n",
     "            \"cta_text\": ad.get(\"cta_text\"),\n"
     "            \"cta_url\": ad.get(\"cta_url\"),\n"
     "            \"ctas\": ad.get(\"ctas\") or [],\n"),
    ("app/services/sponsored_feed.py",
     "        \"cta_text\": unit.get(\"cta_text\"),\n"
     "        \"cta_url\": unit.get(\"cta_url\"),\n",
     "        \"cta_text\": unit.get(\"cta_text\"),\n"
     "        \"cta_url\": unit.get(\"cta_url\"),\n"
     "        \"ctas\": unit.get(\"ctas\") or [],\n"),
    # ---- app/routers/newsfeed.py (main newsfeed sponsored injection) ----
    ("app/routers/newsfeed.py",
     "            \"cta_text\": ad.get(\"cta_text\"),\n"
     "            \"cta_url\": ad.get(\"cta_url\"),\n",
     "            \"cta_text\": ad.get(\"cta_text\"),\n"
     "            \"cta_url\": ad.get(\"cta_url\"),\n"
     "            \"ctas\": ad.get(\"ctas\") or [],\n"),
]


def main():
    results = []
    ok = True
    for relpath, old, new in EDITS:
        path = os.path.join(ROOT, relpath)
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            results.append(("MISSING_FILE", relpath, old[:48]))
            ok = False
            continue
        if new in content:
            results.append(("SKIP_DONE", relpath, old[:48]))
            continue
        if old not in content:
            results.append(("MISS_ANCHOR", relpath, old[:48]))
            ok = False
            continue
        n = content.count(old)
        content = content.replace(old, new)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        results.append(("APPLIED_x%d" % n, relpath, old[:48]))
    for status, relpath, anchor in results:
        print("%-14s %-42s %s" % (status, relpath, anchor.replace("\n", "\\n")))
    print("OVERALL", "OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
