#!/usr/bin/env python3
"""ADV2-E3 (F3 self-advertising) backend patcher. Idempotent, anchored, verbatim.

Applies to a ROOT tree (dev clone OR prod). Usage: apply_adv2e3.py <ROOT>
Adds is_self_promo/self_promo_mode to the campaign model + create-campaign,
self-promo eligibility + D2 auction precedence in serve_ad, and short-circuits
every charge entry point (impression/click/conversion/completion/CTA) on the
minted self_promo flag so a self-promo serve/impression/click writes NO ledger
rows and debits/credits nobody.
"""
import io, os, sys

ROOT = sys.argv[1].rstrip("/")

def patch(rel, edits):
    path = os.path.join(ROOT, rel)
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()
    orig = src
    for i, (old, new, marker) in enumerate(edits):
        if marker in src:
            print("  SKIP (already applied) %s #%d" % (rel, i))
            continue
        if old not in src:
            print("  !!! ANCHOR MISS %s #%d" % (rel, i))
            sys.exit(2)
        if src.count(old) != 1:
            print("  !!! ANCHOR NOT UNIQUE (%d) %s #%d" % (src.count(old), rel, i))
            sys.exit(3)
        src = src.replace(old, new)
        print("  applied %s #%d" % (rel, i))
    if src != orig:
        with io.open(path, "w", encoding="utf-8") as f:
            f.write(src)
        print("  WROTE %s" % rel)
    else:
        print("  nochange %s" % rel)

# ---- 1. models.py -----------------------------------------------------------
patch("app/models.py", [
    (
        '    budget_cents: int = Field(..., ge=100)  # Minimum $1\n',
        '    budget_cents: int = Field(..., ge=0)  # Minimum $1 for paid; 0 allowed for self-promo (ADV2-301)\n',
        'ge=0)  # Minimum $1 for paid',
    ),
    (
        '''    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str) -> str:
        from app.models import VALID_AD_CATEGORIES  # forward ref (defined above)
        if v != "general" and v not in VALID_AD_CATEGORIES:
            raise ValueError(f"Unknown ad category: {v}")
        return v


class CampaignOut(BaseModel):''',
        '''    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str) -> str:
        from app.models import VALID_AD_CATEGORIES  # forward ref (defined above)
        if v != "general" and v not in VALID_AD_CATEGORIES:
            raise ValueError(f"Unknown ad category: {v}")
        return v

    # ADV2-301 (F3): free "promote my content" self-advertising toggle. A
    # self-promo campaign costs 0 (no charge / debit / credit), needs no funding,
    # and serves ONLY in front of the creator's own content. self_promo_mode:
    # fill_only (serve only when no paying ad is eligible for the own slot) vs
    # always_win (always win the own-content slot, may displace a paid ad).
    is_self_promo: bool = False
    self_promo_mode: str = Field(default="fill_only", pattern=r"^(fill_only|always_win)$")

    @model_validator(mode="after")
    def _validate_self_promo(self):
        if self.is_self_promo:
            # Free own-content promo: force all bids to 0, budget optional (no funding).
            self.bid_cpm_cents = 0
            self.bid_cpc_cents = 0
            self.bid_cpa_cents = 0
        elif self.budget_cents < 100:
            raise ValueError("budget_cents must be >= 100 for a paid campaign")
        return self


class CampaignOut(BaseModel):''',
        'def _validate_self_promo(self):',
    ),
    (
        '''    bid_cpa_cents: int = _BID_CPA_DEFAULT


# -- Delegates (DELEGATE-001) --''',
        '''    bid_cpa_cents: int = _BID_CPA_DEFAULT
    # ADV2-301: surface the self-promo flavor.
    is_self_promo: bool = False
    self_promo_mode: str = "fill_only"


# -- Delegates (DELEGATE-001) --''',
        'ADV2-301: surface the self-promo flavor.',
    ),
    (
        '''    bid_cpa_cents: Optional[int] = Field(
        default=None, ge=_BID_CPA_MIN, le=_BID_CPA_MAX
    )


class CampaignReviewIn(BaseModel):''',
        '''    bid_cpa_cents: Optional[int] = Field(
        default=None, ge=_BID_CPA_MIN, le=_BID_CPA_MAX
    )
    # ADV2-301: allow toggling the self-promo flavor/mode on update.
    is_self_promo: Optional[bool] = None
    self_promo_mode: Optional[str] = Field(default=None, pattern=r"^(fill_only|always_win)$")


class CampaignReviewIn(BaseModel):''',
        'allow toggling the self-promo flavor/mode on update.',
    ),
])

# ---- 2. ad_campaigns.py create_campaign -------------------------------------
patch("app/services/ad_campaigns.py", [
    (
        '''    if data.start_date is not None:
        item["start_date"] = data.start_date''',
        '''    # ADV2-301 (F3): persist the self-promo flavor. A free own-content promo
    # forces zero bids/budget (no funding) and auto-activates (skips
    # pending_review) so it serves immediately; paid campaigns stay draft.
    if getattr(data, "is_self_promo", False):
        item["is_self_promo"] = True
        item["self_promo_mode"] = getattr(data, "self_promo_mode", "fill_only") or "fill_only"
        item["bid_cpm_cents"] = 0
        item["bid_cpc_cents"] = 0
        item["bid_cpa_cents"] = 0
        item["status"] = "active"
    else:
        item["is_self_promo"] = False
    if data.start_date is not None:
        item["start_date"] = data.start_date''',
        'ADV2-301 (F3): persist the self-promo flavor.',
    ),
])

# ---- 3. routers/ads.py create_campaign_endpoint -----------------------------
patch("app/routers/ads.py", [
    (
        '''    acct = _require_account_owner(account_id, ctx["user_sub"])
    if acct.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active")
    return create_campaign(account_id, body)''',
        '''    acct = _require_account_owner(account_id, ctx["user_sub"])
    # ADV2-301 (F3): a free self-promo campaign needs no funded/active ad account
    # (the creator promotes their OWN content for free); paid campaigns still
    # require an active account.
    if not getattr(body, "is_self_promo", False) and acct.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active")
    return create_campaign(account_id, body)''',
        'ADV2-301 (F3): a free self-promo campaign needs no funded/active',
    ),
])

# ---- 4. ad_serving.py -------------------------------------------------------
patch("app/services/ad_serving.py", [
    # 4a. loop top + self-promo branch + self-exclusion using pre-fetched owner
    (
        '''    candidates: List[Dict[str, Any]] = []
    for campaign in active_campaigns:
        account_id = campaign["account_id"]

        # Self-ad exclusion (money-path safety): never serve an advertiser their
        # OWN campaign. The viewer must not be shown, charged for, or credited by an
        # ad from an account they own. Skip when the ad-account owner == viewer.
        try:
            from app.services.ad_accounts import get_ad_account
            _acct = get_ad_account(account_id)
            if _acct and str(_acct.get("owner_sub", "") or "") == str(user_id or ""):
                continue
        except Exception:
            pass
''',
        '''    candidates: List[Dict[str, Any]] = []
    # ADV2-302 (F3): self-promo buckets -- a creator's free "promote my content"
    # campaigns, split by fill mode. Precedence (D2): always_win self-promo >
    # paid > fill_only self-promo > house ad. A self-promo is eligible ONLY on the
    # creator's OWN content slot (account.owner_sub == content_owner_id) and
    # bypasses self-ad-exclusion / min-CPM / budget / category for that case.
    self_promo_always: List[Dict[str, Any]] = []
    self_promo_fill: List[Dict[str, Any]] = []
    for campaign in active_campaigns:
        account_id = campaign["account_id"]

        # Resolve the ad-account owner once (used by both self-ad-exclusion and
        # the self-promo own-content eligibility test).
        _acct = None
        try:
            from app.services.ad_accounts import get_ad_account
            _acct = get_ad_account(account_id)
        except Exception:
            _acct = None
        _owner_sub = str((_acct or {}).get("owner_sub", "") or "")

        # ADV2-302 (F3): self-promo campaign branch. Eligible ONLY when the slot
        # is the creator's OWN content (content_owner_id == the campaign's ad
        # account owner). Bypasses self-ad-exclusion, min-CPM floor, budget, and
        # category; fraud-suspension + frequency cap still apply. It NEVER serves
        # on another creator's content nor as a standalone unit (empty
        # content_owner_id -> skipped).
        if bool(campaign.get("is_self_promo")):
            if not (content_owner_id and _owner_sub and _owner_sub == str(content_owner_id)):
                continue
            try:
                from app.services.ad_fraud_prevention import is_account_suspended
                if is_account_suspended(account_id):
                    continue
            except Exception:
                pass
            if _is_frequency_capped(user_id, campaign["campaign_id"]):
                continue
            sp_creatives = list_approved_creatives(campaign["campaign_id"])
            if not sp_creatives:
                # ADV2-304: a free own-content promo may auto-serve unmoderated
                # creatives -- fall back to all creatives when none are approved.
                from app.services.ad_creatives import list_creatives as _list_all_creatives
                sp_creatives = _list_all_creatives(campaign["campaign_id"])
            if not sp_creatives:
                continue
            _entry = {"campaign": campaign, "creatives": sp_creatives, "score": 0}
            if str(campaign.get("self_promo_mode", "fill_only")) == "always_win":
                self_promo_always.append(_entry)
            else:
                self_promo_fill.append(_entry)
            continue

        # Self-ad exclusion (money-path safety): never serve an advertiser their
        # OWN campaign. The viewer must not be shown, charged for, or credited by an
        # ad from an account they own. Skip when the ad-account owner == viewer.
        if _owner_sub and _owner_sub == str(user_id or ""):
            continue
''',
        'self_promo_always: List[Dict[str, Any]] = []',
    ),
    # 4b. winner selection with precedence + zero-price self win
    (
        '''    if not candidates:
        return _house_ad_response("no_eligible_campaigns")

    # 4. Select winner (highest score) + ADV-302 second-price auction.
    candidates.sort(key=lambda c: c["score"], reverse=True)
    winner = candidates[0]
    # ADV-302: rank by effective bid (bid_cpm x relevance=1.0). The winner clears
    # at the runner-up bid + 1c (capped at its own bid); a lone bidder clears at
    # the reserve floor. cleared_cpm is what track_ad_event bills, so an advertiser
    # never pays more than the next-highest rival would have. CPC/CPA carried for
    # the click/conversion charge.
    _CPM_DEF, _CPC_DEF, _CPA_DEF = 500, 50, 500
    win_cpm = int(winner["campaign"].get("bid_cpm_cents", _CPM_DEF) or _CPM_DEF)
    runner_up_cpm = int(round(candidates[1]["score"])) if len(candidates) > 1 else None
    cleared_cpm = clear_second_price(win_cpm, runner_up_cpm, _CPM_FLOOR)
    win_cpc = int(winner["campaign"].get("bid_cpc_cents", _CPC_DEF) or _CPC_DEF)
    win_cpa = int(winner["campaign"].get("bid_cpa_cents", _CPA_DEF) or _CPA_DEF)''',
        '''    if not candidates and not self_promo_always and not self_promo_fill:
        return _house_ad_response("no_eligible_campaigns")

    # 4. Select winner with D2 precedence (ADV2-302):
    #   always_win self-promo  >  paid auction  >  fill_only self-promo  >  house
    # A self-promo win clears at price 0 (free) and NEVER runs the paid auction.
    _CPM_DEF, _CPC_DEF, _CPA_DEF = 500, 50, 500
    is_self_win = False
    if self_promo_always:
        winner = self_promo_always[0]
        is_self_win = True
    elif candidates:
        candidates.sort(key=lambda c: c["score"], reverse=True)
        winner = candidates[0]
    elif self_promo_fill:
        winner = self_promo_fill[0]
        is_self_win = True
    else:
        return _house_ad_response("no_eligible_campaigns")

    if is_self_win:
        # Free self-promo: zero clearing price + zero bids. The charge path
        # short-circuits on the self_promo flag minted below (no ledger / debit /
        # credit on impression / click / conversion / completion).
        cleared_cpm = 0
        win_cpm = 0
        win_cpc = 0
        win_cpa = 0
    else:
        # ADV-302: rank by effective bid (bid_cpm x relevance=1.0). The winner
        # clears at the runner-up bid + 1c (capped at its own bid); a lone bidder
        # clears at the reserve floor. cleared_cpm is what track_ad_event bills, so
        # an advertiser never pays more than the next-highest rival would have.
        win_cpm = int(winner["campaign"].get("bid_cpm_cents", _CPM_DEF) or _CPM_DEF)
        runner_up_cpm = int(round(candidates[1]["score"])) if len(candidates) > 1 else None
        cleared_cpm = clear_second_price(win_cpm, runner_up_cpm, _CPM_FLOOR)
        win_cpc = int(winner["campaign"].get("bid_cpc_cents", _CPC_DEF) or _CPC_DEF)
        win_cpa = int(winner["campaign"].get("bid_cpa_cents", _CPA_DEF) or _CPA_DEF)''',
        'A self-promo win clears at price 0 (free)',
    ),
    # 4c. mint the self_promo flag on the AdClicks row
    (
        '''            "status": "served",
            "effective_price_cents": cleared_cpm,''',
        '''            "status": "served",
            "self_promo": is_self_win,
            "effective_price_cents": cleared_cpm,''',
        '"self_promo": is_self_win,',
    ),
    # 4d. surface is_self_promo on the response
    (
        '''        "is_house_ad": False,
        "campaign_id": winner["campaign"]["campaign_id"],''',
        '''        "is_house_ad": False,
        "is_self_promo": is_self_win,
        "campaign_id": winner["campaign"]["campaign_id"],''',
        '"is_self_promo": is_self_win,',
    ),
    # 4e. track_ad_event short-circuit
    (
        '''            content_owner_sub = str(click_row.get("content_owner_sub", "") or "")
            idem = "%s#%s" % (ad_click_id, event)''',
        '''            content_owner_sub = str(click_row.get("content_owner_sub", "") or "")
            # ADV2-303 (F3): self-promo unit -> record analytics only, NO charge
            # (no ledger row, debit nobody, credit nobody).
            if click_row.get("self_promo"):
                return {
                    "ok": True, "event_id": event_id, "flagged": False,
                    "fraud_score": fraud_score, "charged": False,
                    "charge_cents": 0, "charge_reason": "self_promo_no_charge",
                }
            idem = "%s#%s" % (ad_click_id, event)''',
        'ADV2-303 (F3): self-promo unit -> record analytics only, NO charge',
    ),
    # 4f. record_cta_click short-circuit
    (
        '''    if cta_type in CTA_NO_ADVERTISER_CHARGE:
        # Tip CTA: NO advertiser charge. The tip credits the creator only.
        reason = "tip_no_advertiser_charge"
    else:
        try:
            from app.services import ad_billing''',
        '''    if cta_type in CTA_NO_ADVERTISER_CHARGE:
        # Tip CTA: NO advertiser charge. The tip credits the creator only.
        reason = "tip_no_advertiser_charge"
    elif row.get("self_promo"):
        # ADV2-303 (F3): self-promo unit -> tap recorded, NO advertiser charge.
        reason = "self_promo_no_charge"
    else:
        try:
            from app.services import ad_billing''',
        'self-promo unit -> tap recorded, NO advertiser charge.',
    ),
])

# ---- 5. broadcast_ads.py completion short-circuit ---------------------------
patch("app/services/broadcast_ads.py", [
    (
        '''    if not row:
        return None
    account_id = row.get("account_id", "")
    campaign_id = row.get("campaign_id", "")
    if not account_id or not campaign_id:
        return None''',
        '''    if not row:
        return None
    # ADV2-303 (F3): free self-promo -> no advertiser charge, no ledger, no
    # broadcaster credit. Short-circuit BEFORE the 500c completion floor.
    if row.get("self_promo"):
        return {"ok": True, "reason": "self_promo", "charge_cents": 0}
    account_id = row.get("account_id", "")
    campaign_id = row.get("campaign_id", "")
    if not account_id or not campaign_id:
        return None''',
        'free self-promo -> no advertiser charge, no ledger, no\n    # broadcaster credit',
    ),
])

# ---- 6. vod_ad_supported.py completion short-circuit ------------------------
patch("app/services/vod_ad_supported.py", [
    (
        '''    if not row:
        logger.warning("vod_ad_preroll_click_missing ad_click_id=%s", ad_click_id)
        return None
''',
        '''    if not row:
        logger.warning("vod_ad_preroll_click_missing ad_click_id=%s", ad_click_id)
        return None
    # ADV2-303 (F3): free self-promo -> no advertiser charge, no ledger, no
    # poster credit. Short-circuit BEFORE the 500c completion floor.
    if row.get("self_promo"):
        return {"ok": True, "reason": "self_promo", "charge_cents": 0}
''',
        'free self-promo -> no advertiser charge, no ledger, no\n    # poster credit',
    ),
])

# ---- 7. ad_attribution.py conversion short-circuit --------------------------
patch("app/services/ad_attribution.py", [
    (
        '''    if bid_cpa_cents > 0:
        try:
            charge = ad_billing.charge_conversion(''',
        '''    if row.get("self_promo"):
        # ADV2-303 (F3): self-promo conversion -> attributed for analytics only,
        # NO advertiser CPA charge (no ledger row, credit nobody).
        result["charge"] = {"ok": True, "reason": "self_promo", "charge_cents": 0}
        result["self_promo"] = True
    elif bid_cpa_cents > 0:
        try:
            charge = ad_billing.charge_conversion(''',
        'self-promo conversion -> attributed for analytics only',
    ),
])

print("ALL PATCHES DONE for ROOT=%s" % ROOT)
