p="app/routers/ads.py"
s=open(p).read()
old_create='''    acct = _require_account_owner(account_id, ctx["user_sub"])
    # ADV2-301 (F3): a free self-promo campaign needs no funded/active ad account
    # (the creator promotes their OWN content for free); paid campaigns still
    # require an active account.
    if not getattr(body, "is_self_promo", False) and acct.get("status") != "active":
        raise HTTPException(status_code=403, detail="Account is not active")
    return create_campaign(account_id, body)'''
new_create='''    _require_account_owner(account_id, ctx["user_sub"])
    # ADV3-3 (B1): a brand-new advertiser account is created ``pending_review``.
    # Campaigns are created in ``draft`` and cannot SERVE until they are admin-
    # approved to ``active`` (the launch gate now lives on the submit endpoint,
    # which requires an active account). Allowing DRAFT creation under a pending
    # account unblocks the guided create wizard, which previously forward-chained
    # every net-new advertiser straight into a guaranteed 403 here. A draft
    # campaign is inert (never selected by serve_ad, which reads only ``active``),
    # so no money can move before the account is approved and the campaign is
    # launched. Self-promo campaigns are unchanged (free, own-content only).
    return create_campaign(account_id, body)'''
assert old_create in s, "create anchor not found"
s=s.replace(old_create,new_create)
old_submit='''    _require_account_owner(account_id, ctx["user_sub"])
    try:
        return submit_campaign_for_review(account_id, campaign_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Campaign must be in draft status to submit for review",
        )'''
new_submit='''    acct = _require_account_owner(account_id, ctx["user_sub"])
    # ADV3-3 (B1): the launch gate. A draft campaign may be created under a
    # pending account (see create_campaign_endpoint), but it can only be SUBMITTED
    # for review - the path to going ``active`` and serving - once the owning ad
    # account is approved. Preserves "nothing serves under a non-active account".
    if acct.get("status") != "active":
        raise HTTPException(
            status_code=403,
            detail="Account is not active. An admin must approve this ad account before its campaigns can be submitted for review.",
        )
    try:
        return submit_campaign_for_review(account_id, campaign_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Campaign must be in draft status to submit for review",
        )'''
assert old_submit in s, "submit anchor not found"
s=s.replace(old_submit,new_submit)
open(p,"w").write(s)
print("ads.py patched OK")
