

# ── Ad-messaging: F6 advertiser direct mass-DM (ADV2-E5 / ADV2-601..610) ────
# Reuses the shared ad_messaging engine (PLATFORM-100%, no content owner) via
# app.services.ad_dm_audience. The per-user ad opt-out endpoints + the
# open/click surcharge endpoints are SHARED with F5 (already defined above).
from app.services import ad_dm_audience as _addm


class AdMassDmCreateIn(_AMBase):
    account_id: str = _AMField(..., min_length=1, max_length=128)
    campaign_id: str = _AMField(..., min_length=1, max_length=128)
    body: str = _AMField(..., min_length=1, max_length=20000)
    cta_url: str = _AMField("", max_length=2000)
    image_url: str = _AMField("", max_length=2000)
    creative_id: str = _AMField("", max_length=128)
    sponsor_label: str = _AMField("", max_length=200)


def _addm_http(exc):
    return HTTPException(status_code=getattr(exc, "status_code", 400),
                         detail=getattr(exc, "detail", str(exc)))


@router.get("/mass-dm/audience/preview")
async def ad_mass_dm_audience_preview_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-602/607: preview the advertiser's eligible mass-DM audience (existing
    relationships minus ad opt-outs) before composing/sending."""
    return _addm.resolve_advertiser_audience(ctx["user_sub"])


@router.post("/mass-dm/campaigns", status_code=201)
async def ad_mass_dm_create_endpoint(body: AdMassDmCreateIn, ctx=Depends(require_ui_session)):
    """ADV2-603/604/605/606: advertiser composes + sends a direct mass-DM AS the
    advertiser to ONLY eligible relationships (followers/subscribers) minus ad
    opt-outs. Billed the hybrid stack (delivered 2c / open +5c / click +10c),
    PLATFORM-100% (no content owner). Funds-guarded: an empty balance stops the
    send."""
    _require_account_owner(body.account_id, ctx["user_sub"])
    try:
        return _addm.send_mass_dm(
            advertiser_sub=ctx["user_sub"], account_id=body.account_id,
            campaign_id=body.campaign_id, body=body.body, cta_url=body.cta_url,
            image_url=body.image_url, creative_id=body.creative_id,
            sponsor_label=body.sponsor_label,
        )
    except _addm.AdDmError as exc:
        raise _addm_http(exc)
    except _admsg.AdMessagingError as exc:
        raise _admsg_http(exc)


@router.get("/mass-dm/campaigns")
async def ad_mass_dm_list_endpoint(ctx=Depends(require_ui_session)):
    """ADV2-608: the advertiser's F6 mass-DM sends (delivered/opened/clicked +
    spend counters)."""
    return {"sends": _addm.list_advertiser_sends(ctx["user_sub"])}


@router.get("/mass-dm/campaigns/{send_id}")
async def ad_mass_dm_detail_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-608: F6 mass-DM campaign detail (advertiser-scoped)."""
    send = _addm.get_send(send_id)
    if not send:
        raise HTTPException(status_code=404, detail="Send not found")
    if str(send.get("advertiser_sub") or "") != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="Not authorized for this send")
    return send


@router.post("/mass-dm/campaigns/{send_id}/cancel")
async def ad_mass_dm_cancel_endpoint(send_id: str, ctx=Depends(require_ui_session)):
    """ADV2-603: cancel a mass-DM send (synchronous -> a fully-sent campaign is
    final and returns 409)."""
    try:
        return _addm.cancel_send(send_id=send_id, advertiser_sub=ctx["user_sub"])
    except _addm.AdDmError as exc:
        raise _addm_http(exc)
