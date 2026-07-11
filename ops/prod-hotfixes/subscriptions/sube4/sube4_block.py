

# =============================================================================
# SUB-E4 — CREATOR SUBSCRIBER MANAGEMENT + MRR/ANALYTICS
# (E4-1 owner-scoped subscriber list; E4-2 MRR/analytics). Computed off the
# CREATOR#SUB# index (creator partition, SUB# items) + the creator ledger
# (LEDGER# items) — no fabrication. Owner-scoped: a creator sees only their own
# subscribers; platform admin/root may see any. Header auth (X-User-Id), matching
# every other endpoint in this router.
# =============================================================================
_SUBE4_CANCELED_STATUSES = {"canceled", "cancelled", "expired", "canceling", "cancelling"}
_SUBE4_STATUS_FILTER_MAP = {
    "active": {"active"},
    "trialing": {"trialing"},
    "trial": {"trialing"},
    "past_due": {"past_due"},
    "canceled": set(_SUBE4_CANCELED_STATUSES),
    "cancelled": set(_SUBE4_CANCELED_STATUSES),
}


def _sube4_require_creator_or_admin(x_user_id: Optional[str], creator_id: str) -> str:
    """Owner-scope guard: caller must BE the creator, or be a platform admin/root.
    Returns the resolved caller id. 401 if unauthenticated, 403 if not owner/admin."""
    user_id = require_user(x_user_id)
    if user_id == creator_id:
        return user_id
    try:
        from app.services.subscription_access import is_platform_admin
        if is_platform_admin(user_id):
            return user_id
    except Exception:
        pass
    raise HTTPException(status_code=403, detail="Not authorized to view this creator's subscribers")


def _sube4_monthly_equiv_cents(price_cents: int, interval: str) -> int:
    """Monthly-equivalent gross of a plan price. Year plans amortise price/12."""
    price = int(price_cents or 0)
    if (interval or "month") == "year":
        return int(round(price / 12.0))
    return price


def _sube4_is_trial(sub: Dict[str, Any], now: int) -> bool:
    if (sub.get("status") or "").lower() == "trialing":
        return True
    trial_end = sub.get("trial_end")
    return bool(trial_end and now < int(trial_end))


def _sube4_encode_cursor(offset: int) -> str:
    import base64
    return base64.urlsafe_b64encode(str(int(offset)).encode()).decode()


def _sube4_decode_cursor(cursor: Optional[str]) -> int:
    if not cursor:
        return 0
    try:
        import base64
        return max(0, int(base64.urlsafe_b64decode(cursor.encode()).decode()))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor")


def _sube4_creator_sub_rows(creator_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Return (normalized subscription index rows, {plan_id: plan_name}) for a
    creator from ONE CREATOR# partition read (SUB# + PLAN# items co-located)."""
    items = ddb_query(pk_creator(creator_id))
    subs: List[Dict[str, Any]] = []
    plan_names: Dict[str, str] = {}
    for it in items:
        sk = it.get("sk", "")
        if sk.startswith("SUB#"):
            subs.append(normalize_subscription(it))
        elif sk.startswith("PLAN#") and it.get("plan_id"):
            plan_names[it["plan_id"]] = it.get("name") or it.get("plan_id")
    return subs, plan_names


def _sube4_plan_name(plan_id: Optional[str], plan_names: Dict[str, str]) -> Optional[str]:
    if not plan_id:
        return None
    if plan_id in plan_names:
        return plan_names[plan_id]
    meta = ddb_get_item(pk_plan(plan_id), "META")
    name = (meta or {}).get("name") or plan_id
    plan_names[plan_id] = name
    return name


class SubE4SubscriberOut(BaseModel):
    subscription_id: str
    subscriber_id: str
    subscriber_name: Optional[str] = None
    subscriber_profile: Optional[Dict[str, Optional[str]]] = None
    plan_id: Optional[str] = None
    plan_name: Optional[str] = None
    status: str
    interval: str
    price_cents: int
    currency: str
    since: int  # start_at
    current_period_end: Optional[int] = None
    next_billing_date: Optional[int] = None
    cancel_at_period_end: bool = False
    auto_renew: bool = True
    is_gift: bool = False
    gifter_id: Optional[str] = None
    is_trial: bool = False


class SubE4SubscriberListOut(BaseModel):
    creator_id: str
    status_filter: Optional[str] = None
    count: int
    total: int
    next_cursor: Optional[str] = None
    subscribers: List[SubE4SubscriberOut]


class SubE4AnalyticsOut(BaseModel):
    creator_id: str
    currency: str
    generated_at: int
    # live counts
    active_subscribers: int
    trialing: int
    past_due: int
    canceled_total: int
    total_subscribers: int
    # recurring revenue (monthly-equivalent gross of ACTIVE, non-trial subs)
    mrr_cents: int
    arpu_cents: int
    # growth/churn over the trailing 30d window
    period_days: int
    new_subs_30d: int
    churned_30d: int
    churn_rate: float
    # lifetime subscription revenue from the creator ledger
    gross_revenue_to_date_cents: int
    fee_to_date_cents: int
    refunded_to_date_cents: int
    net_revenue_to_date_cents: int


@router.get("/api/creators/{creator_id}/subscribers", response_model=SubE4SubscriberListOut)
async def list_creator_subscribers(
    creator_id: str,
    status: Optional[str] = Query(default=None, description="active|trialing|past_due|canceled"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    x_user_id: Optional[str] = Header(default=None),
):
    """SUB-E4-1: owner-scoped creator subscriber list off the CREATOR#SUB# index.
    Per-sub subscriber id+name, plan/tier name, status, since (start_at),
    period-end/next-billing, is_gift, is_trial. Optional status filter + paginated
    (opaque cursor). A creator sees only their own subscribers; admin may see any."""
    _sube4_require_creator_or_admin(x_user_id, creator_id)
    now = now_ts()
    subs, plan_names = _sube4_creator_sub_rows(creator_id)

    status_key = (status or "").strip().lower()
    if status_key and status_key not in ("all", ""):
        allowed = _SUBE4_STATUS_FILTER_MAP.get(status_key)
        if allowed is None:
            allowed = {status_key}
        subs = [s for s in subs if (s.get("status") or "").lower() in allowed]

    # newest-subscribed first; stable tiebreak on subscription_id
    subs.sort(key=lambda s: (int(s.get("start_at") or s.get("created_at") or 0), s.get("subscription_id", "")), reverse=True)

    total = len(subs)
    offset = _sube4_decode_cursor(cursor)
    page = subs[offset:offset + limit]
    next_cursor = _sube4_encode_cursor(offset + limit) if offset + limit < total else None

    out: List[SubE4SubscriberOut] = []
    for s in page:
        profile = get_profile_identity(s["subscriber_id"])
        out.append(SubE4SubscriberOut(
            subscription_id=s["subscription_id"],
            subscriber_id=s["subscriber_id"],
            subscriber_name=(profile or {}).get("display_name"),
            subscriber_profile=profile,
            plan_id=s.get("plan_id"),
            plan_name=_sube4_plan_name(s.get("plan_id"), plan_names),
            status=s.get("status") or "unknown",
            interval=s.get("interval") or "month",
            price_cents=int(s.get("price_cents") or 0),
            currency=s.get("currency") or "usd",
            since=int(s.get("start_at") or s.get("created_at") or 0),
            current_period_end=(int(s["current_period_end"]) if s.get("current_period_end") else None),
            next_billing_date=(int(s["next_billing_date"]) if s.get("next_billing_date") else None),
            cancel_at_period_end=bool(s.get("cancel_at_period_end", False)),
            auto_renew=bool(s.get("auto_renew", True)),
            is_gift=bool(s.get("is_gift", False)),
            gifter_id=s.get("gifter_id"),
            is_trial=_sube4_is_trial(s, now),
        ))

    return SubE4SubscriberListOut(
        creator_id=creator_id,
        status_filter=(status_key or None),
        count=len(out),
        total=total,
        next_cursor=next_cursor,
        subscribers=out,
    )


@router.get("/api/creators/{creator_id}/subscription-analytics", response_model=SubE4AnalyticsOut)
async def get_creator_subscription_analytics(
    creator_id: str,
    period_days: int = Query(default=30, ge=1, le=365),
    x_user_id: Optional[str] = Header(default=None),
):
    """SUB-E4-2: MRR/analytics computed from the creator's real subscription
    records + ledger. active/trialing/past_due counts; MRR = sum of the
    monthly-equivalent GROSS price of ACTIVE non-trial subs (year -> price/12);
    ARPU = MRR/active; new (start_at in window) + churned (canceled/expired in
    window) + churn rate; lifetime subscription revenue from the ledger. Owner-scoped."""
    _sube4_require_creator_or_admin(x_user_id, creator_id)
    now = now_ts()
    cutoff = now - period_days * 86400

    items = ddb_query(pk_creator(creator_id))
    active = trialing = past_due = canceled_total = total = 0
    mrr = 0
    new_subs = 0
    churned = 0
    currency = "usd"
    gross = fee = refunded = 0

    for it in items:
        sk = it.get("sk", "")
        if sk.startswith("SUB#"):
            s = normalize_subscription(it)
            total += 1
            st = (s.get("status") or "").lower()
            if s.get("currency"):
                currency = s.get("currency")
            if st == "active":
                active += 1
                if not _sube4_is_trial(s, now):
                    mrr += _sube4_monthly_equiv_cents(int(s.get("price_cents") or 0), s.get("interval") or "month")
            elif st == "trialing":
                trialing += 1
            elif st == "past_due":
                past_due += 1
            elif st in _SUBE4_CANCELED_STATUSES:
                canceled_total += 1
                churn_ts = int(s.get("updated_at") or s.get("canceled_at") or 0)
                if churn_ts >= cutoff and st in ("canceled", "cancelled", "expired"):
                    churned += 1
            if int(s.get("start_at") or s.get("created_at") or 0) >= cutoff:
                new_subs += 1
        elif sk.startswith("LEDGER#"):
            etype = it.get("entry_type")
            amt = int(it.get("amount_cents") or 0)
            if it.get("currency"):
                currency = it.get("currency")
            if etype == "charge":
                gross += amt
            elif etype == "fee":
                fee += amt
            elif etype == "refund":
                refunded += amt

    arpu = int(round(mrr / active)) if active else 0
    churn_denom = active + churned
    churn_rate = round(churned / churn_denom, 4) if churn_denom else 0.0
    net = gross - fee - refunded

    return SubE4AnalyticsOut(
        creator_id=creator_id,
        currency=currency,
        generated_at=now,
        active_subscribers=active,
        trialing=trialing,
        past_due=past_due,
        canceled_total=canceled_total,
        total_subscribers=total,
        mrr_cents=mrr,
        arpu_cents=arpu,
        period_days=period_days,
        new_subs_30d=new_subs,
        churned_30d=churned,
        churn_rate=churn_rate,
        gross_revenue_to_date_cents=gross,
        fee_to_date_cents=fee,
        refunded_to_date_cents=refunded,
        net_revenue_to_date_cents=net,
    )
# === END SUB-E4 ===
