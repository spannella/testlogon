#!/usr/bin/env python3
"""ADV-B1 backend hotfix: ADV-101 (deposit charges PM), ADV-102 (funds-guard),
ADV-103 (serve mints ad_click_id + content_owner), ADV-104 (newsfeed carries fields).

Idempotent, string-replacement based. Usage: apply_advb1.py <repo_root>
Makes a .bak_advb1_<ts> copy of each file it edits (only when it actually edits).
"""
import sys, os, time

ROOT = sys.argv[1].rstrip("/")
TS = time.strftime("%Y%m%d_%H%M%S")

def patch(relpath, edits):
    """edits = list of (marker_if_applied, old, new). Skip an edit if marker present."""
    path = os.path.join(ROOT, relpath)
    with open(path) as f:
        src = f.read()
    orig = src
    for marker, old, new in edits:
        if marker in src:
            print("  SKIP (already applied): %s :: %r" % (relpath, marker[:50]))
            continue
        cnt = src.count(old)
        if cnt != 1:
            raise SystemExit(
                "ABORT %s: expected exactly 1 occurrence of anchor, found %d\nANCHOR>>>\n%s\n<<<"
                % (relpath, cnt, old[:300]))
        src = src.replace(old, new)
        print("  applied: %s :: %r" % (relpath, marker[:50]))
    if src != orig:
        bak = "%s.bak_advb1_%s" % (path, TS)
        with open(bak, "w") as f:
            f.write(orig)
        with open(path, "w") as f:
            f.write(src)
        print("  wrote %s (bak: %s)" % (relpath, os.path.basename(bak)))
    else:
        print("  no change: %s" % relpath)

# -- core/settings.py + core/tables.py: register T.ad_clicks (B0 folded this to
#    the dev clone only; prod created the physical table but never registered it,
#    which ADV-103's serve-time AdClicks write needs). Idempotent marker-skip. --
SETTINGS_OLD = '''    ad_impressions_table_name: str = os.environ.get("DDB_AD_IMPRESSIONS", "AdImpressions")'''
SETTINGS_NEW = '''    ad_impressions_table_name: str = os.environ.get("DDB_AD_IMPRESSIONS", "AdImpressions")
    ad_clicks_table_name: str = os.environ.get("DDB_AD_CLICKS", "AdClicks")'''
patch("app/core/settings.py", [
    ("ad_clicks_table_name", SETTINGS_OLD, SETTINGS_NEW),
])

TABLES_DECL_OLD = '''    ad_impressions: Any
    ad_accounts: Any'''
TABLES_DECL_NEW = '''    ad_impressions: Any
    ad_clicks: Any
    ad_accounts: Any'''
TABLES_INIT_OLD = '''    ad_impressions=_safe_table(S.ad_impressions_table_name),
    ad_accounts=_safe_table(S.ad_accounts_table_name),'''
TABLES_INIT_NEW = '''    ad_impressions=_safe_table(S.ad_impressions_table_name),
    ad_clicks=_safe_table(S.ad_clicks_table_name),
    ad_accounts=_safe_table(S.ad_accounts_table_name),'''
patch("app/core/tables.py", [
    ("    ad_clicks: Any", TABLES_DECL_OLD, TABLES_DECL_NEW),
    ("    ad_clicks=_safe_table(S.ad_clicks_table_name),", TABLES_INIT_OLD, TABLES_INIT_NEW),
])

# -- ad_billing.py --
AB_IMPORTS_OLD = """from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T"""
AB_IMPORTS_NEW = """from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T"""

AB_DEPOSIT_OLD = '''def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:
    """Add funds to advertiser account balance."""
    if amount_cents < MIN_DEPOSIT_CENTS:
        raise ValueError(f"Minimum deposit is $50")

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # Write billing ledger entry. Omit campaign_id entirely (rather than "")
    # because it is the key of the ByCampaign GSI and DynamoDB rejects empty
    # strings as index keys; a deposit is not tied to a campaign, so it should
    # simply be absent from that sparse index.
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "entry_type": "budget_deposit",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Account deposit",
        "meta": {"payment_method_id": payment_method_id},
        "month_key": month_key,
        "created_at": ts,
    })

    # Increment account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
    )

    return {"ok": True, "entry_id": entry_id, "new_balance_cents": _get_balance(account_id)}'''

AB_DEPOSIT_NEW = '''def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:
    """Add funds to advertiser account balance.

    ADV-101: the payment_method_id is now actually CHARGED via the stripe-mock
    PaymentIntent rail (mirrors billing.charge_once / tips._charge_tip) BEFORE any
    balance credit. A declined card / processor error raises HTTPException(402)
    before any ledger row is written or balance credited -- a failed deposit never
    credits the account.
    """
    if amount_cents < MIN_DEPOSIT_CENTS:
        raise ValueError(f"Minimum deposit is $50")

    # ADV-101: charge the payment method FIRST. Resolve the owner sub so the
    # charge lands on the advertiser's own Stripe customer.
    owner_sub = ""
    try:
        from app.services.ad_accounts import get_ad_account
        _acct = get_ad_account(account_id)
        owner_sub = (_acct or {}).get("owner_sub", "")
    except Exception:
        owner_sub = ""
    payment_intent_id = _charge_deposit(
        owner_sub=owner_sub, account_id=account_id,
        amount_cents=amount_cents, payment_method_id=payment_method_id,
    )

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # Write billing ledger entry. Omit campaign_id entirely (rather than "")
    # because it is the key of the ByCampaign GSI and DynamoDB rejects empty
    # strings as index keys; a deposit is not tied to a campaign, so it should
    # simply be absent from that sparse index.
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "entry_type": "budget_deposit",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Account deposit",
        "meta": {
            "payment_method_id": payment_method_id,
            "stripe_payment_intent_id": payment_intent_id or "",
        },
        "month_key": month_key,
        "created_at": ts,
    })

    # Increment account balance (only reached after a successful charge)
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
    )

    return {"ok": True, "entry_id": entry_id, "new_balance_cents": _get_balance(account_id)}


def _charge_deposit(*, owner_sub: str, account_id: str, amount_cents: int,
                    payment_method_id: str) -> Optional[str]:
    """ADV-101: charge an advertiser deposit via the stripe-mock PaymentIntent rail.

    Mirrors app.services.tips._charge_tip / billing.charge_once: off_session +
    confirm with an idempotency_key so a retried deposit never double-charges.

    Returns the PaymentIntent id on success, or None for the dev-stub path
    (Stripe not configured, or no payment method supplied -- preserves the historical
    ledger-only behavior so internal/seed callers without a PM still work).

    Raises HTTPException(402) on a declined card / processor error / non-succeeded
    terminal status so the caller (deposit_funds) never credits the balance.

    stripe-mock nuance: the local stripe-mock cannot truly confirm an off_session
    intent, so when stripe_api_base is overridden we accept the created intent
    unless it is canceled/payment_failed; a real Stripe (no api_base override)
    still requires status == "succeeded" and a real decline surfaces as CardError.
    """
    if not getattr(S, "stripe_secret_key", "") or not payment_method_id:
        return None
    from fastapi import HTTPException
    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    import stripe

    ensure_stripe_configured()
    customer_id = get_or_create_customer(owner_sub or account_id)
    try:
        pi = stripe.PaymentIntent.create(
            amount=int(amount_cents),
            currency="usd",
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description="Ad account deposit",
            metadata={
                "app_user_id": owner_sub,
                "purpose": "ad_deposit",
                "account_id": account_id,
            },
            idempotency_key=f"addep:{account_id}:{amount_cents}:{payment_method_id}",
        )
    except stripe.error.CardError as exc:
        logger.info("ad deposit declined for account=%s: %s", account_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": str(exc)})
    except stripe.error.StripeError as exc:
        logger.warning("ad deposit stripe error for account=%s: %s", account_id, exc)
        raise HTTPException(402, {"code": "payment_failed",
                                  "message": "Deposit charge failed at the payment processor."})

    status = (pi.get("status") or "").lower()
    charged_ok = status == "succeeded" or (
        bool(getattr(S, "stripe_api_base", "")) and status not in ("canceled", "payment_failed")
    )
    if not charged_ok:
        raise HTTPException(
            402,
            {"code": "payment_failed",
             "message": f"Deposit charge did not succeed (status={status})."},
        )
    return pi.get("id")'''

AB_CHARGE_OLD = '''    """Process a charge: debit advertiser, split revenue, check budget."""
    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Write charge to ad_billing ledger
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 2. Debit advertiser account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = balance_cents - :amt, "
                         "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
        ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
    )

    # 3. Increment campaign spend'''

AB_CHARGE_NEW = '''    """Process a charge: debit advertiser, split revenue, check budget.

    ADV-102: the balance debit is now a CONDITIONAL write
    (attribute_exists(balance_cents) AND balance_cents >= :amt) executed FIRST.
    If the account cannot cover the charge the debit is rejected and NOTHING else
    is written (no ledger row, no campaign-spend bump, no revenue split) -- the
    balance can never go negative and concurrent charges never oversell.
    """
    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Debit advertiser balance FIRST, funds-guarded so it can never go negative.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = balance_cents - :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "ad_charge_insufficient_funds account=%s campaign=%s amount=%s",
                account_id, campaign_id, charge_cents,
            )
            return {"ok": False, "reason": "insufficient_funds", "charge_cents": charge_cents}
        raise

    # 2. Write charge to ad_billing ledger (only after a successful debit)
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 3. Increment campaign spend'''

patch("app/services/ad_billing.py", [
    ("from botocore.exceptions import ClientError", AB_IMPORTS_OLD, AB_IMPORTS_NEW),
    ("def _charge_deposit", AB_DEPOSIT_OLD, AB_DEPOSIT_NEW),
    ("ADV-102: the balance debit is now a CONDITIONAL write", AB_CHARGE_OLD, AB_CHARGE_NEW),
])

# -- ad_serving.py --
AS_SIG_OLD = '''    user_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Select and return the best ad for the given context."""'''
AS_SIG_NEW = '''    user_context: Optional[Dict[str, Any]] = None,
    content_owner_id: str = "",
) -> Dict[str, Any]:
    """Select and return the best ad for the given context."""'''

AS_MINT_OLD = '''    creative = _weighted_random_creative(
        winner["creatives"], campaign_weights=winner["campaign"].get("creative_weights") or {}
    )

    # 6. Build tracking URLs
    tracking_base = "/ui/ads/track"
    tracking_params = (
        f"creative_id={creative['creative_id']}"
        f"&campaign_id={winner['campaign']['campaign_id']}"
        f"&account_id={winner['campaign']['account_id']}"
        f"&surface={surface}&slot_type={slot_type}"
        f"&content_id={content_id}&creator_id={creator_id}"
    )'''
AS_MINT_NEW = '''    creative = _weighted_random_creative(
        winner["creatives"], campaign_weights=winner["campaign"].get("creative_weights") or {}
    )

    # ADV-103: mint a per-serve ad_click_id for CPA attribution. Persist a row in
    # AdClicks (status=served, 7d TTL) carrying the content owner so a later
    # purchase/subscribe can resolve the last click. effective_price_cents is the
    # winning bid as a placeholder until the B3 auction sets a cleared price.
    ad_click_id = uuid.uuid4().hex
    _bid_cpm_win = int(winner["campaign"].get("bid_cpm_cents", 500) or 500)
    try:
        _now = now_ts()
        T.ad_clicks.put_item(Item={
            "ad_click_id": ad_click_id,
            "viewer_sub": user_id,
            "campaign_id": winner["campaign"]["campaign_id"],
            "account_id": winner["campaign"]["account_id"],
            "creative_id": creative["creative_id"],
            "content_owner_sub": content_owner_id or "",
            "surface": surface,
            "slot_type": slot_type,
            "content_id": content_id,
            "status": "served",
            "effective_price_cents": _bid_cpm_win,
            "created_at": _now,
            "expires_at": _now + 604800,
        })
    except Exception:
        logger.warning(
            "ad_click_mint_failed campaign=%s", winner["campaign"].get("campaign_id")
        )

    # 6. Build tracking URLs
    tracking_base = "/ui/ads/track"
    tracking_params = (
        f"creative_id={creative['creative_id']}"
        f"&campaign_id={winner['campaign']['campaign_id']}"
        f"&account_id={winner['campaign']['account_id']}"
        f"&surface={surface}&slot_type={slot_type}"
        f"&content_id={content_id}&creator_id={creator_id}"
        f"&ad_click_id={ad_click_id}"
    )'''

AS_RET_OLD = '''        "is_house_ad": False,
        "campaign_id": winner["campaign"]["campaign_id"],
        "promo_code_id": creative.get("promo_code_id"),
        "affiliate_link_id": creative.get("affiliate_link_id"),
    }'''
AS_RET_NEW = '''        "is_house_ad": False,
        "campaign_id": winner["campaign"]["campaign_id"],
        "account_id": winner["campaign"]["account_id"],
        "ad_click_id": ad_click_id,
        "content_owner_id": content_owner_id or "",
        "promo_code_id": creative.get("promo_code_id"),
        "affiliate_link_id": creative.get("affiliate_link_id"),
    }'''

patch("app/services/ad_serving.py", [
    ('    content_owner_id: str = "",\n) -> Dict[str, Any]:', AS_SIG_OLD, AS_SIG_NEW),
    ("ADV-103: mint a per-serve ad_click_id", AS_MINT_OLD, AS_MINT_NEW),
    ('"ad_click_id": ad_click_id,\n        "content_owner_id": content_owner_id', AS_RET_OLD, AS_RET_NEW),
])

# -- newsfeed.py --
NF_OLD = '''            "creative_id": creative_id,
            "campaign_id": ad.get("campaign_id"),
            "reactions_counts": {},'''
NF_NEW = '''            "creative_id": creative_id,
            "campaign_id": ad.get("campaign_id"),
            "account_id": ad.get("account_id", ""),
            "ad_click_id": ad.get("ad_click_id", ""),
            "content_owner_id": ad.get("content_owner_id", ""),
            "reactions_counts": {},'''
patch("app/routers/newsfeed.py", [
    ('"ad_click_id": ad.get("ad_click_id"', NF_OLD, NF_NEW),
])

# -- models.py (AdServeRequestIn add content_owner_id) --
MODELS_OLD = '''    user_context: Optional[Dict[str, Any]] = Field(default=None,
                                                    description="Additional viewer context for targeting")


class AdServeResponseOut(BaseModel):'''
MODELS_NEW = '''    user_context: Optional[Dict[str, Any]] = Field(default=None,
                                                    description="Additional viewer context for targeting")
    content_owner_id: str = Field(default="",
                                  description="Sub of the content owner for CPA attribution; empty for standalone units")


class AdServeResponseOut(BaseModel):'''
patch("app/models.py", [
    ('content_owner_id: str = Field(default="",', MODELS_OLD, MODELS_NEW),
])

# -- ads.py serve route (pass content_owner_id) --
ADS_OLD = '''        user_id=ctx["user_sub"],
        user_context=getattr(body, "user_context", None),
    )
    return result'''
ADS_NEW = '''        user_id=ctx["user_sub"],
        user_context=getattr(body, "user_context", None),
        content_owner_id=getattr(body, "content_owner_id", "") or "",
    )
    return result'''
patch("app/routers/ads.py", [
    ('content_owner_id=getattr(body, "content_owner_id"', ADS_OLD, ADS_NEW),
])

print("DONE apply_advb1")
