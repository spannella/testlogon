#!/usr/bin/env python3
"""PAY-B (PAY-10..12) patcher — routable payout methods + Connect + verify seam.

Applies find/replace edits to app/services/creator_payouts.py,
app/routers/creator_payouts.py, and app/models.py under a repo root passed as
argv[1] (default: current dir). Idempotent-guarded: refuses to double-apply.
Each replacement asserts the anchor exists exactly once.
"""
import sys, os

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

SVC = os.path.join(ROOT, "app/services/creator_payouts.py")
RTR = os.path.join(ROOT, "app/routers/creator_payouts.py")
MDL = os.path.join(ROOT, "app/models.py")


def repl(path, old, new, tag):
    with open(path, "r", encoding="utf-8") as f:
        c = f.read()
    if new.strip() and new in c:
        print(f"SKIP  {tag}: already applied")
        return
    n = c.count(old)
    if n != 1:
        raise SystemExit(f"FAIL  {tag}: anchor count={n} (expected 1) in {path}")
    c = c.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(c)
    print(f"OK    {tag}")


# ---------------------------------------------------------------- SERVICE ----
repl(SVC,
'''PAYOUT_METHOD_TYPES = {"bank_ach", "bank_wire", "paypal", "check"}
PAYOUT_METHOD_KIND = "payout_method"''',
'''PAYOUT_METHOD_TYPES = {"bank_ach", "bank_wire", "paypal", "check", "stripe_connect"}
PAYOUT_METHOD_KIND = "payout_method"

# PAY-10 (PAY-B): a routable method's verification lifecycle. A payout can only
# target a method in the "verified" state (enforced in request_payout).
PAYOUT_METHOD_STATUSES = {"unverified", "verifying", "verified", "failed"}

# PAY-11 (PAY-B): record_kind + key for the per-creator Stripe Connect account
# row, co-located in the single-key CreatorPayouts table under
# payout_id=CONNECT#{user_id}. Stores the connect_account_id the transfer targets.
CONNECT_ACCOUNT_KIND = "connect_account"''',
"svc.constants")

repl(SVC,
'''def _method_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "method_id": item.get("method_id", item.get("payout_id", "")),
        "method_type": item.get("method_type", ""),
        "account_last4": item.get("account_last4", ""),
        "routing_last4": item.get("routing_last4", ""),
        "paypal_email": item.get("paypal_email", ""),
        "nickname": item.get("nickname", ""),
        "is_default": bool(item.get("is_default", False)),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }''',
'''def _method_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "method_id": item.get("method_id", item.get("payout_id", "")),
        "method_type": item.get("method_type", ""),
        "account_last4": item.get("account_last4", ""),
        "routing_last4": item.get("routing_last4", ""),
        "paypal_email": item.get("paypal_email", ""),
        "nickname": item.get("nickname", ""),
        "is_default": bool(item.get("is_default", False)),
        "method_status": item.get("method_status", "unverified"),
        "connect_account_id": item.get("connect_account_id", ""),
        "external_account_ref": item.get("external_account_ref", ""),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }''',
"svc._method_to_dict")

# add_payout_method full-body replace.
repl(SVC,
'''def add_payout_method(
    user_id: str,
    *,
    method_type: str,
    account_last4: str = "",
    routing_last4: str = "",
    paypal_email: str = "",
    nickname: str = "",
    set_as_default: bool = False,
) -> Dict[str, Any]:
    """Add a payout method. Only last-4 digits are persisted for bank accounts (SEC-004)."""
    if method_type not in PAYOUT_METHOD_TYPES:
        raise ValueError(f"invalid_method_type:Must be one of {sorted(PAYOUT_METHOD_TYPES)}")
    if method_type in ("bank_ach", "bank_wire") and (not account_last4 or not routing_last4):
        raise ValueError("bank_details_required:account_last4 and routing_last4 are required for bank methods")
    if method_type == "paypal" and not paypal_email:
        raise ValueError("paypal_email_required:paypal_email is required for PayPal methods")

    # First method becomes default automatically.
    existing = list_payout_methods(user_id)
    make_default = set_as_default or not existing

    ts = now_ts()
    mid = _method_id()
    item = {
        "payout_id": mid,
        "method_id": mid,
        "user_id": user_id,
        "record_kind": PAYOUT_METHOD_KIND,
        "method_type": method_type,
        "account_last4": account_last4,
        "routing_last4": routing_last4,
        "paypal_email": paypal_email,
        "nickname": nickname,
        "is_default": False,
        "created_at": ts,
        "updated_at": ts,
    }
    T.creator_payouts.put_item(Item=item)

    if make_default:
        set_default_payout_method(user_id, mid)
        item["is_default"] = True

    logger.info("payout_method_added user_id=%s method_type=%s", user_id, method_type)
    return _method_to_dict(item)''',
'''def _tokenize_bank_ref(account_number: str, routing_number: str) -> Dict[str, str]:
    """SEC-004: exchange a raw bank account/routing for a NON-reversible routable
    reference. The raw number is NEVER stored — only an opaque token + last-4 for
    display. Real rail (when keyed) would swap the number for a processor token
    (Stripe bank-account token / Plaid processor token); the mock derives a salted
    hash so the destination is routable-shaped but no real account is linked.
    Returns {bank_token, account_last4, routing_last4}.
    """
    import hashlib

    acct = "".join(ch for ch in (account_number or "") if ch.isdigit())
    rout = "".join(ch for ch in (routing_number or "") if ch.isdigit())
    token = ""
    if acct:
        digest = hashlib.sha256(f"{rout}:{acct}:tl_bank_tok".encode()).hexdigest()[:24]
        token = f"btok_mock_{digest}"
    return {
        "bank_token": token,
        "account_last4": acct[-4:] if acct else "",
        "routing_last4": rout[-4:] if rout else "",
    }


def _connect_pk(user_id: str) -> str:
    return f"CONNECT#{user_id}"


def _connect_enabled() -> bool:
    """True only when Stripe Connect is explicitly keyed (dedicated flag + secret).
    Otherwise the Connect / verification rails run in honest mock mode.
    """
    on = os.environ.get("STRIPE_CONNECT_ENABLED", "0") not in ("0", "false", "False")
    return on and bool(getattr(S, "stripe_secret_key", ""))


def get_connect_account(user_id: str) -> Optional[Dict[str, Any]]:
    """Return the creator's stored Stripe Connect account record, or None."""
    item = T.creator_payouts.get_item(Key={"payout_id": _connect_pk(user_id)}).get("Item")
    if not item or item.get("record_kind") != CONNECT_ACCOUNT_KIND:
        return None
    return item


def create_connect_account(user_id: str) -> Dict[str, Any]:
    """PAY-11: create (or return) a Stripe Connect account id for a creator.

    Real rail (only when ``STRIPE_CONNECT_ENABLED`` keyed + secret): performs
    ``stripe.Account.create(type="express")``. Mock: a routable-shaped
    ``acct_mock_<hash>`` id with ``payouts_enabled=False`` until onboarding.
    Idempotent — returns the existing account when present. Honest: under the mock
    no real Connect account exists; only a routable reference is recorded.
    """
    existing = get_connect_account(user_id)
    if existing:
        return existing
    ts = now_ts()
    real = False
    if _connect_enabled():
        try:
            import stripe  # noqa: WPS433

            stripe.api_key = S.stripe_secret_key
            acct = stripe.Account.create(type="express", metadata={"user_id": user_id})
            acct_id = acct.get("id") if isinstance(acct, dict) else getattr(acct, "id", "")
            real = True
        except Exception as exc:
            logger.error("connect_account_create_failed user_id=%s: %s", user_id, exc)
            raise
    else:
        import hashlib

        acct_id = f"acct_mock_{hashlib.sha256((user_id + ':connect').encode()).hexdigest()[:16]}"
    item = {
        "payout_id": _connect_pk(user_id),
        "user_id": user_id,
        "record_kind": CONNECT_ACCOUNT_KIND,
        "connect_account_id": acct_id,
        "onboarding_status": "pending",
        "payouts_enabled": False,
        "provider": "stripe_connect" if real else "mock",
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.creator_payouts.put_item(
            Item=item, ConditionExpression="attribute_not_exists(payout_id)"
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return get_connect_account(user_id) or item
        raise
    logger.info("connect_account_created user_id=%s real=%s", user_id, real)
    return item


def create_connect_onboarding_link(
    user_id: str, *, return_url: str = "", refresh_url: str = ""
) -> Dict[str, Any]:
    """PAY-11: a Connect onboarding-link seam.

    Real (keyed): ``stripe.AccountLink.create(type="account_onboarding")`` — the
    creator completes real onboarding, ``payouts_enabled`` follows the capability.
    Mock: NO real account link — marks the account onboarding-complete +
    payouts_enabled so a ``stripe_connect`` method can be verified (honest
    simulation, no real account linked). Returns {connect_account_id,
    onboarding_url, onboarding_status, payouts_enabled, real}.
    """
    acct = create_connect_account(user_id)
    acct_id = acct["connect_account_id"]
    ts = now_ts()
    if _connect_enabled():
        try:
            import stripe  # noqa: WPS433

            stripe.api_key = S.stripe_secret_key
            link = stripe.AccountLink.create(
                account=acct_id,
                type="account_onboarding",
                return_url=return_url or "https://testlogon.example/connect/return",
                refresh_url=refresh_url or "https://testlogon.example/connect/refresh",
            )
            url = link.get("url") if isinstance(link, dict) else getattr(link, "url", "")
            T.creator_payouts.update_item(
                Key={"payout_id": _connect_pk(user_id)},
                UpdateExpression="SET onboarding_status = :s, updated_at = :t",
                ExpressionAttributeValues={":s": "in_progress", ":t": ts},
            )
            return {
                "connect_account_id": acct_id,
                "onboarding_url": url or "",
                "onboarding_status": "in_progress",
                "payouts_enabled": False,
                "real": True,
            }
        except Exception as exc:
            logger.error("connect_onboarding_link_failed user_id=%s: %s", user_id, exc)
            raise
    # Mock onboarding-complete (no real account link).
    T.creator_payouts.update_item(
        Key={"payout_id": _connect_pk(user_id)},
        UpdateExpression="SET onboarding_status = :s, payouts_enabled = :p, updated_at = :t",
        ExpressionAttributeValues={":s": "complete", ":p": True, ":t": ts},
    )
    return {
        "connect_account_id": acct_id,
        "onboarding_url": f"https://mock.testlogon/connect/onboarding/{acct_id}",
        "onboarding_status": "complete",
        "payouts_enabled": True,
        "real": False,
    }


def verify_payout_method(user_id: str, method_id: str) -> Dict[str, Any]:
    """PAY-12: verify a routable payout method (verification seam).

    Real (keyed): a bank micro-deposit / instant-verify would move the method to
    ``verifying`` until confirmed; a ``stripe_connect`` method is ``verified`` once
    the Connect account's ``payouts_enabled`` capability is live. Mock: mark
    ``verified`` immediately (honest — nothing real is verified). A payout can only
    target a ``verified`` method (enforced in request_payout).
    """
    item = _get_method_item(user_id, method_id)
    if item is None:
        raise LookupError("payout_method_not_found:Payout method not found")
    ts = now_ts()
    mtype = item.get("method_type", "")
    status = "verified"
    if _connect_enabled():
        if mtype == "stripe_connect":
            acct = get_connect_account(user_id)
            status = "verified" if (acct and acct.get("payouts_enabled")) else "verifying"
        else:
            status = "verifying"  # real micro-deposit pending confirmation
    resp = T.creator_payouts.update_item(
        Key={"payout_id": method_id},
        UpdateExpression="SET #ms = :s, updated_at = :t",
        ExpressionAttributeNames={"#ms": "method_status"},
        ExpressionAttributeValues={":s": status, ":t": ts},
        ReturnValues="ALL_NEW",
    )
    logger.info(
        "payout_method_verify user_id=%s method_id=%s status=%s", user_id, method_id, status
    )
    return _method_to_dict(resp["Attributes"])


def add_payout_method(
    user_id: str,
    *,
    method_type: str,
    account_last4: str = "",
    routing_last4: str = "",
    account_number: str = "",
    routing_number: str = "",
    paypal_email: str = "",
    connect_account_id: str = "",
    nickname: str = "",
    set_as_default: bool = False,
) -> Dict[str, Any]:
    """Add a routable payout method (PAY-10).

    Stores a ROUTABLE DESTINATION REFERENCE the transfer can target — never a raw
    account number (SEC-004): bank -> a tokenized bank ref + last-4 for display;
    paypal -> the payout email; stripe_connect -> the creator's connect_account_id.
    Methods start ``unverified``; a payout can only target a ``verified`` method.
    """
    if method_type not in PAYOUT_METHOD_TYPES:
        raise ValueError(f"invalid_method_type:Must be one of {sorted(PAYOUT_METHOD_TYPES)}")

    ts = now_ts()
    mid = _method_id()
    bank_token = ""
    external_account_ref = ""
    conn_id = ""

    if method_type in ("bank_ach", "bank_wire"):
        # SEC-004: tokenize the full number server-side; store token + last-4 only.
        if account_number or routing_number:
            tok = _tokenize_bank_ref(account_number, routing_number)
            bank_token = tok["bank_token"]
            account_last4 = tok["account_last4"] or account_last4
            routing_last4 = tok["routing_last4"] or routing_last4
        if not account_last4 or not routing_last4:
            raise ValueError(
                "bank_details_required:account/routing (or their last-4) are required for bank methods"
            )
        if not bank_token:
            import hashlib

            bank_token = f"btok_mock_{hashlib.sha256((user_id + ':' + mid).encode()).hexdigest()[:24]}"
        external_account_ref = bank_token
    elif method_type == "paypal":
        if not paypal_email:
            raise ValueError("paypal_email_required:paypal_email is required for PayPal methods")
        external_account_ref = f"paypal:{paypal_email}"
    elif method_type == "stripe_connect":
        acct = get_connect_account(user_id) or create_connect_account(user_id)
        conn_id = connect_account_id or acct.get("connect_account_id", "")
        external_account_ref = conn_id

    # First method becomes default automatically.
    existing = list_payout_methods(user_id)
    make_default = set_as_default or not existing

    item = {
        "payout_id": mid,
        "method_id": mid,
        "user_id": user_id,
        "record_kind": PAYOUT_METHOD_KIND,
        "method_type": method_type,
        "account_last4": account_last4,
        "routing_last4": routing_last4,
        "paypal_email": paypal_email,
        "bank_token": bank_token,
        "connect_account_id": conn_id,
        "external_account_ref": external_account_ref,
        "method_status": "unverified",
        "nickname": nickname,
        "is_default": False,
        "created_at": ts,
        "updated_at": ts,
    }
    T.creator_payouts.put_item(Item=item)

    if make_default:
        set_default_payout_method(user_id, mid)
        item["is_default"] = True

    logger.info(
        "payout_method_added user_id=%s method_type=%s status=unverified", user_id, method_type
    )
    return _method_to_dict(item)''',
"svc.add_payout_method+seams")

# request_payout: enforce verified + stamp routable destination.
repl(SVC,
'''        # Resolve the payout destination (GAP-0195 / FIN-009).
        resolved_method = method
        resolved_method_id = ""
        if method_id:
            mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
            if (
                not mitem
                or not _is_payout_method(mitem)
                or mitem.get("user_id") != user_id
            ):
                raise ValueError("invalid_method_id:Payout method not found or not yours")
            resolved_method = mitem.get("method_type", method)
            resolved_method_id = method_id
        else:
            default = get_default_payout_method(user_id)
            if default:
                resolved_method = default["method_type"]
                resolved_method_id = default["method_id"]

        now = now_ts()
        item = {
            "payout_id": payout_id,
            "user_id": user_id,
            "amount_cents": amount_cents,
            "method": resolved_method,
            "method_id": resolved_method_id,
            "status": "requested",
            "created_at": now,
            "updated_at": now,
            "notes": notes,
            "reject_reason": "",
            "approved_by": "",
        }''',
'''        # Resolve the payout destination (GAP-0195 / FIN-009 + PAY-10..12).
        resolved_method = method
        resolved_method_id = ""
        resolved_connect_id = ""
        resolved_ext_ref = ""
        resolved_paypal = ""
        mrec: Optional[Dict[str, Any]] = None
        if method_id:
            mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
            if (
                not mitem
                or not _is_payout_method(mitem)
                or mitem.get("user_id") != user_id
            ):
                raise ValueError("invalid_method_id:Payout method not found or not yours")
            mrec = _method_to_dict(mitem)
        else:
            mrec = get_default_payout_method(user_id)

        if mrec is not None:
            # PAY-12: a payout can only target a VERIFIED method.
            if mrec.get("method_status", "unverified") != "verified":
                raise ValueError(
                    "method_not_verified:Payout method must be verified before a payout"
                )
            resolved_method = mrec.get("method_type", method)
            resolved_method_id = mrec.get("method_id", "") or method_id or ""
            resolved_connect_id = mrec.get("connect_account_id", "")
            resolved_ext_ref = mrec.get("external_account_ref", "")
            resolved_paypal = mrec.get("paypal_email", "")

        now = now_ts()
        item = {
            "payout_id": payout_id,
            "user_id": user_id,
            "amount_cents": amount_cents,
            "method": resolved_method,
            "method_id": resolved_method_id,
            "connect_account_id": resolved_connect_id,
            "external_account_ref": resolved_ext_ref,
            "paypal_email": resolved_paypal,
            "status": "requested",
            "created_at": now,
            "updated_at": now,
            "notes": notes,
            "reject_reason": "",
            "approved_by": "",
        }''',
"svc.request_payout")

# ---------------------------------------------------------------- ROUTER ----
repl(RTR,
'''    PayoutMethodOut,
    PayoutMethodListOut,
)''',
'''    PayoutMethodOut,
    PayoutMethodListOut,
    ConnectAccountOut,
    ConnectOnboardingOut,
)''',
"rtr.models_import")

repl(RTR,
'''    add_payout_method,
    update_payout_method,
    delete_payout_method,
    set_default_payout_method,
)''',
'''    add_payout_method,
    update_payout_method,
    delete_payout_method,
    set_default_payout_method,
    verify_payout_method,
    create_connect_account,
    create_connect_onboarding_link,
    get_connect_account,
)''',
"rtr.service_import")

# Append PAY-B endpoints at end of router file.
RTR_APPEND = '''


# ---------------------------------------------------------------------------
# PAY-B (PAY-11/12): routable-destination verification + Stripe Connect seam.
# ---------------------------------------------------------------------------


@router.post("/methods/{method_id}/verify", response_model=PayoutMethodOut)
def verify_method(method_id: str, session=Depends(require_ui_session)):
    """Verify a payout method (PAY-12). Mock -> verified; real when keyed.

    A payout can only target a verified method.
    """
    try:
        result = verify_payout_method(session["user_sub"], method_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout method not found")
    except ValueError as exc:
        raise _method_error(exc)
    return PayoutMethodOut(**result)


@router.get("/connect", response_model=ConnectAccountOut)
def get_connect(session=Depends(require_ui_session)):
    """Return the creator's Stripe Connect account status (creates none)."""
    acct = get_connect_account(session["user_sub"])
    if not acct:
        return ConnectAccountOut(
            connect_account_id="", onboarding_status="none", payouts_enabled=False
        )
    return ConnectAccountOut(
        connect_account_id=acct.get("connect_account_id", ""),
        onboarding_status=acct.get("onboarding_status", "pending"),
        payouts_enabled=bool(acct.get("payouts_enabled", False)),
    )


@router.post("/connect/account", response_model=ConnectAccountOut, status_code=201)
def create_connect(session=Depends(require_ui_session)):
    """Create (or return) the creator's Stripe Connect account id (PAY-11)."""
    acct = create_connect_account(session["user_sub"])
    return ConnectAccountOut(
        connect_account_id=acct.get("connect_account_id", ""),
        onboarding_status=acct.get("onboarding_status", "pending"),
        payouts_enabled=bool(acct.get("payouts_enabled", False)),
    )


@router.post("/connect/onboarding-link", response_model=ConnectOnboardingOut)
def connect_onboarding_link(session=Depends(require_ui_session)):
    """Return a Connect onboarding link (real AccountLink when keyed; mock
    onboarding-complete otherwise) (PAY-11)."""
    result = create_connect_onboarding_link(session["user_sub"])
    return ConnectOnboardingOut(**result)
'''

with open(RTR, "r", encoding="utf-8") as f:
    rc = f.read()
if "PAY-B (PAY-11/12): routable-destination" in rc:
    print("SKIP  rtr.endpoints: already applied")
else:
    if not rc.endswith("\n"):
        rc += "\n"
    rc = rc.rstrip("\n") + "\n" + RTR_APPEND
    with open(RTR, "w", encoding="utf-8") as f:
        f.write(rc)
    print("OK    rtr.endpoints")

# ---------------------------------------------------------------- MODELS ----
repl(MDL,
'''class PayoutMethodIn(BaseModel):
    method_type: str = Field(..., pattern="^(bank_ach|bank_wire|paypal|check)$")
    account_last4: str = Field(default="", max_length=4, pattern=r"^\\d{0,4}$")
    routing_last4: str = Field(default="", max_length=4, pattern=r"^\\d{0,4}$")
    paypal_email: str = Field(default="", max_length=254)
    nickname: str = Field(default="", max_length=100)
    set_as_default: bool = False''',
'''class PayoutMethodIn(BaseModel):
    method_type: str = Field(..., pattern="^(bank_ach|bank_wire|paypal|check|stripe_connect)$")
    # SEC-004: full account/routing are WRITE-ONLY — tokenized server-side, never
    # stored. Only the last-4 (below) + an opaque token are persisted.
    account_number: str = Field(default="", max_length=17, pattern=r"^\\d{0,17}$")
    routing_number: str = Field(default="", max_length=9, pattern=r"^\\d{0,9}$")
    account_last4: str = Field(default="", max_length=4, pattern=r"^\\d{0,4}$")
    routing_last4: str = Field(default="", max_length=4, pattern=r"^\\d{0,4}$")
    paypal_email: str = Field(default="", max_length=254)
    connect_account_id: str = Field(default="", max_length=64)
    nickname: str = Field(default="", max_length=100)
    set_as_default: bool = False''',
"mdl.PayoutMethodIn")

repl(MDL,
'''class PayoutMethodOut(BaseModel):
    method_id: str
    method_type: str
    account_last4: str = ""
    routing_last4: str = ""
    paypal_email: str = ""
    nickname: str = ""
    is_default: bool = False
    created_at: int
    updated_at: int''',
'''class PayoutMethodOut(BaseModel):
    method_id: str
    method_type: str
    account_last4: str = ""
    routing_last4: str = ""
    paypal_email: str = ""
    nickname: str = ""
    is_default: bool = False
    method_status: str = "unverified"
    connect_account_id: str = ""
    external_account_ref: str = ""
    created_at: int
    updated_at: int''',
"mdl.PayoutMethodOut")

repl(MDL,
'''class PayoutMethodListOut(BaseModel):
    methods: List[PayoutMethodOut]''',
'''class PayoutMethodListOut(BaseModel):
    methods: List[PayoutMethodOut]


class ConnectAccountOut(BaseModel):
    connect_account_id: str = ""
    onboarding_status: str = "pending"
    payouts_enabled: bool = False


class ConnectOnboardingOut(BaseModel):
    connect_account_id: str = ""
    onboarding_url: str = ""
    onboarding_status: str = "pending"
    payouts_enabled: bool = False
    real: bool = False''',
"mdl.ConnectModels")

print("PATCH_DONE")
