from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import ipaddress
import re
from enum import Enum
from datetime import datetime, timezone
from urllib.parse import urlparse

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    conint,
    field_validator,
    model_validator,
)

from app.core.normalize import normalize_email, normalize_phone

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

class UiSessionStartReq(BaseModel):
    # You can include client metadata; auth is handled separately.
    # For example: challenge_context could include risk signals.
    challenge_context: Dict[str, Any] = Field(default_factory=dict)

class UiSessionStartResp(BaseModel):
    auth_required: bool
    challenge_id: Optional[str] = None
    required_factors: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None

class UiSessionFinalizeReq(BaseModel):
    challenge_id: str
    remember_device: bool = False

class UiSessionFinalizeResp(BaseModel):
    status: str
    session_id: Optional[str] = None
    required_factors: List[str] = Field(default_factory=list)
    passed: Dict[str, bool] = Field(default_factory=dict)

class AccountClosureFinalizeReq(BaseModel):
    challenge_id: str

class TotpVerifyReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    challenge_id: str
    totp_code: str = Field(validation_alias=AliasChoices("totp_code", "code"))

class SmsBeginReq(BaseModel):
    challenge_id: str

class SmsVerifyReq(BaseModel):
    challenge_id: str
    code: str

class EmailBeginReq(BaseModel):
    challenge_id: str

class EmailVerifyReq(BaseModel):
    challenge_id: str
    code: str

class RecoveryReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    challenge_id: str
    recovery_code: str = Field(validation_alias=AliasChoices("recovery_code", "code"))
    factor: str = "totp"  # totp|sms|email

class PasswordRecoveryStartReq(BaseModel):
    username: str

class PasswordRecoveryConfirmReq(BaseModel):
    username: str
    confirmation_code: str = Field(validation_alias=AliasChoices("confirmation_code", "code"))
    new_password: str
    challenge_id: Optional[str] = None

class PasswordRecoveryChallengeReq(BaseModel):
    username: str
    challenge_id: str

class PasswordRecoveryTotpVerifyReq(PasswordRecoveryChallengeReq):
    model_config = ConfigDict(populate_by_name=True)
    totp_code: str = Field(validation_alias=AliasChoices("totp_code", "code"))

class PasswordRecoverySmsVerifyReq(PasswordRecoveryChallengeReq):
    code: str

class PasswordRecoveryEmailVerifyReq(PasswordRecoveryChallengeReq):
    code: str

class PasswordRecoveryRecoveryCodeReq(PasswordRecoveryChallengeReq):
    model_config = ConfigDict(populate_by_name=True)
    factor: str
    recovery_code: str = Field(validation_alias=AliasChoices("recovery_code", "code"))

class PasswordlessStartReq(BaseModel):
    username: str

class PasswordlessStartResp(BaseModel):
    status: str
    sent_to: List[str] = Field(default_factory=list)

class PasswordlessVerifyReq(BaseModel):
    token: str

class PasswordlessVerifyResp(BaseModel):
    status: str
    session_id: Optional[str] = None
    auth_required: bool = False
    challenge_id: Optional[str] = None
    required_factors: List[str] = Field(default_factory=list)

class RegisterStartReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    full_name: str
    email: str = Field(validation_alias=AliasChoices("email", "username"))
    password: str
    confirm_password: str
    delivery_method: Literal["email", "sms"] = "email"
    phone: Optional[str] = None
    enable_sms_mfa: bool = False
    enable_totp_mfa: bool = False

    @field_validator("full_name", "email")
    @classmethod
    def _strip_value(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value required")
        return cleaned

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned:
            raise ValueError("Invalid email")
        return cleaned

    @field_validator("phone")
    @classmethod
    def _normalize_phone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return normalize_phone(cleaned)
        except Exception as exc:
            raise ValueError("Invalid phone") from exc

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError("Password must be at least 12 characters")
        if len(value) > 128:
            raise ValueError("Password must be 128 characters or fewer")
        # Basic low-entropy guardrail.
        if len(set(value)) < 4:
            raise ValueError("Password is too weak")
        return value

    @model_validator(mode="after")
    def _validate_password_match(self) -> "RegisterStartReq":
        if self.password != self.confirm_password:
            raise ValueError("Passwords don't match")
        if self.enable_sms_mfa and not self.phone:
            raise ValueError("Phone required for SMS MFA")
        self._validate_password_context()
        return self

    def _validate_password_context(self) -> None:
        password = self.password.lower()
        local_part = self.email.split("@", 1)[0].lower()
        local_tokens = [t for t in _NON_ALNUM.split(local_part) if len(t) >= 3]
        name_tokens = [t for t in _NON_ALNUM.split(self.full_name.lower()) if len(t) >= 3]
        for token in local_tokens + name_tokens:
            if token and token in password:
                raise ValueError("Password is too similar to personal information")

class RegisterStartResp(BaseModel):
    status: str
    verification_required: bool = False
    delivery_medium: Optional[str] = None
    delivery_destination: Optional[str] = None
    session_id: Optional[str] = None

class RegisterConfirmReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    email: str = Field(validation_alias=AliasChoices("email", "username"))
    confirmation_code: str = Field(validation_alias=AliasChoices("confirmation_code", "code"))

    @field_validator("email")
    @classmethod
    def _normalize_confirm_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned:
            raise ValueError("Invalid email")
        return cleaned

class RegisterConfirmResp(BaseModel):
    status: str
    session_id: Optional[str] = None
    mfa_setup: List[str] = Field(default_factory=list)
    sms_phone: Optional[str] = None

class RegisterResendReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    email: str = Field(validation_alias=AliasChoices("email", "username"))
    delivery_method: Literal["email", "sms"] = "email"
    phone: Optional[str] = None
    enable_sms_mfa: bool = False
    enable_totp_mfa: bool = False

    @field_validator("email")
    @classmethod
    def _normalize_resend_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned:
            raise ValueError("Invalid email")
        return cleaned

    @field_validator("phone")
    @classmethod
    def _normalize_resend_phone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return normalize_phone(cleaned)
        except Exception as exc:
            raise ValueError("Invalid phone") from exc

    @model_validator(mode="after")
    def _validate_sms_phone(self) -> "RegisterResendReq":
        if self.enable_sms_mfa and not self.phone:
            raise ValueError("Phone required for SMS MFA")
        return self

class RegisterResendResp(BaseModel):
    status: str
    delivery_medium: Optional[str] = None
    delivery_destination: Optional[str] = None

class RegisterEmailCheckReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    email: str = Field(validation_alias=AliasChoices("email", "username"))

    @field_validator("email")
    @classmethod
    def _normalize_check_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned:
            raise ValueError("Invalid email")
        return cleaned

class RegisterEmailCheckResp(BaseModel):
    status: str
    available: bool
    # Distinguishes a taken+verified account (unverified=False) from a
    # taken+pending-verification account (unverified=True) so the frontend can
    # offer a resume/resend path (GAP-0107). Defaults to False for backward
    # compatibility with clients that only read `available`.
    unverified: bool = False

class WebAuthnRegisterBeginReq(BaseModel):
    label: Optional[str] = None

class WebAuthnRegisterBeginResp(BaseModel):
    options: Dict[str, Any]

class WebAuthnRegisterFinishReq(BaseModel):
    credential: Dict[str, Any]
    label: Optional[str] = None

class WebAuthnRegisterFinishResp(BaseModel):
    credential_id: str

class WebAuthnAuthBeginReq(BaseModel):
    username: str

class WebAuthnAuthBeginResp(BaseModel):
    options: Dict[str, Any]

class WebAuthnAuthFinishReq(BaseModel):
    username: str
    credential: Dict[str, Any]

class WebAuthnAuthFinishResp(BaseModel):
    status: str
    session_id: Optional[str] = None

class CreateApiKeyReq(BaseModel):
    label: Optional[str] = None
    expires_in_days: Optional[int] = None
    # Canonical product scopes; accepts legacy alias `scopes`.
    capabilities: List[str] = Field(default_factory=list)

class RevokeApiKeyReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))

class ApiKeyIpRulesReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))
    allow_cidrs: List[str] = Field(default_factory=list)
    deny_cidrs: List[str] = Field(default_factory=list)


class ApiKeyScopesReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))
    capabilities: List[str] = Field(default_factory=list, validation_alias=AliasChoices("capabilities", "scopes"))

class ApiKeyRouteCapReq(BaseModel):
    monthly_calls_cap: int = Field(default=0, ge=0)
    monthly_spend_cap_micros: int = Field(default=0, ge=0)


class ApiKeyLimitsPatchReq(BaseModel):
    monthly_calls_cap: int = Field(default=0, ge=0)
    monthly_spend_cap_micros: int = Field(default=0, ge=0)
    route_caps: Dict[str, ApiKeyRouteCapReq] = Field(default_factory=dict)

    @field_validator("route_caps")
    @classmethod
    def _validate_route_caps(cls, value: Dict[str, ApiKeyRouteCapReq]) -> Dict[str, ApiKeyRouteCapReq]:
        out: Dict[str, ApiKeyRouteCapReq] = {}
        for route_id, cap in (value or {}).items():
            rid = (route_id or "").strip()
            if not rid or ":" not in rid:
                raise ValueError("route_caps keys must be route_id entries like METHOD:/path")
            method, path = rid.split(":", 1)
            method = method.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                raise ValueError(f"invalid route method in route_caps: {method}")
            if not path.startswith("/"):
                raise ValueError(f"invalid route path in route_caps: {path}")
            out[f"{method}:{path}"] = cap
        return out


class ApiKeySelfLimitsReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))
    monthly_calls_cap: int = Field(default=0, ge=0)
    monthly_spend_cap_micros: int = Field(default=0, ge=0)
    route_caps: Dict[str, ApiKeyRouteCapReq] = Field(default_factory=dict)
    # PLT-001: optional per-window rate-limit overrides
    # (e.g. {"hour": 500, "day": 5000}; null values clear a window).
    rate_limit_overrides: Optional[Dict[str, Any]] = None

    @field_validator("route_caps")
    @classmethod
    def _validate_route_caps(cls, value: Dict[str, ApiKeyRouteCapReq]) -> Dict[str, ApiKeyRouteCapReq]:
        out: Dict[str, ApiKeyRouteCapReq] = {}
        for route_id, cap in (value or {}).items():
            rid = (route_id or "").strip()
            if not rid or ":" not in rid:
                raise ValueError("route_caps keys must be route_id entries like METHOD:/path")
            method, path = rid.split(":", 1)
            method = method.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                raise ValueError(f"invalid route method in route_caps: {method}")
            if not path.startswith("/"):
                raise ValueError(f"invalid route path in route_caps: {path}")
            out[f"{method}:{path}"] = cap
        return out


class RevokeSessionReq(BaseModel):
    session_id: str

class MarkReadReq(BaseModel):
    alert_ids: List[str] = Field(default_factory=list)

class AlertEmailPrefsReq(BaseModel):
    email_event_types: List[str] = Field(default_factory=list)

class AlertSmsPrefsReq(BaseModel):
    sms_event_types: List[str] = Field(default_factory=list)

class AlertToastPrefsReq(BaseModel):
    toast_event_types: List[str] = Field(default_factory=list)

class AlertPushPrefsReq(BaseModel):
    # D2: push-pref toggle. push_event_types = explicit opt-IN list; push_opt_out_event_types =
    # opt-OUT of the default-ON transactional events. Both optional so a partial update keeps the
    # unspecified list unchanged (None -> set_alert_prefs preserves current).
    push_event_types: Optional[List[str]] = None
    push_opt_out_event_types: Optional[List[str]] = None

class AlertWebhookPrefsReq(BaseModel):
    webhook_urls: List[str] = Field(default_factory=list)
    webhook_event_types: List[str] = Field(default_factory=list)

class AlertEmailBeginReq(BaseModel):
    email: str

class AlertEmailConfirmReq(BaseModel):
    challenge_id: str
    code: str

class TokenRefreshReq(BaseModel):
    refresh_token: str

class TokenRefreshResp(BaseModel):
    access_token: str
    id_token: Optional[str] = None
    expires_in: Optional[int] = None

class DeviceTrustOut(BaseModel):
    device_id: str
    user_agent: str
    first_seen_at: int
    last_seen_at: int
    last_ip: str
    trusted: bool

class DeviceTrustListOut(BaseModel):
    devices: List[DeviceTrustOut] = Field(default_factory=list)


class PurchaseMoneyIn(BaseModel):
    amount: float = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=10)


class CarrierEventOut(BaseModel):
    timestamp: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None


class PurchaseShippingIn(BaseModel):
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    tracking_url: Optional[str] = None
    status: Optional[str] = None
    shipped_at: Optional[int] = None
    delivered_at: Optional[int] = None
    estimated_delivery: Optional[str] = None
    carrier_events: Optional[List[Dict[str, Any]]] = None
    last_carrier_check: Optional[int] = None
    address: Optional[Dict[str, Any]] = None


class PurchaseTransactionIn(BaseModel):
    merchant_id: Optional[str] = None
    external_ref: Optional[str] = None
    money: PurchaseMoneyIn
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class PurchaseTransactionSummary(BaseModel):
    txn_id: str
    created_at: int
    updated_at: int
    status: str
    amount: float
    currency: str
    merchant_id: Optional[str] = None
    external_ref: Optional[str] = None
    description: Optional[str] = None


class PurchaseTransactionInfo(PurchaseTransactionSummary):
    buyer_id: str
    buyer_profile: Optional[ProfileBase] = None
    shipping: Optional[PurchaseShippingIn] = None
    cancel: Optional[Dict[str, Any]] = None
    completed_at: Optional[int] = None
    reverted_at: Optional[int] = None
    version: int
    metadata: Optional[Dict[str, Any]] = None
    receipt_path: Optional[str] = None
    receipt_generated_at: Optional[int] = None
    # ECOMX-42 (B2): the physical fulfilment state from the order-lifecycle header
    # (distinct from `status`, which is the money state PENDING/COMPLETED).
    order_status: Optional[str] = None
    fulfillment_status: Optional[str] = None


class PurchaseTransactionCreated(BaseModel):
    txn_id: str
    status: str
    created_at: int


class PurchaseTransactionStatusReq(BaseModel):
    note: Optional[str] = None
    reason: Optional[str] = None
    processor_ref: Optional[str] = None


class PurchaseShippingReq(BaseModel):
    shipping: PurchaseShippingIn


class PurchaseCancelReq(BaseModel):
    reason: Optional[str] = None


class PurchaseCancelRespondReq(BaseModel):
    decision: str
    note: Optional[str] = None


class ReceiptLinkOut(BaseModel):
    txn_id: str
    receipt_path: str
    receipt_url: str
    generated_at: int


class CatalogPageOut(BaseModel):
    next_token: Optional[str] = None


class CatalogCategoryCreateIn(BaseModel):
    category_id: Optional[str] = None
    name: str
    description: Optional[str] = None


class CatalogCategoryOut(BaseModel):
    category_id: str
    name: str
    description: Optional[str] = None
    creator_id: Optional[str] = None
    created_at: str


class CatalogCategoryListOut(CatalogPageOut):
    items: List[CatalogCategoryOut]


class CatalogItemCreateIn(BaseModel):
    item_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    price_cents: int = Field(ge=0, le=10_000_000_00)
    currency: str = "USD"
    image_urls: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    stock_count: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    low_stock_threshold: Optional[int] = Field(default=None, ge=0, le=10_000_000)


class CatalogItemPatchIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price_cents: Optional[int] = Field(default=None, ge=0, le=10_000_000_00)
    currency: Optional[str] = None
    image_urls: Optional[List[str]] = None
    attributes: Optional[Dict[str, Any]] = None
    stock_count: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    low_stock_threshold: Optional[int] = Field(default=None, ge=0, le=10_000_000)


class CatalogStockAdjustIn(BaseModel):
    delta: Optional[int] = Field(default=None, ge=-1_000_000, le=1_000_000)
    absolute: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    reason: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def exactly_one_mode(self):
        if (self.delta is None) == (self.absolute is None):
            raise ValueError("Provide exactly one of 'delta' or 'absolute'")
        return self


class CatalogStockOut(BaseModel):
    item_id: str
    stock_count: Optional[int] = None
    stock_status: str = "unlimited"
    low_stock_threshold: int = 5
    stock_updated_at: Optional[str] = None


# ── OFBiz commerce/ERP Phase 1 — inventory & soft reservations (ADR-001 / OFB-003/004) ──


class InventoryRecordOut(BaseModel):
    sku: str
    location_id: str = "warehouse"
    on_hand: int = 0
    reserved: int = 0
    available: int = 0
    reorder_point: int = 0
    status: str = "in_stock"  # in_stock | low_stock | out_of_stock
    updated_at: int = 0


class InventorySetOnHandIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    on_hand: int = Field(ge=0, le=100_000_000)
    location_id: str = Field(default="warehouse", min_length=1, max_length=128)
    reorder_point: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    reason: Optional[str] = Field(default=None, max_length=200)


class InventoryAdjustIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    delta: int = Field(ge=-100_000_000, le=100_000_000)
    location_id: str = Field(default="warehouse", min_length=1, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=200)


class InventoryReserveIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    quantity: int = Field(ge=1, le=10_000_000)
    location_id: str = Field(default="warehouse", min_length=1, max_length=128)
    cart_id: Optional[str] = Field(default=None, max_length=256)
    ttl_seconds: Optional[int] = Field(default=None, ge=10, le=86_400)


class ReservationOut(BaseModel):
    reservation_id: str
    sku: str
    location_id: str = "warehouse"
    quantity: int
    status: str  # active | committed | released | expired
    cart_id: Optional[str] = None
    user_sub: Optional[str] = None
    created_at: int = 0
    expires_at: int = 0


# ── Returns / RMA (ADR-001 OFB-008..010) ────────────────────────────────────


class ReturnLineIn(BaseModel):
    item_id: str = Field(min_length=1, max_length=64)
    quantity: int = Field(ge=1, le=10_000_000)


class ReturnRequestIn(BaseModel):
    order_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=500)
    lines: List[ReturnLineIn] = Field(min_length=1)


class ReturnDecisionIn(BaseModel):
    note: Optional[str] = Field(default=None, max_length=500)


class ReturnLineOut(BaseModel):
    item_id: str
    sku: Optional[str] = None
    quantity: int = 0
    amount_cents: int = 0


class ReturnOut(BaseModel):
    return_id: str
    order_id: str
    user_sub: str
    status: str  # requested | approved | rejected | received | refunded | closed
    reason: Optional[str] = None
    currency: str = "usd"
    refund_amount_cents: int = 0
    refund_ledger_sk: Optional[str] = None
    provider: Optional[str] = None
    lines: List[ReturnLineOut] = Field(default_factory=list)
    created_at: int = 0
    updated_at: int = 0
    decided_by: Optional[str] = None
    decision_note: Optional[str] = None


class CatalogItemOut(BaseModel):
    category_id: str
    item_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str
    image_urls: List[str]
    attributes: Dict[str, Any]
    creator_id: Optional[str] = None
    created_at: str
    updated_at: str
    stock_count: Optional[int] = None
    stock_status: str = "unlimited"
    low_stock_threshold: int = 5
    stock_updated_at: Optional[str] = None
    position: Optional[int] = None
    # ECM-003: integration layer enrichment (default None = flag off / not enriched)
    variants: Optional[List["StorefrontVariantOut"]] = None
    availability: Optional["StorefrontAvailabilityOut"] = None


class CatalogItemListOut(CatalogPageOut):
    items: List[CatalogItemOut]


class CatalogReorderReq(BaseModel):
    """Request body for catalog item reorder."""
    item_ids: List[str] = Field(..., min_length=1, max_length=100)


class CatalogReviewCreateIn(BaseModel):
    review_id: Optional[str] = None
    rating: int = Field(ge=1, le=5)
    title: Optional[str] = None
    body: Optional[str] = None
    # ECOMX-53: reviewer display name is caller-supplied ONLY as a label; the
    # authoritative author identity is forced from the session user_sub server
    # side (see add_review). A spoofed ``reviewer`` can no longer impersonate.
    reviewer: Optional[str] = None


class CatalogReviewSellerResponseIn(BaseModel):
    # ECOMX-53 (E10): a seller/owner public reply to a review.
    response: str = Field(min_length=1, max_length=2000)


class CatalogReviewOut(BaseModel):
    item_id: str
    review_id: str
    rating: int
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: str
    # ECOMX-53: verified-purchase badge + optional seller response.
    verified_purchase: bool = False
    seller_response: Optional[str] = None
    seller_response_at: Optional[str] = None


class CatalogReviewListOut(CatalogPageOut):
    items: List[CatalogReviewOut]


class TotpDeviceBeginReq(BaseModel):
    label: Optional[str] = None

class TotpDeviceConfirmReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    device_id: str
    totp_code: str = Field(validation_alias=AliasChoices("totp_code", "code"))
    totp_code2: str = Field(validation_alias=AliasChoices("totp_code2", "code2"))

class TotpDeviceRemoveReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    totp_code: str = Field(validation_alias=AliasChoices("totp_code", "code"))

class SmsDeviceBeginReq(BaseModel):
    phone_e164: str
    label: Optional[str] = None

class SmsDeviceConfirmReq(BaseModel):
    challenge_id: str
    code: str

class SmsDeviceRemoveConfirmReq(BaseModel):
    challenge_id: str
    code: str

class EmailDeviceBeginReq(BaseModel):
    email: str
    label: Optional[str] = None

class EmailDeviceConfirmReq(BaseModel):
    challenge_id: str
    code: str

class EmailDeviceRemoveConfirmReq(BaseModel):
    challenge_id: str
    code: str

class AlertSmsBeginReq(BaseModel):
    phone: str

class AlertSmsConfirmReq(BaseModel):
    challenge_id: str
    code: str

class AlertSmsRemoveReq(BaseModel):
    phone: str

class AlertEmailRemoveReq(BaseModel):
    email: str

class PushRegisterReq(BaseModel):
    token: str
    platform: str

class PushRevokeReq(BaseModel):
    device_id: str

class PushSubscribeReq(BaseModel):
    endpoint: str
    keys_p256dh: str
    keys_auth: str

class PushUnsubscribeReq(BaseModel):
    endpoint: str


class PaymentMethodOut(BaseModel):
    payment_token_id: str
    label: Optional[str] = None
    priority: int
    provider: Optional[str] = None
    provider_method_id: Optional[str] = None
    is_default: bool = False


class SavePaymentTokenIn(BaseModel):
    payment_token_id: str
    label: Optional[str] = None
    make_default: bool = True


class SetPriorityIn(BaseModel):
    payment_token_id: str
    priority: int = Field(ge=0, le=100000)


class SetDefaultIn(BaseModel):
    payment_token_id: str


class SetAutopayIn(BaseModel):
    enabled: bool






class ApiPackageSkuCreateIn(BaseModel):
    sku: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    amount_cents: conint(ge=0, le=100000000)
    currency: str = Field(default="USD", min_length=3, max_length=8)
    billing_model: Literal["credit_pack", "subscription", "one_time"] = "credit_pack"
    effective_at: str
    credit_grant: Optional[Dict[str, Any]] = None
    limit_overrides: Optional[Dict[str, Any]] = None
    access_template: Optional[Dict[str, Any]] = None


class ApiPackageSkuOut(BaseModel):
    sku: str
    product_type: Literal["api_package"] = "api_package"
    display_name: str
    amount_cents: int
    currency: str
    billing_model: Literal["credit_pack", "subscription", "one_time"]
    effective_at: str
    credit_grant: Dict[str, Any] = Field(default_factory=dict)
    limit_overrides: Dict[str, Any] = Field(default_factory=dict)
    access_template: Dict[str, Any] = Field(default_factory=dict)

class FileBundleSkuCreateIn(BaseModel):
    sku: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=256)
    amount_cents: conint(ge=0, le=100000000)
    currency: str = Field(default="USD", min_length=3, max_length=8)
    date_start: str
    date_end: str
    access_mode: Literal["purchase", "rental"] = "purchase"
    rental_duration_hours: Optional[conint(ge=1, le=24 * 365)] = None


class FileBundleSkuOut(BaseModel):
    sku: str
    display_name: str
    amount_cents: int
    currency: str
    product_type: Literal["file_bundle"] = "file_bundle"
    billing_model: Literal["one_time", "rental"]
    date_start: str
    date_end: str
    access_mode: Literal["purchase", "rental"]
    rental_duration_hours: Optional[int] = None
    created_at: str
    created_by: str


class FileBundleCheckoutSessionIn(BaseModel):
    sku: str = Field(min_length=1, max_length=128)
    date_start: str
    date_end: str
    access_mode: Literal["purchase", "rental"]


class FileBundleCheckoutSessionOut(BaseModel):
    checkout_session_id: str
    order_id: str
    status: str
    sku: str
    amount_cents: int
    currency: str
    access_mode: Literal["purchase", "rental"]



class UnifiedCheckoutSessionIn(BaseModel):
    source: Literal["cart", "direct", "subscription_action"]
    cart_id: Optional[str] = None
    sku: Optional[str] = None
    product_type: Optional[Literal["file_bundle", "api_package", "internal_api_package"]] = None
    billing_model: Optional[Literal["one_time", "rental", "subscription", "credit_pack"]] = None
    quantity: conint(ge=1, le=1000) = 1
    scope: Dict[str, Any] = Field(default_factory=dict)
    pricing_ref: Dict[str, Any] = Field(default_factory=dict)
    subscription_plan: Optional[Dict[str, Any]] = None


class UnifiedCheckoutSessionOut(BaseModel):
    order_id: str
    checkout_session_id: str
    source: Literal["cart", "direct", "subscription_action"]
    line_items: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "pending_payment"

class ShoppingCartSummary(BaseModel):
    cart_id: str
    status: str
    created_at: str
    purchased_at: Optional[str] = None
    purchased_total_cents: Optional[int] = None
    currency: str = "USD"
    # SHOP-003: Abandonment tracking
    last_activity_at: Optional[int] = 0
    abandoned_at: Optional[int] = 0
    reminder_count: Optional[int] = 0


class CartAbandonmentSweepIn(BaseModel):
    # SHOP-003: Manual sweep trigger. `now` is injectable for deterministic E2E.
    threshold_hours: Optional[conint(ge=0, le=8760)] = None
    now: Optional[conint(ge=0)] = None
    expire: bool = False
    expire_hours: Optional[conint(ge=0, le=87600)] = None


class CartAbandonmentSweepOut(BaseModel):
    scanned: int
    reminded: int
    expired: int = 0
    threshold_hours: int


class ShoppingCartItemIn(BaseModel):
    sku: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    quantity: conint(ge=1, le=1000) = 1
    unit_price_cents: conint(ge=0, le=100000000)
    image_url: Optional[str] = None
    category_id: Optional[str] = None
    item_id: Optional[str] = None
    product_type: Optional[Literal["file_bundle", "api_package", "internal_api_package"]] = None
    scope: Optional[Dict[str, Any]] = None
    access_mode: Optional[Literal["purchase", "rental"]] = None
    rental_metadata: Optional[Dict[str, Any]] = None
    entitlement_template_metadata: Optional[Dict[str, Any]] = None


class CatalogCartItemIn(BaseModel):
    category_id: str = Field(min_length=1, max_length=128)
    item_id: str = Field(min_length=1, max_length=128)
    quantity: conint(ge=1, le=1000) = 1


class ShoppingCartItemOut(BaseModel):
    sku: str
    name: str
    quantity: int
    unit_price_cents: int
    line_total_cents: int
    updated_at: str
    image_url: Optional[str] = None
    category_id: Optional[str] = None
    item_id: Optional[str] = None
    product_type: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    access_mode: Optional[str] = None
    rental_metadata: Optional[Dict[str, Any]] = None
    entitlement_template_metadata: Optional[Dict[str, Any]] = None


class ShoppingCartItemsOut(BaseModel):
    cart_id: str
    items: List[ShoppingCartItemOut]


class ShoppingCartUpdateQtyIn(BaseModel):
    quantity: conint(ge=0, le=1000)


class ShoppingCartTotalOut(BaseModel):
    cart_id: str
    total_cents: int
    currency: str = "USD"
    # ECM-003: pricing rules breakdown (None = flag off or rules not applicable)
    pricing_breakdown: Optional["CartPricingBreakdownOut"] = None


class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None
    promo_code_id: Optional[str] = None
    # ECOMX-40 (B3): shipping address selected in the checkout address step; the
    # order's ship_to + shipping/tax computation key off it. Digital-only carts
    # may omit it (no shipping/tax collected).
    address_id: Optional[str] = None
    # ECOMX-40: chosen shipping method code (from the rate estimate); optional.
    shipping_method: Optional[str] = None
    # ADV-403: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None
    # LIVECOM L3: in-stream purchase attribution (broadcast session + host).
    broadcast_session_id: Optional[str] = None
    host_id: Optional[str] = None


class ShoppingCartPurchaseOut(BaseModel):
    cart_id: str
    order_id: str
    purchased_at: str
    purchased_total_cents: int
    currency: str = "USD"
    buyer: Optional[ShoppingCartBuyer] = None
    purchase_txn_id: Optional[str] = None
    original_total_cents: Optional[int] = None
    discount_cents: Optional[int] = None
    promo_code_id: Optional[str] = None
    promo_discount_type: Optional[str] = None
    # ECOMX-40 (B3): shipping + tax breakdown so the app can show the true total.
    merchandise_cents: Optional[int] = None
    shipping_cents: Optional[int] = None
    tax_cents: Optional[int] = None


class WorkingHoursWindow(BaseModel):
    start: str
    end: str


class CalendarCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    timezone: str = Field(default="UTC", max_length=64)
    conflict_detection: bool = False
    working_hours: Dict[str, List[WorkingHoursWindow]] | None = None
    buffer_before_minutes: int = 0
    buffer_after_minutes: int = 0


class CalendarOut(BaseModel):
    calendar_id: str
    name: str
    timezone: str
    conflict_detection: bool = False
    working_hours: Dict[str, List[WorkingHoursWindow]] | None = None
    buffer_before_minutes: int = 0
    buffer_after_minutes: int = 0
    owner_user_id: str
    created_at_utc: str


class CalendarShareIn(BaseModel):
    user_sub: str = Field(min_length=1, max_length=200)
    permission: Literal["read", "write"]


class CalendarShareOut(BaseModel):
    calendar_id: str
    user_sub: str
    permission: Literal["read", "write"]
    created_at_utc: str


class CalendarAccessOut(BaseModel):
    calendar_id: str
    name: str
    timezone: str
    owner_user_id: str
    permission: Literal["owner", "read", "write"]


class GoogleCalendarConnectStartOut(BaseModel):
    provider: Literal["google"] = "google"
    authorization_url: str
    state: str
    nonce: str
    expires_at_utc: str


class GoogleCalendarConnectCallbackOut(BaseModel):
    provider: Literal["google"] = "google"
    connection_id: str
    account_email: str
    linked: bool
    updated_at_utc: str


class GoogleCalendarDisconnectOut(BaseModel):
    provider: Literal["google"] = "google"
    connection_id: str
    account_email: str
    active: bool
    revoked: bool
    revoke_status: str
    disconnected_at_utc: str


class GoogleCalendarIntegrationStatusOut(BaseModel):
    provider: Literal["google"] = "google"
    sync_enabled: bool
    writeback_enabled: bool
    rollout_mode: Literal["all", "cohort", "off"]
    rollout_percent: int = Field(ge=0, le=100)
    in_rollout_cohort: bool
    connection_active: bool = False
    sync_health: str = "unknown"
    last_sync_status: str = "never_synced"
    last_sync_at_utc: str = ""
    reauth_required: bool = False


class GoogleCalendarProviderCalendarOut(BaseModel):
    google_calendar_id: str
    summary: str = ""
    access_role: str | None = None
    primary: bool = False
    mapped_internal_calendar_id: str | None = None


class GoogleCalendarProviderCalendarsOut(BaseModel):
    calendars: List[GoogleCalendarProviderCalendarOut]


class GoogleCalendarMappingCreateIn(BaseModel):
    internal_calendar_id: str
    google_calendar_id: str


class GoogleCalendarMappingOut(BaseModel):
    mapping_id: str
    provider: Literal["google"] = "google"
    user_sub: str
    internal_calendar_id: str
    google_calendar_id: str
    active: bool
    created_at_utc: str
    updated_at_utc: str
    unmapped_at_utc: str


class GoogleCalendarSyncRunOut(BaseModel):
    accepted: bool
    mode: Literal["incremental", "full"] = "incremental"
    rate_limited: bool = False
    metrics: Dict[str, Any] = Field(default_factory=dict)


class CalendarUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    timezone: str | None = Field(default=None, max_length=64)
    conflict_detection: bool | None = None
    working_hours: Dict[str, List[WorkingHoursWindow]] | None = None
    buffer_before_minutes: int | None = None
    buffer_after_minutes: int | None = None


class AppleCalendarConnectIn(BaseModel):
    username: str = Field(min_length=3, max_length=320)
    app_specific_password: str = Field(min_length=1, max_length=256)


class AppleCalendarConnectionOut(BaseModel):
    connection_id: str
    provider: str
    user_sub: str
    status: str
    credential_ref: str
    credential_validation_status: str
    credential_last_validated_at: str | None = None
    credential_rotated_at: str | None = None
    created_at: str
    updated_at: str
    has_secret: bool


class AppleCalendarStatusOut(BaseModel):
    provider: str = "apple_caldav"
    connection_state: Literal["connected", "degraded", "disconnected"]
    is_connected: bool
    connection_id: str | None = None
    credential_validation_status: str | None = None
    last_successful_sync_at: str | None = None
    last_error_snapshot: Dict[str, Any] | None = None
    selected_calendar_count: int = 0
    conflict_count: int = 0
    recent_conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    updated_at: str | None = None


class AppleCalendarSelectionIn(BaseModel):
    external_calendar_id: str = Field(min_length=1, max_length=512)
    sync_enabled: bool = True
    sync_direction: Literal["read_only", "two_way"] = "two_way"
    timezone: str | None = Field(default=None, max_length=64)


class AppleCalendarSelectionUpdateIn(BaseModel):
    calendars: List[AppleCalendarSelectionIn] = Field(default_factory=list)


class AppleCalendarExternalCalendarOut(BaseModel):
    external_calendar_id: str
    calendar_url: str
    display_name: str
    sync_enabled: bool = False
    sync_direction: Literal["read_only", "two_way"] = "two_way"
    timezone: str | None = None


class AppleCalendarInitialImportIn(BaseModel):
    external_calendar_ids: List[str] = Field(default_factory=list)
    lookback_days: int | None = Field(default=None, ge=0, le=3650)
    lookahead_days: int | None = Field(default=None, ge=0, le=3650)


class AppleCalendarImportRunOut(BaseModel):
    run_id: str
    connection_id: str
    external_calendar_id: str
    run_type: str
    status: str
    started_at: str
    historical_window_start: str
    historical_window_end: str


class AppleCalendarSyncNowOut(BaseModel):
    triggered_calendar_count: int
    success_count: int
    failure_count: int
    results: List[Dict[str, Any]] = Field(default_factory=list)


class AdminAppleCalendarTroubleshootOut(BaseModel):
    user_sub: str
    connection: Dict[str, Any] | None = None
    status: Dict[str, Any] | None = None
    selected_calendars: List[Dict[str, Any]] = Field(default_factory=list)
    run_history: List[Dict[str, Any]] = Field(default_factory=list)
    dead_letters: List[Dict[str, Any]] = Field(default_factory=list)
    recent_conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class AdminAppleCalendarRelinkIn(BaseModel):
    user_sub: str = Field(min_length=1, max_length=128)
    external_calendar_id: str = Field(min_length=1, max_length=512)
    remote_uid: str = Field(min_length=1, max_length=512)
    internal_event_id: str = Field(min_length=1, max_length=512)
    resource_url: str | None = Field(default=None, max_length=2048)
    etag: str | None = Field(default=None, max_length=512)


class AdminAppleCalendarRelinkOut(BaseModel):
    updated_existing: bool
    link: Dict[str, Any]


class AdminAppleCalendarRepairSyncIn(BaseModel):
    user_sub: str = Field(min_length=1, max_length=128)


class EventOccurrenceOverrideIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    timezone: str | None = Field(default=None, max_length=64)
    start_utc: str | None = None
    end_utc: str | None = None
    all_day: bool | None = None
    all_day_date: str | None = None
    status: str | None = None
    category: str | None = None


class EventCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    timezone: str | None = Field(default=None, max_length=64)
    start_utc: str | None = None
    end_utc: str | None = None
    all_day: bool = False
    all_day_date: str | None = None
    attendees: List[str] = Field(default_factory=list)
    booking_enabled: bool = False
    approval_required: bool = False
    status: str = "busy"
    category: str | None = None
    recurrence_rule: RecurrenceRule | None = None
    exdates_utc: List[str] | None = None
    recurrence_overrides: Dict[str, EventOccurrenceOverrideIn] | None = None


class EventOut(BaseModel):
    event_id: str
    calendar_id: str
    name: str
    description: str
    timezone: str
    start_utc: str | None = None
    end_utc: str | None = None
    all_day: bool
    all_day_date: str | None = None
    attendees: List[str]
    booking_enabled: bool
    approval_required: bool
    status: str
    category: str | None = None
    recurrence_rule: RecurrenceRule | None = None
    exdates_utc: List[str] | None = None
    recurrence_overrides: Dict[str, EventOccurrenceOverrideIn] | None = None
    created_at_utc: str
    sync_state: str | None = None
    sync_conflict_reason: str | None = None
    sync_conflict_detected_at_utc: str | None = None


class EventUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    timezone: str | None = Field(default=None, max_length=64)
    start_utc: str | None = None
    end_utc: str | None = None
    all_day: bool | None = None
    all_day_date: str | None = None
    attendees: List[str] | None = None
    booking_enabled: bool | None = None
    approval_required: bool | None = None
    status: str | None = None
    category: str | None = None
    recurrence_rule: RecurrenceRule | None = None
    exdates_utc: List[str] | None = None
    recurrence_overrides: Dict[str, EventOccurrenceOverrideIn] | None = None


class EventConflictPreviewIn(EventCreateIn):
    event_id: str | None = None


class EventConflictPreviewOut(BaseModel):
    requested_start_utc: str
    requested_end_utc: str
    timezone: str
    conflicts: List[EventOut]


class EventSuggestionsIn(BaseModel):
    start_utc: str
    end_utc: str
    duration_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    limit: Optional[int] = Field(default=5, ge=1, le=50)
    window_days: Optional[int] = Field(default=7, ge=1, le=30)


class OpeningsOut(BaseModel):
    start_utc: str
    end_utc: str


class EventsPageOut(BaseModel):
    events: List[EventOut]
    next_cursor: str | None = None

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def __getitem__(self, index: int) -> EventOut:
        return self.events[index]


class RecurrenceRule(BaseModel):
    freq: Literal["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]
    interval: int = Field(default=1, ge=1)
    until_utc: Optional[str] = None
    count: Optional[int] = Field(default=None, ge=1)
    byday: Optional[List[Literal["MO", "TU", "WE", "TH", "FR", "SA", "SU"]]] = None
    bymonthday: Optional[List[int]] = None
    bysetpos: Optional[List[int]] = None


class BookingLinkCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    duration_minutes: conint(ge=5, le=1440)
    timezone: str | None = Field(default=None, max_length=64)


class BookingLinkOut(BaseModel):
    link_id: str
    calendar_id: str
    name: str
    duration_minutes: int
    timezone: str
    created_at_utc: str
    public_url: str


class BookingRequestIn(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    start_utc: str
    end_utc: str
    timezone: str | None = Field(default=None, max_length=64)
    notify: bool = False


class TeamAvailabilityIn(BaseModel):
    calendar_ids: List[str] = Field(min_length=1)
    start_utc: str
    end_utc: str


class MailingAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None


class ShoppingCartBuyer(BaseModel):
    display_name: Optional[str] = None
    displayed_email: Optional[str] = None
    displayed_telephone_number: Optional[str] = None
    mailing_address: Optional[MailingAddress] = None


class AddressBase(BaseModel):
    name: Optional[str] = None
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    label: Optional[str] = None
    notes: Optional[str] = None


class AddressIn(AddressBase):
    pass


class AddressOut(AddressBase):
    address_id: str
    is_primary_mailing: bool = False
    created_at: int
    updated_at: int


class AddressSearchReq(BaseModel):
    query: str


class AddressSearchResp(BaseModel):
    query: str
    matches: List[AddressOut]


class AddressPrimaryReq(BaseModel):
    address_id: str


class AddressValidateReq(BaseModel):
    line1: str = ""
    line2: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = "US"


class ValidatedAddressOut(BaseModel):
    line1: str
    line2: str = ""
    city: str
    state: str
    postal_code: str
    country: str


class AddressValidateResp(BaseModel):
    valid: bool
    dpv_match_code: str = ""  # "Y", "S", "D", "A"
    candidates: List[ValidatedAddressOut] = []


class LanguageIn(BaseModel):
    name: str
    level: str


class ProfileBase(BaseModel):
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    last_name: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    birthday: Optional[str] = None
    gender: Optional[str] = None
    location: Optional[str] = None
    displayed_email: Optional[str] = None
    displayed_telephone_number: Optional[str] = None
    mailing_address: Optional[MailingAddress] = None
    languages: Optional[List[LanguageIn]] = None
    profile_photo_url: Optional[str] = None
    cover_photo_url: Optional[str] = None
    locale: Optional[str] = None


class ProfilePatchReq(ProfileBase):
    pass


class ProfilePutReq(ProfileBase):
    pass


class PreferencesPatchReq(BaseModel):
    """Partial update for user UI preferences.

    All fields are optional -- only provided fields are merged into the
    existing preferences map.
    """
    theme: Optional[Literal["system", "light", "dark"]] = None
    sidebar_collapsed: Optional[bool] = None
    accent_color: Optional[Literal["blue", "purple", "green", "orange", "pink", "red", "teal", "custom"]] = None
    custom_accent_hex: Optional[str] = Field(None, max_length=7)
    font_size: Optional[Literal["small", "default", "large", "xlarge"]] = None
    density: Optional[Literal["compact", "comfortable", "spacious"]] = None
    high_contrast: Optional[bool] = None

    @field_validator("custom_accent_hex")
    @classmethod
    def validate_custom_accent_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        raw = v.strip().lstrip("#")
        if not re.match(r"^[0-9A-Fa-f]{6}$", raw):
            raise ValueError("custom_accent_hex must be a 6-digit hex color (e.g. #FF5722)")
        return f"#{raw.upper()}"


class PayBalanceIn(BaseModel):
    amount_cents: Optional[int] = Field(default=None, ge=1)
    idempotency_key: Optional[str] = None


class OneTimeChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    payment_token_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    reason: str = "one_time_charge"


class SubscribeMonthlyIn(BaseModel):
    plan_id: str = "monthly"
    monthly_price_cents: Optional[int] = Field(default=None, ge=1)
    payment_token_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class AddChargeIn(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"


class RefundIn(BaseModel):
    transaction_id: str
    amount_cents: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = None


class BillingCheckoutReq(BaseModel):
    amount_cents: int
    currency: Optional[str] = None
    description: Optional[str] = None

class StripePaymentMethodOut(BaseModel):
    payment_method_id: str
    method_type: str
    label: Optional[str] = None
    brand: Optional[str] = None
    last4: Optional[str] = None
    exp_month: Optional[int] = None
    exp_year: Optional[int] = None
    priority: int
    provider: Optional[str] = None
    provider_method_id: Optional[str] = None
    is_default: bool = False

class SetPriorityReq(BaseModel):
    payment_method_id: str
    priority: int = Field(ge=0, le=100000)

class SetDefaultReq(BaseModel):
    payment_method_id: str

class SetAutopayReq(BaseModel):
    enabled: bool

class PayBalanceReq(BaseModel):
    amount_cents: Optional[int] = Field(default=None, ge=1)
    idempotency_key: Optional[str] = None

class StripeChargeReq(BaseModel):
    amount_cents: int = Field(ge=1)
    payment_method_id: Optional[str] = None
    description: Optional[str] = None
    idempotency_key: Optional[str] = None


class StripeRefundReq(BaseModel):
    payment_intent_id: str
    amount_cents: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = None


# ── Refund Requests (BILLING-001) ────────────────────────────────────────────

class RefundRequestIn(BaseModel):
    transaction_entry_id: str = Field(min_length=1)
    reason: str = Field(min_length=10, max_length=2000)
    amount_cents: Optional[int] = Field(default=None, ge=1)


class RefundRequestOut(BaseModel):
    refund_request_id: str
    status: str
    amount_cents: int
    currency: str = "USD"
    reason: str
    transaction_type: Optional[str] = None
    transaction_entry_id: Optional[str] = None
    created_at: int
    admin_notes: Optional[str] = None
    completed_at: Optional[int] = None
    requester_user_id: Optional[str] = None


class AdminRefundApproveIn(BaseModel):
    notes: Optional[str] = None
    amount_cents: Optional[int] = Field(default=None, ge=1)


class AdminRefundDenyIn(BaseModel):
    notes: str = Field(min_length=1, max_length=2000)


# ── Billing Disputes / Chargebacks (BILLING-001) ─────────────────────────────

class DisputeFileIn(BaseModel):
    """Customer-initiated dispute (e.g. a chargeback claim) for a transaction.

    DISP-010: ``reason`` is now the canonical enum
    (not_received|not_as_described|unauthorized|duplicate|quality); ``charge_type``
    + ``charge_ref`` (or ``transaction_entry_id`` for auto-detection) locate the
    underlying charge for the reversal-rail dispatcher; ``reason_detail`` carries
    the free-text the old ``reason`` field used to.
    """
    transaction_entry_id: Optional[str] = Field(default=None, max_length=200)
    amount_cents: int = Field(ge=1)
    currency: str = "USD"
    # accept the enum OR a legacy free-text reason (>=1 char); gating happens in
    # dispute_lifecycle.validate_reason once the charge_type is known.
    reason: str = Field(min_length=1, max_length=2000)
    reason_detail: Optional[str] = Field(default=None, max_length=2000)
    charge_type: Optional[str] = Field(default=None, max_length=40)
    charge_ref: Optional[str] = Field(default=None, max_length=200)
    recipient_id: Optional[str] = Field(default=None, max_length=200)
    provider: str = Field(default="manual", max_length=40)


class DisputeOut(BaseModel):
    dispute_id: str
    provider: str
    provider_dispute_id: Optional[str] = None
    user_id: Optional[str] = None
    amount_cents: int
    currency: str = "USD"
    reason: str
    status: str
    evidence_submitted: bool = False
    evidence_text: Optional[str] = None
    resolution: Optional[str] = None
    admin_notes: Optional[str] = None
    transaction_entry_id: Optional[str] = None
    created_at: int
    updated_at: Optional[int] = None
    deadline_at: Optional[int] = None


class DisputeRespondIn(BaseModel):
    evidence_text: str = Field(min_length=1, max_length=5000)
    evidence_files: Optional[List[str]] = None


class DisputeResolveIn(BaseModel):
    # DISP-013: user-track outcomes drive the reversal dispatcher; legacy
    # won|lost|accepted still accepted + mapped for the old admin path.
    resolution: str = Field(pattern="^(refunded|partial|denied|won|lost|accepted)$")
    override_amount_cents: Optional[int] = Field(default=None, ge=1)
    notes: Optional[str] = Field(default=None, max_length=2000)
    # DISP-022: a money-moving resolve above the dual-approval threshold requires
    # a second, distinct PAYMENT_DISPUTES admin id (validated server-side; a
    # fabricated/self/non-scoped id is rejected).
    second_approver_admin_user_id: Optional[str] = Field(default=None, max_length=200)


class CreatorDisputeRespondIn(BaseModel):
    """DISP-021: the creator/seller rebuts a dispute within the response window."""
    response_text: str = Field(min_length=1, max_length=5000)
    evidence_files: Optional[List[str]] = None


# ---- FIN-017: Bulk Payout & Refund Tools ----

class BulkEligibleItem(BaseModel):
    ref_id: str
    amount_cents: int
    recipient: str
    currency: str = "usd"
    status: str = "pending"
    created_at: int = 0


class BulkPreviewIn(BaseModel):
    kind: str
    ref_ids: List[str] = Field(default_factory=list)


class BulkExecuteIn(BaseModel):
    kind: Optional[str] = None
    ref_ids: Optional[List[str]] = None
    batch_id: Optional[str] = None


class BulkBatchItem(BaseModel):
    ref_id: str
    amount_cents: int
    recipient: str = ""
    status: str
    reason: str = ""


class BulkBatchOut(BaseModel):
    batch_id: str
    created_at: int
    created_by: Optional[str] = None
    kind: str
    status: str
    item_count: int
    success_count: int = 0
    failure_count: int = 0
    total_cents: int
    items: List[BulkBatchItem] = Field(default_factory=list)
    # GAP-0212: 5-minute reversal window. ``undo_expires_at`` is the Unix ts
    # until which an undo is valid (set only on completed batches);
    # ``undo_performed_at`` is set when an undo completes. Both nullable for
    # backward compatibility with batches that predate this field.
    undo_expires_at: Optional[int] = None
    undo_performed_at: Optional[int] = None


class VerifyMicrodepositsReq(BaseModel):
    setup_intent_id: str
    amounts: Optional[List[int]] = None
    descriptor_code: Optional[str] = None

class AddCardReq(BaseModel):
    card_number: str
    exp_month: int = Field(ge=1, le=12)
    exp_year: int = Field(ge=2000, le=2100)
    cvc: str
    cardholder_name: Optional[str] = None

class AddBankReq(BaseModel):
    # BK-C: dev/test path to add a FAKE US bank (checking/savings) account
    # directly from routing + account numbers (no Stripe.js / Financial
    # Connections). Works against stripe-mock in DEV_MODE.
    routing_number: str = Field(min_length=9, max_length=9)
    account_number: str = Field(min_length=4, max_length=17)
    account_holder_type: str = Field(default="individual", pattern="^(individual|company)$")
    account_type: str = Field(default="checking", pattern="^(checking|savings)$")
    account_holder_name: Optional[str] = Field(default=None, max_length=200)

class AddChargeReq(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"


class WalletDepositReq(BaseModel):
    amount_cents: int = Field(ge=100)  # minimum $1.00
    payment_method_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class WalletWithdrawReq(BaseModel):
    amount_cents: int = Field(ge=100)  # minimum $1.00


class PaymentIncidentEvidenceUploadReq(BaseModel):
    summary: Optional[str] = Field(default=None, max_length=2_000)
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    file_refs: List[str] = Field(default_factory=list)

    @field_validator("summary")
    @classmethod
    def _normalize_summary(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("file_refs")
    @classmethod
    def _normalize_file_refs(cls, value: List[str]) -> List[str]:
        out: List[str] = []
        for ref in value or []:
            cleaned = str(ref or "").strip()
            if cleaned:
                out.append(cleaned)
        return out


class PaymentIncidentSubmitResponseReq(BaseModel):
    response_summary: str = Field(min_length=1, max_length=4_000)
    rationale: Optional[str] = Field(default=None, max_length=4_000)
    event_type: str = Field(default="admin.submit_response", min_length=1, max_length=128)

    @field_validator("response_summary", "rationale")
    @classmethod
    def _trim_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if cleaned == "":
            return None
        return cleaned


class AccountStatusReq(BaseModel):
    reason: Optional[str] = None


class ProjectModel(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    tags: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str

    @field_validator("id", "owner", "name")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value required")
        return cleaned

    @field_validator("description")
    @classmethod
    def _strip_optional_description(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for tag in value or []:
            normalized = (tag or "").strip().lower()
            if not normalized:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        return out

    @field_validator("created_at", "updated_at")
    @classmethod
    def _validate_iso(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value


class TrackedFileModel(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    project_id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=32)
    provider_ref: str = Field(min_length=1, max_length=2048)
    display_path: str = Field(min_length=1, max_length=2048)
    status: Literal["active", "missing", "archived"] = "active"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    last_seen_at: Optional[str] = None
    archived_at: Optional[str] = None

    @field_validator("id", "project_id", "owner", "provider", "provider_ref", "display_path")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Value required")
        return cleaned

    @field_validator("provider")
    @classmethod
    def _normalize_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", normalized):
            raise ValueError("invalid provider")
        return normalized

    @field_validator("provider_ref")
    @classmethod
    def _normalize_provider_ref(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("provider_ref required")
        return cleaned

    @field_validator("created_at", "updated_at", "last_seen_at", "archived_at")
    @classmethod
    def _validate_optional_iso(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value

    @model_validator(mode="after")
    def _validate_archive_consistency(self) -> "TrackedFileModel":
        if self.status == "archived" and not self.archived_at:
            self.archived_at = datetime.now(timezone.utc).isoformat()
        if self.status != "archived":
            self.archived_at = None
        return self


class ProjectEventModel(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    project_id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)
    event_type: Literal["file_added", "file_removed", "sync_ran", "provider_error"]
    tracked_file_id: Optional[str] = Field(default=None, max_length=128)
    provider: Optional[str] = Field(default=None, max_length=32)
    provider_ref: Optional[str] = Field(default=None, max_length=2048)
    message: Optional[str] = Field(default=None, max_length=1024)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str

    @field_validator("id", "project_id", "owner", "tracked_file_id", "provider", "provider_ref", "message")
    @classmethod
    def _strip_optional(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("created_at")
    @classmethod
    def _validate_iso(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value




class MountModel(BaseModel):
    mount_id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=64)
    mount_path: str = Field(min_length=1, max_length=2048)
    provider_root_ref: str = Field(min_length=1, max_length=2048)
    mode: Literal["read_only", "read_write"] = "read_only"
    status: Literal["active", "disabled"] = "active"
    status_reason: Optional[str] = None
    reconnect_required: bool = False
    last_checked_at: Optional[str] = None
    created_at: str
    updated_at: str

    @field_validator("mount_id", "owner", "provider", "mount_path", "provider_root_ref")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value required")
        return cleaned

    @field_validator("provider")
    @classmethod
    def _normalize_provider(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("mount_path")
    @classmethod
    def _normalize_mount_path(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.startswith("/"):
            raise ValueError("mount_path must start with '/'")
        return cleaned.rstrip("/") or "/"

    @field_validator("status_reason")
    @classmethod
    def _normalize_status_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip().lower()
        return cleaned or None

    @field_validator("created_at", "updated_at", "last_checked_at")
    @classmethod
    def _validate_iso(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value

class ProviderCredentialModel(BaseModel):
    owner: str = Field(min_length=1, max_length=256)
    provider: Literal["github", "gitlab", "google_drive", "s3"]
    org: Optional[str] = Field(default=None, max_length=256)
    token_ct_b64: str = Field(min_length=1)
    scopes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str

    @field_validator("owner", "org", "token_ct_b64")
    @classmethod
    def _strip_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        return cleaned

    @field_validator("scopes")
    @classmethod
    def _normalize_scopes(cls, value: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for raw in value or []:
            normalized = (raw or "").strip().lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        return out

    @field_validator("created_at", "updated_at")
    @classmethod
    def _validate_iso(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value


class FileMountModel(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)
    provider: Literal["s3"] = "s3"
    mount_path: str = Field(min_length=1, max_length=2048)
    bucket: str = Field(min_length=3, max_length=255)
    prefix: Optional[str] = Field(default=None, max_length=2048)
    mode: Literal["read_only", "read_write"] = "read_only"
    auth_ref: str = Field(min_length=1, max_length=256)
    status: Literal["active", "degraded", "error", "disabled"] = "active"
    created_at: str
    updated_at: str
    last_check_at: Optional[str] = None
    last_error: Optional[str] = Field(default=None, max_length=1024)

    @field_validator("id", "owner", "mount_path", "bucket", "auth_ref", "prefix", "last_error")
    @classmethod
    def _strip_optional_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        return cleaned

    @field_validator("mount_path")
    @classmethod
    def _validate_mount_path(cls, value: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned.startswith("/"):
            raise ValueError("mount_path must be absolute")
        if cleaned == "/":
            raise ValueError("mount_path cannot be root")
        if "//" in cleaned or ".." in cleaned:
            raise ValueError("invalid mount_path")
        normalized = cleaned.rstrip("/") + "/"
        if not re.fullmatch(r"/(?:[^/]+/)+", normalized):
            raise ValueError("invalid mount_path")
        return normalized

    @field_validator("bucket")
    @classmethod
    def _validate_bucket(cls, value: str) -> str:
        cleaned = (value or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,253}[a-z0-9]", cleaned):
            raise ValueError("invalid bucket")
        return cleaned

    @field_validator("prefix")
    @classmethod
    def _normalize_prefix(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip().strip("/")
        if not cleaned:
            return None
        if ".." in cleaned:
            raise ValueError("invalid prefix")
        return cleaned

    @field_validator("created_at", "updated_at", "last_check_at")
    @classmethod
    def _validate_optional_iso(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return value


# ──────────────────────────────────────────────────────────────────────────────
# Internal Dev Tools (DLU-002) canonical read models
# ──────────────────────────────────────────────────────────────────────────────

class DevtoolsParseWarningOut(BaseModel):
    """Parser warning surfaced to callers without failing the whole response."""

    source: Literal["email", "sms", "billing"]
    line_number: Optional[int] = None
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=512)
    sample: Optional[str] = Field(default=None, max_length=1024)


class DevtoolsIdentityOut(BaseModel):
    """Stable deterministic identifier metadata.

    `id` should remain stable across refreshes for unchanged source logs.
    `id_strategy` documents what inputs were hashed/combined by parsers.
    """

    id: str = Field(min_length=1, max_length=128)
    id_strategy: str = Field(min_length=1, max_length=128)


class DevtoolsTimestampMixin(BaseModel):
    """Normalize API timestamps to UTC RFC3339 (`YYYY-MM-DDTHH:MM:SSZ`)."""

    @staticmethod
    def _normalize_utc_timestamp(value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class DevtoolsEmailMessageOut(DevtoolsTimestampMixin, DevtoolsIdentityOut):
    thread_id: str = Field(min_length=1, max_length=128)
    mailbox: str = Field(min_length=1, max_length=320)
    sent_at: str
    event_kind: Literal["mfa_email_code", "alert_email", "unknown"] = "unknown"
    direction: Literal["inbound", "outbound", "unknown"] = "unknown"
    from_email: Optional[str] = Field(default=None, max_length=320)
    to_emails: List[str] = Field(default_factory=list)
    subject: Optional[str] = Field(default=None, max_length=512)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    code: Optional[str] = Field(default=None, max_length=64)
    purpose: Optional[str] = Field(default=None, max_length=64)
    status: Optional[str] = Field(default=None, max_length=64)
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)

    @field_validator("sent_at")
    @classmethod
    def _normalize_sent_at(cls, value: str) -> str:
        return cls._normalize_utc_timestamp(value)


class DevtoolsEmailThreadOut(DevtoolsTimestampMixin, DevtoolsIdentityOut):
    mailbox: str = Field(min_length=1, max_length=320)
    subject: Optional[str] = Field(default=None, max_length=512)
    message_count: int = Field(default=0, ge=0)
    unread_count: int = Field(default=0, ge=0)
    participant_emails: List[str] = Field(default_factory=list)
    latest_message_at: str

    @field_validator("latest_message_at")
    @classmethod
    def _normalize_latest_message_at(cls, value: str) -> str:
        return cls._normalize_utc_timestamp(value)


class DevtoolsEmailMailboxOut(DevtoolsIdentityOut):
    mailbox: str = Field(min_length=1, max_length=320)
    thread_count: int = Field(default=0, ge=0)
    unread_count: int = Field(default=0, ge=0)


class DevtoolsEmailMessagesOut(BaseModel):
    mailboxes: List[DevtoolsEmailMailboxOut] = Field(default_factory=list)
    threads: List[DevtoolsEmailThreadOut] = Field(default_factory=list)
    messages: List[DevtoolsEmailMessageOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)


class DevtoolsSmsMessageOut(DevtoolsTimestampMixin, DevtoolsIdentityOut):
    conversation_id: str = Field(min_length=1, max_length=128)
    sent_at: str
    from_number: Optional[str] = Field(default=None, max_length=32)
    to_number: Optional[str] = Field(default=None, max_length=32)
    direction: Literal["inbound", "outbound", "unknown"] = "unknown"
    body_text: Optional[str] = None
    code: Optional[str] = Field(default=None, max_length=64)
    status: Optional[str] = Field(default=None, max_length=64)
    provider_message_id: Optional[str] = Field(default=None, max_length=128)
    event_kind: Literal["mfa_sms_code", "alert_sms", "unknown"] = "unknown"
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)

    @field_validator("sent_at")
    @classmethod
    def _normalize_sent_at(cls, value: str) -> str:
        return cls._normalize_utc_timestamp(value)


class DevtoolsSmsConversationOut(DevtoolsTimestampMixin, DevtoolsIdentityOut):
    participant_numbers: List[str] = Field(default_factory=list)
    message_count: int = Field(default=0, ge=0)
    latest_message_at: str
    latest_preview: Optional[str] = Field(default=None, max_length=256)

    @field_validator("latest_message_at")
    @classmethod
    def _normalize_latest_message_at(cls, value: str) -> str:
        return cls._normalize_utc_timestamp(value)


class DevtoolsSmsConversationsOut(BaseModel):
    conversations: List[DevtoolsSmsConversationOut] = Field(default_factory=list)
    messages: List[DevtoolsSmsMessageOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)


class DevtoolsBillingLedgerEntryOut(DevtoolsTimestampMixin, DevtoolsIdentityOut):
    provider: Literal["stripe", "ccbill", "paypal", "unknown"] = "unknown"
    event_type: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=64)
    occurred_at: str
    external_id: Optional[str] = Field(default=None, max_length=128)
    amount: float = 0.0
    fee: float = 0.0
    net: float = 0.0
    currency: str = Field(default="usd", min_length=3, max_length=3)
    source_path: Optional[str] = Field(default=None, max_length=512)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)

    @field_validator("occurred_at")
    @classmethod
    def _normalize_occurred_at(cls, value: str) -> str:
        return cls._normalize_utc_timestamp(value)

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if len(normalized) != 3:
            raise ValueError("currency must be an ISO-4217 3-letter code")
        return normalized


class DevtoolsBillingLedgerSummaryOut(BaseModel):
    gross_inflow: float = 0.0
    fees: float = 0.0
    net_total_balance: float = 0.0
    transaction_count: int = Field(default=0, ge=0)
    provider_counts: Dict[str, int] = Field(default_factory=dict)
    status_counts: Dict[str, int] = Field(default_factory=dict)
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)


class DevtoolsBillingLedgerOut(BaseModel):
    entries: List[DevtoolsBillingLedgerEntryOut] = Field(default_factory=list)
    summary: DevtoolsBillingLedgerSummaryOut = Field(default_factory=DevtoolsBillingLedgerSummaryOut)
    next_cursor: Optional[str] = None
    parse_warnings: List[DevtoolsParseWarningOut] = Field(default_factory=list)


class DevtoolsFfmpegHealthOut(BaseModel):
    """FFmpeg binary health for the internal dev-tools surface (GAP-0301).

    `validate_ffmpeg()` returns a FULL dict only when the binary is available;
    when it is unavailable it returns just ``{"status", "path", "error"}``.
    All non-status/path fields are therefore optional so that
    ``DevtoolsFfmpegHealthOut(**result)`` never raises on the unavailable path.
    """

    status: Literal["healthy", "degraded", "unavailable"]
    path: str = ""
    error: Optional[str] = None
    version: Optional[str] = None
    codecs: List[str] = Field(default_factory=list)
    missing_required: List[str] = Field(default_factory=list)
    missing_recommended: List[str] = Field(default_factory=list)
    issues: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# MOD-002: DMCA Takedown Workflow
# ---------------------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>")


class DmcaClaimIn(BaseModel):
    """DMCA takedown notice submission by rights holder (17 U.S.C. Section 512(c)(3))."""

    claimant_name: str = Field(min_length=2, max_length=256)
    claimant_email: str = Field(min_length=5, max_length=320)
    claimant_address: str = Field(min_length=10, max_length=1000)
    claimant_phone: str = Field(default="", max_length=30)
    content_url: str = Field(min_length=5, max_length=2000)
    content_type: Literal["feed_post", "feed_media", "message_media", "video", "other"] = Field(default="other")
    content_id: str = Field(default="", max_length=256)
    original_work_description: str = Field(min_length=20, max_length=5000)
    sworn_statement: bool
    good_faith_belief: bool
    signature: str = Field(min_length=2, max_length=256)

    @field_validator("claimant_name", "claimant_address", "original_work_description", "signature")
    @classmethod
    def _sanitize_text_fields(cls, v: str) -> str:
        return _HTML_TAG_RE.sub("", v)

    @field_validator("content_url")
    @classmethod
    def _validate_content_url(cls, v: str) -> str:
        v = v.strip()
        # Existing scheme-prefix check (kept intact for backward compat).
        if v.startswith("javascript:") or v.startswith("data:"):
            raise ValueError("Invalid content URL scheme")

        # Relative URLs (bare paths) are platform-internal and safe.
        if v.startswith("/"):
            return v

        parsed = urlparse(v)
        scheme = (parsed.scheme or "").lower()

        # No scheme + not a leading-slash path: treat as a relative reference
        # (e.g. "feed/post/abc"); leave to downstream resolution.
        if not scheme:
            return v

        # SSRF defence #1: only http/https are permitted for absolute URLs.
        # Rejects file:, ftp:, gopher:, dict:, ldap:, sftp:, etc.
        if scheme not in ("http", "https"):
            raise ValueError(f"content_url scheme '{scheme}:' is not permitted")

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            raise ValueError("content_url must include a hostname")

        # SSRF defence #2: reject well-known internal hostnames.
        _BLOCKED_HOSTS = {"localhost", "metadata", "metadata.google.internal"}
        if hostname in _BLOCKED_HOSTS or hostname.endswith(
            (".localhost", ".local", ".internal")
        ):
            raise ValueError("content_url must not point to an internal hostname")

        # SSRF defence #3: classify literal IP hosts (no DNS lookup) and reject
        # private / loopback / link-local / reserved / unspecified addresses.
        # urlparse strips the brackets from IPv6 literals in .hostname.
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            ip = None
        if ip is not None and (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("content_url must not point to an internal network address")

        return v

    @model_validator(mode="after")
    def _validate_sworn_fields(self) -> "DmcaClaimIn":
        if not self.sworn_statement:
            raise ValueError("sworn_statement must be True to file a DMCA claim")
        if not self.good_faith_belief:
            raise ValueError("good_faith_belief must be True to file a DMCA claim")
        return self


class DmcaClaimOut(BaseModel):
    claim_id: str
    status: str
    claimant_name: str
    claimant_email: str
    content_url: str
    content_type: str
    content_id: str = ""
    target_user_id: str = ""
    original_work_description: str
    created_at: int
    updated_at: int
    content_removed_at: Optional[int] = None
    counter_notice_filed_at: Optional[int] = None
    waiting_period_expires_at: Optional[int] = None
    resolved_at: Optional[int] = None
    resolution: Optional[str] = None
    strike_number: int = 0


class DmcaClaimCreateOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    content_removed: bool
    strike_number: int
    created_at: int


class DmcaCounterNoticeIn(BaseModel):
    """Counter-notice filed by content creator under 17 U.S.C. Section 512(g)."""

    counter_notice_text: str = Field(min_length=50, max_length=5000)
    consent_to_jurisdiction: bool
    counter_notice_signature: str = Field(min_length=2, max_length=256)

    @field_validator("counter_notice_text", "counter_notice_signature")
    @classmethod
    def _sanitize_text(cls, v: str) -> str:
        return _HTML_TAG_RE.sub("", v)

    @model_validator(mode="after")
    def _validate_consent(self) -> "DmcaCounterNoticeIn":
        if not self.consent_to_jurisdiction:
            raise ValueError("consent_to_jurisdiction must be True to file a counter-notice")
        return self


class DmcaCounterNoticeOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    waiting_period_expires_at: int
    counter_notice_filed_at: int


class DmcaClaimListOut(BaseModel):
    items: List[DmcaClaimOut]
    next_cursor: Optional[str] = None


class DmcaClaimDetailOut(BaseModel):
    claim: DmcaClaimOut
    content_snapshot: Dict[str, Any] = Field(default_factory=dict)
    target_user_profile: Dict[str, Any] = Field(default_factory=dict)
    claimant_full_details: Dict[str, Any] = Field(default_factory=dict)
    prior_claims_against_user: int = 0
    prior_claims_by_claimant: int = 0
    repeat_infringer_status: str = "clear"


class DmcaResolveIn(BaseModel):
    resolution: Literal["restored", "upheld", "court_order", "withdrawn"]
    resolution_notes: str = Field(default="", max_length=2000)

    @field_validator("resolution_notes")
    @classmethod
    def _sanitize_notes(cls, v: str) -> str:
        return _HTML_TAG_RE.sub("", v)


class DmcaResolveOut(BaseModel):
    ok: bool
    claim_id: str
    status: str
    resolution: str
    resolved_at: int


class DmcaAgentConfigIn(BaseModel):
    agent_name: str = Field(min_length=2, max_length=256)
    agent_email: str = Field(min_length=5, max_length=320)
    agent_address: str = Field(min_length=10, max_length=1000)
    agent_phone: str = Field(default="", max_length=30)


class DmcaAgentConfigOut(BaseModel):
    agent_name: str
    agent_email: str
    agent_address: str
    agent_phone: str


class RepeatInfringerStatusOut(BaseModel):
    user_id: str
    total_claims: int
    upheld_claims: int
    strike_count: int
    threshold: int
    status: str  # clear | warning | banned
    claim_history: List[Dict[str, Any]] = Field(default_factory=list)


# -- Appeals (MOD-003) --

_APPEAL_HTML_TAG_RE = re.compile(r"<[^>]+>")


class AppealCreateIn(BaseModel):
    enforcement_id: str = Field(min_length=1, max_length=128)
    appeal_text: str = Field(min_length=5, max_length=5000)

    @field_validator("appeal_text")
    @classmethod
    def _sanitize_appeal_text(cls, v: str) -> str:
        return _APPEAL_HTML_TAG_RE.sub("", v)

    @field_validator("enforcement_id")
    @classmethod
    def _validate_enforcement_id(cls, v: str) -> str:
        if not v.startswith("enf_"):
            raise ValueError("enforcement_id must start with 'enf_'")
        return v


class AppealOut(BaseModel):
    appeal_id: str
    user_id: str
    enforcement_id: str
    enforcement_type: str = ""
    source_ticket_id: str = ""
    appeal_text: str
    status: str
    created_at: int
    updated_at: int
    decided_at: Optional[int] = None
    decision_note: Optional[str] = None
    modified_enforcement_type: Optional[str] = None
    modified_duration_days: Optional[int] = None


class EnforcementOptionOut(BaseModel):
    """MODX-13: one selectable enforcement in the appeal picker (the user never types
    an opaque enforcement id by hand)."""
    enforcement_id: str
    enforcement_type: str = ""
    status: str = ""
    source_ticket_id: Optional[str] = None
    created_at: int = 0
    duration_days: int = 0
    note: str = ""
    has_appeal: bool = False


class EnforcementOptionsOut(BaseModel):
    items: List[EnforcementOptionOut] = Field(default_factory=list)


class AppealCreateOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str
    created_at: int


class AppealListOut(BaseModel):
    items: List[AppealOut]
    next_cursor: Optional[str] = None


class AppealWithdrawOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str


class AppealDetailOut(BaseModel):
    appeal: AppealOut
    enforcement_record: Dict[str, Any] = Field(default_factory=dict)
    moderation_ticket: Dict[str, Any] = Field(default_factory=dict)
    user_enforcement_history: List[Dict[str, Any]] = Field(default_factory=list)
    user_appeal_history: List[AppealOut] = Field(default_factory=list)


class AppealDecisionIn(BaseModel):
    decision: str = Field(pattern="^(upheld|modified|reversed)$")
    decision_note: str = Field(default="", max_length=2000)
    modified_enforcement_type: Optional[str] = None
    modified_duration_days: Optional[int] = Field(default=None, ge=1, le=3650)

    @field_validator("decision_note")
    @classmethod
    def _sanitize_note(cls, v: str) -> str:
        return _APPEAL_HTML_TAG_RE.sub("", v)


class AppealDecisionOut(BaseModel):
    ok: bool
    appeal_id: str
    status: str
    decision: str
    decided_at: int
    enforcement_reversed: bool = False
    enforcement_modified: bool = False


class AppealClaimOut(BaseModel):
    ok: bool
    appeal_id: str
    assigned_admin_user_id: str


class AppealQueueStatsOut(BaseModel):
    total_submitted: int = 0
    total_under_review: int = 0
    oldest_submitted_age_minutes: int = 0


# -- Creator Earnings (MON-003) --

class EarningsBreakdown(BaseModel):
    subscriptions: int = 0
    tips: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    # ECOMX-50: shop + live-commerce revenue as distinct earnings buckets
    # (previously collapsed into "other").
    shop_sales: int = 0
    live_commerce: int = 0
    other: int = 0


class TimeSeriesPoint(BaseModel):
    date: str
    total: int = 0
    tips: int = 0
    subscriptions: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    other: int = 0


class EarningsSummaryOut(BaseModel):
    total_cents: int = 0
    breakdown: EarningsBreakdown = Field(default_factory=EarningsBreakdown)
    transaction_count: int = 0
    currency: str = "USD"
    time_series: List[TimeSeriesPoint] = Field(default_factory=list)


class EarningsTransactionOut(BaseModel):
    entry_id: str
    ts: int
    amount_cents: int
    reason: str = ""
    category: str = ""
    currency: str = "USD"
    meta: Dict[str, Any] = Field(default_factory=dict)


class EarningsTransactionsOut(BaseModel):
    items: List[EarningsTransactionOut]
    next_cursor: Optional[str] = None


class EarningsQuickStatsOut(BaseModel):
    today_cents: int = 0
    this_week_cents: int = 0
    this_month_cents: int = 0
    all_time_cents: int = 0
    currency: str = "USD"
    pending_payout_cents: int = 0


# -- Creator Payouts (MON-004) --

class PayoutBalanceOut(BaseModel):
    available_cents: int = 0
    pending_cents: int = 0
    total_earned_cents: int = 0
    hold_cents: int = 0
    currency: str = "USD"
    minimum_payout_cents: int = 1000


class PayoutRequestIn(BaseModel):
    amount_cents: int = Field(ge=100)
    method: str = "bank_transfer"
    method_id: Optional[str] = None
    notes: str = Field(default="", max_length=500)


class PayoutOut(BaseModel):
    payout_id: str
    user_id: str
    amount_cents: int
    method: str = "bank_transfer"
    status: str
    created_at: int
    updated_at: int
    notes: str = ""
    reject_reason: str = ""
    approved_by: str = ""
    completed_at: Optional[int] = None


class PayoutCreateOut(BaseModel):
    ok: bool
    payout_id: str
    amount_cents: int
    status: str


class PayoutListOut(BaseModel):
    items: List[PayoutOut]
    next_cursor: Optional[str] = None


class PayoutActionOut(BaseModel):
    ok: bool
    payout_id: str
    status: str


class WalletSummaryOut(BaseModel):
    available_cents: int = 0
    held_cents: int = 0
    held_count: int = 0
    held_release_at: Optional[int] = None
    pending_cents: int = 0
    pending_count: int = 0
    lifetime_paid_cents: int = 0
    total_earned_cents: int = 0
    currency: str = "USD"
    minimum_payout_cents: int = 1000


class PayoutTimelineEvent(BaseModel):
    status: str
    ts: int = 0
    note: str = ""


class PayoutDetailOut(BaseModel):
    payout_id: str
    user_id: str
    amount_cents: int
    method: str = "bank_transfer"
    method_id: str = ""
    method_last4: str = ""
    status: str
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None
    notes: str = ""
    reject_reason: str = ""
    fail_reason: str = ""
    approved_by: str = ""
    manual_hold: bool = False
    hold_reason: str = ""
    debit_reversed: bool = False
    transfer_provider: str = ""
    transfer_ref: str = ""
    transfer_attempts: int = 0
    timeline: List[PayoutTimelineEvent] = []


class PayoutStatsOut(BaseModel):
    total_requested: int = 0
    total_requested_amount_cents: int = 0
    total_approved: int = 0
    total_processing: int = 0


class PayoutRejectIn(BaseModel):
    reason: str = Field(default="", max_length=1000)


class PayoutMarkPaidIn(BaseModel):
    reference: str = Field(default="", max_length=500)


# -- Payout Methods (GAP-0195 / FIN-009) --

class PayoutMethodIn(BaseModel):
    method_type: str = Field(..., pattern="^(bank_ach|bank_wire|paypal|check|stripe_connect)$")
    # SEC-004: full account/routing are WRITE-ONLY — tokenized server-side, never
    # stored. Only the last-4 (below) + an opaque token are persisted.
    account_number: str = Field(default="", max_length=17, pattern=r"^\d{0,17}$")
    routing_number: str = Field(default="", max_length=9, pattern=r"^\d{0,9}$")
    account_last4: str = Field(default="", max_length=4, pattern=r"^\d{0,4}$")
    routing_last4: str = Field(default="", max_length=4, pattern=r"^\d{0,4}$")
    paypal_email: str = Field(default="", max_length=254)
    connect_account_id: str = Field(default="", max_length=64)
    nickname: str = Field(default="", max_length=100)
    set_as_default: bool = False


class PayoutMethodUpdateIn(BaseModel):
    nickname: str = Field(..., max_length=100)


class PayoutMethodOut(BaseModel):
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
    updated_at: int


class PayoutMethodListOut(BaseModel):
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
    real: bool = False


# ─── Tip Leaderboards (SOCIAL-005) ──────────────────────────────────


class TopSupporterItem(BaseModel):
    rank: int
    user_id: str
    display_name: str = ""
    avatar_url: Optional[str] = None
    total_cents: int = 0
    tip_count: int = 0
    last_tip_at: int = 0


class TopSupportersOut(BaseModel):
    creator_id: str
    period: str
    supporters: List[TopSupporterItem] = Field(default_factory=list)
    total_tip_cents: int = 0
    total_supporters: int = 0
    computed_at: int = 0


# ─── Broadcast-Exclusive Pricing (LCOM-004) ────────────────────────


class BroadcastPriceSetIn(BaseModel):
    """Request body for setting a broadcast-exclusive price.

    The broadcast_price_cents MUST be strictly less than the catalog price.
    This is enforced in the service layer against the actual DDB value.
    """
    broadcast_price_cents: int = Field(..., gt=0, le=99999999,
        description="Broadcast-exclusive price in cents. Must be less than catalog price.")
    expires_in_seconds: Optional[int] = Field(
        default=None, ge=60, le=86400,
        description="Optional: price expires N seconds from now (1 min to 24 hours)",
    )


class BroadcastPriceOut(BaseModel):
    """Response after setting a broadcast price."""
    session_id: str
    item_id: str
    original_price_cents: int
    broadcast_price_cents: int
    broadcast_price_expires_at: Optional[int] = None
    discount_pct: int = Field(..., ge=0, le=100)
    set_by: str
    set_at: int


# --------------------------------------------------------------------------- #
#  ENGAGE-003: Live Q&A Mode                                                    #
# --------------------------------------------------------------------------- #


class QAModeToggleIn(BaseModel):
    enabled: bool


class QAModeToggleOut(BaseModel):
    ok: bool = True
    qa_mode_enabled: bool


class QAQuestionSubmitIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)


class QAQuestionOut(BaseModel):
    question_id: str
    session_id: str
    submitter_id: str
    submitter_display_name: str
    text: str
    status: str  # "pending", "featured", "answered", "dismissed", "removed"
    upvote_count: int
    featured_at: Optional[int] = None
    answered_at: Optional[int] = None
    created_at: int
    featured_by: Optional[str] = None


class QAQueueOut(BaseModel):
    questions: List[QAQuestionOut]
    has_more: bool = False


class QAStatsOut(BaseModel):
    total_questions: int
    answered: int
    dismissed: int
    pending: int
    total_upvotes: int
    avg_upvotes: float
    answer_rate: float


# --------------------------------------------------------------------------- #
#  SOC-004: Social alert type preferences                                       #
# --------------------------------------------------------------------------- #

class AlertTypePreferenceUpdate(BaseModel):
    """Request body for POST /alerts/type-preferences."""
    alert_type: str = Field(..., min_length=1, max_length=64)
    enabled: Optional[bool] = None
    email: Optional[bool] = None
    push: Optional[bool] = None
    in_app: Optional[bool] = None
    sms: Optional[bool] = None


class AlertTypePreference(BaseModel):
    """Single type preference entry."""
    enabled: bool = True
    email: bool = True
    push: bool = True
    in_app: bool = True
    sms: bool = False


class AlertTypePreferencesResponse(BaseModel):
    """Response for GET /alerts/type-preferences."""
    type_preferences: Dict[str, AlertTypePreference]


class UnreadCountResponse(BaseModel):
    """Response for GET /alerts/unread-count."""
    unread_count: int = Field(..., ge=0, le=99)


class MarkAllReadResponse(BaseModel):
    """Response for POST /alerts/mark-all-read."""
    marked_count: int


# --------------------------------------------------------------------------- #
#  NOTIFY-001: Notification Delivery Enhancements                               #
# --------------------------------------------------------------------------- #

class UnreadCountSentinelResponse(BaseModel):
    """Response for GET /ui/alerts/unread-count (sentinel-based)."""
    count: int = Field(..., ge=0)


class MarkAllReadSentinelResponse(BaseModel):
    """Response for POST /ui/alerts/mark-all-read (sentinel-based)."""
    ok: bool = True
    count: int = 0


# ---------------------------------------------------------------------------
# SOC-005: Public Profile
# ---------------------------------------------------------------------------

class PublicProfileResponse(BaseModel):
    user_id: str
    identifier: str
    canonical_identifier: Optional[str] = None
    display_name: str
    title: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    profile_photo_url: Optional[str] = None
    cover_photo_url: Optional[str] = None
    follower_count: int = 0
    following_count: int = 0
    post_count: int = 0
    is_following: bool = False
    is_followed_by: bool = False
    is_mutual: bool = False
    has_subscription_plans: bool = False
    created_at: Optional[str] = None
    discoverability: Optional[str] = None

    @field_validator("follower_count", "following_count", "post_count", mode="before")
    @classmethod
    def coerce_to_int(cls, v: Any) -> int:
        """DDB stores numbers as Decimal; coerce to int."""
        if v is None:
            return 0
        return int(v)


class PublicPostSummary(BaseModel):
    post_id: str
    created_at: str
    body_preview: Optional[str] = None
    image_urls: List[str] = Field(default_factory=list)
    video_id: Optional[str] = None
    has_video: bool = False
    locked: bool = False
    unlock_price_cents: Optional[int] = None
    like_count: int = 0
    comment_count: int = 0
    tip_total_cents: int = 0

    @field_validator("like_count", "comment_count", "tip_total_cents", mode="before")
    @classmethod
    def coerce_counts_to_int(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class PublicPostListResponse(BaseModel):
    items: List[PublicPostSummary]
    next_cursor: Optional[str] = None
    total_count: int = 0


# -- Creator Analytics Dashboard (ANALYTICS-001) --

class AnalyticsTopContentItem(BaseModel):
    content_id: str = ""
    content_type: str = ""  # "vod" | "post"
    title: str = ""
    views: int = 0
    revenue_cents: int = 0
    engagement_rate: float = 0.0


class AnalyticsOverviewOut(BaseModel):
    period_views: int = 0
    period_revenue_cents: int = 0
    period_new_subscribers: int = 0
    total_subscribers: int = 0
    top_content: List[AnalyticsTopContentItem] = Field(default_factory=list)
    currency: str = "USD"


class AnalyticsRevenueTimeSeriesItem(BaseModel):
    date: str
    total_cents: int = 0
    tips_cents: int = 0
    subscriptions_cents: int = 0
    unlocks_cents: int = 0
    vod_cents: int = 0
    ads_cents: int = 0
    calls_cents: int = 0


class AnalyticsRevenueBreakdown(BaseModel):
    tips: int = 0
    subscriptions: int = 0
    unlocks: int = 0
    vod: int = 0
    ads: int = 0
    calls: int = 0


class AnalyticsRevenueOut(BaseModel):
    total_cents: int = 0
    breakdown: AnalyticsRevenueBreakdown = Field(default_factory=AnalyticsRevenueBreakdown)
    time_series: List[AnalyticsRevenueTimeSeriesItem] = Field(default_factory=list)
    currency: str = "USD"


class AnalyticsViewsTimeSeriesItem(BaseModel):
    date: str
    views: int = 0
    unique_viewers: int = 0
    watch_time_seconds: int = 0


class AnalyticsViewsOut(BaseModel):
    time_series: List[AnalyticsViewsTimeSeriesItem] = Field(default_factory=list)
    total_views: int = 0
    total_watch_time_seconds: int = 0


class AnalyticsSubscribersTimeSeriesItem(BaseModel):
    date: str
    new: int = 0
    churned: int = 0
    net: int = 0
    total: int = 0


class AnalyticsSubscribersOut(BaseModel):
    time_series: List[AnalyticsSubscribersTimeSeriesItem] = Field(default_factory=list)
    current_total: int = 0
    net_change: int = 0


class AnalyticsTopContentOut(BaseModel):
    items: List[AnalyticsTopContentItem] = Field(default_factory=list)
    total_items: int = 0


class AnalyticsCountryItem(BaseModel):
    code: str
    name: str = ""
    viewers: int = 0
    percentage: float = 0.0


class AnalyticsDeviceItem(BaseModel):
    type: str
    viewers: int = 0
    percentage: float = 0.0


class AnalyticsAudienceOut(BaseModel):
    countries: List[AnalyticsCountryItem] = Field(default_factory=list)
    devices: List[AnalyticsDeviceItem] = Field(default_factory=list)
    total_unique_viewers: int = 0


class AnalyticsRefreshOut(BaseModel):
    ok: bool = True
    message: str = ""
    days_refreshed: int = 0


# -- Creator Analytics Content Detail (ANALYTICS-002) --

class ContentAnalyticsViewsItem(BaseModel):
    """A single data point in the per-content view time series."""
    date: str
    views: int = 0
    unique_viewers: int = 0


class ContentAnalyticsRevenueBreakdown(BaseModel):
    """Revenue breakdown by source for a single content item."""
    tips: int = 0
    unlocks: int = 0
    vod: int = 0


class ContentAnalyticsOut(BaseModel):
    """Full per-content analytics response."""
    content_id: str
    content_type: str  # "vod" | "post"
    title: str
    thumbnail_url: Optional[str] = None
    published_at: Optional[int] = None
    total_views: int = 0
    total_revenue_cents: int = 0
    engagement_rate: float = 0.0
    like_count: int = 0
    comment_count: int = 0
    view_time_series: List[ContentAnalyticsViewsItem] = Field(default_factory=list)
    revenue_breakdown: ContentAnalyticsRevenueBreakdown = Field(
        default_factory=ContentAnalyticsRevenueBreakdown
    )
    currency: str = "USD"


# -- Privacy / GDPR (PRIVACY-001) --

class ExportRequestIn(BaseModel):
    include_messages: bool = True
    include_files: bool = True
    include_billing: bool = True
    include_profile: bool = True

class DeleteAccountRequestIn(BaseModel):
    password: str
    reason: Optional[str] = None

class AdminPrivacyActionIn(BaseModel):
    note: Optional[str] = None

class AdminHoldIn(BaseModel):
    reason: str

class DataRequestOut(BaseModel):
    request_id: str
    request_type: str
    status: str
    created_at: int
    updated_at: Optional[int] = None
    completed_at: Optional[int] = None
    grace_period_ends_at: Optional[int] = None
    export_size_bytes: Optional[int] = None
    export_download_url: Optional[str] = None
    deletion_reason: Optional[str] = None
    deletion_summary: Optional[Dict[str, Any]] = None
    retention_hold: bool = False
    retention_hold_reason: Optional[str] = None
    user_sub: Optional[str] = None
    admin_actor: Optional[str] = None
    admin_note: Optional[str] = None

class DataRequestListOut(BaseModel):
    requests: List[DataRequestOut]
    next_cursor: Optional[str] = None

class DataRequestAuditEntry(BaseModel):
    action: str
    actor: str
    created_at: int
    details: Optional[Dict[str, Any]] = None


# ─── Rate Limiting (PLATFORM-001) ────────────────────────────────

class RateLimitGlobalIpConfig(BaseModel):
    window_seconds: int = 60
    max_requests: int = 300
    enabled: bool = True


class RateLimitGroupConfig(BaseModel):
    description: str = ""
    paths: List[str] = Field(default_factory=list)
    window_seconds: int = 60
    max_requests_per_user: int = 120
    max_requests_per_ip: int = 200
    bypass_roles: List[str] = Field(default_factory=list)
    is_override: bool = False


class RateLimitConfigResponse(BaseModel):
    global_ip: RateLimitGlobalIpConfig
    groups: Dict[str, RateLimitGroupConfig]


class RateLimitUpdateConfigReq(BaseModel):
    group: str
    window_seconds: Optional[int] = None
    max_requests_per_user: Optional[int] = None
    max_requests_per_ip: Optional[int] = None
    bypass_roles: Optional[List[str]] = None


class RateLimitUpdateConfigResp(BaseModel):
    ok: bool = True
    group: str = ""
    previous: Dict[str, Any] = Field(default_factory=dict)
    updated: Dict[str, Any] = Field(default_factory=dict)


class RateLimitTopOffenderIp(BaseModel):
    ip: str = ""
    rejected_count: int = 0
    last_seen: int = 0


class RateLimitTopOffenderUser(BaseModel):
    user_sub: str = ""
    rejected_count: int = 0
    last_seen: int = 0


class RateLimitTopOffendersResp(BaseModel):
    top_ips: List[RateLimitTopOffenderIp] = Field(default_factory=list)
    top_users: List[RateLimitTopOffenderUser] = Field(default_factory=list)


class RateLimitBlocklistAddReq(BaseModel):
    ip: str
    reason: str = ""
    expires_in_hours: Optional[int] = None


class RateLimitAllowlistAddReq(BaseModel):
    cidr: str
    reason: str = ""


# ─── Webhooks (PLATFORM-002) ──────────────────────────────────────

class WebhookRetryPolicyReq(BaseModel):
    strategy: str = Field(default="exponential", pattern=r"^(linear|exponential|fibonacci|fixed)$")
    max_attempts: int = Field(default=5, ge=1, le=20)
    initial_delay_seconds: int = Field(default=60, ge=10, le=3600)
    max_delay_seconds: int = Field(default=7200, ge=60, le=86400)
    jitter_enabled: bool = True
    jitter_max_seconds: int = Field(default=30, ge=0, le=300)
    retry_window_seconds: int = Field(default=86400, ge=3600, le=604800)

class WebhookEndpointCreateReq(BaseModel):
    url: str
    description: str = ""
    event_types: List[str]
    retry_policy: Optional[dict] = None
    signature_version: str = Field(default="v2", pattern=r"^(v1|v2|both)$")
    circuit_failure_threshold: Optional[int] = Field(default=None, ge=3, le=100)

class WebhookEndpointUpdateReq(BaseModel):
    url: Optional[str] = None
    description: Optional[str] = None
    event_types: Optional[List[str]] = None
    enabled: Optional[bool] = None
    retry_policy: Optional[dict] = None
    signature_version: Optional[str] = Field(default=None, pattern=r"^(v1|v2|both)$")

class WebhookEndpointOut(BaseModel):
    endpoint_id: str
    url: str
    description: str = ""
    event_types: List[str] = Field(default_factory=list)
    enabled: bool = True
    secret: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0
    last_delivery_at: Optional[int] = None
    failure_count: int = 0
    disabled_reason: Optional[str] = None
    # v2 fields
    retry_policy: Optional[dict] = None
    signature_version: str = "v2"
    circuit_state: Optional[str] = None
    circuit_consecutive_failures: int = 0
    circuit_failure_threshold: int = 10
    circuit_cooldown_seconds: Optional[int] = None
    circuit_test_at: Optional[int] = None

class WebhookDeliveryStatsOut(BaseModel):
    endpoint_id: str
    period: str
    buckets: list = Field(default_factory=list)
    total_deliveries: int = 0
    success_rate: float = 1.0
    avg_latency_ms: float = 0.0

class WebhookDeadLetterOut(BaseModel):
    delivery_id: str
    endpoint_id: str
    event_type: str = ""
    event_id: str = ""
    payload_preview: str = ""
    created_at: int = 0
    failed_at: int = 0
    failure_reason: str = ""
    attempt_count: int = 0
    last_http_status: Optional[int] = None
    last_error_message: Optional[str] = None

class WebhookCircuitStateOut(BaseModel):
    state: str = "closed"
    consecutive_failures: int = 0
    failure_threshold: int = 10
    cooldown_seconds: int = 300
    opened_at: Optional[int] = None
    next_test_at: Optional[int] = None

class WebhookDeliveryOut(BaseModel):
    delivery_id: str
    endpoint_id: str
    event_type: str = ""
    event_id: str = ""
    status: str = "pending"
    attempt_count: int = 0
    max_attempts: int = 5
    next_retry_at: Optional[int] = None
    last_attempt_at: Optional[int] = None
    last_response_code: Optional[int] = None
    last_response_body: Optional[str] = None
    last_error: Optional[str] = None
    created_at: int = 0
    payload: Optional[str] = None

class WebhookTestResult(BaseModel):
    delivery_id: str
    status: str
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    error: Optional[str] = None
    duration_ms: int = 0

class WebhookHealthSummary(BaseModel):
    total_endpoints: int = 0
    enabled_endpoints: int = 0
    disabled_endpoints: int = 0
    total_deliveries_24h: int = 0
    success_count_24h: int = 0
    failed_count_24h: int = 0
    dead_letter_count_24h: int = 0

class AdminEndpointDisableReq(BaseModel):
    reason: str = "admin_disabled"


# ─── Unified Content Scheduling (SCHED-001) ─────────────────────

SCHEDULED_ACTION_TYPES = {"post", "file_share", "catalog_sale"}


class ScheduledActionCreateIn(BaseModel):
    action_type: str
    scheduled_at: int
    title: str = ""
    description: str = ""
    payload: dict = {}
    notify_before_seconds: int = 0

    @model_validator(mode="after")
    def _validate_type(self):
        if self.action_type not in SCHEDULED_ACTION_TYPES:
            raise ValueError(f"Invalid action_type: {self.action_type}")
        return self


class ScheduledActionUpdateIn(BaseModel):
    scheduled_at: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    payload: Optional[dict] = None
    notify_before_seconds: Optional[int] = None


class ScheduledActionOut(BaseModel):
    action_id: str
    action_type: str
    status: str
    scheduled_at: int
    created_at: int
    updated_at: Optional[int] = None
    completed_at: Optional[int] = None
    title: str = ""
    description: str = ""
    payload: dict = {}
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    notify_before_seconds: int = 0
    reminder_sent: bool = False


class ScheduledActionListOut(BaseModel):
    actions: list[ScheduledActionOut] = []
    cursor: Optional[str] = None


class ScheduledCalendarOut(BaseModel):
    actions: list[ScheduledActionOut] = []
    total: int = 0


class ScheduledPostIn(BaseModel):
    text: str = ""
    image_urls: list[str] = []
    lock_price_cents: int = 0
    visibility: str = "public"
    scheduled_at: int = 0


class CatalogSaleIn(BaseModel):
    sale_price_cents: int
    sale_starts_at: int
    sale_ends_at: int
    sale_label: str = ""


class CatalogSaleOut(BaseModel):
    start_action_id: str
    end_action_id: str
    sale_starts_at: int
    sale_ends_at: int


# ─── Geo-Blocking (GEO-001) ─────────────────────────────────────


_VALID_ISO_COUNTRY_CODES = {
    "AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW","AX",
    "AZ","BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ",
    "BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD","CF","CG","CH","CI","CK",
    "CL","CM","CN","CO","CR","CU","CV","CW","CX","CY","CZ","DE","DJ","DK","DM",
    "DO","DZ","EC","EE","EG","EH","ER","ES","ET","FI","FJ","FK","FM","FO","FR",
    "GA","GB","GD","GE","GF","GG","GH","GI","GL","GM","GN","GP","GQ","GR","GS",
    "GT","GU","GW","GY","HK","HM","HN","HR","HT","HU","ID","IE","IL","IM","IN",
    "IO","IQ","IR","IS","IT","JE","JM","JO","JP","KE","KG","KH","KI","KM","KN",
    "KP","KR","KW","KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT","LU","LV",
    "LY","MA","MC","MD","ME","MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ",
    "MR","MS","MT","MU","MV","MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI",
    "NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PM",
    "PN","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","RW","SA","SB","SC",
    "SD","SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS","ST","SV",
    "SX","SY","SZ","TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO","TR",
    "TT","TV","TW","TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE","VG","VI",
    "VN","VU","WF","WS","YE","YT","ZA","ZM","ZW",
}


class GeoRestrictionRequest(BaseModel):
    geo_mode: Optional[Literal["allow", "block"]] = None
    geo_countries: Optional[List[str]] = Field(default=None, max_length=250)

    @model_validator(mode="after")
    def validate_geo_fields(self):
        if self.geo_mode and not self.geo_countries:
            raise ValueError("geo_countries is required when geo_mode is set")
        if self.geo_countries:
            for code in self.geo_countries:
                if not re.match(r"^[A-Z]{2}$", code):
                    raise ValueError(f"invalid country code: {code}")
                if code not in _VALID_ISO_COUNTRY_CODES:
                    raise ValueError(f"invalid country code: {code}")
        if self.geo_mode is None:
            self.geo_countries = None
        return self


class GeoRestrictionOut(BaseModel):
    ok: bool = True
    geo_mode: Optional[str] = None
    geo_countries: Optional[List[str]] = None


class GeoCountryOut(BaseModel):
    code: str
    name: str


class GeoCountriesListOut(BaseModel):
    countries: List[GeoCountryOut]


class MyCountryOut(BaseModel):
    country: Optional[str] = None
    ip: str
    source: str


class GeoCheckResult(BaseModel):
    allowed: bool
    country: Optional[str] = None
    geo_mode: Optional[str] = None
    matched_rule: Optional[str] = None


# ─── Promo Codes & Coupons (PROMO-001) ──────────────────────────


class PromoCodeCreateIn(BaseModel):
    code: str = Field(..., min_length=3, max_length=30)
    discount_type: Literal["percentage", "fixed_amount", "free_trial"]
    discount_value: int = 0
    free_trial_days: int = 0
    applies_to: List[Literal["subscription", "vod", "shop"]] = Field(default=["subscription"])
    min_purchase_cents: int = 0
    max_uses: int = 0  # 0 = unlimited
    max_uses_per_user: int = 1
    expires_at: int = 0  # 0 = no expiry


class PromoCodeUpdateIn(BaseModel):
    active: Optional[bool] = None
    expires_at: Optional[int] = None
    max_uses: Optional[int] = None


class PromoCodeOut(BaseModel):
    code_id: str
    code: str
    discount_type: str
    discount_value: int = 0
    free_trial_days: int = 0
    applies_to: List[str] = []
    min_purchase_cents: int = 0
    max_uses: int = 0
    max_uses_per_user: int = 1
    current_uses: int = 0
    expires_at: int = 0
    active: bool = True
    created_at: int = 0
    creator_user_id: str = ""


class PromoCodeListOut(BaseModel):
    items: List[PromoCodeOut] = []
    next_cursor: Optional[str] = None


class PromoRedemptionOut(BaseModel):
    user_id: str
    redeemed_at: int
    discount_applied_cents: int = 0
    original_price_cents: int = 0
    final_price_cents: int = 0
    checkout_type: str = ""
    checkout_item_id: str = ""


class PromoCodeStatsOut(PromoCodeOut):
    stats: Optional[dict] = None


class PromoValidateIn(BaseModel):
    code: str
    checkout_type: Literal["subscription", "vod", "shop", "tip", "unlock"]
    item_price_cents: int = 0
    creator_user_id: str


class PromoValidateOut(BaseModel):
    valid: bool
    code_id: Optional[str] = None
    discount_type: Optional[str] = None
    discount_cents: int = 0
    discount_pct: Optional[int] = None
    original_price_cents: int = 0
    final_price_cents: int = 0
    free_trial_days: int = 0
    buy_x: Optional[int] = None
    get_y: Optional[int] = None
    free_item_description: Optional[str] = None
    error_code: Optional[str] = None
    message: Optional[str] = None


class PromoRedeemIn(BaseModel):
    code: str
    user_id: str
    original_price_cents: int = 0
    final_price_cents: int = 0
    checkout_type: str = ""
    checkout_item_id: str = ""


class PromoDeactivateOut(BaseModel):
    ok: bool = True
    code_id: str
    active: bool = False


# ─── Group Video Calls (CALL-012) ────────────────────────────────


class GroupCallMediaStatus(BaseModel):
    audio: bool = True
    video: bool = True
    screen: bool = False


class GroupCallParticipantOut(BaseModel):
    user_id: str
    display_name: str = ""
    joined_at: int = 0
    left_at: int = 0
    media_status: GroupCallMediaStatus = GroupCallMediaStatus()
    connection_quality: str = "good"
    state: str = "active"


class GroupCallCreateIn(BaseModel):
    conversation_id: str
    mode: Literal["audio", "video"] = "video"
    max_participants: int = Field(default=8, ge=2, le=8)


class GroupCallSignalingInfo(BaseModel):
    mode: str = "mesh"
    ice_servers: list[dict] = []


class GroupCallOut(BaseModel):
    call_id: str
    conversation_id: str
    creator_user_id: str
    state: str = "created"
    mode: str = "video"
    max_participants: int = 8
    current_participant_count: int = 0
    participants: list[GroupCallParticipantOut] = []
    created_at: int = 0
    started_at: int = 0
    end_ts: int = 0
    end_reason: str = ""
    duration_seconds: int = 0
    signaling: Optional[GroupCallSignalingInfo] = None


class GroupCallJoinOut(BaseModel):
    call_id: str
    state: str
    mode: str
    current_participant_count: int
    participants: list[GroupCallParticipantOut]
    signaling: GroupCallSignalingInfo = GroupCallSignalingInfo()


class GroupCallLeaveOut(BaseModel):
    ok: bool = True
    call_ended: bool = False
    remaining_participants: int = 0


class GroupCallEndOut(BaseModel):
    ok: bool = True
    call_id: str
    duration_seconds: int = 0
    total_participants: int = 0


class GroupCallParticipantsOut(BaseModel):
    participants: list[GroupCallParticipantOut] = []
    total_active: int = 0
    total_joined: int = 0


class GroupCallSignalIn(BaseModel):
    type: str  # "offer", "answer", "ice_candidate"
    target_user_id: str
    payload: dict = {}


class GroupCallSignalOut(BaseModel):
    ok: bool = True
    relayed_to: str = ""


class GroupCallMediaUpdateIn(BaseModel):
    audio: Optional[bool] = None
    video: Optional[bool] = None
    screen: Optional[bool] = None


class GroupCallMediaUpdateOut(BaseModel):
    ok: bool = True
    media_status: GroupCallMediaStatus = GroupCallMediaStatus()


# ─── Collaboration Requests (CREATOR-001) ──────────────────────────

class CollaborationCreateIn(BaseModel):
    recipient_id: str = Field(..., min_length=1, max_length=128)
    content_types: List[str] = Field(..., min_length=1)
    split_pct: int = Field(..., ge=1, le=99)
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    terms_text: Optional[str] = Field(default=None, max_length=5000)
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    max_content_items: Optional[int] = Field(default=None, ge=1, le=10000)

    @model_validator(mode="after")
    def validate_collab_create(self):
        if self.valid_from and self.valid_until and self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be before valid_until")
        for ct in self.content_types:
            if ct not in ("broadcast", "post", "vod"):
                raise ValueError(f"Invalid content_type: {ct}. Must be one of: broadcast, post, vod")
        return self


class CollaborationCounterIn(BaseModel):
    counter_split_pct: int = Field(..., ge=1, le=99)
    counter_terms_text: Optional[str] = Field(default=None, max_length=5000)
    counter_valid_until: Optional[int] = None
    reason: Optional[str] = Field(default=None, max_length=500)


class CollaborationTerminateIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class CollaborationOut(BaseModel):
    collaboration_id: str
    initiator_id: str
    recipient_id: str
    status: str
    content_types: List[str] = Field(default_factory=list)
    split: Dict[str, int] = Field(default_factory=dict)
    title: str = ""
    description: Optional[str] = None
    terms_text: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    max_content_items: Optional[int] = None
    content_count: int = 0
    total_revenue_cents: int = 0
    revision: int = 1
    created_at: int = 0
    updated_at: int = 0
    accepted_at: Optional[int] = None
    terminated_at: Optional[int] = None
    terminated_by: Optional[str] = None
    termination_reason: Optional[str] = None
    last_proposed_by: Optional[str] = None

    @field_validator(
        "content_count", "total_revenue_cents", "revision", "created_at", "updated_at",
        mode="before",
    )
    @classmethod
    def coerce_decimal_to_int(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class CollaborationListOut(BaseModel):
    items: List[CollaborationOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class CollaborationRevisionOut(BaseModel):
    revision: int
    split: Dict[str, int] = Field(default_factory=dict)
    terms_text: Optional[str] = None
    proposed_by: str = ""
    proposed_at: int = 0
    status: str = "superseded"


class CollaborationSettingsIn(BaseModel):
    accepting_requests: Optional[bool] = None
    min_split_pct: Optional[int] = Field(default=None, ge=1, le=99)
    allowed_content_types: Optional[List[str]] = None
    auto_expire_days: Optional[int] = Field(default=None, ge=1, le=365)


class CollaborationSettingsOut(BaseModel):
    accepting_requests: bool = True
    min_split_pct: int = 1
    allowed_content_types: List[str] = Field(default_factory=lambda: ["broadcast", "post", "vod"])
    auto_expire_days: int = 7
    updated_at: int = 0


class CollaborationSplitIn(BaseModel):
    collaboration_id: str
    amount_cents: int = Field(..., gt=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    content_type: str = "collaboration"
    content_id: str = ""


# ─── Collaboration Revenue Splitting (FIN-011) ───────────────────

class CollabContentAssignIn(BaseModel):
    content_id: str = Field(..., min_length=1, max_length=200)
    content_type: str = Field(..., pattern="^(vod|post|broadcast)$")
    title: str = Field(default="", max_length=200)


class CollabContentItem(BaseModel):
    content_id: str
    content_type: str
    title: str = ""
    assigned_by: str = ""
    assigned_at: int = 0
    total_revenue_cents: int = 0
    split_count: int = 0

    @field_validator(
        "assigned_at", "total_revenue_cents", "split_count", mode="before",
    )
    @classmethod
    def _collab_content_coerce(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class CollabContentListOut(BaseModel):
    items: List[CollabContentItem] = Field(default_factory=list)
    collaboration_id: str = ""


class CollabSplitDistribution(BaseModel):
    user_id: str
    amount_cents: int = 0
    percentage: int = 0

    @field_validator("amount_cents", "percentage", mode="before")
    @classmethod
    def _collab_dist_coerce(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class CollabSplitRecord(BaseModel):
    split_id: str
    content_id: str
    content_type: str = ""
    gross_amount_cents: int = 0
    source: str = ""
    distributions: List[CollabSplitDistribution] = Field(default_factory=list)
    created_at: int = 0
    dispute_status: Optional[str] = None

    @field_validator("gross_amount_cents", "created_at", mode="before")
    @classmethod
    def _collab_split_coerce(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class CollabSplitHistoryOut(BaseModel):
    items: List[CollabSplitRecord] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class CollabContentSplitTriggerIn(BaseModel):
    content_id: str = Field(..., min_length=1, max_length=200)
    amount_cents: int = Field(..., gt=0)
    source: str = Field(default="tip", pattern="^(tip|unlock|vod_purchase|subscription|sale)$")
    currency: str = Field(default="USD", min_length=3, max_length=3)


class CollabDisputeIn(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)
    proposed_split: Optional[Dict[str, int]] = None


class CollabDisputeResolveIn(BaseModel):
    resolution: str = Field(..., min_length=5, max_length=2000)
    accept: bool = True


class CollabDisputeOut(BaseModel):
    dispute_id: str
    split_id: str
    collaboration_id: str = ""
    filed_by: str
    reason: str
    proposed_split: Optional[Dict[str, int]] = None
    status: str
    resolution: str = ""
    resolved_by: str = ""
    resolved_at: int = 0
    created_at: int = 0

    @field_validator("resolved_at", "created_at", mode="before")
    @classmethod
    def _collab_dispute_coerce(cls, v: Any) -> int:
        if v is None:
            return 0
        return int(v)


class CollabDisputeListOut(BaseModel):
    items: List[CollabDisputeOut] = Field(default_factory=list)


# ─── Fan Clubs / Membership Tiers (CREATOR-002) ──────────────────

class TierBenefit(BaseModel):
    type: str = Field(..., description="Benefit type: early_access, exclusive_chat, custom_emoji, badge, text, discount, priority_dm")
    label: Optional[str] = Field(default=None, max_length=200)
    delay_hours: Optional[int] = Field(default=None, ge=0, le=720)
    channel_id: Optional[str] = Field(default=None)
    emoji_pack_id: Optional[str] = Field(default=None)
    display: Optional[bool] = Field(default=None)
    percent_off: Optional[int] = Field(default=None, ge=1, le=100)
    applies_to: Optional[List[str]] = Field(default=None)


class TierCreateIn(BaseModel):
    plan_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=50)
    level: int = Field(..., ge=1, le=6)
    color: str = Field(..., pattern=r"^#[0-9a-fA-F]{6}$")
    badge_emoji: Optional[str] = Field(default=None, max_length=32)
    description: Optional[str] = Field(default=None, max_length=500)
    benefits: List[TierBenefit] = Field(default_factory=list)
    welcome_message: Optional[str] = Field(default=None, max_length=1000)
    sort_order: int = Field(default=0, ge=0, le=10)


class TierUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    color: Optional[str] = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    badge_emoji: Optional[str] = Field(default=None, max_length=32)
    description: Optional[str] = Field(default=None, max_length=500)
    benefits: Optional[List[TierBenefit]] = Field(default=None)
    welcome_message: Optional[str] = Field(default=None, max_length=1000)
    sort_order: Optional[int] = Field(default=None, ge=0, le=10)
    active: Optional[bool] = None


class TierOut(BaseModel):
    tier_id: str
    creator_id: str
    plan_id: str
    name: str
    level: int
    color: str
    badge_emoji: Optional[str] = None
    badge_image_url: Optional[str] = None
    description: Optional[str] = None
    benefits: List[Dict[str, Any]] = Field(default_factory=list)
    welcome_message: Optional[str] = None
    member_count: int = 0
    sort_order: int = 0
    active: bool = True
    created_at: int = 0
    updated_at: int = 0


class TierReorderIn(BaseModel):
    tier_ids: List[str] = Field(..., min_length=1, max_length=6)


class ChannelCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    min_tier_level: int = Field(..., ge=1, le=6)
    slowmode_seconds: int = Field(default=0, ge=0, le=3600)
    max_message_length: int = Field(default=500, ge=1, le=2000)


class ChannelOut(BaseModel):
    channel_id: str
    creator_id: str
    name: str
    description: Optional[str] = None
    min_tier_level: int = 1
    message_count: int = 0
    last_message_at: int = 0
    last_message_preview: Optional[str] = None
    pinned_message_id: Optional[str] = None
    slowmode_seconds: int = 0
    max_message_length: int = 500
    created_at: int = 0
    updated_at: int = 0


class ChannelMessageIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)
    reply_to_message_id: Optional[str] = None


class ChannelMessageOut(BaseModel):
    message_id: str
    channel_id: str
    sender_id: str
    sender_display_name: str
    sender_badge: Optional[Dict[str, Any]] = None
    text: str
    kind: str = "text"
    reply_to_message_id: Optional[str] = None
    reactions: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0
    deleted: bool = False


class MemberBadgeOut(BaseModel):
    tier_name: str
    tier_level: int
    badge_emoji: Optional[str] = None
    badge_color: Optional[str] = None
    badge_image_url: Optional[str] = None


# ─── Organizations / Workspaces (ENTERPRISE-003) ─────────────────

class OrgCreateReq(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    billing_mode: str = Field(default="individual", pattern=r"^(org|individual)$")


class OrgUpdateReq(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1024)
    billing_mode: Optional[str] = Field(default=None, pattern=r"^(org|individual)$")
    default_file_permission: Optional[str] = Field(default=None, pattern=r"^(viewer|editor|admin)$")


class OrgMemberInviteReq(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    org_role: str = Field(default="member", pattern=r"^(admin|member|viewer)$")


class OrgMemberRoleUpdateReq(BaseModel):
    org_role: str = Field(pattern=r"^(admin|member|viewer)$")


class OrgTransferOwnershipReq(BaseModel):
    new_owner_user_sub: str = Field(min_length=1)


class OrgInviteAcceptReq(BaseModel):
    token: str = Field(min_length=1)


class OrgOut(BaseModel):
    org_id: str
    name: str
    description: Optional[str] = None
    slug: str = ""
    owner_user_sub: str = ""
    status: str = "active"
    plan: str = "free"
    member_count: int = 0
    storage_used_bytes: int = 0
    storage_limit_bytes: int = 0
    billing_mode: str = "individual"
    created_at: int = 0
    updated_at: int = 0
    org_role: Optional[str] = None
    team_calendar_id: Optional[str] = None


class OrgMemberOut(BaseModel):
    user_sub: str
    org_role: str
    status: str
    joined_at: int = 0
    storage_used_bytes: int = 0
    last_active_at: Optional[int] = None


class OrgInviteOut(BaseModel):
    invite_id: str
    org_id: str
    org_name: str = ""
    email: str = ""
    org_role: str = "member"
    status: str = "pending"
    invited_by: str = ""
    created_at: int = 0
    expires_at: int = 0
    token: Optional[str] = None


class OrgEventCreateReq(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    start_time: str = Field(description="ISO 8601 datetime")
    end_time: str = Field(description="ISO 8601 datetime")
    all_day: bool = False
    attendees: Optional[list] = None


class OrgEventUpdateReq(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class OrgEventOut(BaseModel):
    event_id: str
    title: str
    description: Optional[str] = None
    start_time: str
    end_time: str
    all_day: bool = False
    created_by: str = ""
    org_id: str = ""
    attendees: list = Field(default_factory=list)
    created_at: int = 0
    updated_at: int = 0


# ─── Watch Parties (ENGAGE-004) ──────────────────────────────────────────────

class CreatePartyIn(BaseModel):
    video_id: str = Field(..., min_length=1)
    title: Optional[str] = Field(default=None, max_length=256)
    max_participants: int = Field(default=50, ge=2, le=500)


class PlaybackControlIn(BaseModel):
    action: str = Field(..., pattern="^(play|pause|seek)$")
    position: Optional[float] = None


class GrantCoHostIn(BaseModel):
    user_sub: str = Field(..., min_length=1)


class ParticipantOut(BaseModel):
    party_id: str
    user_sub: str
    role: str = "member"
    status: str = "active"
    joined_at: int = 0
    last_seen: Optional[int] = None


class PartyOut(BaseModel):
    party_id: str
    host_user_sub: str
    video_id: str
    video_title: str
    video_duration_seconds: int = 0
    title: str = ""
    invite_code: str = ""
    status: str = "waiting"
    max_participants: int = 50
    participant_count: int = 0
    position: float = 0
    position_updated_at: int = 0
    created_at: int = 0
    updated_at: int = 0
    ended_at: Optional[int] = None


class InviteResolveOut(BaseModel):
    party_id: str
    title: str
    host_user_sub: str
    video_title: str
    status: str
    participant_count: int = 0
    max_participants: int = 50


# ── Multi-Tenancy (ENTERPRISE-001) ──────────────────────────────────────────

class TenantCreateReq(BaseModel):
    slug: str = Field(min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    display_name: str = Field(min_length=1, max_length=256)
    plan: str = Field(default="starter", pattern=r"^(free|starter|enterprise)$")
    primary_domain: Optional[str] = None


class TenantUpdateReq(BaseModel):
    display_name: Optional[str] = None
    plan: Optional[str] = None
    status: Optional[str] = None
    branding: Optional[dict] = None
    settings_overrides: Optional[dict] = None


class TenantDomainAddReq(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


class TenantOut(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    status: str
    plan: str
    custom_domains: list = Field(default_factory=list)
    primary_domain: Optional[str] = None
    branding: Optional[dict] = None
    settings_overrides: Optional[dict] = None
    limits: Optional[dict] = None
    member_count: int = 0
    storage_used_bytes: int = 0
    created_at: int = 0
    updated_at: int = 0


class TenantBrandingOut(BaseModel):
    tenant_id: str
    display_name: str
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    primary_color: str = "#2563EB"
    accent_color: str = "#7C3AED"


class TenantInfoOut(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    status: str
    plan: str


# ─── Content Calendar (CREATOR-005) ──────────────────────────────────────

class ContentCalendarItem(BaseModel):
    """A single scheduled content item in the calendar."""
    id: str
    type: Literal["post", "broadcast", "vod"]
    title: str = Field(max_length=60)
    scheduled_at: int = Field(description="Unix timestamp of the scheduled publish time")
    timezone: Optional[str] = Field(default=None)
    local_time: Optional[str] = Field(default=None)
    status: str = Field(description="scheduled | overdue | cancelled")
    color: str = Field(description="Hex color code for display")
    icon: str = Field(description="Lucide icon name for display")

    # Post-specific fields
    has_images: bool = False
    has_video: bool = False
    visibility: Optional[str] = None
    locked: bool = False
    unlock_price_cents: int = 0

    # Broadcast-specific fields
    description: Optional[str] = None
    profile_id: Optional[str] = None
    has_announcement: bool = False

    # VOD-specific fields
    duration_seconds: Optional[float] = None
    thumbnail_url: Optional[str] = None


class ContentCalendarConflict(BaseModel):
    """A pair of items scheduled too close together."""
    item_a_id: str
    item_a_type: Literal["post", "broadcast", "vod"]
    item_b_id: str
    item_b_type: Literal["post", "broadcast", "vod"]
    gap_seconds: int
    gap_minutes: float


class ContentCalendarOut(BaseModel):
    """Response for the content calendar endpoint."""
    items: List[ContentCalendarItem] = Field(default_factory=list)
    from_ts: int
    to_ts: int
    count: int = 0
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)


class TodayAgendaOut(BaseModel):
    """Response for the today endpoint."""
    today: List[ContentCalendarItem] = Field(default_factory=list)
    tomorrow: List[ContentCalendarItem] = Field(default_factory=list)
    today_count: int = 0
    tomorrow_count: int = 0
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)


class ConflictsOut(BaseModel):
    """Response for the conflicts endpoint."""
    conflicts: List[ContentCalendarConflict] = Field(default_factory=list)
    count: int = 0


# --- Broadcast Clip Models (ENGAGE-005) ---

class CreateClipIn(BaseModel):
    start_seconds: float = Field(..., ge=0)
    end_seconds: float = Field(..., ge=0)
    title: Optional[str] = Field(default=None, max_length=100)


class ClipOut(BaseModel):
    clip_id: str
    session_id: str
    broadcaster_user_id: str
    creator_user_id: str
    creator_display_name: str
    video_id: str
    title: str
    start_seconds: float
    end_seconds: float
    duration_seconds: float
    status: Literal["processing", "ready", "failed", "deleted"]
    view_count: int
    share_count: int
    thumbnail_url: str
    created_at: int


class ClipListOut(BaseModel):
    clips: List[ClipOut]
    next_cursor: Optional[str] = None


class PublicClipOut(BaseModel):
    clip_id: str
    session_id: str
    broadcaster_user_id: str
    broadcaster_display_name: str
    profile_id: str
    creator_user_id: str
    creator_display_name: str
    video_id: str
    title: str
    start_seconds: float
    end_seconds: float
    duration_seconds: float
    status: Literal["processing", "ready", "failed", "deleted"]
    view_count: int
    share_count: int
    thumbnail_url: str
    created_at: int


# --- SSO / SAML Models (ENTERPRISE-002) ---

class SsoProviderCreateReq(BaseModel):
    display_name: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="saml", pattern=r"^(saml|oidc)$")
    tenant_id: str = Field(default="default")
    metadata_xml: Optional[str] = None
    sso_only: bool = False
    jit_provisioning_enabled: bool = True
    auto_update_profile: bool = True
    auto_update_role: bool = False
    default_role: str = Field(default="user", pattern=r"^(user|admin)$")
    allowed_email_domains: Optional[List[str]] = None


class SsoProviderOut(BaseModel):
    provider_id: str
    tenant_id: str
    protocol: str
    display_name: str
    status: str
    sso_only: bool
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    sp_entity_id: str = ""
    sp_acs_url: str = ""
    attribute_mappings: dict = {}
    role_mappings: list = []
    jit_provisioning_enabled: bool = True
    auto_update_profile: bool = True
    auto_update_role: bool = False
    default_role: str = "user"
    allowed_email_domains: Optional[List[str]] = None
    login_count: int = 0
    last_login_at: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0


class SsoInfoOut(BaseModel):
    sso_available: bool
    sso_only: bool
    sso_login_url: Optional[str] = None
    provider_display_name: Optional[str] = None
    provider_protocol: Optional[str] = None


# ─── Social / Follow System (SOC-001) ─────────────────────────────────


class FollowRequest(BaseModel):
    """Request body for POST /social/follow and POST /social/unfollow."""
    target_user_id: str = Field(..., min_length=1, max_length=128)

    @field_validator("target_user_id")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class FollowResponse(BaseModel):
    """Response for POST /social/follow."""
    ok: bool
    status: Literal["followed", "already_following"]
    follower_count: int = Field(ge=0)
    following_count: int = Field(ge=0)


class UnfollowResponse(BaseModel):
    """Response for POST /social/unfollow."""
    ok: bool
    status: Literal["unfollowed", "not_following"]


class FollowUser(BaseModel):
    """A user in a follower/following list."""
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    is_following: bool = False
    is_mutual: bool = False


class FollowListResponse(BaseModel):
    """Paginated list of followers or following."""
    items: List[FollowUser]
    next_cursor: Optional[str] = None
    total_count: int = Field(ge=0)


class FollowCountsResponse(BaseModel):
    """Follower and following counts for a user."""
    follower_count: int = Field(ge=0)
    following_count: int = Field(ge=0)


class FollowStatusResponse(BaseModel):
    """Bidirectional follow status between viewer and target."""
    is_following: bool
    is_followed_by: bool
    is_mutual: bool


# -- LLM Provider Keys (AGENT-001) --


class LlmKeyCreateIn(BaseModel):
    provider: str = Field(..., pattern=r"^(openai|anthropic|deepseek|gemini|elevenlabs|custom)$")
    label: str = Field(..., min_length=1, max_length=200)
    api_key: str = Field(..., min_length=8, max_length=500)
    base_url: str = Field(default="", max_length=500)
    model_preference: str = Field(default="", max_length=200)
    voice_preference: str = Field(default="", max_length=200)
    rate_limit_rpm: int = Field(default=60, ge=1, le=10000)
    monthly_budget_cents: int = Field(default=0, ge=0)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, v: str) -> str:
        # SSRF protection (GAP-0009): reject non-HTTPS / private-range URLs.
        # Reuses the existing webhook SSRF validator (blocks RFC-1918,
        # loopback, link-local; allows http://localhost only in dev mode).
        if not v:
            return v
        from app.services.webhook_ssrf import validate_webhook_url

        validate_webhook_url(v)  # raises ValueError on disallowed URL
        return v


class LlmKeyRotateIn(BaseModel):
    new_api_key: str = Field(..., min_length=8, max_length=500)


class LlmKeyAssignIn(BaseModel):
    worker_id: str = Field(..., min_length=1)


class LlmKeyOut(BaseModel):
    key_id: str
    user_id: str = ""
    provider: str
    label: str
    key_suffix: str = ""
    base_url: str = ""
    model_preference: str = ""
    voice_preference: str = ""
    available_models: List[str] = Field(default_factory=list)
    rate_limit_rpm: int = 60
    monthly_budget_cents: int = 0
    current_month_usage_cents: int = 0
    total_requests: int = 0
    total_tokens_used: int = 0
    status: str = "active"
    last_tested_at: int = 0
    last_used_at: int = 0
    created_at: int = 0
    updated_at: int = 0
    assigned_worker_ids: List[str] = Field(default_factory=list)


class LlmKeyListOut(BaseModel):
    keys: List[LlmKeyOut]
    count: int


class LlmKeyTestOut(BaseModel):
    ok: bool
    models: List[str] = Field(default_factory=list)
    error: str = ""
    latency_ms: int = 0


class LlmKeyUsageOut(BaseModel):
    key_id: str
    provider: str
    local_usage_cents: int = 0
    local_total_requests: int = 0
    local_total_tokens: int = 0
    provider_balance_cents: Optional[int] = None
    provider_usage_cents: Optional[int] = None
    budget_remaining_cents: Optional[int] = None


class LlmProviderInfo(BaseModel):
    provider: str
    display_name: str
    base_url: str
    models: List[str] = Field(default_factory=list)
    supports_usage_api: bool = False
    # MVA-001: TTS/STT capability metadata (ElevenLabs).
    stt_model: str = ""
    default_voice_id: str = ""


class LlmProviderListOut(BaseModel):
    providers: List[LlmProviderInfo]


# --- Messenger Voice & Translation AI (MVA-004 / MVA-007 / MVA-009) ---


class TranslateMessageRequest(BaseModel):
    target_lang: str = Field(..., min_length=2, max_length=35)


class TranslateMessageOut(BaseModel):
    translated_text: str
    source_lang: str = "auto"
    target_lang: str
    cached: bool = False


class TranscribeMessageOut(BaseModel):
    transcript: str
    transcript_lang: str = ""
    cached: bool = False


class TtsVoiceMessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    voice_id: str = Field(default="", max_length=200)
    model_id: str = Field(default="", max_length=200)
    reply_to_message_id: Optional[str] = None
    send_at: Optional[int] = None
# --- Advertiser Accounts & Campaigns (ADS-001) ---

class AdAccountOut(BaseModel):
    account_id: str
    owner_sub: str
    company_name: str
    billing_email: str
    status: str  # pending_review, active, suspended, rejected
    balance_cents: int = 0
    lifetime_spend_cents: int = 0
    created_at: int
    updated_at: int


class AdAccountReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject|suspend)$")
    notes: Optional[str] = Field(default=None, max_length=1000)


class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=3, max_length=320)


# Reasonable bid bounds (in cents):
# Floor: $0.50 CPM = 50 cents
# Ceiling: $200 CPM = 20000 cents
_BID_CPM_MIN = 50
_BID_CPM_MAX = 20_000
_BID_CPM_DEFAULT = 500  # $5.00 CPM default
# ADV-301: CPC/CPA bid bounds (cents). CPC $0.01..$100 default $0.50;
# CPA $0.01..$1000 default $5.00.
_BID_CPC_MIN = 1
_BID_CPC_MAX = 10_000
_BID_CPC_DEFAULT = 50
_BID_CPA_MIN = 1
_BID_CPA_MAX = 100_000
_BID_CPA_DEFAULT = 500


class CampaignCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., pattern=r"^(awareness|traffic|conversions)$")
    budget_cents: int = Field(..., ge=0)  # Minimum $1 for paid; 0 allowed for self-promo (ADV2-301)
    budget_type: str = Field(..., pattern=r"^(daily|lifetime)$")
    start_date: Optional[int] = None  # Unix timestamp
    end_date: Optional[int] = None    # Unix timestamp
    # Auction bid (GAP-0044): CPM bid in cents used by the serving engine to
    # rank candidates. Defaults to $5.00 so existing clients that omit the field
    # keep working; bounded to a sane range to prevent garbage bids.
    bid_cpm_cents: int = Field(
        default=_BID_CPM_DEFAULT, ge=_BID_CPM_MIN, le=_BID_CPM_MAX
    )
    # ADV-301: advertiser-set CPC/CPA bids (traffic/conversion objectives + auction).
    bid_cpc_cents: int = Field(
        default=_BID_CPC_DEFAULT, ge=_BID_CPC_MIN, le=_BID_CPC_MAX
    )
    bid_cpa_cents: int = Field(
        default=_BID_CPA_DEFAULT, ge=_BID_CPA_MIN, le=_BID_CPA_MAX
    )
    # Ad category for the campaign. Validated against the same VALID_AD_CATEGORIES
    # taxonomy that creators use for allowed_ad_categories (see CreatorAdSettingsIn)
    # so the serving-engine whitelist comparison is meaningful. "general" is the
    # default for campaigns that do not declare a category (treated as
    # uncategorized — only served when a creator imposes no whitelist).
    category: str = Field(default="general")

    @field_validator("category")
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


class CampaignOut(BaseModel):
    campaign_id: str
    account_id: str
    name: str
    objective: str
    budget_cents: int
    budget_type: str
    daily_budget_cents: int = 0
    spent_today_cents: int = 0
    lifetime_spent_cents: int = 0
    status: str
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    created_at: int
    updated_at: int
    category: str = "general"
    # GAP-0044: surface the auction bid so advertisers can audit their CPM.
    # Defaults to $5.00 for legacy items written before this attribute existed.
    bid_cpm_cents: int = _BID_CPM_DEFAULT
    # ADV-301: surface CPC/CPA bids for advertiser audit.
    bid_cpc_cents: int = _BID_CPC_DEFAULT
    bid_cpa_cents: int = _BID_CPA_DEFAULT
    # ADV2-301: surface the self-promo flavor.
    is_self_promo: bool = False
    self_promo_mode: str = "fill_only"


# -- Delegates (DELEGATE-001) --
# -- Delegate Management (DELEGATE-001) --

class DelegateAddIn(BaseModel):
    delegate_id: str = Field(min_length=1, max_length=255, description="User ID or email of the delegate")
    permissions: List[str] = Field(min_length=1, description="List of permission keys")
    preset: Optional[str] = Field(None, description="Permission preset key")
    label: str = Field(default="", max_length=200, description="Optional label for the delegate")


class DelegateUpdatePermissionsIn(BaseModel):
    permissions: List[str] = Field(min_length=1)
    preset: Optional[str] = None


class DelegateInviteRespondIn(BaseModel):
    accept: bool


class DelegateSettingsIn(BaseModel):
    require_acceptance: bool = True
    max_delegates: int = Field(default=10, ge=1, le=20)
    default_preset: Optional[str] = None
    delegate_tag_enabled: bool = True
    delegate_tag_format: str = Field(default="[via @{delegate_name}]", max_length=100)
    hide_delegate_from_recipients: bool = False


class DelegateOut(BaseModel):
    delegate_id: str
    creator_id: str
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    status: str = ""
    label: str = ""
    show_delegate_tag: bool = True
    delegate_tag_format: str = "[via @{delegate_name}]"
    invited_at: int = 0
    accepted_at: int = 0
    updated_at: int = 0


class ManagedCreatorOut(BaseModel):
    creator_id: str
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    status: str = ""
    label: str = ""
    accepted_at: int = 0


class DelegateSettingsOut(BaseModel):
    require_acceptance: bool = True
    max_delegates: int = 10
    default_preset: Optional[str] = None
    delegate_tag_enabled: bool = True
    delegate_tag_format: str = "[via @{delegate_name}]"
    hide_delegate_from_recipients: bool = False


class DelegateAuditOut(BaseModel):
    event_id: str
    actor_id: str
    actor_type: str = ""
    action: str = ""
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0


class PermissionPresetOut(BaseModel):
    key: str
    label: str
    permissions: List[str]


# -- Chat Delegation (DELEGATE-002) --

class DelegatedSendMessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    reply_to_message_id: Optional[str] = None

class DelegatedMessageOut(BaseModel):
    conversation_id: str
    message_id: str
    sender_id: str
    created_at: int = 0
    kind: str = "text"
    text: Optional[str] = None
    is_encrypted: bool = False
    sent_by_delegate: Optional[str] = None
    delegate_display_name: Optional[str] = None
    delegate_tag: Optional[str] = None
    delegate_cannot_decrypt: bool = False
    reply_to_message_id: Optional[str] = None

class DelegatedConversationOut(BaseModel):
    conversation_id: str
    type: str = "dm"
    title: Optional[str] = None
    created_at: int = 0
    last_message_at: int = 0
    last_message_preview: Optional[str] = None
    participant_count: int = 0
    status: str = "active"
    unread_count: int = 0
    participants: List[Dict[str, Any]] = Field(default_factory=list)

class ChatDelegateAuditEntry(BaseModel):
    event_id: str
    delegate_id: str
    conversation_id: str
    message_id: str = ""
    text_preview: str = ""
    delegate_display_name: str = ""
    created_at: int = 0


# -- Syndicates (SYND-001) --

class SyndicateCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)

class SyndicateUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)

class SyndicateInviteIn(BaseModel):
    user_id: str

class SyndicateInviteRespondIn(BaseModel):
    accept: bool

class SyndicateJoinRequestIn(BaseModel):
    message: str = Field(default="", max_length=500)

class SyndicateTransferAdminIn(BaseModel):
    new_admin_user_id: str

class SyndicateMemberOut(BaseModel):
    user_id: str
    display_name: str = ""
    role: str = "member"
    joined_at: int = 0

class SyndicateOut(BaseModel):
    syndicate_id: str
    name: str
    description: str = ""
    admin_user_id: str
    status: str = "active"
    member_count: int = 0
    created_at: int = 0
    updated_at: int = 0
    members: List[SyndicateMemberOut] = Field(default_factory=list)

class SyndicateInviteOut(BaseModel):
    syndicate_id: str
    syndicate_name: str = ""
    user_id: str
    invited_by: str
    invited_at: int = 0
    status: str

class SyndicateRequestOut(BaseModel):
    syndicate_id: str
    user_id: str
    display_name: str = ""
    requested_at: int = 0
    message: str = ""
    status: str

class SyndicateAuditOut(BaseModel):
    event_id: str
    actor_id: str
    action: str
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0
# -- User Groups (GROUP-001) --
# ── User Groups (GROUP-001) ──────────────────────────────────────────────────

class CreateGroupIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    description: str = Field(default="", max_length=2000)
    visibility: Literal["public", "private"] = "public"
    topic: Optional[str] = Field(default=None, max_length=50)

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Group name cannot be blank")
        return v.strip()


class UpdateGroupIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[Literal["public", "private"]] = None
    topic: Optional[str] = Field(default=None, max_length=50)

class GroupInviteIn(BaseModel):
    user_id: str


class GroupInviteResponseIn(BaseModel):
    accept: bool


class GroupReviewRequestIn(BaseModel):
    approved: bool


class GroupUpdateRoleIn(BaseModel):
    role: Literal["moderator", "member"]


class GroupOut(BaseModel):
    group_id: str
    name: str
    description: str = ""
    topic: Optional[str] = None
    visibility: str = "public"
    status: str = "active"
    admin_user_id: str
    admin_user_id: str = ""
    cover_image_url: Optional[str] = None
    member_count: int = 0
    created_at: int = 0
    updated_at: int = 0
    my_role: Optional[str] = None


class GroupMemberOut(BaseModel):
    user_id: str
    role: str = "member"
    status: str = "active"
    display_name: str = ""
    joined_at: Optional[int] = None
    promoted_at: Optional[int] = None


class GroupListOut(BaseModel):
    groups: List[GroupOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    has_more: bool = False

class GroupMemberListOut(BaseModel):
    members: List[GroupMemberOut] = Field(default_factory=list)
    count: int = 0
# ─── SSH Key Manager (INFRA-002) ──────────────────────────────────────────────

class UploadSshKeyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    private_key_pem: str = Field(..., min_length=50, max_length=16_384)
    passphrase: Optional[str] = Field(default=None, max_length=256)


class GenerateSshKeyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    key_type: str = Field(default="ed25519", pattern="^(rsa|ed25519)$")
    key_bits: int = Field(default=4096, ge=2048, le=8192)


class SshKeyOut(BaseModel):
    key_id: str
    label: str
    key_type: str
    key_bits: int
    public_key_openssh: str
    public_key_fingerprint: str
    passphrase_protected: bool
    created_at: int
    last_used_at: int
    associated_hosts: List[str] = []
    use_count: int = 0


class SshKeyListOut(BaseModel):
    keys: List[SshKeyOut]
    count: int


class PublicKeyOut(BaseModel):
    key_id: str
    public_key_openssh: str
    public_key_fingerprint: str


class AssociateKeyIn(BaseModel):
    host_id: str = Field(..., min_length=1)


# --- Ad Creatives (ADS-002) ---

class CampaignUpdateIn(BaseModel):
    name: Optional[str] = None
    objective: Optional[str] = None
    budget_cents: Optional[int] = None
    budget_type: Optional[str] = None
    status: Optional[str] = None
    # GAP-0044: bound the bid range on update to match creation validation.
    bid_cpm_cents: Optional[int] = Field(
        default=None, ge=_BID_CPM_MIN, le=_BID_CPM_MAX
    )
    # ADV-301: bound CPC/CPA on update to match creation validation.
    bid_cpc_cents: Optional[int] = Field(
        default=None, ge=_BID_CPC_MIN, le=_BID_CPC_MAX
    )
    bid_cpa_cents: Optional[int] = Field(
        default=None, ge=_BID_CPA_MIN, le=_BID_CPA_MAX
    )
    # ADV2-301: allow toggling the self-promo flavor/mode on update.
    is_self_promo: Optional[bool] = None
    self_promo_mode: Optional[str] = Field(default=None, pattern=r"^(fill_only|always_win)$")


class CampaignReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None


# ── Ad Creatives (ADS-002) ──────────────────────────────────────────
# ── Ad Creatives (ADS-002) ─────────────────────────────────────────────


class CtaActionIn(BaseModel):
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


class CreativeCreateIn(BaseModel):
    format: str = Field(..., pattern="^(native_post|image|video|carousel)$")
    title: str = Field(..., min_length=1, max_length=200)
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    alt_text: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    duration_seconds: Optional[int] = None
    skip_after_seconds: Optional[int] = None
    rotation_weight: int = Field(default=50, ge=0, le=100)
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
    ctas: Optional[List[CtaActionIn]] = Field(default=None, max_length=8)

    @field_validator("cta_url")
    @classmethod
    def validate_cta_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("CTA URL must start with http:// or https://")
        return v

    @field_validator("title")
    @classmethod
    def strip_title(cls, v: str) -> str:
        return v.strip()

    @field_validator("headline")
    @classmethod
    def strip_headline(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if v else v

    @field_validator("body_text")
    @classmethod
    def sanitize_body(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return re.sub(r"<script[^>]*>.*?</script>", "", v, flags=re.DOTALL | re.IGNORECASE).strip()


class CreativeUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    alt_text: Optional[str] = Field(default=None, max_length=200)
    rotation_weight: Optional[int] = Field(default=None, ge=0, le=100)
    skip_after_seconds: Optional[int] = Field(default=None, ge=0, le=30)
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
    ctas: Optional[List[CtaActionIn]] = Field(default=None, max_length=8)

    @field_validator("cta_url")
    @classmethod
    def validate_cta_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith(("http://", "https://")):
            raise ValueError("CTA URL must start with http:// or https://")
        return v


class CreativeOut(BaseModel):
    creative_id: str
    campaign_id: str
    account_id: str
    format: str
    title: str


class CreativeReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None


# ── Advertiser API (ADS-011) ────────────────────────────────────────
# Models for the programmatic, API-key-authenticated advertiser API
# (router prefix /api/v1/ads). These wrap the existing ad services.

class AdsApiCampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(default="awareness", pattern=r"^(awareness|traffic|conversions)$")
    budget_cents: int = Field(..., ge=100)  # minimum $1
    budget_type: str = Field(default="daily", pattern=r"^(daily|lifetime)$")
    start_date: Optional[int] = None
    end_date: Optional[int] = None


class AdsApiCampaignUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    budget_cents: Optional[int] = Field(default=None, ge=100)
    budget_type: Optional[str] = Field(default=None, pattern=r"^(daily|lifetime)$")
    status: Optional[str] = Field(default=None, pattern=r"^(draft|active|paused|archived)$")
    start_date: Optional[int] = None
    end_date: Optional[int] = None


class AdsApiBudgetUpdate(BaseModel):
    budget_cents: int = Field(..., ge=100)
    budget_type: Optional[str] = Field(default=None, pattern=r"^(daily|lifetime)$")


class AdsApiBulkAction(BaseModel):
    campaign_ids: List[str] = Field(..., min_length=1, max_length=100)
    action: str = Field(..., pattern=r"^(pause|resume|archive)$")


class AdsApiCreativeCreate(BaseModel):
    campaign_id: str = Field(..., min_length=1)
    format: str = Field(..., pattern="^(native_post|image|video|carousel)$")
    title: str = Field(..., min_length=1, max_length=200)
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    alt_text: Optional[str] = None
    rotation_weight: int = Field(default=50, ge=0, le=100)


class AdsApiCreativeUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    rotation_weight: Optional[int] = Field(default=None, ge=0, le=100)


# ── Ad Targeting (ADS-003) ──────────────────────────────────────────


# ── Ad Serving (ADS-004) ───────────────────────────────────────────


class AdServeRequestIn(BaseModel):
    """Request body for POST /ui/ads/serve."""
    surface: str = Field(..., pattern="^(newsfeed|broadcast|vod)$",
                         description="Ad surface: newsfeed, broadcast, or vod")
    content_type: str = Field(default="",
                              description="Content type: post, broadcast_session, video")
    creator_id: str = Field(..., min_length=1,
                            description="Creator who owns the content being viewed")
    content_id: str = Field(..., min_length=1,
                            description="ID of the content item")
    slot_type: str = Field(default="sponsored_post",
                           pattern="^(pre_roll|mid_roll|overlay|sponsored_post|broadcast_preroll|broadcast_midroll)$",
                           description="Type of ad slot within the surface")
    user_context: Optional[Dict[str, Any]] = Field(default=None,
                                                    description="Additional viewer context for targeting")
    content_owner_id: str = Field(default="",
                                  description="Sub of the content owner for CPA attribution; empty for standalone units")


class AdServeResponseOut(BaseModel):
    """Response from POST /ui/ads/serve."""
    filled: bool
    creative_id: Optional[str] = None
    format: Optional[str] = None
    title: str = ""
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    ctas: List[Dict[str, Any]] = Field(default_factory=list)
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    alt_text: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    duration_seconds: Optional[int] = None
    skip_after_seconds: int = 5
    rotation_weight: int = 50
    status: str
    review_notes: Optional[str] = None
    reviewed_by: Optional[str] = None
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
# ── Ad Feedback / Sponsored Posts (ADS-005) ──────────────────────────────


VALID_AD_FEEDBACK_TYPES = {"hide", "not_relevant", "repetitive", "offensive"}


class AdFeedbackIn(BaseModel):
    creative_id: str = Field(..., min_length=1, max_length=100)
    campaign_id: str = Field(default="", max_length=100)
    feedback_type: str = Field(..., min_length=1)
    reason: str = Field(default="", max_length=500)

    @field_validator("feedback_type")
    @classmethod
    def validate_feedback_type(cls, v: str) -> str:
        if v not in VALID_AD_FEEDBACK_TYPES:
            raise ValueError(f"Invalid feedback type: {v}. Must be one of {VALID_AD_FEEDBACK_TYPES}")
        return v


class WhyThisAdOut(BaseModel):
    reason: str
    categories: List[str]
    note: str


# ── Ad Targeting (ADS-003) ─────────────────────────────────────────────

VALID_AGE_RANGES = {"18-24", "25-34", "35-44", "45-54", "55+"}
VALID_GENDERS = {"male", "female", "other"}
VALID_DEVICE_TYPES = {"mobile", "desktop", "tablet"}
VALID_CONTENT_TYPES = {"newsfeed", "broadcast", "vod"}
VALID_AD_CATEGORIES = {
    "gaming", "music", "fitness", "beauty", "tech", "food", "travel",
    "finance", "education", "entertainment", "lifestyle", "sports",
}
_ISO_3166_PATTERN = re.compile(r"^[A-Z]{2}$")


class TargetingCreateIn(BaseModel):
    name: str = Field(default="Default", max_length=100)
    age_ranges: Optional[List[str]] = None
    genders: Optional[List[str]] = None
    country_codes: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    cities: Optional[List[str]] = None
    content_categories: Optional[List[str]] = None
    active_hours: Optional[List[int]] = None
    device_types: Optional[List[str]] = None
    new_user_only: bool = False
    creator_ids: Optional[List[str]] = None
    content_types: Optional[List[str]] = None
    exclude_creator_ids: Optional[List[str]] = None
    exclude_categories: Optional[List[str]] = None

    @field_validator("age_ranges")
    @classmethod
    def validate_age_ranges(cls, v):
        if v is None:
            return v
        for r in v:
            if r not in VALID_AGE_RANGES:
                raise ValueError(f"Invalid age range: {r}. Must be one of {VALID_AGE_RANGES}")
        return v

    @field_validator("genders")
    @classmethod
    def validate_genders(cls, v):
        if v is None:
            return v
        for g in v:
            if g not in VALID_GENDERS:
                raise ValueError(f"Invalid gender: {g}. Must be one of {VALID_GENDERS}")
        return v

    @field_validator("country_codes")
    @classmethod
    def validate_country_codes(cls, v):
        if v is None:
            return v
        for code in v:
            if not _ISO_3166_PATTERN.match(code):
                raise ValueError(f"Invalid country code: {code}. Must be ISO 3166-1 alpha-2")
        return v

    @field_validator("active_hours")
    @classmethod
    def validate_active_hours(cls, v):
        if v is None:
            return v
        for h in v:
            if not (0 <= h <= 23):
                raise ValueError(f"Active hour {h} out of range. Must be 0-23")
        return v

    @field_validator("device_types")
    @classmethod
    def validate_device_types(cls, v):
        if v is None:
            return v
        for d in v:
            if d not in VALID_DEVICE_TYPES:
                raise ValueError(f"Invalid device type: {d}. Must be one of {VALID_DEVICE_TYPES}")
        return v

    @field_validator("content_types")
    @classmethod
    def validate_content_types(cls, v):
        if v is None:
            return v
        for ct in v:
            if ct not in VALID_CONTENT_TYPES:
                raise ValueError(f"Invalid content type: {ct}. Must be one of {VALID_CONTENT_TYPES}")
        return v

    @field_validator("creator_ids")
    @classmethod
    def validate_creator_ids_limit(cls, v):
        if v is not None and len(v) > 100:
            raise ValueError("Maximum 100 creator IDs per targeting set")
        return v

    @field_validator("exclude_creator_ids")
    @classmethod
    def validate_no_contradictory_creators(cls, v, info):
        if v is None:
            return v
        creator_ids = info.data.get("creator_ids") or []
        overlap = set(v) & set(creator_ids)
        if overlap:
            raise ValueError(f"Cannot exclude and include the same creator: {overlap}")
        return v


class TargetingOut(BaseModel):
    target_set_id: str
    campaign_id: str
    name: str
    age_ranges: Optional[List[str]] = None
    genders: Optional[List[str]] = None
    country_codes: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    cities: Optional[List[str]] = None
    content_categories: Optional[List[str]] = None
    active_hours: Optional[List[int]] = None
    device_types: Optional[List[str]] = None
    new_user_only: bool = False
    creator_ids: Optional[List[str]] = None
    content_types: Optional[List[str]] = None
    exclude_creator_ids: Optional[List[str]] = None
    exclude_categories: Optional[List[str]] = None
    created_at: int
    updated_at: int


# -- Issued Licenses (LICENSE-002) --
# ─── Issued Licenses (LICENSE-002) ────────────────────────────────────────────

class IssueLicenseIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")
    license_mode: str = Field(description="One of: per_user, blanket")
    licensee_id: Optional[str] = Field(default=None, description="Required for per_user mode")
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)
    currency: str = Field(default="usd", max_length=3)
    title: str = Field(default="", max_length=200)
    thumbnail_url: str = Field(default="", max_length=500)
    expires_at: Optional[int] = None


class UpdateLicenseTermsIn(BaseModel):
    profit_share_pct: Optional[int] = Field(default=None, ge=0, le=100)
    fixed_cost_cents: Optional[int] = Field(default=None, ge=0)
    revenue_share_pct: Optional[int] = Field(default=None, ge=0, le=100)
    expires_at: Optional[int] = None


class RevokeLicenseIn(BaseModel):
    reason: str = Field(default="", max_length=500)


class IssuedLicenseOut(BaseModel):
    issued_license_id: str
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    licensee_id: Optional[str] = None
    license_mode: str
    status: str
    profit_share_pct: int = 0
    fixed_cost_cents: int = 0
    revenue_share_pct: int = 0
    currency: str = "usd"
    title: str = ""
    thumbnail_url: str = ""
    created_at: int = 0
    updated_at: int = 0
    expires_at: Optional[int] = None


class IssuedLicenseIndexItem(BaseModel):
    issued_license_id: str = ""
    content_id: str = ""
    licensee_id: Optional[str] = None
    license_mode: str = ""
    status: str = ""
    created_at: int = 0


class HeldLicenseOut(BaseModel):
    issued_license_id: str
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    status: str
    license_mode: str = "per_user"
    syndicate_id: Optional[str] = None
    terms_snapshot: Dict[str, Any] = Field(default_factory=dict)


class LibraryItemOut(BaseModel):
    content_id: str
    content_type: str
    licensor_id: str
    licensor_display_name: str = ""
    title: str = ""
    thumbnail_url: str = ""
    profit_share_pct: int = 0
    fixed_cost_cents: int = 0
    created_at: int = 0


class LicenseCheckOut(BaseModel):
    has_license: bool
    issued_license_id: Optional[str] = None
    license_mode: Optional[str] = None
    terms: Optional[Dict[str, Any]] = None
class AudienceEstimateOut(BaseModel):
    estimated_reach: int
    targeting_summary: dict


class CreatorAdSettingsIn(BaseModel):
    allow_ads: Optional[bool] = None
    allowed_ad_categories: Optional[List[str]] = None
    min_cpm_cents: Optional[int] = Field(default=None, ge=0)

    @field_validator("allowed_ad_categories")
    @classmethod
    def validate_ad_categories(cls, v):
        if v is None:
            return v
        for cat in v:
            if cat not in VALID_AD_CATEGORIES:
                raise ValueError(f"Invalid ad category: {cat}")
        return v


class CreatorAdSettingsOut(BaseModel):
    allow_ads: bool = True
    allowed_ad_categories: List[str] = Field(default_factory=list)
    min_cpm_cents: int = 0
    updated_at: Optional[int] = None


class AdBlockIn(BaseModel):
    account_id: str
    reason: str = ""

# -- Syndicate Bundled Subscriptions (SYND-002) --

class BundlePlanCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    price_cents: int = Field(ge=100, le=100000)
    interval: str = Field(default="month", pattern="^(month|year)$")

class BundlePlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: Optional[int] = Field(default=None, ge=100, le=100000)

    @model_validator(mode="before")
    @classmethod
    def at_least_one_field(cls, values):
        if isinstance(values, dict):
            non_none = {k: v for k, v in values.items() if v is not None}
            if not non_none:
                raise ValueError("At least one field must be provided")
        return values

class BundlePlanOut(BaseModel):
    plan_id: str
    plan_type: str = "syndicate_bundle"
    syndicate_id: str
    name: str
    description: str = ""
    price_cents: int = 0
    interval: str = "month"
    status: str = "active"
    included_creator_ids: List[str] = Field(default_factory=list)
    current_members: List[SyndicateMemberOut] = Field(default_factory=list)
    created_at: int = 0

class BundleSubscribeIn(BaseModel):
    payment_method_id: Optional[str] = None

class BundleSubscriptionOut(BaseModel):
    subscription_id: str
    plan_id: str
    plan_type: str = "syndicate_bundle"
    syndicate_id: str
    syndicate_name: str = ""
    status: str
    price_cents: int = 0
    interval: str = "month"
    current_period_start: int = 0
    current_period_end: int = 0
    created_at: int = 0
    cancelled_at: Optional[int] = None
    included_creators: List[SyndicateMemberOut] = Field(default_factory=list)
# ─── Media Preferences (CALL-003) ────────────────────────────────

class MediaPreferencesIn(BaseModel):
    preferred_audio_input_id: Optional[str] = None
    preferred_video_input_id: Optional[str] = None
    preferred_audio_output_id: Optional[str] = None
    default_audio_muted: bool = False
    default_video_off: bool = False
    video_resolution: Literal["360", "480", "720", "1080"] = "720"

class MediaPreferencesOut(BaseModel):
    user_sub: str
    preferred_audio_input_id: Optional[str] = None
    preferred_video_input_id: Optional[str] = None
    preferred_audio_output_id: Optional[str] = None
    default_audio_muted: bool = False
    default_video_off: bool = False
    video_resolution: str = "720"
    updated_at: int = 0
    skip_after_seconds: int = 5
    impression_url: Optional[str] = None
    click_url: Optional[str] = None
    skip_url: Optional[str] = None
    is_house_ad: bool = False
    campaign_id: Optional[str] = None
    promo_code_id: Optional[str] = None
    affiliate_link_id: Optional[str] = None
    fill_reason: Optional[str] = None


class AdTrackEventIn(BaseModel):
    """Request body for POST /ui/ads/track."""
    event: str = Field(..., pattern="^(impression|click|skip|complete)$")
    creative_id: str = Field(..., min_length=1)
    campaign_id: str = Field(..., min_length=1)
    account_id: str = Field(..., min_length=1)
    surface: str = Field(..., min_length=1)
    slot_type: str = Field(..., min_length=1)
    content_id: str = Field(..., min_length=1)
    creator_id: str = Field(..., min_length=1)
    # Fraud-detection signals (ADS-014). All optional; defaults are benign.
    view_time_ms: int = Field(default=0, ge=0)
    user_agent: str = ""
    geo_country: str = ""
    # ADV-303: per-serve ad_click_id minted by serve_ad; carries the cleared
    # auction price + content owner so track can bill the impression/click.
    ad_click_id: str = ""


class AdTrackEventOut(BaseModel):
    """Response from POST /ui/ads/track."""
    ok: bool
    event_id: str = ""
    flagged: bool = False
    fraud_score: int = 0
# ─── EC2 Instance Launcher (INFRA-003) ────────────────────────────────────────

class Ec2LaunchIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    instance_type: str = Field(..., min_length=1)
    ami_id: str = Field(..., min_length=1)
    ssh_key_id: Optional[str] = None
    auto_terminate_after: int = Field(default=7200, ge=600, le=86400)
    startup_script: str = Field(default="", max_length=16_384)
    template_id: Optional[str] = None
    security_group_id: Optional[str] = None  # INFRA-009: defaults to user's default SG


class Ec2InstanceOut(BaseModel):
    instance_id: str
    ec2_instance_id: str
    label: str
    instance_type: str
    ami_id: str
    ami_name: str
    status: str
    public_ip: str
    private_ip: str
    ssh_key_id: str = ""
    host_id: str = ""
    created_at: int = 0
    started_at: int = 0
    stopped_at: int = 0
    terminated_at: int = 0
    last_activity_at: int = 0
    auto_terminate_after: int = 7200


# ─── Kubernetes Container Launcher (INFRA-004) ──────────────────────────────

class K8sLaunchPodIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    image: str = Field(..., min_length=1)
    preset: Literal["small", "medium", "large", "xlarge"] = "small"
    ssh_key_id: Optional[str] = None
    ttl_seconds: int = Field(default=14400, ge=600, le=86400)
    env_vars: Dict[str, str] = Field(default_factory=dict)
    template_id: Optional[str] = None


class K8sPodOut(BaseModel):
    pod_id: str
    k8s_pod_name: str
    namespace: str
    label: str
    image: str
    image_display_name: str
    preset: str
    cpu_millicores: int
    memory_mb: int
    status: str
    pod_ip: str
    service_hostname: str
    ssh_port: int = 22
    ssh_key_id: str = ""
    host_id: str = ""
    created_at: int
    started_at: int = 0
    stopped_at: int = 0
    terminated_at: int = 0
    ttl_seconds: int = 14400
    expires_at: int = 0
    last_activity_at: int = 0
    auto_terminate_after: int = 7200


class Ec2InstanceListOut(BaseModel):
    instances: List[Ec2InstanceOut]
    count: int


class Ec2InstanceTypeInfo(BaseModel):
    instance_type: str
    vcpu: int = 0
    memory_gb: float = 0.0
    cost_cents_per_min: float = 0.0
    description: str = ""


# -- Agent Worker Provisioning (AGENT-002) --

# GAP-0078: shell metacharacters that must never appear in user-supplied worker
# install/verify commands (they would enable command injection once a prod
# provisioner embeds them in a shell / cloud-init script).
_WORKER_SHELL_METACHARS = re.compile(r"[;&|`$()<>\n\r]")
_WORKER_MAX_CUSTOM_CMDS = 20


class CreateWorkerIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    agent_type: str = Field(..., pattern=r"^(coder|qa|reviewer|devops|custom)$")
    tool: str = Field(..., pattern=r"^(claude_code|codex|custom)$")
    compute_type: str = Field(..., pattern=r"^(ec2|k8s)$")
    instance_type: str = Field(..., min_length=1)
    llm_key_id: str = Field(..., min_length=1)
    repo_url: str = Field(default="", max_length=500)
    branch_convention: str = Field(default="agent/{worker_id}/{ticket_id}", max_length=200)
    idle_timeout_seconds: int = Field(default=7200, ge=600, le=86400)
    template_id: str = Field(default="", max_length=100)
    custom_install_commands: Optional[List[str]] = None
    custom_env_var: str = Field(default="", max_length=100)
    custom_verify_command: str = Field(default="", max_length=500)

    # GAP-0078: these fields feed a (future) provisioner that may embed them in a
    # shell / cloud-init script. Reject shell metacharacters so arbitrary command
    # strings (`;`, `|`, `&`, backtick, `$()`, newline, redirects) can never be
    # stored, even though the current dev provisioner does not execute them.
    @field_validator("custom_install_commands")
    @classmethod
    def _validate_custom_install_commands(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        if len(v) > _WORKER_MAX_CUSTOM_CMDS:
            raise ValueError(f"At most {_WORKER_MAX_CUSTOM_CMDS} install commands allowed")
        for cmd in v:
            if _WORKER_SHELL_METACHARS.search(cmd):
                raise ValueError(
                    f"Install command contains forbidden shell metacharacters: {cmd[:40]!r}"
                )
        return v

    @field_validator("custom_verify_command")
    @classmethod
    def _validate_custom_verify_command(cls, v: str) -> str:
        if v and _WORKER_SHELL_METACHARS.search(v):
            raise ValueError(
                f"Verify command contains forbidden shell metacharacters: {v[:40]!r}"
            )
        return v

    @field_validator("custom_env_var")
    @classmethod
    def _validate_custom_env_var(cls, v: str) -> str:
        # Name of an env var only — no value/assignment/injection. Must be a
        # valid POSIX-ish shell identifier.
        if v and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v):
            raise ValueError(
                "custom_env_var must be a valid environment variable name "
                "([A-Za-z_][A-Za-z0-9_]*)"
            )
        return v


class ProvisionStepOut(BaseModel):
    step: str
    status: str
    ts: int
    detail: str = ""


class WorkerOut(BaseModel):
    worker_id: str
    user_id: str
    label: str
    agent_type: str
    tool: str
    tool_version: str = ""
    compute_type: str
    compute_instance_id: str = ""
    instance_type: str
    llm_key_id: str
    llm_provider: str = ""
    host_id: str = ""
    # AQA-002: SSH key injected during provisioning, used by the agent QA exec
    # engine to resolve credentials by id (never PEM). Empty when no key.
    ssh_key_id: str = ""
    public_ip: str = ""
    worker_status: str
    provision_log: List[ProvisionStepOut] = Field(default_factory=list)
    repo_url: str = ""
    branch_convention: str = ""
    idle_timeout_seconds: int = 7200
    last_activity_at: int = 0
    created_at: int = 0
    started_at: int = 0
    stopped_at: int = 0
    terminated_at: int = 0
    template_id: str = ""
    error_message: str = ""


class WorkerListOut(BaseModel):
    workers: List[WorkerOut]
    count: int


# --- Agent SSH QA actions (ADR-003 / AQA-003) ---


class RunAgentActionIn(BaseModel):
    """Submit a non-interactive SSH QA action for a worker.

    SECURITY: this request carries ONLY identifiers (`host_id`, `ssh_key_id`,
    `path_id`) — never a key, PEM, or password. Credentials are resolved
    server-side from the owner's KMS-encrypted store. A raw hostname is never
    accepted; the target is resolved from `host_id` via host inventory.
    """

    action_type: str = "run_command"  # run_command | run_test_suite
    command: str
    host_id: str = ""
    # Optional explicit key id; defaults to the worker's persisted ssh_key_id.
    ssh_key_id: str = ""
    # Optional multi-hop bastion path id (resolved server-side).
    path_id: str = ""
    timeout_seconds: int = 0  # 0 -> use the configured default cap


class AgentActionOut(BaseModel):
    action_id: str
    worker_id: str
    action_type: str = "run_command"
    host_id: str = ""
    command: str = ""
    status: str = "pending"  # pending|running|completed|failed|timed_out|cancelled|denied
    exit_code: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    error_code: str = ""
    error_message: str = ""
    created_at: int = 0
    started_at: int = 0
    finished_at: int = 0
    timeout_seconds: int = 0


class AgentActionListOut(BaseModel):
    actions: List[AgentActionOut]
    count: int


# --- Interactive Claude Code sessions (ACS-002 / ADR-002) ---


class CreateSessionIn(BaseModel):
    cols: int = 80
    rows: int = 24


class SessionOut(BaseModel):
    session_id: str
    worker_id: str
    user_id: str
    state: str
    created_at: int = 0
    started_at: int = 0
    ended_at: int = 0
    last_activity_at: int = 0
    cols: int = 80
    rows: int = 24
    claude_pid: int = 0
    error_message: str = ""
    # WS URL the dedicated agent-terminal frontend connects to (ACS-004).
    ws_path: str = "/api/agent-session/ws"


class SessionListOut(BaseModel):
    sessions: List[SessionOut]
    count: int


class ToolInfo(BaseModel):
    tool: str
    display_name: str
    description: str
    install_time_seconds: int
    required_provider: str


class ToolListOut(BaseModel):
    tools: List[ToolInfo]


class ComputeOption(BaseModel):
    compute_type: str
    instance_type: str
    vcpu: int
    memory_gb: float
    cost_cents_per_min: float


class Ec2InstanceTypeListOut(BaseModel):
    types: List[Ec2InstanceTypeInfo]


class Ec2AmiInfo(BaseModel):
    ami_id: str
    name: str
    os_type: str = ""
    username: str = ""


class K8sPodListOut(BaseModel):
    pods: List[K8sPodOut]
    count: int


class K8sPodLogsOut(BaseModel):
    pod_id: str
    lines: List[str]


class K8sImageInfo(BaseModel):
    image: str
    display_name: str
    os_type: str
    username: str


class Ec2AmiListOut(BaseModel):
    amis: List[Ec2AmiInfo]
# ─── Bot Auto-Reply (BOT-003) ────────────────────────────────────


class AutoReplyRuleIn(BaseModel):
    trigger_pattern: str = Field(..., min_length=1, max_length=500)
    response_template: str = Field(..., min_length=1, max_length=2000)
    match_type: Literal["keyword", "regex", "contains", "exact"] = "contains"
    priority: int = Field(default=100, ge=1, le=10000)
    enabled: bool = True


class AutoReplyRuleOut(BaseModel):
    rule_id: str
    bot_id: str
    creator_id: str
    trigger_pattern: str
    response_template: str
    match_type: str
    priority: int
    enabled: bool
    created_at: int
    updated_at: int
    match_count: int


class AutoReplyTestIn(BaseModel):
    message_text: str = Field(..., min_length=1, max_length=5000)


class AutoReplyTestOut(BaseModel):
    matched: bool
    first_match: Optional[Dict[str, Any]] = None
    all_matches: List[Dict[str, Any]] = Field(default_factory=list)
    match_count: int = 0


# ─── License Revenue (LICENSE-003) ─────────────────────────────────────────────


class RevenueSummaryOut(BaseModel):
    total_cents: int = 0
    total_transactions: int = 0
    last_transaction_at: Optional[int] = None
    currency: str = "usd"


class RevenueTransactionOut(BaseModel):
    txn_id: str
    issued_license_id: str = ""
    content_id: str = ""
    counterparty_id: str = ""
    source_type: str = ""
    source_amount_cents: int = 0
    split_amount_cents: int = 0
    split_type: str = ""
    currency: str = "usd"
    created_at: int = 0


class RevenueListOut(BaseModel):
    summary: RevenueSummaryOut
    transactions: List[RevenueTransactionOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class RevenueSplitPreviewOut(BaseModel):
    source_amount_cents: int = 0
    platform_fee_cents: int = 0
    revenue_share_cents: int = 0
    profit_share_cents: int = 0
    total_licensor_share_cents: int = 0
    licensee_net_cents: int = 0


class AdminRevenueEntryOut(BaseModel):
    txn_id: str = ""
    licensor_id: str = ""
    licensee_id: str = ""
    content_id: str = ""
    source_type: str = ""
    source_amount_cents: int = 0
    split_amount_cents: int = 0
    created_at: int = 0


class AdminRevenueListOut(BaseModel):
    transactions: List[AdminRevenueEntryOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# ── Group Feed (GROUP-002) ───────────────────────────────────────────────────

class CreateGroupPostIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    body_format: Literal["plain", "markdown", "richtext"] = "plain"
    image_url: Optional[str] = Field(default=None, max_length=2048)
    audience: Literal["public", "members_only"] = "public"
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)

    @field_validator("text")
    @classmethod
    def text_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Post text cannot be blank or whitespace-only")
        return v

    @field_validator("image_url")
    @classmethod
    def validate_image_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not (v.startswith("http://") or v.startswith("https://") or v.startswith("/mock/")):
            raise ValueError("Invalid image URL format")
        return v


class GroupFeedPostOut(BaseModel):
    post_id: str
    user_id: str
    user_display_name: str = ""
    user_avatar_url: Optional[str] = None
    text: Optional[str] = None
    body_format: str = "plain"
    image_url: Optional[str] = None
    group_id: str = ""
    audience: Literal["public", "members_only"] = "public"
    pinned: bool = False
    pinned_at: Optional[int] = None
    pinned_by: Optional[str] = None
    unlock_price_cents: Optional[int] = None
    unlocked: bool = True
    tip_total_cents: int = 0
    reactions_counts: Dict[str, int] = Field(default_factory=dict)
    my_reactions: List[str] = Field(default_factory=list)
    comment_count: int = 0
    created_at: int = 0
    updated_at: Optional[int] = None


class GroupFeedResponse(BaseModel):
    posts: List[GroupFeedPostOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    has_more: bool = False


class PinPostOut(BaseModel):
    post_id: str
    pinned: bool
    pinned_at: Optional[int] = None
    pinned_by: Optional[str] = None


class DeleteGroupPostOut(BaseModel):
    ok: bool = True
    post_id: str
    deleted_by: str
# ─── Activity Feed (SOC-003) ────────────────────────────────────


class ActivityOut(BaseModel):
    activity_id: str
    actor_id: str
    activity_type: str
    target_type: str = ""
    target_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0
    read: bool = False


class ActivityFeedResponse(BaseModel):
    items: List[ActivityOut]
    next_cursor: Optional[str] = None
    total_unread: int = 0


class MarkActivitiesReadIn(BaseModel):
    up_to_ts: Optional[int] = None
# -- Newsfeed Delegation (DELEGATE-003) --

class DelegatedPostCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    image_url: Optional[str] = None
    lock_price_cents: int = Field(default=0, ge=0)
    tags: List[str] = Field(default_factory=list)
    scheduled_at: Optional[int] = None


class DelegatedPostEditIn(BaseModel):
    text: Optional[str] = Field(None, min_length=1, max_length=10000)
    image_url: Optional[str] = None
    lock_price_cents: Optional[int] = Field(None, ge=0)
    tags: Optional[List[str]] = None


class DraftApprovalIn(BaseModel):
    note: str = Field(default="", max_length=500)


class CommentModerationIn(BaseModel):
    action: str = Field(description="hide | pin | unpin | delete")


class FeedDelegationSettingsIn(BaseModel):
    require_post_approval: bool = False
    allow_delegate_scheduling: bool = True
    allow_delegate_locking: bool = False
    delegate_tag_on_posts: bool = False
    delegate_tag_format: str = Field(default="[posted by @{delegate_name}]", max_length=100)


class DelegatedPostOut(BaseModel):
    post_id: str
    author_id: str
    text: str = ""
    image_url: Optional[str] = None
    lock_price_cents: int = 0
    tags: List[str] = Field(default_factory=list)
    status: str = "published"
    posted_by_delegate: Optional[str] = None
    delegate_display_name: Optional[str] = None
    delegate_tag: Optional[str] = None
    approval_status: Optional[str] = None
    approval_note: Optional[str] = None
    approved_at: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0


class FeedAnalyticsOut(BaseModel):
    period: str
    total_posts: int = 0
    total_views: int = 0
    total_likes: int = 0
    total_comments: int = 0
    engagement_rate: float = 0.0
    locked_post_revenue_cents: int = 0
    delegate_post_count: int = 0
    top_posts: List[Dict[str, Any]] = Field(default_factory=list)


class FeedDelegateAuditEntry(BaseModel):
    event_id: str
    delegate_id: str
    delegate_display_name: str = ""
    action: str = ""
    target_id: str = ""
    details: Optional[Dict[str, Any]] = None
    ts: int = 0


class FeedDelegationSettingsOut(BaseModel):
    require_post_approval: bool = False
    allow_delegate_scheduling: bool = True
    allow_delegate_locking: bool = False
    delegate_tag_on_posts: bool = False
    delegate_tag_format: str = "[posted by @{delegate_name}]"
# ─── Notification Engine (SOC-004) ────────────────────────────────


class NotificationOut(BaseModel):
    notification_id: str
    notification_type: str = ""
    title: str = ""
    body: str = ""
    data: Dict[str, Any] = Field(default_factory=dict)
    read: bool = False
    created_at: int = 0
    batch_key: Optional[str] = None
    batch_count: int = 1
    batch_actors: List[str] = Field(default_factory=list)


class NotificationListResponse(BaseModel):
    items: List[NotificationOut]
    next_cursor: Optional[str] = None
    unread_count: int = 0


class MarkNotificationsReadIn(BaseModel):
    notification_ids: List[str] = Field(default_factory=list)


class SendNotificationIn(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=256)
    notification_type: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=500)
    body: str = Field(default="", max_length=2000)
    data: Dict[str, Any] = Field(default_factory=dict)
    batch_key: Optional[str] = Field(default=None, max_length=256)
# ─── Call History (CALL-004) ─────────────────────────────────────

class CallRecordIn(BaseModel):
    caller_id: str
    callee_id: str
    call_type: Literal["audio", "video"]
    duration_seconds: int = Field(ge=0)
    status: Literal["completed", "missed", "declined", "failed"]


class CallRecordOut(BaseModel):
    call_id: str
    caller_id: str
    callee_id: str
    call_type: str
    duration_seconds: int = 0
    status: str = "completed"
    direction: str = "outgoing"
    created_at: int = 0


class CallHistoryResponse(BaseModel):
    items: List[CallRecordOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class CallStatsOut(BaseModel):
    total_calls: int = 0
    total_duration_seconds: int = 0
    calls_by_type: Dict[str, int] = Field(default_factory=dict)
    calls_by_status: Dict[str, int] = Field(default_factory=dict)
# ─── Risk Scoring (KYC-008) ─────────────────────────────────────────

class RiskScoreOut(BaseModel):
    score_id: str
    case_id: str
    user_sub: str
    total_score: int = Field(ge=0, le=100)
    risk_tier: str
    factors: dict
    trigger: str
    auto_action_taken: str = "none"
    model_version: str
    created_at: int
    previous_score: Optional[int] = None
    previous_tier: Optional[str] = None


class RiskFactorOut(BaseModel):
    factor_name: str
    score: int = Field(ge=0, le=100)
    weight: float
    weighted_score: float
    raw_value: str
    description: str


class RiskProfileOut(BaseModel):
    user_sub: str
    latest_score: Optional[RiskScoreOut] = None
    history: list = Field(default_factory=list)


class RiskOverrideIn(BaseModel):
    score: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1, max_length=500)


# ─── License Requests (LICENSE-004) ───────────────────────────────────────────

class LicenseTermsIn(BaseModel):
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)


class LicenseRequestCreateIn(BaseModel):
    content_id: str
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")
    owner_id: str
    proposed_terms: LicenseTermsIn
    message: str = Field(default="", max_length=1000)


class LicenseRequestDenyIn(BaseModel):
    reason: str = Field(default="", max_length=500)


class LicenseRequestCounterIn(BaseModel):
    counter_terms: LicenseTermsIn


class LicenseRequestOut(BaseModel):
    request_id: str
    content_id: str
    content_type: str
    requester_id: str
    requester_display_name: str = ""
    owner_id: str
    owner_display_name: str = ""
    status: str  # pending, approved, denied, negotiating, withdrawn, expired
    proposed_terms: Dict[str, Any] = Field(default_factory=dict)
    counter_terms: Optional[Dict[str, Any]] = None
    denial_reason: str = ""
    message: str = ""
    created_at: int = 0
    updated_at: int = 0
    expires_at: int = 0


class LicenseRequestApprovalOut(BaseModel):
    request: LicenseRequestOut
    issued_license: Optional[IssuedLicenseOut] = None


class LicenseRequestListOut(BaseModel):
    items: List[LicenseRequestOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
# -- Broadcast Delegation (DELEGATE-004) --

class BroadcastMuteIn(BaseModel):
    user_id: str
    duration_seconds: int = Field(ge=30, le=86400, description="Mute duration in seconds (30s to 24h)")


class BroadcastBanIn(BaseModel):
    user_id: str
    reason: str = Field(default="", max_length=500)


class BroadcastAnnouncementIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)


class BroadcastScheduleIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    scheduled_at: int = Field(description="Unix timestamp, must be in the future")
    profile_id: Optional[str] = None


class BroadcastModeratorOut(BaseModel):
    delegate_id: str
    display_name: str = ""
    connected_at: int = 0
    status: str = "online"
    actions_count: int = 0


class BroadcastBanOut(BaseModel):
    user_id: str
    banned_by: str
    banned_by_display_name: str = ""
    banned_at: int = 0
    reason: str = ""


class BroadcastModerationLogEntry(BaseModel):
    event_id: str
    moderator_id: str
    moderator_display_name: str = ""
    moderation_type: str = ""
    target_user_id: Optional[str] = None
    target_message_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ts: int = 0
class K8sImageListOut(BaseModel):
    images: List[K8sImageInfo]


class K8sPresetInfo(BaseModel):
    preset: str
    cpu_millicores: int
    memory_mb: int
    cost_cents_per_min: float


class K8sPresetListOut(BaseModel):
    presets: List[K8sPresetInfo]


# -- Ad Billing (ADS-007) --

class AdDepositIn(BaseModel):
    """Request body for POST /ui/ads/accounts/{id}/deposit."""
    amount_cents: int = Field(..., ge=1, le=10000000,
                              description="Deposit amount in cents ($100k maximum); the $50 "
                                          "minimum is enforced in the service so the client gets "
                                          "a 400 with a clear 'Minimum deposit' message")
    payment_method_id: str = Field(default="",
                                    description="Payment method ID from billing system")


class AdDepositOut(BaseModel):
    """Response from POST /ui/ads/accounts/{id}/deposit."""
    ok: bool
    entry_id: str
    new_balance_cents: int


class AdBillingEntryOut(BaseModel):
    """Single billing ledger entry."""
    entry_id: str
    account_id: str
    campaign_id: str
    entry_type: str
    amount_cents: int
    state: str
    reason: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    created_at: int


class AdInvoiceCampaignLine(BaseModel):
    """One campaign's line item in an invoice."""
    campaign_id: str
    impressions: int
    clicks: int
    conversions: int
    total_cents: int


class AdInvoiceOut(BaseModel):
    """Monthly invoice summary."""
    account_id: str
    month: str
    campaigns: List[AdInvoiceCampaignLine]
    total_charges_cents: int
    total_deposits_cents: int
    entry_count: int
# ---------------------------------------------------------------------------
# Group Treasury (GROUP-004)
# ---------------------------------------------------------------------------


class ContributeIn(BaseModel):
    amount_cents: int = Field(..., ge=100, le=10000000)


class SpendIn(BaseModel):
    amount_cents: int = Field(..., ge=1)
    reason: str = Field(..., min_length=3, max_length=500)
    category: Literal["ad_spend", "event", "premium_feature", "other"] = "ad_spend"
    reference_id: Optional[str] = Field(default=None, max_length=200)


class SetGoalIn(BaseModel):
    goal_cents: Optional[int] = Field(default=None, ge=0)


class TreasuryBalanceOut(BaseModel):
    balance_cents: int
    currency: str = "usd"
    total_contributed_cents: int
    total_donated_cents: int
    total_spent_cents: int
    fundraising_goal_cents: Optional[int] = None


class TreasuryLedgerEntry(BaseModel):
    entry_id: str
    amount_cents: int
    currency: str = "usd"
    direction: Literal["credit", "debit"]
    reason: str
    category: str
    actor_user_id: Optional[str] = None
    actor_display_name: Optional[str] = None
    reference_id: Optional[str] = None
    created_at: int


class TreasuryLedgerResponse(BaseModel):
    entries: List[TreasuryLedgerEntry]
    cursor: Optional[str] = None
    has_more: bool = False


class ContributorOut(BaseModel):
    user_id: str
    display_name: str
    total_contributed_cents: int
    contribution_count: int
    first_contributed_at: int
    last_contributed_at: int


class ContributorListResponse(BaseModel):
    contributors: List[ContributorOut]
    count: int


class ContributeResponse(BaseModel):
    ok: bool = True
    balance_cents: int
    personal_balance_cents: int
    contribution_total_cents: int
    ledger_entry_id: str


class SpendResponse(BaseModel):
    ok: bool = True
    balance_cents: int
    total_spent_cents: int
    ledger_entry_id: str
class ComputeOptionListOut(BaseModel):
    options: List[ComputeOption]


# -- Agent Orchestrator (AGENT-003) --

class TicketFilterConfig(BaseModel):
    types: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    space_ids: List[str] = Field(default_factory=list)
    priorities: List[str] = Field(default_factory=list)

class AgentStatusOut(BaseModel):
    worker_id: str
    agent_state: str = "idle"
    current_ticket_id: str = ""
    current_ticket_title: str = ""
    tickets_completed: int = 0
    tickets_failed: int = 0
    heartbeat_at: int = 0
    last_activity_at: int = 0
    ticket_filter: Optional[TicketFilterConfig] = None
    loop_running: bool = False

class AgentClaimOut(BaseModel):
    ticket_id: str
    worker_id: str
    claimed_at: int
    status: str
    checkpoint: str = ""

class EligibleTicketOut(BaseModel):
    ticket_id: str
    title: str = ""
    priority: str = ""
    type: str = ""
    tags: List[str] = Field(default_factory=list)
    space_id: str = ""
    created_at: int = 0

class EligibleTicketsOut(BaseModel):
    tickets: List[Dict[str, Any]]
    count: int
    filter_applied: Optional[TicketFilterConfig] = None

class CheckpointOut(BaseModel):
    ticket_id: str = ""
    checkpoint: Dict[str, Any] = Field(default_factory=dict)
    claimed_at: int = 0
# ── Ad Analytics (ADS-008) ─────────────────────────────────────────────────


class AdAnalyticsSummaryOut(BaseModel):
    impressions: int = 0
    clicks: int = 0
    ctr_pct: float = 0.0
    spend_cents: int = 0
    cpa_cents: float = 0
    effective_cpm_cents: float = 0.0
    completes: int = 0
    skips: int = 0
    completion_rate_pct: float = 0.0
    previous_period: Dict[str, int] = Field(default_factory=dict)
    impressions_change_pct: float = 0.0
    clicks_change_pct: float = 0.0
    spend_change_pct: float = 0.0
    days: int = 30


class AdTimeSeriesPointOut(BaseModel):
    date: str = ""
    impressions: int = 0
    clicks: int = 0
    spend_cents: int = 0
    completes: int = 0
    ctr_pct: float = 0.0


class AdBreakdownEntryOut(BaseModel):
    dimension_key: str = ""
    dimension: str = ""
    impressions: int = 0
    clicks: int = 0
    spend_cents: int = 0
    ctr_pct: float = 0.0


# ---------------------------------------------------------------------------
# Compute Cost Tracking (INFRA-005)
# ---------------------------------------------------------------------------

class ComputeBillingTickIn(BaseModel):
    resource_type: str = Field(..., pattern=r"^(ec2|k8s)$")
    resource_id: str = Field(..., min_length=1, max_length=128)
    resource_label: str = Field(default="", max_length=256)
    instance_type_or_preset: str = Field(..., min_length=1, max_length=64)
    duration_minutes: float = Field(..., gt=0, le=1440)


class ComputeBillingTickOut(BaseModel):
    ok: bool = True
    entry_id: str
    amount_cents: int
    wallet_balance_after: int
    rate_cents_per_min: float
    created_at: int


class SpendingSummaryOut(BaseModel):
    month: str
    total_cents: int
    budget_cents: int
    budget_pct: float
    ec2_total_cents: int
    k8s_total_cents: int
    resource_count: int


class BillingLedgerEntry(BaseModel):
    entry_id: str
    resource_type: str
    resource_id: str
    resource_label: str
    instance_type_or_preset: str
    event: str
    amount_cents: int
    duration_minutes: float
    rate_cents_per_min: float
    wallet_balance_after: int
    created_at: int


class BillingLedgerOut(BaseModel):
    entries: List[BillingLedgerEntry]
    count: int
    cursor: Optional[str] = None


class ResourceBreakdownEntry(BaseModel):
    resource_id: str
    resource_label: str
    resource_type: str
    instance_type_or_preset: str
    total_cents: int
    total_minutes: float
    status: str


class ResourceBreakdownOut(BaseModel):
    resources: List[ResourceBreakdownEntry]
    month: str


class BudgetOut(BaseModel):
    budget_monthly_cents: int
    alert_thresholds: List[int]
    current_month_total_cents: int
    current_month_pct: float


class UpdateBudgetIn(BaseModel):
    budget_monthly_cents: int = Field(..., ge=100, le=1_000_000)
    alert_thresholds: Optional[List[int]] = None

# -- Agent Fleet Management (AGENT-004) --

class WorkerSummary(BaseModel):
    worker_id: str
    label: str
    agent_type: str
    tool: str
    worker_status: str
    agent_state: str = "idle"
    current_ticket_id: str = ""
    current_ticket_title: str = ""
    uptime_seconds: int = 0
    estimated_cost_cents: int = 0
    tickets_completed: int = 0

class FleetStatusOut(BaseModel):
    total_workers: int = Field(ge=0)
    status_counts: Dict[str, int]
    queue_depth: int = Field(ge=0)
    workers: List[WorkerSummary]

class BulkActionOut(BaseModel):
    count: int
    errors: List[Dict[str, str]] = Field(default_factory=list)

class CapacityOut(BaseModel):
    queue_by_type: Dict[str, int]
    workers_by_type: Dict[str, int]
    workers_by_state: Dict[str, int]
    recommended_action: str = ""

class WorkerTemplateIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    agent_type: str = Field(..., min_length=1, max_length=50)
    tool: str = Field(..., min_length=1, max_length=50)
    compute_type: str = Field(..., min_length=1, max_length=50)
    instance_type: str = Field(..., min_length=1, max_length=100)
    llm_key_id: str = Field(..., min_length=1, max_length=100)
    repo_url: str = Field(default="", max_length=500)
    branch_convention: str = Field(default="", max_length=200)
    idle_timeout_seconds: int = Field(default=7200, ge=600, le=86400)
    ticket_filter: Optional[TicketFilterConfig] = None

class WorkerTemplateOut(BaseModel):
    template_id: str
    label: str
    agent_type: str
    tool: str
    compute_type: str
    instance_type: str
    llm_key_id: str
    repo_url: str = ""
    branch_convention: str = ""
    idle_timeout_seconds: int = 7200
    ticket_filter: Optional[Dict[str, Any]] = None
    created_at: int = 0

class WorkerTemplateListOut(BaseModel):
    templates: List[WorkerTemplateOut]
    count: int
# -- Agent Memory & Context Injection (AGENT-005) --


class AgentIdentityOut(BaseModel):
    agent_type: str
    identity_text: str
    custom_instructions: str = ""
    updated_at: int = 0


class AgentIdentityUpdateIn(BaseModel):
    identity_text: Optional[str] = None
    custom_instructions: Optional[str] = None


class ProjectContextOut(BaseModel):
    repo_url: str = ""
    branch_convention: str = ""
    coding_standards: str = ""
    pr_template: str = ""
    test_framework: str = ""
    ci_commands: str = ""
    file_structure_notes: str = ""
    updated_at: int = 0


class ProjectContextUpdateIn(BaseModel):
    repo_url: Optional[str] = Field(None, max_length=500)
    branch_convention: Optional[str] = Field(None, max_length=200)
    coding_standards: Optional[str] = Field(None, max_length=5000)
    pr_template: Optional[str] = Field(None, max_length=5000)
    test_framework: Optional[str] = Field(None, max_length=200)
    ci_commands: Optional[str] = Field(None, max_length=2000)
    file_structure_notes: Optional[str] = Field(None, max_length=5000)


class MemoryEntryIn(BaseModel):
    category: str = Field(..., pattern=r"^(learning|decision|pattern|error|custom)$")
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=10000)
    ticket_id: str = Field(default="", max_length=100)
    importance: int = Field(default=3, ge=1, le=5)


class MemoryEntryUpdateIn(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    content: Optional[str] = Field(None, min_length=1, max_length=10000)
    importance: Optional[int] = Field(None, ge=1, le=5)


class MemoryEntryOut(BaseModel):
    memory_id: str
    category: str
    title: str
    content: str
    ticket_id: str = ""
    importance: int = 3
    token_count: int = 0
    created_at: int = 0
    summarized: bool = False
    summary: str = ""


class MemoryListOut(BaseModel):
    entries: List[MemoryEntryOut]
    count: int
    total_tokens: int


class FullContextOut(BaseModel):
    context_text: str
    total_tokens: int
    sections: List[str]


class MemoryExportOut(BaseModel):
    worker_id: str
    exported_at: int
    identity: Optional[AgentIdentityOut] = None
    project_context: Optional[ProjectContextOut] = None
    memories: List[MemoryEntryOut] = Field(default_factory=list)


class MemoryImportIn(BaseModel):
    identity: Optional[Dict[str, Any]] = None
    project_context: Optional[Dict[str, Any]] = None
    memories: List[Dict[str, Any]] = Field(default_factory=list)


class MemoryImportOut(BaseModel):
    identity: bool = False
    project: bool = False
    memories: int = 0


class MemoryTemplateOut(BaseModel):
    agent_type: str
    identity_text: str
    description: str = ""
# -- Agent Feedback & Terminal Monitoring (AGENT-006) --


class FeedbackRequestOut(BaseModel):
    request_id: str
    worker_id: str
    ticket_id: str
    feedback_status: str  # pending, responded, timed_out, skipped
    question: str
    terminal_context: str = ""
    detected_pattern: str = ""
    response_text: str = ""
    responded_at: int = 0
    timeout_at: int = 0
    timeout_action: str = "skip"
    created_at: int = 0
    user_id: str = ""


class FeedbackListOut(BaseModel):
    requests: List[FeedbackRequestOut]
    count: int
    pending_count: int


class CreateFeedbackRequestIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=200)
    question: str = Field(..., min_length=1, max_length=5000)
    terminal_context: str = Field(default="", max_length=5000)
    detected_pattern: str = Field(default="", max_length=500)
    timeout_seconds: int = Field(default=14400, ge=60, le=86400)
    timeout_action: str = Field(default="skip")


class FeedbackRespondIn(BaseModel):
    response_text: str = Field(..., min_length=1, max_length=5000)


class TerminalOutputOut(BaseModel):
    worker_id: str
    output: str
    char_count: int


class TerminalSearchOut(BaseModel):
    worker_id: str
    keyword: str
    matches: List[str]
    match_count: int


class PatternConfigOut(BaseModel):
    agent_type: str
    completion: List[str]
    feedback_needed: List[str]
    error: List[str]


class PatternUpdateIn(BaseModel):
    completion: Optional[List[str]] = None
    feedback_needed: Optional[List[str]] = None
    error: Optional[List[str]] = None


class PatternTestIn(BaseModel):
    patterns: Dict[str, List[str]]
    sample_text: str = Field(..., min_length=1, max_length=10000)


class PatternTestOut(BaseModel):
    matches: List[Dict[str, str]]
    match_count: int


# ---------------------------------------------------------------------------
# Agent PR & Ticket Integration (AGENT-007)
# ---------------------------------------------------------------------------


class AgentPrCreateIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=200)
    repo_url: str = Field(default="", max_length=500)
    branch: str = Field(default="", max_length=200)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10000)
    files_changed: Optional[List[str]] = None
    method: str = Field(default="cli", pattern="^(cli|api)$")


class AgentPrOut(BaseModel):
    pr_id: str
    worker_id: str
    ticket_id: str
    repo_url: str = ""
    pr_url: str = ""
    pr_number: int = 0
    branch: str = ""
    title: str = ""
    description: str = ""
    files_changed: List[str] = Field(default_factory=list)
    commit_count: int = 0
    status: str = "open"
    created_at: int = 0
    merged_at: int = 0
    user_id: str = ""


class AgentPrListOut(BaseModel):
    prs: List[AgentPrOut]
    count: int


class WorkSummaryOut(BaseModel):
    ticket_id: str
    text: str
    files_changed: List[str] = Field(default_factory=list)
    decisions: List[str] = Field(default_factory=list)
    test_results: Dict[str, int] = Field(default_factory=dict)


class AgentCompletionOut(BaseModel):
    ticket_id: str
    summary: WorkSummaryOut
    pr: Optional[AgentPrOut] = None
    new_status: str
    next_agent_type: str = ""


class StatusFlowConfig(BaseModel):
    agent_type: str
    on_claim: str = "in_progress"
    on_working: str = "in_progress"
    on_complete: str = "code_complete"
    on_pr_created: str = "in_review"
    on_pr_merged: str = "done"
    next_agent_type: str = ""


class StatusFlowUpdateIn(BaseModel):
    on_claim: Optional[str] = Field(default=None, max_length=64)
    on_working: Optional[str] = Field(default=None, max_length=64)
    on_complete: Optional[str] = Field(default=None, max_length=64)
    on_pr_created: Optional[str] = Field(default=None, max_length=64)
    on_pr_merged: Optional[str] = Field(default=None, max_length=64)
    next_agent_type: Optional[str] = Field(default=None, max_length=64)


class AgentWorkCompleteIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=200)


class GithubWebhookResult(BaseModel):
    handled: bool
    action: str = ""
    reason: str = ""
    pr_url: str = ""
    ticket_id: str = ""
    review_state: str = ""
# Admin Compute Dashboard (INFRA-012)
# ---------------------------------------------------------------------------

class AdminInstanceOut(BaseModel):
    instance_id: str
    user_sub: str
    label: str
    instance_type: str
    ami_name: str
    status: str
    public_ip: str
    created_at: int
    last_activity_at: int
    auto_terminate_after: int


class AdminInstanceListOut(BaseModel):
    instances: List[AdminInstanceOut]
    count: int
    cursor: Optional[str] = None


class AdminPodOut(BaseModel):
    pod_id: str
    user_sub: str
    label: str
    image: str
    preset: str
    status: str
    pod_ip: str
    created_at: int
    ttl_seconds: int
    expires_at: int


class AdminPodListOut(BaseModel):
    pods: List[AdminPodOut]
    count: int
    cursor: Optional[str] = None


class ForceTerminateIn(BaseModel):
    reason: str = Field(default="", max_length=500)


class PlatformSpendingOut(BaseModel):
    month: str
    total_cents: int
    ec2_total_cents: int
    k8s_total_cents: int
    active_user_count: int
    active_instance_count: int
    active_pod_count: int


class PerUserSpendingEntry(BaseModel):
    user_sub: str
    total_cents: int
    ec2_cents: int
    k8s_cents: int
    instance_count: int
    pod_count: int


class PerUserSpendingOut(BaseModel):
    users: List[PerUserSpendingEntry]
    month: str


class InstanceTypeStatEntry(BaseModel):
    instance_type: str
    running_count: int
    total_launched: int


class InstanceTypeStatsOut(BaseModel):
    stats: List[InstanceTypeStatEntry]


class QuotaOut(BaseModel):
    user_sub: str
    max_ec2_instances: int
    max_k8s_pods: int
    max_monthly_spend_cents: int
    allowed_instance_types: List[str]
    allowed_k8s_presets: List[str]
    is_custom: bool
    updated_at: int = 0
    updated_by: str = ""
    notes: str = ""


class SetQuotaIn(BaseModel):
    max_ec2_instances: int = Field(default=3, ge=0, le=100)
    max_k8s_pods: int = Field(default=5, ge=0, le=100)
    max_monthly_spend_cents: int = Field(default=5000, ge=0, le=1_000_000)
    allowed_instance_types: List[str] = Field(default_factory=list)
    allowed_k8s_presets: List[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=500)
# Coder Agent (AGENT-008)
# ---------------------------------------------------------------------------


class CoderConfigIn(BaseModel):
    repo_url: str = Field(..., min_length=5, max_length=500)
    repo_branch_base: str = Field(default="main", max_length=100)
    branch_pattern: str = Field(default="feat/{ticket_id}-{slug}", max_length=200)
    test_commands: List[str] = Field(..., min_length=1, max_length=20)
    test_timeout_seconds: int = Field(default=600, ge=60, le=7200)
    test_retry_limit: int = Field(default=3, ge=0, le=10)
    pr_template: str = Field(default="Closes #{ticket_id}\n\n{summary}", max_length=5000)
    pr_base_branch: str = Field(default="main", max_length=100)
    skill_level: Literal["junior", "mid", "senior"] = "mid"
    max_ticket_time_seconds: int = Field(default=3600, ge=300, le=28800)
    complexity_labels: Optional[Dict[str, List[str]]] = None
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    pre_commands: Optional[List[str]] = Field(default=None, max_length=20)
    post_commands: Optional[List[str]] = Field(default=None, max_length=20)
    file_exclude_patterns: Optional[List[str]] = Field(default=None, max_length=50)

    @field_validator("repo_url")
    @classmethod
    def _validate_repo_url(cls, v: str) -> str:
        if not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("Repository URL must start with https:// or git@")
        if " " in v:
            raise ValueError("Repository URL must not contain spaces")
        return v

    @field_validator("branch_pattern")
    @classmethod
    def _validate_branch_pattern(cls, v: str) -> str:
        if "{ticket_id}" not in v:
            raise ValueError("Branch pattern must include {ticket_id} placeholder")
        if not re.match(r"^[a-zA-Z0-9_/{}\-]+$", v):
            raise ValueError("Branch pattern contains invalid characters")
        return v

    @field_validator("test_commands")
    @classmethod
    def _validate_test_commands(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one test command is required")
        for cmd in v:
            if not cmd.strip():
                raise ValueError("Test commands must not be empty strings")
            if len(cmd) > 500:
                raise ValueError("Individual test command must be <= 500 characters")
        return v

    @field_validator("complexity_labels")
    @classmethod
    def _validate_complexity_labels(cls, v: Optional[Dict[str, List[str]]]) -> Optional[Dict[str, List[str]]]:
        if v is None:
            return v
        allowed = {"junior", "mid", "senior"}
        for level in v:
            if level not in allowed:
                raise ValueError(f"Complexity label key must be one of {sorted(allowed)}")
            if not isinstance(v[level], list):
                raise ValueError(f"Complexity labels for {level} must be a list")
        return v


class CoderConfigOut(BaseModel):
    repo_url: str = ""
    repo_branch_base: str = "main"
    branch_pattern: str = "feat/{ticket_id}-{slug}"
    test_commands: List[str] = Field(default_factory=list)
    test_timeout_seconds: int = 600
    test_retry_limit: int = 3
    pr_template: str = "Closes #{ticket_id}\n\n{summary}"
    pr_base_branch: str = "main"
    skill_level: str = "mid"
    max_ticket_time_seconds: int = 3600
    complexity_labels: Optional[Dict[str, List[str]]] = None
    coding_tool: str = "claude_code"
    coding_tool_model: Optional[str] = None
    pre_commands: Optional[List[str]] = None
    post_commands: Optional[List[str]] = None
    file_exclude_patterns: Optional[List[str]] = None
    updated_at: Optional[int] = None


class CoderConfigValidationOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)


class TicketClaimIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)


class TestWorkflowIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)


class EligibleTicketOutCoder(BaseModel):
    ticket_id: str
    subject: str = ""
    labels: List[str] = Field(default_factory=list)
    complexity: Optional[str] = None
    estimated_effort_hours: Optional[int] = None
    created_at: int = 0


class EligibleTicketsOutCoder(BaseModel):
    tickets: List[EligibleTicketOutCoder] = Field(default_factory=list)
    count: int = 0


class CoderOutputOut(BaseModel):
    branch_name: str = ""
    pr_url: str = ""
    pr_number: int = 0
    files_changed: List[str] = Field(default_factory=list)
    files_added: List[str] = Field(default_factory=list)
    files_deleted: List[str] = Field(default_factory=list)
    insertions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    test_results: List[Dict[str, Any]] = Field(default_factory=list)
    test_retry_count: int = Field(default=0, ge=0)
    total_duration_seconds: int = Field(default=0, ge=0)
    escalated: bool = False
    escalation_reason: Optional[str] = None


class CoderMetricsOut(BaseModel):
    completed_count: int = Field(default=0, ge=0)
    avg_duration_seconds: float = Field(default=0, ge=0)
    failure_rate: float = Field(default=0, ge=0, le=1)
    escalation_rate: float = Field(default=0, ge=0, le=1)
    tickets_by_skill_level: Dict[str, int] = Field(default_factory=dict)
    period_start: int = 0
    period_end: int = 0


class TicketCreateCoderIn(BaseModel):
    subject: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=10000)
    labels: List[str] = Field(default_factory=list, max_length=20)
    space_id: Optional[str] = Field(default=None, max_length=100)
    estimated_effort_hours: Optional[int] = Field(default=None, ge=0, le=1000)


class WorkflowStepOut(BaseModel):
    step_id: int
    type: str
    command: Optional[str] = None
    timeout_seconds: int = 0
    on_failure: str = "next"


class WorkflowPreviewOut(BaseModel):
    steps: List[WorkflowStepOut] = Field(default_factory=list)
    branch_name: str = ""
    total_timeout_seconds: int = 0


# ---------------------------------------------------------------------------
# QA Agent (AGENT-009)
# ---------------------------------------------------------------------------


class QaConfigIn(BaseModel):
    test_framework: Literal["playwright", "cypress", "pytest"] = "playwright"
    browser: Literal["chromium", "firefox", "webkit"] = "chromium"
    test_dir: str = Field(default="frontend/e2e/", max_length=200)
    test_file_pattern: str = Field(default="{feature}.spec.ts", max_length=200)
    test_run_command: str = Field(default="cd frontend && npx playwright test", min_length=1, max_length=500)
    test_run_specific_command: str = Field(
        default="cd frontend && npx playwright test e2e/{file}", min_length=1, max_length=500
    )
    regression_scope: Literal["full", "affected", "none"] = "affected"
    regression_command: str = Field(default="just e2e", max_length=500)
    screenshot_enabled: bool = True
    screenshot_on_failure: bool = False
    screenshot_s3_prefix: str = Field(default="qa-screenshots/", max_length=200)
    visual_diff_threshold: float = Field(default=0.01, ge=0.0, le=1.0)
    max_test_time_seconds: int = Field(default=1800, ge=300, le=14400)
    flaky_retry_count: int = Field(default=2, ge=0, le=5)
    bug_ticket_space_id: Optional[str] = Field(default=None, max_length=100)
    pr_review_enabled: bool = True
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)


class QaConfigOut(BaseModel):
    test_framework: str = "playwright"
    browser: str = "chromium"
    test_dir: str = "frontend/e2e/"
    test_file_pattern: str = "{feature}.spec.ts"
    test_run_command: str = "cd frontend && npx playwright test"
    test_run_specific_command: str = "cd frontend && npx playwright test e2e/{file}"
    regression_scope: str = "affected"
    regression_command: str = "just e2e"
    screenshot_enabled: bool = True
    screenshot_on_failure: bool = False
    screenshot_s3_prefix: str = "qa-screenshots/"
    visual_diff_threshold: float = 0.01
    max_test_time_seconds: int = 1800
    flaky_retry_count: int = 2
    bug_ticket_space_id: Optional[str] = None
    pr_review_enabled: bool = True
    coding_tool: str = "claude_code"
    coding_tool_model: Optional[str] = None
    updated_at: Optional[int] = None


class QaConfigValidationOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)


# Solution Architect Agent (AGENT-011)
# ---------------------------------------------------------------------------


class ArchitectConfigIn(BaseModel):
    repo_url: str = Field(..., min_length=5, max_length=500)
    repo_branch: str = Field(default="main", max_length=100)
    reference_docs: List[str] = Field(default=["CLAUDE.md"], max_length=20)
    scan_paths: List[str] = Field(
        default=["app/services/", "app/routers/", "frontend/src/"], max_length=20
    )
    ticket_template: str = Field(default="", max_length=20000)
    architecture_guidelines: str = Field(default="", max_length=10000)
    tech_stack_constraints: Optional[Dict[str, str]] = None
    naming_conventions: Optional[Dict[str, str]] = None
    max_tickets_per_feature: int = Field(default=8, ge=1, le=20)
    target_ticket_space_id: Optional[str] = Field(default=None, max_length=100)
    complexity_estimation: Optional[Dict[str, float]] = None
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    max_analysis_time_seconds: int = Field(default=900, ge=120, le=3600)
    require_design_review: bool = False
    ticket_spec_style: Literal["full", "compact"] = "compact"

    @field_validator("repo_url")
    @classmethod
    def _validate_repo_url(cls, v: str) -> str:
        if not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("Repository URL must start with https:// or git@")
        if " " in v:
            raise ValueError("Repository URL must not contain spaces")
        return v

    @field_validator("reference_docs")
    @classmethod
    def _validate_reference_docs(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one reference document path is required")
        for p in v:
            if ".." in p:
                raise ValueError("Reference doc path must not traverse outside the repository")
        return v

    @field_validator("scan_paths")
    @classmethod
    def _validate_scan_paths(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one scan path is required")
        for p in v:
            if ".." in p:
                raise ValueError("Scan path must not traverse outside the repository")
        return v

    @field_validator("ticket_template")
    @classmethod
    def _validate_ticket_template(cls, v: str) -> str:
        if v:
            for placeholder in ("{subject}", "{overview}"):
                if placeholder not in v:
                    raise ValueError(f"Ticket template missing required placeholder: {placeholder}")
        return v


class ArchitectConfigOut(BaseModel):
    repo_url: str = ""
    repo_branch: str = "main"
    reference_docs: List[str] = Field(default_factory=list)
    scan_paths: List[str] = Field(default_factory=list)
    ticket_template: str = ""
    architecture_guidelines: str = ""
    tech_stack_constraints: Optional[Dict[str, str]] = None
    naming_conventions: Optional[Dict[str, str]] = None
    max_tickets_per_feature: int = 8
    target_ticket_space_id: Optional[str] = None
    complexity_estimation: Optional[Dict[str, float]] = None
    coding_tool: str = "claude_code"
    coding_tool_model: Optional[str] = None
    max_analysis_time_seconds: int = 900
    require_design_review: bool = False
    ticket_spec_style: str = "compact"
    updated_at: Optional[int] = None


class ArchitectConfigValidationOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)


# ─── DevOps/SRE Agent (AGENT-010) ───────────────────────────────────


class EnvironmentConfigIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    requires_approval: bool = False
    deploy_commands: List[str] = Field(..., min_length=1, max_length=50)
    rollback_commands: List[str] = Field(default_factory=list, max_length=50)
    health_check_urls: List[str] = Field(default_factory=list, max_length=20)
    health_check_timeout_seconds: int = Field(default=120, ge=10, le=600)
    smoke_test_command: Optional[str] = Field(default=None, max_length=1000)
    rollback_window_seconds: int = Field(default=300, ge=0, le=3600)
    env_vars: Optional[Dict[str, str]] = None

    @field_validator("health_check_urls")
    @classmethod
    def _validate_health_urls(cls, v: List[str]) -> List[str]:
        for url in v:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise ValueError("Health check URLs must be valid HTTP or HTTPS URLs")
        return v


class MonitoringEndpointIn(BaseModel):
    name: str = Field(..., max_length=100)
    url: str = Field(..., max_length=500)
    metric_type: str = Field(..., max_length=50)
    threshold: float = Field(ge=0)


class RunbookIn(BaseModel):
    trigger_label: str = Field(..., max_length=100)
    name: str = Field(..., max_length=200)
    steps: List[str] = Field(..., min_length=1, max_length=50)


class DevOpsConfigIn(BaseModel):
    environments: List[EnvironmentConfigIn] = Field(..., min_length=1, max_length=10)
    deploy_ticket_labels: List[str] = Field(default=["type:deployment"], max_length=20)
    infra_ticket_labels: List[str] = Field(default=["type:infrastructure"], max_length=20)
    incident_ticket_labels: List[str] = Field(default=["type:incident"], max_length=20)
    auto_deploy_on_qa_approved: bool = False
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    max_operation_time_seconds: int = Field(default=1800, ge=300, le=14400)
    incident_space_id: Optional[str] = None
    monitoring_endpoints: Optional[List[MonitoringEndpointIn]] = None
    runbooks: Optional[List[RunbookIn]] = None

    @field_validator("environments")
    @classmethod
    def _validate_unique_envs(cls, v: List[EnvironmentConfigIn]) -> List[EnvironmentConfigIn]:
        names = [e.name for e in v]
        if len(names) != len(set(names)):
            raise ValueError("Environment names must be unique")
        return v


class DevOpsConfigOut(BaseModel):
    type_id: str
    devops_config: DevOpsConfigIn
    updated_at: int


class DevOpsConfigValidationOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)


class QaScreenshotItem(BaseModel):
    name: str = ""
    s3_key: str = ""
    step: str = ""
    status: str = "pass"


class QaOutputOut(BaseModel):
    verdict: Literal["pass", "fail", "flaky", "error"]
    pr_url: str = ""
    pr_branch: str = ""
    ticket_id: str = ""
    acceptance_criteria_count: int = Field(default=0, ge=0)
    new_tests_written: int = Field(default=0, ge=0)
    new_test_file: str = ""
    new_tests_pass_count: int = Field(default=0, ge=0)
    new_tests_fail_count: int = Field(default=0, ge=0)
    regression_tests_run: int = Field(default=0, ge=0)
    regression_tests_pass: int = Field(default=0, ge=0)
    regression_tests_fail: int = Field(default=0, ge=0)
    regression_failures: List[str] = Field(default_factory=list)
    screenshots: List[QaScreenshotItem] = Field(default_factory=list)
    bug_ticket_ids: List[str] = Field(default_factory=list)
    pr_review_action: Literal["approved", "changes_requested", "none"] = "none"
    total_duration_seconds: int = Field(default=0, ge=0)
    flaky_tests: List[str] = Field(default_factory=list)


class QaReportOut(BaseModel):
    run_id: str
    verdict: str
    report_markdown: str
    generated_at: int


class QaScreenshotOut(BaseModel):
    name: str
    presigned_url: str
    step: str = ""
    status: str = "pass"


class QaScreenshotsOut(BaseModel):
    screenshots: List[QaScreenshotOut] = Field(default_factory=list)


class QaMetricsOut(BaseModel):
    tested_count: int = Field(default=0, ge=0)
    pass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    bugs_found_count: int = Field(default=0, ge=0)
    avg_duration_seconds: float = Field(default=0.0, ge=0.0)
    flaky_test_rate: float = Field(default=0.0, ge=0.0, le=1.0)
class DeploymentApprovalIn(BaseModel):
    approved: bool = True
    approver_notes: Optional[str] = Field(default=None, max_length=2000)


class DeploymentApprovalOut(BaseModel):
    run_id: str
    deployment_id: str
    approval_status: Literal["approved", "rejected"]
    approved_by: str
    approved_at: int
    notes: Optional[str] = None


class HealthCheckResult(BaseModel):
    url: str
    status_code: int
    response_time_ms: int
    healthy: bool


class SmokeTestResult(BaseModel):
    command: str
    exit_code: int
    passed: bool


class DeploymentLogStepOut(BaseModel):
    step_number: int
    step_type: str
    command: str
    exit_code: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    started_at: int = 0
    completed_at: int = 0
    duration_seconds: int = 0
    status: str = "success"


class DeploymentLogOut(BaseModel):
    deployment_id: str
    environment: str
    steps: List[DeploymentLogStepOut] = Field(default_factory=list)


class DevOpsOutputOut(BaseModel):
    deployment_id: str
    ticket_id: str = ""
    environment: str
    operation_type: str
    status: str
    version_deployed: Optional[str] = None
    steps_total: int = Field(default=0, ge=0)
    steps_completed: int = Field(default=0, ge=0)
    health_check_results: List[HealthCheckResult] = Field(default_factory=list)
    smoke_test_result: Optional[SmokeTestResult] = None
    rollback_executed: bool = False
    rollback_success: Optional[bool] = None
    incident_ticket_id: Optional[str] = None
    total_duration_seconds: int = Field(default=0, ge=0)
    approval_received_at: Optional[int] = None
    monitoring_snapshot: Optional[Dict[str, Any]] = None


class DevOpsMetricsOut(BaseModel):
    deployment_frequency: float = Field(default=0, ge=0)
    success_rate: float = Field(default=0, ge=0, le=1)
    mttr_seconds: float = Field(default=0, ge=0)
    rollback_rate: float = Field(default=0, ge=0, le=1)
    incidents_count: int = Field(default=0, ge=0)
    period_start: int = 0
    period_end: int = 0


class QaEligibleTicketOut(BaseModel):
    ticket_id: str
    subject: str = ""
    status: str = ""
    pr_url: Optional[str] = None
    pr_branch: Optional[str] = None
    created_at: int = 0
    labels: List[str] = Field(default_factory=list)


class QaEligibleTicketsOut(BaseModel):
    tickets: List[QaEligibleTicketOut] = Field(default_factory=list)
    count: int = 0


class QaWorkflowStepOut(BaseModel):
    step_id: int
    type: str
    command: Optional[str] = None
    timeout_seconds: int = 0
    on_failure: str = "next"


class DevOpsEligibleTicketOut(BaseModel):
    ticket_id: str
    subject: str = ""
    labels: List[str] = Field(default_factory=list)
    operation_type: str = "deployment"
class ArchitectEligibleTicketOut(BaseModel):
    ticket_id: str
    subject: str = ""
    labels: List[str] = Field(default_factory=list)
    status: str = "open"
    created_at: int = 0


class DevOpsEligibleTicketsOut(BaseModel):
    tickets: List[DevOpsEligibleTicketOut] = Field(default_factory=list)
    count: int = 0


class DevOpsDeploymentRowOut(BaseModel):
    run_id: str = ""
    agent_type_id: str = ""
    deployment_id: str = ""
    ticket_id: str = ""
    environment: str = ""
    status: str = ""
    version_deployed: Optional[str] = None
    total_duration_seconds: int = 0
    created_at: int = 0


class DevOpsDeploymentsOut(BaseModel):
    deployments: List[DevOpsDeploymentRowOut] = Field(default_factory=list)
    count: int = 0


class DevOpsWorkflowStepOut(BaseModel):
    step_id: int
    type: str
    command: Optional[str] = None
    timeout_seconds: int = 0
    on_failure: str = "next"


class ArchitectEligibleTicketsOut(BaseModel):
    tickets: List[ArchitectEligibleTicketOut] = Field(default_factory=list)
    count: int = 0


class TestArchitectWorkflowIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)


class ArchitectWorkflowStepOut(BaseModel):
    step_id: int
    type: str
    command: Optional[str] = None
    timeout_seconds: int = 0
    on_failure: str = "next"


class QaWorkflowPreviewOut(BaseModel):
    steps: List[QaWorkflowStepOut] = Field(default_factory=list)
    new_test_file: str = ""
    pr_branch: str = ""
    total_timeout_seconds: int = 0


class QaClaimIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)


class QaExecuteIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)
    scenario: Literal["pass", "fail", "flaky", "error"] = "fail"
class DevOpsWorkflowPreviewOut(BaseModel):
    steps: List[DevOpsWorkflowStepOut] = Field(default_factory=list)
    environment: str = ""
    operation_type: str = "deployment"
    requires_approval: bool = False
    total_timeout_seconds: int = 0


class DevOpsTestWorkflowIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)
    environment_name: Optional[str] = Field(default=None, max_length=50)
    version: Optional[str] = Field(default=None, max_length=100)


class DevOpsExecuteWorkflowIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)
    environment_name: Optional[str] = Field(default=None, max_length=50)
    version: Optional[str] = Field(default=None, max_length=100)
    force_health_failure: bool = False


class TicketCreateDevOpsIn(BaseModel):
    subject: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=10000)
    labels: List[str] = Field(default_factory=list, max_length=20)
    space_id: Optional[str] = None


class ArchitectWorkflowPreviewOut(BaseModel):
    steps: List[ArchitectWorkflowStepOut] = Field(default_factory=list)
    feature_ticket_id: str = ""
    require_design_review: bool = False
    total_timeout_seconds: int = 0


class DevTicketSummaryOut(BaseModel):
    ticket_id: str
    subject: str = ""
    complexity: str = "medium"
    estimated_hours: float = 0
    order: int = 0
    depends_on: List[str] = Field(default_factory=list)
    ticket_type: str = "development"


class DecompositionOut(BaseModel):
    feature_ticket_id: str
    decomposition_summary: str = ""
    total_tickets_created: int = 0
    total_estimated_hours: float = 0
    dependency_graph: Dict[str, List[str]] = Field(default_factory=dict)
    tickets: List[DevTicketSummaryOut] = Field(default_factory=list)


class DevTicketListOut(BaseModel):
    tickets: List[DevTicketSummaryOut] = Field(default_factory=list)
    count: int = 0


class DependencyGraphNodeOut(BaseModel):
    id: str
    subject: str = ""
    complexity: str = "medium"
    order: int = 0
    status: Optional[str] = "open"


class DependencyGraphEdgeOut(BaseModel):
    from_: str = Field(..., alias="from")
    to: str

    model_config = {"populate_by_name": True}


class DependencyGraphOut(BaseModel):
    nodes: List[DependencyGraphNodeOut] = Field(default_factory=list)
    edges: List[DependencyGraphEdgeOut] = Field(default_factory=list)


class ArchitectOutputOut(BaseModel):
    feature_ticket_id: str = ""
    decomposition_summary: str = ""
    tickets_created: List[DevTicketSummaryOut] = Field(default_factory=list)
    total_tickets: int = 0
    total_estimated_hours: float = 0
    dependency_graph: Dict[str, List[str]] = Field(default_factory=dict)
    codebase_analysis: Dict[str, Any] = Field(default_factory=dict)
    design_decisions: List[Dict[str, Any]] = Field(default_factory=list)
    feedback_requested: bool = False
    feedback_response: Optional[str] = None
    total_duration_seconds: int = 0


class ArchitectMetricsOut(BaseModel):
    features_decomposed: int = 0
    avg_tickets_per_feature: float = 0
    avg_hours_per_feature: float = 0
    decomposition_rate: float = 0
    period_start: int = 0
    period_end: int = 0


class TicketCreateFeatureIn(BaseModel):
    subject: str = Field(..., min_length=1, max_length=300)
    description: str = Field(default="", max_length=10000)
    labels: List[str] = Field(default_factory=lambda: ["type:feature_request"], max_length=20)
    space_id: Optional[str] = Field(default=None, max_length=100)


# ---------------------------------------------------------------------------
# Documentation Agent (AGENT-014)
# ---------------------------------------------------------------------------


class RegisterDocIn(BaseModel):
    doc_path: str = Field(..., min_length=1, max_length=500)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme", "inline"]
    source_refs: List[str] = Field(default_factory=list, max_length=50)
    coverage_score: float = Field(default=1.0, ge=0.0, le=1.0)


class UpdateDocIn(BaseModel):
    source_refs: Optional[List[str]] = Field(default=None, max_length=50)
    coverage_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AssessPrIn(BaseModel):
    changed_files: List[str] = Field(..., min_length=1, max_length=200)


class DocCoverageOut(BaseModel):
    doc_path: str
    doc_type: str
    source_refs: List[str]
    coverage_score: float
    is_stale: bool
    stale_since: Optional[int] = None
    last_verified: int
    last_updated: int
    created_at: int


class DocCoverageDetailsOut(BaseModel):
    docs: List[DocCoverageOut]
    count: int


class DocCoverageSummaryOut(BaseModel):
    overall_coverage: float = Field(ge=0.0, le=1.0)
    total_docs: int = Field(ge=0)
    stale_docs: int = Field(ge=0)
    by_type: Dict[str, dict]


class StaleDocOut(BaseModel):
    doc_path: str
    doc_type: str
    changed_sources: List[str]
    stale_since: int


class FreshnessCheckOut(BaseModel):
    total: int
    stale: int
    fresh: int
    stale_docs: List[StaleDocOut]
    checked_at: int


class StaleDocsListOut(BaseModel):
    docs: List[DocCoverageOut]
    count: int


class PrImpactOut(BaseModel):
    docs_to_update: List[DocCoverageOut]
    uncovered_files: List[str]
    impact_level: Literal["none", "low", "medium", "high"]


class CreateDocTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme"]
    template_body: str = Field(..., min_length=1, max_length=10000)
    required_sections: List[str] = Field(default_factory=list, max_length=20)


class UpdateDocTemplateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    doc_type: Optional[Literal["api", "architecture", "user_guide", "adr", "readme"]] = None
    template_body: Optional[str] = Field(default=None, min_length=1, max_length=10000)
    required_sections: Optional[List[str]] = Field(default=None, max_length=20)


class DocTemplateOut(BaseModel):
    template_id: str
    name: str
    doc_type: str
    template_body: str
    required_sections: List[str]
    created_at: int


class DocTemplatesListOut(BaseModel):
    templates: List[DocTemplateOut]
    count: int


class DocAgentConfigOut(BaseModel):
    trigger_on_pr_merge: bool
    freshness_check_frequency: str
    freshness_check_hour_utc: int
    doc_format: str
    doc_root: str
    min_coverage_threshold: float
    create_tickets_for_inline_docs: bool
    inline_doc_target_agent_type: str
    ignored_paths: List[str]
    model_config = ConfigDict(extra="allow")


class UpdateDocConfigIn(BaseModel):
    trigger_on_pr_merge: Optional[bool] = None
    freshness_check_frequency: Optional[Literal["hourly", "daily", "weekly"]] = None
    freshness_check_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    min_coverage_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    create_tickets_for_inline_docs: Optional[bool] = None
    ignored_paths: Optional[List[str]] = Field(default=None, max_length=50)


class CreateInlineDocTicketIn(BaseModel):
    source_file: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=5000)
# Product Manager Agent (AGENT-013)
# ---------------------------------------------------------------------------


class PmIdeaCategory(str, Enum):
    UX = "ux"
    FEATURE = "feature"
    PERFORMANCE = "performance"
    INTEGRATION = "integration"
    MONETIZATION = "monetization"
    ACCESSIBILITY = "accessibility"


class PmIdeaPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PmIdeaStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class PmEvidenceItem(BaseModel):
    type: str = Field(max_length=50)
    url: Optional[str] = Field(default=None, max_length=500)
    description: str = Field(default="", max_length=500)


class PmCompetitorRef(BaseModel):
    url: str = Field(max_length=500)
    feature: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=500)


class CreateFeatureIdeaIn(BaseModel):
    agent_id: str = Field(default="pm-agent", max_length=200)
    worker_id: str = Field(default="", max_length=200)
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    category: PmIdeaCategory
    priority_suggestion: PmIdeaPriority
    user_impact: str = Field(default="", max_length=1000)
    mockup_description: Optional[str] = Field(default=None, max_length=2000)
    evidence: Optional[List[PmEvidenceItem]] = None
    competitor_refs: Optional[List[PmCompetitorRef]] = None
    support_ticket_refs: Optional[List[str]] = None


class FeatureIdeaOut(BaseModel):
    idea_id: str
    user_id: str
    agent_id: str
    title: str
    description: str
    category: PmIdeaCategory
    priority_suggestion: PmIdeaPriority
    user_impact: str
    mockup_description: Optional[str] = None
    evidence: Optional[List[PmEvidenceItem]] = None
    competitor_refs: Optional[List[PmCompetitorRef]] = None
    support_ticket_refs: Optional[List[str]] = None
    status: PmIdeaStatus
    rejection_reason: Optional[str] = None
    created_ticket_id: Optional[str] = None
    created_at: int
    reviewed_at: Optional[int] = None


class FeatureIdeaListOut(BaseModel):
    ideas: List[FeatureIdeaOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class RejectIdeaIn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class PreferenceSummaryOut(BaseModel):
    category: str
    total_suggested: int = Field(ge=0)
    total_approved: int = Field(ge=0)
    total_rejected: int = Field(ge=0)
    approval_rate: float = Field(ge=0.0, le=1.0)


class PreferenceSummaryListOut(BaseModel):
    preferences: List[PreferenceSummaryOut] = Field(default_factory=list)


class UpdatePmConfigIn(BaseModel):
    review_frequency: Optional[Literal["daily", "weekly", "biweekly"]] = None
    review_day: Optional[
        Literal["monday", "tuesday", "wednesday", "thursday", "friday"]
    ] = None
    review_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    focus_areas: Optional[List[str]] = None
    competitor_urls: Optional[List[Dict[str, Any]]] = None
    max_ideas_per_review: Optional[int] = Field(default=None, ge=1, le=20)
    analyze_support_tickets: Optional[bool] = None
    support_ticket_lookback_days: Optional[int] = Field(default=None, ge=1, le=90)
    app_url: Optional[str] = Field(default=None, max_length=500)


class PmAgentConfigOut(BaseModel):
    review_frequency: str
    review_day: Optional[str] = None
    review_hour_utc: int
    focus_areas: List[str] = Field(default_factory=list)
    competitor_urls: List[Dict[str, Any]] = Field(default_factory=list)
    max_ideas_per_review: int
    analyze_support_tickets: bool
    support_ticket_lookback_days: int
    app_url: Optional[str] = None


class TriggerReviewIn(BaseModel):
    agent_id: str = Field(default="pm-agent", max_length=200)
    count: int = Field(default=3, ge=1, le=20)


class TriggerReviewOut(BaseModel):
    ok: bool
    agent_id: str
    ideas_created: int
    ideas: List[FeatureIdeaOut] = Field(default_factory=list)
    completed_at: int


class ReviewSessionOut(BaseModel):
    review_id: str
    agent_id: str
    worker_id: str = ""
    ideas_count: int = 0
    screenshots_count: int = 0
    session_at: int = 0


class ReviewSessionListOut(BaseModel):
    reviews: List[ReviewSessionOut] = Field(default_factory=list)


class ReviewScreenshotOut(BaseModel):
    idea_id: Optional[str] = None
    description: str = ""
    url: Optional[str] = None


class ReviewScreenshotListOut(BaseModel):
    screenshots: List[ReviewScreenshotOut] = Field(default_factory=list)
# ─── Project Manager Agent (AGENT-012) ──────────────────────────────


class PmConfigIn(BaseModel):
    priority_framework: Dict[str, str] = Field(
        default_factory=lambda: {
            "P0": "Critical/blocking",
            "P1": "High/next sprint",
            "P2": "Medium/backlog",
            "P3": "Low/nice-to-have",
        }
    )
    priority_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "user_impact": 0.4,
            "revenue_impact": 0.3,
            "technical_debt": 0.15,
            "effort_inverse": 0.15,
        }
    )
    sprint_duration_days: int = Field(default=14, ge=1, le=90)
    capacity_per_agent_type: Dict[str, int] = Field(
        default_factory=lambda: {"coder": 80, "qa": 40, "devops": 20, "architect": 20}
    )
    reporting_cadence: Literal["daily", "weekly", "both"] = "both"
    report_time_utc: str = Field(default="09:00", pattern=r"^\d{2}:\d{2}$")
    idea_intake_enabled: bool = True
    auto_prioritize: bool = True
    auto_create_feature_requests: bool = False
    blocker_stale_hours: int = Field(default=48, ge=1, le=720)
    escalation_on_conflict: bool = True
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    project_space_id: Optional[str] = Field(default=None, max_length=100)
    stakeholder_subs: Optional[List[str]] = Field(default=None, max_length=20)

    @field_validator("priority_framework")
    @classmethod
    def _validate_framework(cls, v: Dict[str, str]) -> Dict[str, str]:
        for level in ("P0", "P1", "P2", "P3"):
            if level not in v:
                raise ValueError(f"Priority framework must define {level}")
        return v

    @field_validator("priority_weights")
    @classmethod
    def _validate_weights(cls, v: Dict[str, float]) -> Dict[str, float]:
        total = sum(float(x) for x in v.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError("Priority weights must sum to 1.0")
        return v

    @field_validator("capacity_per_agent_type")
    @classmethod
    def _validate_capacity(cls, v: Dict[str, int]) -> Dict[str, int]:
        if "coder" not in v:
            raise ValueError("Capacity must include at least 'coder' agent type")
        for agent_type, hours in v.items():
            if int(hours) <= 0:
                raise ValueError(f"Capacity for {agent_type} must be greater than 0")
        return v


class PmConfigOut(BaseModel):
    priority_framework: Dict[str, str] = Field(default_factory=dict)
    priority_weights: Dict[str, float] = Field(default_factory=dict)
    sprint_duration_days: int = 14
    capacity_per_agent_type: Dict[str, int] = Field(default_factory=dict)
    reporting_cadence: str = "both"
    report_time_utc: str = "09:00"
    idea_intake_enabled: bool = True
    auto_prioritize: bool = True
    auto_create_feature_requests: bool = False
    blocker_stale_hours: int = 48
    escalation_on_conflict: bool = True
    coding_tool: str = "claude_code"
    coding_tool_model: Optional[str] = None
    project_space_id: Optional[str] = None
    stakeholder_subs: Optional[List[str]] = None
    updated_at: Optional[int] = None


class PmConfigValidationOut(BaseModel):
    valid: bool
    errors: List[str] = Field(default_factory=list)


class SubmitIdeaIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=10, max_length=5000)


class UpdateIdeaIn(BaseModel):
    status: Literal["accepted", "rejected"]
    rejection_reason: Optional[str] = Field(default=None, max_length=1000)


class IdeaOut(BaseModel):
    idea_id: str
    submitted_by: str
    title: str
    description: str
    status: str
    priority_suggestion: Optional[str] = None
    impact_score: Optional[float] = None
    effort_score: Optional[float] = None
    priority_rationale: Optional[str] = None
    feature_ticket_id: Optional[str] = None
    agent_run_id: Optional[str] = None
    rejection_reason: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class IdeaListOut(BaseModel):
    ideas: List[IdeaOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class BacklogItemOut(BaseModel):
    ticket_id: str
    subject: str = ""
    labels: List[str] = Field(default_factory=list)
    priority: str = "P3"
    priority_score: float = 0.0
    complexity: Optional[str] = None
    estimated_hours: float = 0.0
    status: str = "open"
    assigned_to: Optional[str] = None
    age_hours: float = 0.0


class BacklogOut(BaseModel):
    items: List[BacklogItemOut] = Field(default_factory=list)
    count: int = 0


class ReprioritizeOut(BaseModel):
    tickets_reprioritized: int = 0
    operation_type: str = "backlog_prioritize"
    escalations_created: int = 0


class CreateSprintIn(BaseModel):
    start_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    planned_ticket_ids: Optional[List[str]] = None


class UpdateSprintIn(BaseModel):
    action: Literal["activate", "close"]


class SprintOut(BaseModel):
    sprint_id: str
    sprint_number: int = 0
    start_date: str = ""
    end_date: str = ""
    status: str = "planned"
    planned_hours: float = 0.0
    completed_hours: float = 0.0
    tickets_planned: int = 0
    tickets_completed: int = 0
    tickets_carried_over: int = 0
    velocity: float = 0.0
    blockers_count: int = 0
    created_at: int = 0
    updated_at: int = 0
    planned_ticket_ids: List[str] = Field(default_factory=list)


class SprintListOut(BaseModel):
    sprints: List[SprintOut] = Field(default_factory=list)
    count: int = 0


class SprintBurndownPointOut(BaseModel):
    date: str
    remaining_hours: float = 0.0
    ideal_hours: float = 0.0


class SprintDetailOut(BaseModel):
    sprint: SprintOut
    burndown: List[SprintBurndownPointOut] = Field(default_factory=list)


class PmReportOut(BaseModel):
    report_id: str
    report_type: str = "daily"
    content: str = ""
    metrics_snapshot: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0


class ReportListOut(BaseModel):
    reports: List[PmReportOut] = Field(default_factory=list)
    count: int = 0


class BlockerOut(BaseModel):
    ticket_id: str
    ticket_subject: str = ""
    blocker_type: str = "stale"
    stale_since: Optional[int] = None
    assigned_agent: Optional[str] = None
    details: str = ""
    priority: str = "P3"


class BlockerListOut(BaseModel):
    blockers: List[BlockerOut] = Field(default_factory=list)
    count: int = 0


class AgentCapacityOut(BaseModel):
    agent_type: str
    total_capacity_hours: float = 0.0
    used_hours: float = 0.0
    available_hours: float = 0.0
    utilization_pct: float = 0.0


class AgentProjectCapacityOut(BaseModel):
    capacity: List[AgentCapacityOut] = Field(default_factory=list)
    fits: bool = True
    overflow_hours: float = 0.0
    recommendation: str = ""


class PmOutputOut(BaseModel):
    operation_type: str = ""
    ideas_processed: int = 0
    ideas_accepted: int = 0
    ideas_rejected: int = 0
    feature_tickets_created: List[str] = Field(default_factory=list)
    tickets_reprioritized: int = 0
    blockers_found: int = 0
    escalations_created: int = 0
    report_id: Optional[str] = None
    sprint_id: Optional[str] = None
    velocity_current: Optional[float] = None
    velocity_trend: Optional[str] = None
    total_duration_seconds: int = 0


class PmMetricsOut(BaseModel):
    ideas_submitted: int = 0
    ideas_converted: int = 0
    features_in_pipeline: int = 0
    velocity_current: float = 0.0
    velocity_trend: str = "stable"
    backlog_size: int = 0
    p0_count: int = 0
    blockers_count: int = 0
    avg_cycle_time_hours: float = 0.0
    period_start: int = 0
    period_end: int = 0


class ProjectDashboardVelocityPointOut(BaseModel):
    sprint_number: int = 0
    velocity: float = 0.0


class ProjectPipelineStageOut(BaseModel):
    stage: str
    count: int = 0


class ProjectCompletionOut(BaseModel):
    ticket_id: str
    subject: str = ""
    completed_at: int = 0


class ProjectDashboardOut(BaseModel):
    sprint: Optional[SprintOut] = None
    velocity_trend: List[ProjectDashboardVelocityPointOut] = Field(default_factory=list)
    backlog_by_priority: Dict[str, int] = Field(default_factory=dict)
    pipeline_funnel: List[ProjectPipelineStageOut] = Field(default_factory=list)
    agent_utilization: List[AgentCapacityOut] = Field(default_factory=list)
    blockers: List[BlockerOut] = Field(default_factory=list)
    recent_completions: List[ProjectCompletionOut] = Field(default_factory=list)


class TriggerPmOperationIn(BaseModel):
    operation_type: Literal[
        "idea_triage", "backlog_prioritize", "report_generate", "blocker_detect"
    ]
    report_type: Literal["daily", "weekly"] = "daily"


# ---------------------------------------------------------------------------
# Stylist / UI Agent (AGENT-016)
# ---------------------------------------------------------------------------


class StylistScreenshot(BaseModel):
    url: str = ""
    viewport: str = ""
    label: str = ""


class StylistAnnotation(BaseModel):
    screenshot_index: int = 0
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0
    issue: str = ""


class UIReviewIssueOut(BaseModel):
    issue_id: str
    category: str
    severity: Literal["error", "warning", "info"]
    title: str = ""
    description: str = ""
    page_element: Optional[str] = None
    screenshot_index: Optional[int] = None
    annotation_rect: Optional[Dict[str, int]] = None
    design_rule_id: Optional[str] = None
    suggestion: str = ""
    created_ticket_id: Optional[str] = None


class UIReviewIssueIn(BaseModel):
    category: Literal[
        "spacing", "color", "typography", "layout", "component", "responsive", "accessibility", "design"
    ] = "design"
    severity: Literal["error", "warning", "info"] = "warning"
    title: str = Field(default="", max_length=300)
    description: str = Field(default="", max_length=2000)
    page_element: Optional[str] = Field(default=None, max_length=500)
    screenshot_index: Optional[int] = None
    annotation_rect: Optional[Dict[str, int]] = None
    suggestion: str = Field(default="", max_length=2000)


class UIReviewOut(BaseModel):
    review_id: str
    agent_id: str = ""
    worker_id: str = ""
    page_url: str
    page_name: str = ""
    review_type: Literal["full_page", "component", "responsive", "accessibility", "pr_review"]
    source_ref: Optional[str] = None
    screenshots: List[Dict[str, Any]] = Field(default_factory=list)
    annotations: List[Dict[str, Any]] = Field(default_factory=list)
    design_score: float = 0.0
    accessibility_score: Optional[float] = None
    issues_found: int = 0
    issues: List[UIReviewIssueOut] = Field(default_factory=list)
    status: Literal["completed", "in_progress", "failed"] = "completed"
    created_at: int = 0


class CreateUIReviewIn(BaseModel):
    page_url: str = Field(..., min_length=1, max_length=500)
    page_name: str = Field(default="", max_length=300)
    review_type: Literal["full_page", "component", "responsive", "accessibility", "pr_review"] = "full_page"
    agent_id: str = Field(default="", max_length=200)
    worker_id: str = Field(default="", max_length=200)
    source_ref: Optional[str] = Field(default=None, max_length=200)
    design_score: float = Field(default=0.0, ge=0.0, le=100.0)
    accessibility_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    screenshots: List[StylistScreenshot] = Field(default_factory=list)
    annotations: List[StylistAnnotation] = Field(default_factory=list)
    issues: List[UIReviewIssueIn] = Field(default_factory=list)


class UIReviewListOut(BaseModel):
    reviews: List[UIReviewOut] = Field(default_factory=list)
# Compliance & Security Agent (AGENT-015)
# ---------------------------------------------------------------------------


class CreateSecurityFindingIn(BaseModel):
    agent_id: str = Field(default="", max_length=200)
    source: Literal["pr_review", "ticket_review", "periodic_audit", "manual_scan"]
    source_ref: str = Field(max_length=300)
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str = Field(max_length=100)
    title: str = Field(max_length=200)
    description: str = Field(max_length=5000)
    file_path: Optional[str] = Field(default=None, max_length=500)
    line_range: Optional[str] = Field(default=None, max_length=50)
    code_snippet: Optional[str] = Field(default=None, max_length=1000)
    remediation: str = Field(default="", max_length=2000)


class SecurityFindingOut(BaseModel):
    finding_id: str
    agent_id: str = ""
    source: str
    source_ref: str
    severity: str
    category: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_range: Optional[str] = None
    code_snippet: Optional[str] = None
    remediation: str = ""
    status: str
    remediation_ticket_id: Optional[str] = None
    resolved_at: Optional[int] = None
    note: Optional[str] = None
    created_at: int


class SecurityFindingsListOut(BaseModel):
    findings: List[SecurityFindingOut] = Field(default_factory=list)
    count: int = 0
    next_cursor: Optional[str] = None


class PageDesignScoreOut(BaseModel):
    page_url: str
    page_name: str = ""
    design_score: float = 0.0
    accessibility_score: Optional[float] = None
    issues_found: int = 0
    last_reviewed: int = 0


class OverallDesignScoreOut(BaseModel):
    overall_design_score: float = 0.0
    overall_accessibility_score: float = 0.0
    pages_reviewed: int = 0
    total_issues: int = 0


class DesignRuleOut(BaseModel):
    rule_id: str
    name: str
    category: str
    description: str = ""
    severity: Literal["error", "warning", "info"] = "warning"
    enabled: bool = True
    config: Optional[Dict[str, Any]] = None
    created_at: int = 0


class CreateDesignRuleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: Literal[
        "spacing", "color", "typography", "layout", "component", "responsive", "accessibility"
    ]
    description: str = Field(..., min_length=1, max_length=1000)
    severity: Literal["error", "warning", "info"]
    config: Optional[Dict[str, Any]] = None


class UpdateDesignRuleIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    category: Optional[
        Literal["spacing", "color", "typography", "layout", "component", "responsive", "accessibility"]
    ] = None
    description: Optional[str] = Field(default=None, min_length=1, max_length=1000)
    severity: Optional[Literal["error", "warning", "info"]] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


class CreateIssueTicketOut(BaseModel):
    ok: bool = True
    ticket_id: str
    review_id: str
    issue_id: str


class TriggerUIReviewIn(BaseModel):
    pages: List[str] = Field(..., min_length=1, max_length=20)
    review_type: Literal["full_page", "responsive", "accessibility"] = "full_page"
    viewports: Optional[List[Dict[str, int]]] = None


class TriggerUIReviewOut(BaseModel):
    ok: bool = True
    reviews: List[UIReviewOut] = Field(default_factory=list)
    count: int = 0


class StylistConfigOut(BaseModel):
    review_on_pr_merge: bool = True
    review_on_ui_ticket: bool = True
    periodic_review_frequency: str = "weekly"
    periodic_review_day: str = "wednesday"
    periodic_review_hour_utc: int = 10
    viewports: List[Dict[str, Any]] = Field(default_factory=list)
    pages_to_review: List[str] = Field(default_factory=list)
    design_system_ref: str = "shadcn-ui"
    tailwind_config_path: str = "frontend/src/globals.css"
    contrast_ratio_min: float = 4.5
    auto_create_tickets: bool = False
    ticket_min_severity: Literal["error", "warning", "info"] = "warning"
    brand_colors: List[str] = Field(default_factory=list)
    font_families: List[str] = Field(default_factory=list)
    # GAP-0103: derived indicator only. The raw app-auth secret name/ARN and the
    # credentials behind it are never exposed in this output model.
    has_app_credentials: bool = False
    updated_at: Optional[int] = None


class UpdateStylistConfigIn(BaseModel):
    review_on_pr_merge: Optional[bool] = None
    review_on_ui_ticket: Optional[bool] = None
    periodic_review_frequency: Optional[Literal["daily", "weekly", "biweekly"]] = None
    periodic_review_day: Optional[str] = None
    periodic_review_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    viewports: Optional[List[Dict[str, int]]] = None
    pages_to_review: Optional[List[str]] = None
    contrast_ratio_min: Optional[float] = Field(default=None, ge=3.0, le=7.0)
    auto_create_tickets: Optional[bool] = None
    ticket_min_severity: Optional[Literal["error", "warning", "info"]] = None
    brand_colors: Optional[List[str]] = None
    font_families: Optional[List[str]] = None
    # GAP-0103: pointer to a Secrets Manager secret holding live-app auth
    # credentials. Stored as a name/ARN only; the raw credential is never
    # persisted and never returned. Empty string clears it.
    app_auth_credentials_secret_name: Optional[str] = Field(default=None, max_length=2048)
# Marketing Agent (AGENT-017)
# ---------------------------------------------------------------------------


_MARKETING_CONTENT_TYPES = (
    "blog_post",
    "social_twitter",
    "social_linkedin",
    "social_instagram",
    "newsletter",
    "release_notes",
    "changelog",
    "landing_page",
    "meta_seo",
)


class CreateMarketingContentIn(BaseModel):
    """Request model for creating marketing content."""
    content_type: Literal[
        "blog_post", "social_twitter", "social_linkedin",
        "social_instagram", "newsletter", "release_notes",
        "changelog", "landing_page", "meta_seo",
    ]
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=20000)
    summary: Optional[str] = Field(default=None, max_length=500)
    feature_refs: Optional[List[str]] = Field(default=None, max_length=10)
    tags: Optional[List[str]] = Field(default=None, max_length=20)
    seo_meta: Optional[Dict[str, Any]] = None
    variations: Optional[List[Dict[str, str]]] = Field(default=None, max_length=5)
    target_platform: Optional[str] = Field(default=None, max_length=50)


class UpdateMarketingContentIn(BaseModel):
    """Request model for updating marketing content."""
    content_type: Optional[Literal[
        "blog_post", "social_twitter", "social_linkedin",
        "social_instagram", "newsletter", "release_notes",
        "changelog", "landing_page", "meta_seo",
    ]] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    body: Optional[str] = Field(default=None, min_length=1, max_length=20000)
    summary: Optional[str] = Field(default=None, max_length=500)
    feature_refs: Optional[List[str]] = Field(default=None, max_length=10)
    tags: Optional[List[str]] = Field(default=None, max_length=20)
    seo_meta: Optional[Dict[str, Any]] = None
    variations: Optional[List[Dict[str, str]]] = Field(default=None, max_length=5)
    target_platform: Optional[str] = Field(default=None, max_length=50)


class ScheduleMarketingContentIn(BaseModel):
    """Request model for scheduling marketing content."""
    publish_at: int = Field(..., gt=0)


class GenerateMarketingContentIn(BaseModel):
    """Request model for triggering content generation."""
    feature_ticket_ids: List[str] = Field(..., min_length=1, max_length=10)
    content_types: List[str] = Field(
        default_factory=lambda: ["blog_post", "changelog"]
    )
    tone_override: Optional[str] = Field(default=None, max_length=100)
    target_audience_override: Optional[str] = Field(default=None, max_length=200)


class MarketingContentOut(BaseModel):
    """Response model for marketing content."""
    content_id: str
    user_id: str
    agent_id: Optional[str] = None
    content_type: str
    title: str
    body: str
    summary: Optional[str] = None
    feature_refs: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    seo_meta: Optional[Dict[str, Any]] = None
    variations: Optional[List[Dict[str, Any]]] = None
    status: str
    scheduled_publish_at: Optional[int] = None
    published_at: Optional[int] = None
    target_platform: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class MarketingContentListOut(BaseModel):
    """Paginated list of marketing content."""
    items: List[MarketingContentOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    count: int = 0


class EngagementStatsOut(BaseModel):
    """Response model for content engagement statistics."""
    content_id: str
    total_views: int = 0
    total_clicks: int = 0
    total_signups: int = 0
    total_shares: int = 0
    click_rate: float = 0.0
    signup_rate: float = 0.0
    by_day: List[Dict[str, Any]] = Field(default_factory=list)
    by_variant: Optional[List[Dict[str, Any]]] = None


class CalendarEntryOut(BaseModel):
    """Response model for content calendar entry."""
    content_id: str
    title: str
    content_type: str
    status: str
    date: int


class EngagementSummaryOut(BaseModel):
    """Response model for aggregate engagement summary."""
    total_content: int = 0
    total_views: int = 0
    total_clicks: int = 0
    total_signups: int = 0
    avg_click_rate: float = 0.0
    avg_signup_rate: float = 0.0
    top_performing: List[Dict[str, Any]] = Field(default_factory=list)


class UpdateMarketingConfigIn(BaseModel):
    """Request model for updating marketing agent configuration."""
    trigger_on_feature_completion: Optional[bool] = None
    auto_generate_content_types: Optional[List[str]] = None
    brand_voice: Optional[Dict[str, Any]] = None
    target_audience: Optional[Dict[str, Any]] = None
    social_platforms: Optional[List[str]] = None
    content_calendar_enabled: Optional[bool] = None
    newsletter_frequency: Optional[Literal["daily", "weekly", "biweekly", "monthly"]] = None
    newsletter_day: Optional[str] = None
    ab_test_variations: Optional[int] = Field(default=None, ge=0, le=5)
    seo_keywords: Optional[List[str]] = None
    max_content_per_feature: Optional[int] = Field(default=None, ge=1, le=10)


class MarketingConfigOut(BaseModel):
    """Response model for marketing agent configuration."""
    trigger_on_feature_completion: bool = True
    auto_generate_content_types: List[str] = Field(default_factory=list)
    brand_voice: Dict[str, Any] = Field(default_factory=dict)
    target_audience: Dict[str, Any] = Field(default_factory=dict)
    social_platforms: List[str] = Field(default_factory=list)
    content_calendar_enabled: bool = True
    newsletter_frequency: Optional[str] = None
    newsletter_day: Optional[str] = None
    ab_test_variations: int = 0
    seo_keywords: List[str] = Field(default_factory=list)
    max_content_per_feature: int = 3
    updated_at: Optional[int] = None


class MarketingGenerateResultOut(BaseModel):
    """Response model for content generation."""
    status: str
    executed: bool = False
    content_types_requested: List[str] = Field(default_factory=list)
    feature_ticket_ids: List[str] = Field(default_factory=list)
    missing_ticket_ids: List[str] = Field(default_factory=list)
    contents: List[MarketingContentOut] = Field(default_factory=list)
    count: int = 0
class UpdateFindingStatusIn(BaseModel):
    status: Literal["acknowledged", "remediated", "false_positive", "accepted_risk"]
    note: Optional[str] = Field(default=None, max_length=1000)


class SecurityAuditOut(BaseModel):
    audit_id: str
    agent_id: str = ""
    worker_id: str = ""
    status: str
    started_at: int
    completed_at: Optional[int] = None
    finding_counts: Dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)
    report_s3_key: Optional[str] = None


class SecurityAuditsListOut(BaseModel):
    audits: List[SecurityAuditOut] = Field(default_factory=list)
    count: int = 0
    next_cursor: Optional[str] = None


class SecurityTrendWeekOut(BaseModel):
    week_start: int
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    total: int = 0


class SecurityTrendsOut(BaseModel):
    weeks: List[SecurityTrendWeekOut] = Field(default_factory=list)
    days: int = 90
    total: int = 0


class ComplianceFrameworkStatusOut(BaseModel):
    name: str
    passed: int = 0
    failed: int = 0
    open_findings: int = 0
    status: str = "unknown"


class AgentComplianceStatusOut(BaseModel):
    frameworks: Dict[str, ComplianceFrameworkStatusOut] = Field(default_factory=dict)


class UpdateSecurityConfigIn(BaseModel):
    scan_on_pr: Optional[bool] = None
    scan_on_ticket_update: Optional[bool] = None
    block_merge_on_critical: Optional[bool] = None
    block_merge_on_high: Optional[bool] = None
    periodic_audit_frequency: Optional[
        Literal["daily", "weekly", "biweekly", "monthly"]
    ] = None
    periodic_audit_day: Optional[str] = Field(default=None, max_length=20)
    periodic_audit_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    compliance_frameworks: Optional[
        List[Literal["owasp_top_10", "gdpr", "pci_dss", "wcag"]]
    ] = None
    wcag_level: Optional[Literal["A", "AA", "AAA"]] = None
    severity_thresholds: Optional[
        Dict[str, Literal["critical", "high", "medium", "low", "info"]]
    ] = None
    ignored_paths: Optional[List[str]] = None
    auto_create_remediation_tickets: Optional[bool] = None
    remediation_ticket_min_severity: Optional[
        Literal["critical", "high", "medium", "low"]
    ] = None


class SecurityAgentConfigOut(BaseModel):
    scan_on_pr: bool = True
    scan_on_ticket_update: bool = True
    block_merge_on_critical: bool = True
    block_merge_on_high: bool = False
    periodic_audit_frequency: str = "weekly"
    periodic_audit_day: str = "sunday"
    periodic_audit_hour_utc: int = 2
    compliance_frameworks: List[str] = Field(default_factory=list)
    wcag_level: str = "AA"
    severity_thresholds: Dict[str, str] = Field(default_factory=dict)
    ignored_paths: List[str] = Field(default_factory=list)
    auto_create_remediation_tickets: bool = True
    remediation_ticket_min_severity: str = "high"
    # GAP-0101: SSRF allowlist of repo hosts the agent may act against.
    allowed_repo_hosts: List[str] = Field(
        default_factory=lambda: ["github.com", "gitlab.com"]
    )
    # GAP-0102: write-only Secrets Manager reference (name/ARN). The raw GitHub
    # token is NEVER exposed here; only the boolean indicator below is returned.
    github_token_secret_name: Optional[str] = None
    has_github_token: bool = False
    updated_at: Optional[int] = None


# ─── Admin Subscription Tier Manager (ADMIN-001) ─────────────────────────────


class AdminSubscriptionTierCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    price_cents: int = Field(ge=100, le=100000)
    billing_cycle: str = Field(default="monthly", pattern=r"^(monthly|quarterly|yearly)$")
    description: str = Field(default="", max_length=500)
    benefits: List[str] = Field(default_factory=list, max_length=20)
    access_level: str = Field(default="basic", pattern=r"^(basic|premium|vip)$")
    plan_id: Optional[str] = Field(default=None, max_length=200)

    @field_validator("benefits")
    @classmethod
    def _validate_benefits(cls, v: List[str]) -> List[str]:
        for b in v:
            if len(b) > 200:
                raise ValueError("Each benefit must be 200 characters or fewer")
            if not b.strip():
                raise ValueError("Benefits must not be empty strings")
        return v


class AdminSubscriptionTierUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    price_cents: Optional[int] = Field(default=None, ge=100, le=100000)
    billing_cycle: Optional[str] = Field(default=None, pattern=r"^(monthly|quarterly|yearly)$")
    description: Optional[str] = Field(default=None, max_length=500)
    benefits: Optional[List[str]] = Field(default=None, max_length=20)
    access_level: Optional[str] = Field(default=None, pattern=r"^(basic|premium|vip)$")
    plan_id: Optional[str] = Field(default=None, max_length=200)

    @field_validator("benefits")
    @classmethod
    def _validate_benefits(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        for b in v:
            if len(b) > 200:
                raise ValueError("Each benefit must be 200 characters or fewer")
            if not b.strip():
                raise ValueError("Benefits must not be empty strings")
        return v


class AdminSubscriptionTierOut(BaseModel):
    tier_id: str
    name: str
    price_cents: int
    billing_cycle: str
    description: str
    benefits: List[str]
    access_level: str
    display_order: int
    status: str
    subscriber_count: int
    plan_id: Optional[str] = None
    created_at: int
    updated_at: int
    archived_at: Optional[int] = None


class AdminSubscriptionTierReorder(BaseModel):
    tier_ids: List[str] = Field(min_length=1)

    @field_validator("tier_ids")
    @classmethod
    def _validate_unique(cls, v: List[str]) -> List[str]:
        if len(v) != len(set(v)):
            raise ValueError("tier_ids must contain unique values")
        return v


class AdminSubscriptionTierAnalytics(BaseModel):
    tiers: List[Dict[str, Any]]
    total_subscribers: int
    total_revenue_cents: int
    growth_series: List[Dict[str, Any]]


class AdminSubscriptionTierPreviewOut(BaseModel):
    tiers: List[Dict[str, Any]]
    creator_id: str
# ---------------------------------------------------------------------------
# Accountant / Cost Tracking Agent (AGENT-018)
# ---------------------------------------------------------------------------


class RecordCostEntryIn(BaseModel):
    """Request model for recording a cost entry (internal/ingestion worker)."""

    worker_id: str = Field(..., min_length=1, max_length=100)
    agent_type: str = Field(..., min_length=1, max_length=50)
    agent_id: str = Field(..., min_length=1, max_length=100)
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    llm_input_tokens: int = Field(default=0, ge=0)
    llm_output_tokens: int = Field(default=0, ge=0)
    llm_cached_tokens: int = Field(default=0, ge=0)
    llm_cost_cents: int = Field(default=0, ge=0)
    llm_provider: str = Field(default="anthropic", max_length=50)
    llm_model: str = Field(default="unknown", max_length=100)
    compute_hours: float = Field(default=0.0, ge=0.0)
    compute_cost_cents: int = Field(default=0, ge=0)
    tickets_worked: int = Field(default=0, ge=0)
    tickets_completed: int = Field(default=0, ge=0)


class AttributeTicketCostIn(BaseModel):
    """Request model for attributing cost to a ticket."""

    ticket_id: str = Field(..., min_length=1, max_length=100)
    agent_type: str = Field(..., min_length=1, max_length=50)
    llm_tokens: int = Field(default=0, ge=0)
    llm_cost_cents: int = Field(default=0, ge=0)
    compute_hours: float = Field(default=0.0, ge=0.0)
    compute_cost_cents: int = Field(default=0, ge=0)


class CreateCostBudgetIn(BaseModel):
    """Request model for creating a cost budget."""

    name: str = Field(..., min_length=1, max_length=200)
    scope: Literal["overall", "agent_type", "agent_instance"]
    scope_ref: Optional[str] = Field(default=None, max_length=100)
    period: Literal["daily", "weekly", "monthly"]
    limit_cents: int = Field(..., ge=100)
    alert_threshold_pct: int = Field(default=80, ge=10, le=100)
    auto_pause_on_exceed: bool = False

    @model_validator(mode="after")
    def _validate_scope_ref(self) -> "CreateCostBudgetIn":
        if self.scope in ("agent_type", "agent_instance") and not self.scope_ref:
            raise ValueError("scope_ref is required when scope is agent_type or agent_instance")
        return self


class UpdateCostBudgetIn(BaseModel):
    """Request model for updating a cost budget."""

    name: Optional[str] = Field(default=None, max_length=200)
    limit_cents: Optional[int] = Field(default=None, ge=100)
    alert_threshold_pct: Optional[int] = Field(default=None, ge=10, le=100)
    auto_pause_on_exceed: Optional[bool] = None
    enabled: Optional[bool] = None


class UpdateAccountantConfigIn(BaseModel):
    """Request model for updating accountant agent configuration."""

    collection_frequency: Optional[Literal["hourly", "every_6h", "daily"]] = None
    report_frequency: Optional[Literal["daily", "weekly", "monthly"]] = None
    report_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    compute_pricing: Optional[Dict[str, int]] = None
    anomaly_detection_enabled: Optional[bool] = None
    anomaly_threshold_pct: Optional[int] = Field(default=None, ge=100, le=1000)
    idle_worker_threshold_minutes: Optional[int] = Field(default=None, ge=10, le=1440)
    optimization_suggestions_enabled: Optional[bool] = None


class CostEntryOut(BaseModel):
    """Response model for a cost entry."""

    worker_id: str
    agent_type: str
    agent_id: str
    date: str
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cached_tokens: int = 0
    llm_cost_cents: int = 0
    llm_provider: str = ""
    llm_model: str = ""
    compute_hours: float = 0.0
    compute_cost_cents: int = 0
    total_cost_cents: int = 0
    tickets_worked: int = 0
    tickets_completed: int = 0


class CostDailySummaryOut(BaseModel):
    """Response model for daily cost summary."""

    date: str
    total_cents: int = 0
    llm_cents: int = 0
    compute_cents: int = 0
    by_agent_type: Dict[str, int] = Field(default_factory=dict)
    by_worker: List[CostEntryOut] = Field(default_factory=list)


class CostPeriodSummaryOut(BaseModel):
    """Response model for period cost summary."""

    period: str
    start_date: str
    end_date: str
    total_cents: int = 0
    llm_cents: int = 0
    compute_cents: int = 0
    by_agent_type: Dict[str, int] = Field(default_factory=dict)
    budget_utilization: List[Dict[str, Any]] = Field(default_factory=list)


class TicketCostOut(BaseModel):
    """Response model for ticket cost data."""

    ticket_id: str
    agent_type: str = ""
    total_llm_tokens: int = 0
    total_llm_cost_cents: int = 0
    total_compute_hours: float = 0.0
    total_compute_cost_cents: int = 0
    total_cost_cents: int = 0
    worker_sessions: int = 0
    status: str = "in_progress"
    started_at: Optional[int] = None
    completed_at: Optional[int] = None


class TicketCostListOut(BaseModel):
    """Response model for a list of ticket costs."""

    ticket_costs: List[TicketCostOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class CostBudgetOut(BaseModel):
    """Response model for a cost budget."""

    budget_id: str
    name: str
    scope: str
    scope_ref: Optional[str] = None
    period: str
    limit_cents: int
    alert_threshold_pct: int = 80
    auto_pause_on_exceed: bool = False
    enabled: bool = True
    created_at: int = 0


class CostAlertOut(BaseModel):
    """Response model for a cost alert."""

    alert_id: str
    budget_id: Optional[str] = None
    alert_type: str
    severity: str
    title: str
    message: str
    current_spend_cents: int = 0
    budget_limit_cents: Optional[int] = None
    acknowledged: bool = False
    auto_action_taken: Optional[str] = None
    created_at: int = 0


class CostAlertListOut(BaseModel):
    """Response model for a list of cost alerts."""

    alerts: List[CostAlertOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class CostTrendsOut(BaseModel):
    """Response model for cost trends data."""

    weeks: List[Dict[str, Any]] = Field(default_factory=list)


class OptimizationRecommendationOut(BaseModel):
    """Response model for a cost optimization recommendation."""

    type: Literal["idle_worker", "model_downgrade", "high_cost_ticket", "underutilized_agent"]
    title: str
    description: str
    potential_savings_cents: int = 0
    action: str


class AccountantConfigOut(BaseModel):
    """Response model for accountant agent configuration."""

    collection_frequency: str = "hourly"
    report_frequency: str = "daily"
    report_hour_utc: int = 8
    compute_pricing: Dict[str, int] = Field(default_factory=dict)
    anomaly_detection_enabled: bool = True
    anomaly_threshold_pct: int = 200
    idle_worker_threshold_minutes: int = 60
    optimization_suggestions_enabled: bool = True
    updated_at: Optional[int] = None
# ──────────────────────────────────────────────────────────────────────
# ADMIN-002: Admin Email/SMS Dashboards
# ──────────────────────────────────────────────────────────────────────


class EmailDashboardStatsOut(BaseModel):
    sent: int = 0
    delivered: int = 0
    bounced: int = 0
    complained: int = 0
    failed: int = 0
    suppressed: int = 0
    total: int = 0
    delivery_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    bounce_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    complaint_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    period_days: int = Field(default=7, ge=1, le=365)

    @field_validator("delivery_rate", "bounce_rate", "complaint_rate", mode="before")
    @classmethod
    def _round_email_rates(cls, v):
        if isinstance(v, (int, float)):
            return round(float(v), 2)
        return v


class SmsDashboardStatsOut(BaseModel):
    sent: int = 0
    delivered: int = 0
    failed: int = 0
    total: int = 0
    total_segments: int = 0
    estimated_cost_usd: float = 0.0
    suppressed_numbers: int = 0
    delivery_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    failure_rate: float = Field(default=0.0, ge=0.0, le=100.0)
    period_days: int = Field(default=7, ge=1, le=365)

    @field_validator("delivery_rate", "failure_rate", mode="before")
    @classmethod
    def _round_sms_rates(cls, v):
        if isinstance(v, (int, float)):
            return round(float(v), 2)
        return v


class DashboardTimeseriesPoint(BaseModel):
    date: str
    sent: int = 0
    delivered: int = 0
    bounced: int = 0
    complained: int = 0
    failed: int = 0
    segments: int = 0


class DashboardTimeseriesOut(BaseModel):
    channel: str
    period_days: int = Field(default=7, ge=1, le=365)
    points: List[DashboardTimeseriesPoint] = Field(default_factory=list)


class DashboardBreakdownItem(BaseModel):
    key: str
    label: str
    count: int = 0


class DashboardBreakdownOut(BaseModel):
    channel: str
    dimension: str
    items: List[DashboardBreakdownItem] = Field(default_factory=list)


class SmsSendTestIn(BaseModel):
    """Admin send-test request (PLATFORM-007 production pipeline)."""
    phone: str = Field(min_length=3, max_length=20)
    body: str = Field(default="Test SMS from admin console", min_length=1, max_length=1400)

    @field_validator("phone", mode="before")
    @classmethod
    def _strip_phone(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v


class SmsSendTestOut(BaseModel):
    """Result of an admin send-test through the production pipeline."""
    number: str
    message_id: Optional[str] = None
    status: str


class DashboardSuppressionAdd(BaseModel):
    address: str = Field(min_length=1, max_length=320)
    reason: str = Field(default="manual", max_length=200)

    @field_validator("address", mode="before")
    @classmethod
    def _normalize_suppress_address(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


class NotificationTemplateOut(BaseModel):
    template_id: str
    channel: str
    name: str
    subject: Optional[str] = None
    body: str = ""
    variables: List[str] = Field(default_factory=list)
    active: bool = True
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class NotificationTemplateUpdate(BaseModel):
    subject: Optional[str] = Field(default=None, max_length=200)
    body: Optional[str] = Field(default=None, max_length=10000)
    active: Optional[bool] = None

    @field_validator("body", mode="before")
    @classmethod
    def _strip_script_tags(cls, v):
        """Prevent executable scripts in template body."""
        if isinstance(v, str):
            return re.sub(
                r"<script[^>]*>.*?</script>", "", v, flags=re.DOTALL | re.IGNORECASE
            )
        return v


class NotificationTemplatePreviewRequest(BaseModel):
    sample_vars: Dict[str, str] = Field(default_factory=dict)


class NotificationTemplatePreviewOut(BaseModel):
    template_id: str
    channel: str
    rendered_subject: Optional[str] = None
    rendered_body: str = ""
    missing_vars: List[str] = Field(default_factory=list)


class NotificationTemplateTestSend(BaseModel):
    recipient: str = Field(min_length=1, max_length=320)
    sample_vars: Dict[str, str] = Field(default_factory=dict)

    @field_validator("recipient", mode="before")
    @classmethod
    def _normalize_recipient(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


# ---------------------------------------------------------------------------
# ADMIN-003: Rate Limit Admin UI models
# ---------------------------------------------------------------------------

class RateLimitLiveSummary(BaseModel):
    """Aggregated rate-limit hit summary for the live dashboard."""

    by_group: Dict[str, int] = Field(default_factory=dict)
    by_source: List[Dict[str, Any]] = Field(default_factory=list)
    time_series: List[Dict[str, Any]] = Field(default_factory=list)
    total_hits: int = 0
    window_hours: int = 1


class RateLimitConfigReset(BaseModel):
    """Response when an endpoint group config override is reset to default."""

    ok: bool = True
    group: str
    is_override: bool = False


# ---------------------------------------------------------------------------
# KYC-002: Identity Document Verification models
# ---------------------------------------------------------------------------

class KycDocumentUploadRequest(BaseModel):
    """Request to upload an identity document image for verification."""

    document_type: Literal["id_front", "id_back"]
    file_name: str = Field(min_length=1, max_length=255)
    case_id: Optional[str] = None
    # Base64-encoded image bytes. Optional in dev/E2E (mock provider keys off
    # the filename, not the bytes).
    content_b64: Optional[str] = None


class KycDocumentFieldMatch(BaseModel):
    """Per-field comparison of an extracted value against the user profile."""

    status: Literal["match", "mismatch", "partial", "not_available"]
    profile_value: Optional[str] = None
    extracted_value: Optional[str] = None
    similarity: Optional[float] = None


class KycDocumentOut(BaseModel):
    """A KYC identity document record with its extraction/verification state."""

    document_id: str
    case_id: Optional[str] = None
    user_sub: Optional[str] = None
    document_type: Literal["id_front", "id_back"]
    file_name: str
    status: Literal["pending", "extracted", "failed", "approved", "rejected"]
    provider: Optional[str] = None
    image_url: Optional[str] = None
    extraction_id: Optional[str] = None
    extracted_fields: Dict[str, str] = Field(default_factory=dict)
    match_results: Optional[Dict[str, KycDocumentFieldMatch]] = None
    overall_confidence: Optional[Literal["high", "medium", "low", "failed"]] = None
    review_decision: Optional[str] = None
    review_note: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycDocumentListResponse(BaseModel):
    """List of KYC identity documents."""

    documents: List[KycDocumentOut] = Field(default_factory=list)


class KycDocumentReviewRequest(BaseModel):
    """Reviewer approve/reject decision for a document."""

    decision: Literal["approve", "reject"]
    note: Optional[str] = Field(default=None, max_length=2000)


# ---------------------------------------------------------------------------
# KYC-010: Passport / National-ID Scanner models
# ---------------------------------------------------------------------------


class KycIdScannerScanRequest(BaseModel):
    """Request to scan an uploaded passport / national-ID document image."""

    document_type: Literal["passport", "national_id_card", "driving_license", "residence_permit"]
    file_type: Literal["id_front", "id_back"] = "id_front"
    mrz_lines: Optional[List[str]] = Field(
        default=None,
        description="Optional manual MRZ lines (2 for TD3 passport, 3 for TD1 ID card).",
    )
    image_ref: Optional[str] = Field(default=None, max_length=512)


class KycIdScannerValidateRequest(BaseModel):
    """Request to validate document-type side / MRZ requirements for a case."""

    document_type: Literal["passport", "national_id_card", "driving_license", "residence_permit"]


class KycIdScannerAdjudicateRequest(BaseModel):
    """Reviewer approve/decline decision for a scan result."""

    decision: Literal["approve", "decline"]
    note: Optional[str] = Field(default=None, max_length=2000)


class KycIdScannerChecksums(BaseModel):
    """Per-field MRZ check-digit validation results."""

    document_number: bool
    date_of_birth: bool
    expiry_date: bool
    optional_data: Optional[bool] = None
    composite: bool


class KycIdScannerExtraction(BaseModel):
    """Parsed MRZ / document-field extraction."""

    valid: Optional[bool] = None
    format: Optional[str] = None
    error: Optional[str] = None
    document_type: Optional[str] = None
    issuing_state: Optional[str] = None
    surname: Optional[str] = None
    given_names: Optional[str] = None
    document_number: Optional[str] = None
    nationality: Optional[str] = None
    date_of_birth: Optional[str] = None
    sex: Optional[str] = None
    expiry_date: Optional[str] = None
    checksums: Optional[KycIdScannerChecksums] = None


class KycIdScannerExpiryCheck(BaseModel):
    """Document expiry check result."""

    status: Literal["valid", "expired", "expiring_soon", "unknown"]
    message: str
    expiry_date: Optional[str] = None
    days_until_expiry: Optional[int] = None


class KycIdScannerCrossReference(BaseModel):
    """Cross-reference of extraction against the case / user profile."""

    match_score: int = Field(ge=0, le=100)
    total_fields_checked: int
    fields_matched: int
    matches: Dict[str, Any] = Field(default_factory=dict)
    mismatches: Dict[str, Any] = Field(default_factory=dict)


class KycIdScannerScanOut(BaseModel):
    """A complete passport / national-ID scan result."""

    scan_id: str
    case_id: str
    user_sub: Optional[str] = None
    document_type: str
    file_type: str
    status: Literal["matched", "flagged", "rejected", "approved", "declined"]
    mrz_valid: bool
    extraction: KycIdScannerExtraction
    expiry_check: KycIdScannerExpiryCheck
    cross_reference: Optional[KycIdScannerCrossReference] = None
    image_url: Optional[str] = None
    review_decision: Optional[str] = None
    review_note: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycIdScannerScanListResponse(BaseModel):
    """List of scan-result summaries for a case / reviewer queue."""

    scans: List[Dict[str, Any]] = Field(default_factory=list)


class KycIdScannerValidationOut(BaseModel):
    """Document-type requirement validation result."""

    document_type: str
    sides_required: List[str]
    has_mrz: bool
    mrz_format: Optional[str] = None
    sides_present: List[str] = Field(default_factory=list)
    all_sides_present: bool


# ---------------------------------------------------------------------------
# KYC-004: Proof of Residency Verification models
# ---------------------------------------------------------------------------


class KycResidencyUploadRequest(BaseModel):
    """Request to upload a proof-of-residency document for verification."""

    document_type: Literal[
        "utility_bill", "bank_statement", "government_letter", "tax_document", "lease_agreement"
    ]
    issuing_entity: str = Field(min_length=1, max_length=200)
    document_date: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$", description="ISO date, e.g. 2026-04-15"
    )
    file_name: str = Field(min_length=1, max_length=255)
    case_id: Optional[str] = None
    # Base64-encoded file bytes. Optional in dev/E2E (mock provider keys off the
    # filename, not the bytes).
    content_b64: Optional[str] = None


class KycResidencyAddressMatch(BaseModel):
    """Result of comparing the extracted address against the profile address."""

    status: Literal["match", "partial", "mismatch", "not_available"]
    profile_address: Dict[str, str] = Field(default_factory=dict)
    field_matches: Dict[str, Literal["match", "partial", "mismatch"]] = Field(default_factory=dict)


class KycResidencyDocumentOut(BaseModel):
    """A KYC proof-of-residency document with its extraction/verification state."""

    document_id: str
    case_id: Optional[str] = None
    user_sub: Optional[str] = None
    document_type: Literal[
        "utility_bill", "bank_statement", "government_letter", "tax_document", "lease_agreement"
    ]
    issuing_entity: Optional[str] = None
    document_date: Optional[str] = None
    file_name: str
    status: Literal["pending", "verified", "rejected", "expired"]
    provider: Optional[str] = None
    document_url: Optional[str] = None
    extraction_id: Optional[str] = None
    recency_valid: bool = False
    recency_days: int = 0
    extracted_address: Optional[Dict[str, str]] = None
    address_match: Optional[KycResidencyAddressMatch] = None
    review_decision: Optional[str] = None
    review_note: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycResidencyListResponse(BaseModel):
    """List of KYC proof-of-residency documents."""

    documents: List[KycResidencyDocumentOut] = Field(default_factory=list)


class KycResidencyReviewRequest(BaseModel):
    """Reviewer approve/reject decision for a residency document."""

    decision: Literal["approve", "reject"]
    note: Optional[str] = Field(default=None, max_length=2000)


# KYC-003: Liveness Video Verification Call models
# ---------------------------------------------------------------------------

KycLivenessCallStatus = Literal[
    "scheduled", "in_progress", "passed", "failed", "cancelled", "expired"
]


class KycLivenessCallScheduleRequest(BaseModel):
    """Owner request to schedule a liveness video verification call for a case."""

    case_id: str = Field(min_length=1, max_length=128)
    scheduled_at: int = Field(..., description="Unix timestamp of the call start")
    duration_minutes: int = Field(default=15, ge=5, le=60)
    verifier_sub: Optional[str] = Field(default=None, max_length=256)
    note: Optional[str] = Field(default=None, max_length=500)


class KycLivenessCallResultRequest(BaseModel):
    """Verifier request to record the pass/fail outcome of a conducted call."""

    result: Literal["passed", "failed"]
    notes: str = Field(min_length=1, max_length=2000)
    recording_linked: bool = True


class KycLivenessCallOut(BaseModel):
    """Full verifier/admin view of a KYC liveness verification call."""

    call_id: str
    case_id: str
    user_sub: Optional[str] = None
    status: KycLivenessCallStatus
    scheduled_at: int = 0
    duration_minutes: int = 0
    note: Optional[str] = None
    verifier_sub: Optional[str] = None
    result: Optional[Literal["passed", "failed"]] = None
    result_notes: Optional[str] = None
    result_set_at: Optional[int] = None
    recording_ref: Optional[str] = None
    started_at: Optional[int] = None
    join_url: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycLivenessCallStatusOut(BaseModel):
    """Owner-facing view of a KYC liveness verification call (no verifier identity)."""

    call_id: str
    case_id: str
    status: KycLivenessCallStatus
    scheduled_at: int = 0
    duration_minutes: int = 0
    result: Optional[Literal["passed", "failed"]] = None
    join_url: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycLivenessCallListResponse(BaseModel):
    """List of KYC liveness verification calls."""

    calls: List[KycLivenessCallOut] = Field(default_factory=list)


class KycLivenessCallStatusResponse(BaseModel):
    """Owner verification-call status wrapper (call may be null)."""

    verification_call: Optional[KycLivenessCallStatusOut] = None


# FIN-001: Invoice / Receipt PDF models
# ---------------------------------------------------------------------------

class InvoiceLineItemOut(BaseModel):
    description: str
    quantity: int = 1
    amount_cents: int
    unit_price_cents: int = 0  # QUO-005 (additive; 0 for legacy items)


class InvoiceOut(BaseModel):
    invoice_id: str
    invoice_number: str
    invoice_type: str  # tip, unlock, subscription, shop, deposit
    user_sub: str
    amount_cents: int
    tax_cents: int = 0
    total_cents: int
    currency: str = "usd"
    status: str = "generated"  # generated, emailed
    seller_id: str = ""
    seller_name: str = ""
    buyer_name: str = ""
    buyer_email: str = ""
    line_items: List[InvoiceLineItemOut] = Field(default_factory=list)
    payment_method_summary: str = ""
    ledger_entry_id: str = ""
    created_at: int = 0
    # QUO-003 (additive): back-reference to the originating quote.
    aos_quote_id: str = ""
    # QUO-005 (additive): standalone invoice lifecycle fields.
    payment_terms_days: Optional[int] = None
    due_date: Optional[int] = None
    voided_at: Optional[int] = None


class InvoiceListOut(BaseModel):
    invoices: List[InvoiceOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class InvoiceEmailOut(BaseModel):
    ok: bool = True
    emailed_to: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# MOD-001: Video Review Queue
# ---------------------------------------------------------------------------


class VideoReviewQueueEnqueueIn(BaseModel):
    video_id: str = Field(min_length=1, max_length=128)
    owner_user_id: str = Field(min_length=1, max_length=256)
    title: str = Field(default="", max_length=512)
    description: str = Field(default="", max_length=4000)
    priority: Literal["urgent", "high", "normal", "low"] = "normal"
    source: Literal["manual", "flagged", "upload"] = "manual"
    thumbnail_url: Optional[str] = Field(default=None, max_length=2048)
    hls_manifest_url: Optional[str] = Field(default=None, max_length=2048)
    duration_seconds: Optional[float] = None
    flag_reason: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("flag_reason", "description")
    @classmethod
    def _strip_html(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewQueueItemOut(BaseModel):
    entry_id: str
    video_id: str
    owner_user_id: str
    title: str = ""
    description: str = ""
    status: str
    priority: str = "normal"
    priority_rank: int = 2
    source: str = "manual"
    created_at: int = 0
    updated_at: int = 0
    claimed_by: str = ""
    claimed_at: int = 0
    reviewed_by: str = ""
    reviewed_at: int = 0
    review_notes: str = ""
    decision: str = ""
    escalated: bool = False
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    flag_reason: Optional[str] = None


class VideoReviewQueueListOut(BaseModel):
    items: List[VideoReviewQueueItemOut] = Field(default_factory=list)
    total: int = 0
    next_cursor: Optional[str] = None


class VideoReviewQueueStatsOut(BaseModel):
    counts: Dict[str, int] = Field(default_factory=dict)
    total_open: int = 0


class VideoReviewDetailOut(BaseModel):
    entry: VideoReviewQueueItemOut
    prior_review_history: List[Dict[str, Any]] = Field(default_factory=list)
    prior_approvals_count: int = 0
    prior_rejections_count: int = 0


class VideoReviewApproveIn(BaseModel):
    review_notes: str = Field(default="", max_length=2000)
    notify_creator: bool = True

    @field_validator("review_notes")
    @classmethod
    def _sanitize_notes(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewRejectIn(BaseModel):
    rejection_reason: str = Field(min_length=5, max_length=2000)
    notify_creator: bool = True

    @field_validator("rejection_reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewEscalateIn(BaseModel):
    escalation_reason: str = Field(min_length=5, max_length=2000)
    notify_creator: bool = False

    @field_validator("escalation_reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewClaimOut(BaseModel):
    ok: bool = True
    entry: VideoReviewQueueItemOut


class VideoReviewDecisionOut(BaseModel):
    ok: bool = True
    entry_id: str
    decision: str
    new_status: str
    reviewed_by: str
    reviewed_at: int
    audit_id: str
# -- Syndicate Revenue Splitting (SYND-003) --
# Money is integer cents; split percentages are integer basis points (10000 = 100%).

class SplitConfigIn(BaseModel):
    mode: Literal["equal", "weighted", "performance"] = "equal"
    weights_bps: Optional[Dict[str, int]] = None
    performance_metric: Optional[str] = None
    performance_window_days: int = Field(default=30, ge=7, le=365)
    platform_fee_bps: int = Field(default=1500, ge=0, le=5000)


class SplitConfigOut(BaseModel):
    mode: str = "equal"
    platform_fee_bps: int = 1500
    weights_bps: Dict[str, int] = Field(default_factory=dict)
    performance_metric: str = ""
    performance_window_days: int = 30
    updated_at: int = 0
    updated_by: str = ""


class SplitDistributionOut(BaseModel):
    user_id: str
    display_name: str = ""
    amount_cents: int = 0
    percentage_bps: int = 0
    ledger_entry_id: str = ""


class SplitExecutionOut(BaseModel):
    split_id: str
    syndicate_id: str = ""
    source_type: str = "subscription"
    subscription_id: str = ""
    invoice_id: str = ""
    gross_amount_cents: int = 0
    platform_fee_cents: int = 0
    platform_fee_bps: int = 0
    net_amount_cents: int = 0
    currency: str = "usd"
    mode: str = "equal"
    distributions: List[SplitDistributionOut] = Field(default_factory=list)
    created_at: int = 0


class ExecuteSplitIn(BaseModel):
    source_type: Literal["subscription", "tip"] = "subscription"
    subscription_id: str = ""
    invoice_id: str = ""
    gross_amount_cents: int = Field(gt=0)
    currency: str = "usd"


class MemberEarningEntryOut(BaseModel):
    split_id: str = ""
    amount_cents: int = 0
    percentage_bps: int = 0
    created_at: int = 0
    source_type: str = ""


class MemberEarningsOut(BaseModel):
    syndicate_id: str = ""
    user_id: str = ""
    total_cents: int = 0
    split_count: int = 0
    entries: List[MemberEarningEntryOut] = Field(default_factory=list)


class PerformanceScoresIn(BaseModel):
    metric: Literal["views", "engagement", "subscribers"] = "views"
    scores: Dict[str, int] = Field(default_factory=dict)


# ─── Account Deletion (PLATFORM-018) ────────────────────────────

_ACCOUNT_DELETION_CONFIRM_TEXT = "DELETE MY ACCOUNT"
_EXPORT_CATEGORY_KEYS = {
    "profile", "messages", "posts", "billing", "files",
    "contacts", "calendar", "subscriptions", "push_devices",
    "tickets", "sessions",
}


class AccountDeletionRequestIn(BaseModel):
    """Request body for POST /ui/privacy/account-deletion/request."""
    password: str = Field(min_length=1, max_length=200)
    confirm_text: str = Field(...)
    reason: Optional[str] = Field(default=None, max_length=500)

    @field_validator("confirm_text")
    @classmethod
    def _validate_confirm(cls, v: str) -> str:
        if v != _ACCOUNT_DELETION_CONFIRM_TEXT:
            raise ValueError("Confirmation text must be exactly 'DELETE MY ACCOUNT'")
        return v


class AccountDeletionStatusOut(BaseModel):
    request_id: str
    status: str
    created_at: int
    scheduled_for: Optional[int] = None
    grace_days_remaining: Optional[int] = None
    can_cancel: bool = False
    retention_hold: bool = False
    retention_hold_reason: Optional[str] = None
    reason: Optional[str] = None
    completed_at: Optional[int] = None
    deletion_summary: Optional[Dict[str, Any]] = None
    user_sub: Optional[str] = None


class AccountDeletionListOut(BaseModel):
    requests: List[AccountDeletionStatusOut] = Field(default_factory=list)
    total: int = 0


class AccountDeletionCancelOut(BaseModel):
    ok: bool = True
    request_id: str
    status: str
    cancelled_at: int


class PrivacyExportRequestIn(BaseModel):
    """Request body for POST /ui/privacy/account-deletion/export."""
    categories: Dict[str, bool] = Field(
        default_factory=lambda: {k: True for k in _EXPORT_CATEGORY_KEYS}
    )

    @field_validator("categories")
    @classmethod
    def _validate_categories(cls, v: Dict[str, bool]) -> Dict[str, bool]:
        invalid = set(v.keys()) - _EXPORT_CATEGORY_KEYS
        if invalid:
            raise ValueError(f"Unknown categories: {', '.join(sorted(invalid))}")
        return v


class PrivacyExportStatusOut(BaseModel):
    request_id: str
    status: str
    created_at: int
    completed_at: Optional[int] = None
    download_url: Optional[str] = None
    download_expires_at: Optional[int] = None
    categories_requested: int = 0
    file_size_bytes: Optional[int] = None
    data: Optional[Dict[str, Any]] = None


class AccountDeletionRetentionHoldIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class AccountDeletionRetentionHoldOut(BaseModel):
    ok: bool = True
    request_id: str
    retention_hold: bool
    retention_hold_reason: Optional[str] = None
    held_by: Optional[str] = None
    held_at: Optional[int] = None


class AccountDeletionAuditEventOut(BaseModel):
    event_id: str
    event_type: str
    actor: str
    timestamp: int
    details: Dict[str, Any] = Field(default_factory=dict)


class AccountDeletionAuditTrailOut(BaseModel):
    request_id: str
    events: List[AccountDeletionAuditEventOut] = Field(default_factory=list)


class AccountDeletionProcessDueOut(BaseModel):
    ok: bool = True
    processed: int = 0
    skipped: int = 0
    request_ids: List[str] = Field(default_factory=list)
# ── Live Q&A Mode (ENGAGE-003) ──────────────────────────────────────────────


class LiveQaModeToggleIn(BaseModel):
    enabled: bool


class LiveQaModeOut(BaseModel):
    ok: bool = True
    session_id: str
    qa_mode_enabled: bool


class LiveQaQuestionSubmitIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)


class LiveQaPinIn(BaseModel):
    pinned: bool = True


class LiveQaQuestionOut(BaseModel):
    question_id: str
    session_id: str
    submitter_id: str
    submitter_display_name: str
    text: str
    status: Literal["pending", "featured", "answered", "dismissed", "removed"]
    vote_count: int
    pinned: bool = False
    featured_at: Optional[int] = None
    answered_at: Optional[int] = None
    created_at: int
    featured_by: Optional[str] = None


class LiveQaQueueOut(BaseModel):
    questions: List[LiveQaQuestionOut] = Field(default_factory=list)
    has_more: bool = False


class LiveQaStatsOut(BaseModel):
    total_questions: int
    answered: int
    dismissed: int
    featured: int
    pending: int
    total_upvotes: int
    avg_upvotes: float
    answer_rate: float
# ---------------------------------------------------------------------------
# Platform Financial Dashboard (FIN-013)
# ---------------------------------------------------------------------------

class PlatformFinancialKpis(BaseModel):
    gmv_cents: int = 0
    net_revenue_cents: int = 0
    refunds_cents: int = 0
    take_rate_bps: int = 0  # basis points (2000 = 20%)
    tx_count: int = 0
    unique_payers: int = 0
    avg_tx_cents: int = 0
    period: Dict[str, str] = Field(default_factory=dict)


class PlatformFinancialTrendPoint(BaseModel):
    date: str
    gmv_cents: int = 0
    net_revenue_cents: int = 0
    tx_count: int = 0


class PlatformFinancialTrendsResponse(BaseModel):
    data: List[PlatformFinancialTrendPoint] = Field(default_factory=list)
    granularity: str = "daily"


class PlatformFinancialProviderEntry(BaseModel):
    provider: str
    total_cents: int = 0
    tx_count: int = 0
    avg_cents: int = 0
    pct: float = 0.0
    success_rate: float = 0.0


class PlatformFinancialProviderResponse(BaseModel):
    data: List[PlatformFinancialProviderEntry] = Field(default_factory=list)


class PlatformFinancialTypeEntry(BaseModel):
    entry_type: str
    total_cents: int = 0
    tx_count: int = 0
    avg_cents: int = 0


class PlatformFinancialTypeResponse(BaseModel):
    data: List[PlatformFinancialTypeEntry] = Field(default_factory=list)


class PlatformFinancialTopCreatorEntry(BaseModel):
    user_id: str
    revenue_cents: int = 0
    tx_count: int = 0
    avg_cents: int = 0


class PlatformFinancialTopCreatorsResponse(BaseModel):
    data: List[PlatformFinancialTopCreatorEntry] = Field(default_factory=list)


class PlatformFinancialRollupIn(BaseModel):
    date: Optional[str] = None  # YYYY-MM-DD; defaults to today (UTC)


class PlatformFinancialRollupOut(BaseModel):
    date: str
    gmv_cents: int = 0
    net_revenue_cents: int = 0
    tx_count: int = 0
    unique_payers: int = 0
    computed_at: int = 0


# ── License Agreements (LICENSE-001) ─────────────────────────────────────────

class LicenseAgreementCreateIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    licensor_name: str = Field(min_length=1, max_length=200)
    license_type: str = Field(description="royalty_free|creative_commons|commercial|custom|editorial|public_domain")
    territory: str = Field(default="worldwide", max_length=100)
    expires_at: Optional[int] = Field(default=None, description="Unix timestamp of expiration date")
    notes: str = Field(default="", max_length=1000)


class LicenseAgreementUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=2, max_length=200)
    licensor_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    license_type: Optional[str] = None
    territory: Optional[str] = Field(default=None, max_length=100)
    expires_at: Optional[int] = None
    notes: Optional[str] = Field(default=None, max_length=1000)


class LicenseAgreementStatusIn(BaseModel):
    status: str = Field(description="active|archived")


class LicenseAgreementContentLinkIn(BaseModel):
    content_id: str = Field(min_length=1, max_length=200)
    content_type: str = Field(description="video|post|broadcast")


class LicenseAgreementAdminReviewIn(BaseModel):
    verified: bool
    rejection_reason: str = Field(default="", max_length=500)


class LicenseAgreementOut(BaseModel):
    license_id: str
    title: str
    licensor_name: str = ""
    license_type: str
    file_name: str = ""
    file_size: int = 0
    mime_type: str = ""
    status: str
    version: int = 1
    territory: str = "worldwide"
    expires_at: Optional[int] = None
    notes: str = ""
    rejection_reason: str = ""
    created_at: int = 0
    updated_at: int = 0
    content_count: int = 0
    expiring_soon: bool = False


class LicenseAgreementListOut(BaseModel):
    items: List[LicenseAgreementOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class LicenseAgreementContentLinkOut(BaseModel):
    content_id: str
    content_type: str
    license_id: str
    linked_at: int = 0


class LicenseAgreementDownloadOut(BaseModel):
    download_url: str


class LicenseAgreementReviewItemOut(BaseModel):
    license_id: str
    creator_id: str
    creator_display_name: str = ""
    title: str
    licensor_name: str = ""
    license_type: str = ""
    submitted_at: int = 0


class LicenseAgreementReviewQueueOut(BaseModel):
    items: List[LicenseAgreementReviewItemOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
# ─── Security Groups & Network Rules (INFRA-009) ────────────────────────────

class SecurityRuleIn(BaseModel):
    protocol: Literal["tcp", "udp", "icmp", "all"]
    port_from: int = Field(default=0, ge=0, le=65535)
    port_to: int = Field(default=0, ge=0, le=65535)
    source: str = Field(..., min_length=1, max_length=100)
    direction: Literal["inbound", "outbound"] = "inbound"
    description: str = Field(default="", max_length=200)


class SecurityRuleOut(BaseModel):
    rule_id: str
    protocol: str
    port_from: int
    port_to: int
    source: str
    direction: str
    description: str


class CreateSgIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    rules: List[SecurityRuleIn] = Field(default_factory=list)


class UpdateSgIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)


class SecurityGroupOut(BaseModel):
    sg_id: str
    name: str
    description: str
    rules: List[SecurityRuleOut]
    is_default: bool
    created_at: int
    updated_at: int
    associated_instances: List[str]


class SgListOut(BaseModel):
    security_groups: List[SecurityGroupOut]
    count: int


class AddRuleIn(SecurityRuleIn):
    pass


class UpdateRuleIn(BaseModel):
    protocol: Optional[Literal["tcp", "udp", "icmp", "all"]] = None
    port_from: Optional[int] = Field(default=None, ge=0, le=65535)
    port_to: Optional[int] = Field(default=None, ge=0, le=65535)
    source: Optional[str] = Field(default=None, min_length=1, max_length=100)
    direction: Optional[Literal["inbound", "outbound"]] = None
    description: Optional[str] = Field(default=None, max_length=200)


class EffectiveRuleOut(BaseModel):
    rule_id: str
    protocol: str
    port_from: int
    port_to: int
    source: str
    resolved_sources: List[str]
    direction: str
    description: str


class EffectiveRulesOut(BaseModel):
    sg_id: str
    rules: List[EffectiveRuleOut]
    count: int
# ─── Ad Fraud Prevention (ADS-014) ────────────────────────────────────────────

class AdFraudEventOut(BaseModel):
    """A flagged ad fraud event (admin view)."""
    event_id: str = ""
    user_id: str = ""
    ip_address: str = ""
    account_id: str = ""
    campaign_id: str = ""
    creative_id: str = ""
    event_type: str = ""
    fraud_score: int = 0
    rule_scores: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str = "flagged"
    created_at: int = 0
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[int] = None


class AdFraudAccountRiskOut(BaseModel):
    """Fraud risk summary for one advertiser account."""
    account_id: str = ""
    fraud_rate_bps: int = 0
    total_events: int = 0
    flagged_events: int = 0
    status: str = "unknown"
    last_fraud_event_at: Optional[int] = None
    last_event_at: Optional[int] = None


class AdFraudSummaryOut(BaseModel):
    """Platform-wide ad fraud summary stats."""
    flagged_events_today: int = 0
    total_events: int = 0
    flagged_events: int = 0
    fraud_rate_bps: int = 0
    suspended_accounts: int = 0
    tracked_accounts: int = 0
    top_fraud_rules: Dict[str, int] = Field(default_factory=dict)


class AdFraudReviewIn(BaseModel):
    """Admin confirm/dismiss decision on a flagged fraud event."""
    decision: str = Field(..., pattern="^(confirm|dismiss)$")


class AdFraudSuspendIn(BaseModel):
    """Admin manual account suspension reason."""
    reason: str = ""


# ── Ad Scheduling & Dayparting (ADS-016) ──────────────────────────────


class DaypartingSchedule(BaseModel):
    """Per-campaign dayparting schedule: day-of-week → active hours (0-23)."""
    timezone: str = "UTC"
    schedule: Dict[str, List[int]] = Field(default_factory=dict)


class CampaignFlight(BaseModel):
    """A single phase ("flight") within a campaign."""
    flight_id: Optional[str] = None
    name: str = Field(default="Flight", max_length=100)
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    daily_budget_cents: int = Field(ge=100)
    creative_ids: List[str] = Field(min_length=1)
    status: Optional[str] = None


class CampaignScheduleUpdate(BaseModel):
    """Update dayparting and/or flight schedule on a campaign."""
    dayparting: Optional[DaypartingSchedule] = None
    flights: Optional[List[CampaignFlight]] = None
    campaign_timezone: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class DaypartingEligibility(BaseModel):
    """Result of an "is active now" dayparting check."""
    eligible: bool
    timezone: str = "UTC"
    local_time: Optional[str] = None
    day: Optional[str] = None
    hour: Optional[int] = None
    active_hours: List[int] = Field(default_factory=list)
    reason: Optional[str] = None
    active_flight: Optional[Dict[str, Any]] = None


class BudgetPacing(BaseModel):
    """Dayparting-aware budget pacing for a campaign."""
    active_hours_today: int = 0
    hours_remaining: int = 0
    hourly_budget_cents: int = 0
    remaining_budget_cents: int = 0


class CampaignScheduleOut(BaseModel):
    """Current schedule configuration for a campaign."""
    campaign_id: Optional[str] = None
    campaign_timezone: str = "UTC"
    dayparting: Optional[Dict[str, Any]] = None
    flights: Optional[List[Dict[str, Any]]] = None
    start_date: Optional[Any] = None
    end_date: Optional[Any] = None
# ---------------------------------------------------------------------------
# FIN-014: Payment Provider Health
# ---------------------------------------------------------------------------

class PaymentHealthProviderStatus(BaseModel):
    """Current health status for a single payment provider."""
    provider: str
    status: str  # "healthy" | "degraded" | "down"
    enabled: bool = True
    success_rate: float = 100.0
    error_rate_bps: int = 0
    avg_latency_ms: int = 0
    p50_latency_ms: int = 0
    p95_latency_ms: int = 0
    p99_latency_ms: int = 0
    total_success: int = 0
    total_failure: int = 0
    last_check_at: int = 0


class PaymentHealthTimeline(BaseModel):
    """Hourly health snapshots for the timeline chart."""
    provider: str
    hours: int
    data: List[Dict[str, Any]] = Field(default_factory=list)


class PaymentHealthErrorDrilldown(BaseModel):
    """Error type breakdown and recent failures for a provider."""
    provider: str
    error_types: Dict[str, int] = Field(default_factory=dict)
    recent_failures: List[Dict[str, Any]] = Field(default_factory=list)


class PaymentHealthProviderConfig(BaseModel):
    """Provider configuration (enabled state + alert thresholds)."""
    provider: str
    enabled: bool = True
    alert_error_rate_threshold: int = 500  # bps
    alert_latency_threshold_ms: int = 500
    alert_email: str = ""
    disabled_at: Optional[int] = None
    disabled_by: str = ""
    disable_reason: str = ""


class PaymentHealthConfigUpdate(BaseModel):
    """Root-only update to a provider's alert thresholds."""
    alert_error_rate_threshold: Optional[int] = Field(default=None, ge=1, le=10000)
    alert_latency_threshold_ms: Optional[int] = Field(default=None, ge=50, le=10000)
    alert_email: Optional[str] = Field(default=None, max_length=320)


class PaymentHealthToggleIn(BaseModel):
    """Root-only enable/disable of a payment provider."""
    enabled: bool
    reason: str = Field(default="", max_length=500)


class PaymentHealthToggleOut(BaseModel):
    """Result of a provider enable/disable toggle."""
    provider: str
    enabled: bool
    toggled_at: int
    reason: str = ""


class PaymentHealthIncident(BaseModel):
    """A historical provider outage/degradation incident."""
    incident_id: str
    provider: str
    started_at: int
    ended_at: Optional[int] = None
    status: str
    peak_error_rate: int = 0
    affected_webhooks: int = 0


class PaymentHealthIncidentCreate(BaseModel):
    """Manually open an incident for a provider."""
    status: str = Field(default="degraded", pattern="^(degraded|down)$")
    peak_error_rate: int = Field(default=0, ge=0, le=10000)
    affected_webhooks: int = Field(default=0, ge=0)


class PaymentHealthUptimeReport(BaseModel):
    """Availability percentage for a provider over a date range."""
    provider: str
    days: int
    uptime_pct: float
    total_incidents: int = 0
    total_downtime_minutes: int = 0
# ---------------------------------------------------------------------------
# Delegation API (DELEGATE-005)
# ---------------------------------------------------------------------------


class DelegationApiKeyCreateIn(BaseModel):
    """Request to issue a delegation-scoped API key."""
    label: str = Field(min_length=1, max_length=200)
    creator_id: str = Field(min_length=1)
    permissions: List[str] = Field(min_length=1)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)


class DelegationApiKeyOut(BaseModel):
    """A delegation API key (key_secret only present at creation)."""
    key_id: str
    label: str = ""
    owner_sub: str = ""
    creator_id: str = ""
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    status: str = "active"
    prefix: str = ""
    rate_limit_rpm: int = 60
    total_calls: int = 0
    last_used_at: int = 0
    created_at: int = 0
    expires_at: int = 0
    key_secret: Optional[str] = None


class DelegationApiKeyScopeOut(BaseModel):
    """Scope discovery for a delegation API key."""
    key_id: str
    creator_id: str = ""
    permissions: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    available_actions: List[Dict[str, str]] = Field(default_factory=list)
    rate_limit_rpm: int = 60
    total_calls: int = 0


class DelegationApiSendMessageIn(BaseModel):
    """Send a message as the creator via a delegation API key."""
    text: str = Field(min_length=1, max_length=10000)
    reply_to_message_id: Optional[str] = None


# ---------------------------------------------------------------------------
# SSH Session Recording & Playback (INFRA-010)
# ---------------------------------------------------------------------------

class StartSshRecordingIn(BaseModel):
    """Start a new SSH session recording."""
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    terminal_cols: int = Field(default=80, ge=1, le=1000)
    terminal_rows: int = Field(default=24, ge=1, le=1000)
    host_id: str = Field(default="", max_length=128)
    session_id: str = Field(default="", max_length=128)


class SshRecordingEventIn(BaseModel):
    """A single asciicast event: offset (seconds), type, and terminal data."""
    offset: float = Field(default=0.0, ge=0)
    type: Literal["o", "i"] = "o"
    data: str = Field(default="", max_length=131072)


class AppendSshRecordingEventsIn(BaseModel):
    """Append a batch of output/input events to an in-progress recording."""
    events: List[SshRecordingEventIn] = Field(default_factory=list, max_length=2000)


class SshRecordingOut(BaseModel):
    recording_id: str
    session_id: str = ""
    host_id: str = ""
    hostname: str
    port: int = 22
    username: str = ""
    host_key: str = ""
    status: str = "recording"
    start_time: int = 0
    end_time: int = 0
    duration_seconds: int = 0
    file_size_bytes: int = 0
    terminal_cols: int = 80
    terminal_rows: int = 24
    event_count: int = 0
    created_at: int = 0
    retention_days: int = 0
    expires_at: int = 0


class SshRecordingListOut(BaseModel):
    recordings: List[SshRecordingOut] = Field(default_factory=list)
    count: int = 0


class SshRecordingPlaybackOut(BaseModel):
    recording_id: str
    content_type: str = "application/x-asciicast"
    header: Dict[str, Any] = Field(default_factory=dict)
    events: List[List[Any]] = Field(default_factory=list)
    event_count: int = 0
# ─── VOD-019: Rental / View-Once Access ───────────────────────────────────────


class VodRentalStartIn(BaseModel):
    """Start a rental or view-once access grant for a video."""
    tier: str = Field(pattern=r"^(rental|view_once)$")
    payment_method_id: Optional[str] = None
    rental_duration_hours: Optional[int] = Field(default=None, ge=1, le=720)


class VodRentalStartOut(BaseModel):
    """Response after starting a rental / view-once grant."""
    video_id: str
    rental_id: str
    tier: str
    already_active: bool = False
    started: bool = False
    expires_at: Optional[int] = None
    views_remaining: int = -1
    amount_cents: int = 0
    duration_hours: Optional[int] = None


class VodRentalAccessOut(BaseModel):
    """Current rental access state for a video + viewer."""
    active: bool
    tier: str = ""
    reason: str = "not_rented"
    expires_at: Optional[int] = None
    remaining_seconds: int = 0
    views_remaining: int = -1
    rental_id: str = ""
    started: bool = False


class VodRentalPlaybackOut(BaseModel):
    """Gated playback URL issued for a valid rental."""
    video_id: str
    playback_url: str
    manifest_key: str = ""
    mode: str = "dev"
    thumbnail_url: Optional[str] = None
    token_expires_at: int = 0
    access: VodRentalAccessOut


class VodRentalConsumeOut(BaseModel):
    """Result of consuming a view-once rental after playback."""
    ok: bool
    tier: str = ""
    views_remaining: int = -1
    consumed: bool = False


class VodRentalStatusOut(BaseModel):
    """Rental status / history entry for a single video."""
    video_id: str
    rental_id: str = ""
    tier: str = ""
    amount_cents: int = 0
    created_at: int = 0
    started_at: int = 0
    duration_hours: int = 0
    active: bool = False
    reason: str = "not_rented"
    expires_at: Optional[int] = None
    remaining_seconds: int = 0
    views_remaining: int = -1
    started: bool = False


class VodRentalListOut(BaseModel):
    """List of a viewer's rentals."""
    items: List[VodRentalStatusOut] = Field(default_factory=list)
# ── Per-Content Revenue Breakdown (FIN-006) ──────────────────────────

class ContentRevenueItem(BaseModel):
    """Single content item with per-source revenue breakdown (cents)."""
    content_id: str
    content_type: str = "post"  # "vod" | "post" | "broadcast"
    title: str = ""
    published_at: int = 0
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0


class ContentRevenueListOut(BaseModel):
    """Paginated list of content items with revenue."""
    items: List[ContentRevenueItem] = Field(default_factory=list)
    total_items: int = 0
    total_revenue_cents: int = 0
    next_cursor: Optional[str] = None
    currency: str = "USD"


class ContentRevenueTimeSeriesPoint(BaseModel):
    """Single day in the content revenue time series."""
    date: str
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0


class ContentRevenueDetailOut(BaseModel):
    """Revenue breakdown for a single content item with time series."""
    content_id: str
    content_type: str = "post"
    title: str = ""
    published_at: int = 0
    tips_cents: int = 0
    unlocks_cents: int = 0
    subscriptions_cents: int = 0
    ads_cents: int = 0
    vod_cents: int = 0
    total_cents: int = 0
    time_series: List[ContentRevenueTimeSeriesPoint] = Field(default_factory=list)
    currency: str = "USD"


# ---------------------------------------------------------------------------
# Instance Monitoring & Health (INFRA-008)
# ---------------------------------------------------------------------------

class InstanceMetricIngestIn(BaseModel):
    """A single metric datapoint pushed by/for an instance."""
    cpu_pct: int = Field(ge=0, le=100)
    mem_pct: int = Field(ge=0, le=100)
    disk_pct: int = Field(ge=0, le=100)
    net_in_kbps: int = Field(default=0, ge=0)
    net_out_kbps: int = Field(default=0, ge=0)
    status: str = Field(default="running")
    ts: Optional[int] = Field(default=None, description="Unix seconds; defaults to now")


class InstanceMonitoringSeedIn(BaseModel):
    """Deterministic test seeding of metric datapoints."""
    points: int = Field(default=20, ge=1, le=500)
    interval_seconds: int = Field(default=60, ge=1, le=86400)
    base_cpu_pct: int = Field(default=30, ge=0, le=100)
    base_mem_pct: int = Field(default=40, ge=0, le=100)
    base_disk_pct: int = Field(default=20, ge=0, le=100)


class InstanceMetricPoint(BaseModel):
    instance_id: str
    ts: int
    cpu_pct: int
    mem_pct: int
    disk_pct: int
    net_in_kbps: int
    net_out_kbps: int
    status: str


class InstanceMetricLatestOut(BaseModel):
    instance_id: str
    has_data: bool
    point: Optional[InstanceMetricPoint] = None


class InstanceMetricSeriesOut(BaseModel):
    instance_id: str
    points: List[InstanceMetricPoint] = Field(default_factory=list)
    count: int = 0


class InstanceHealthOut(BaseModel):
    instance_id: str
    instance_type: str = ""
    instance_status: str = ""
    health_status: str = "unknown"  # healthy | warning | critical | unknown
    reasons: List[str] = Field(default_factory=list)
    cpu_pct: int = 0
    mem_pct: int = 0
    disk_pct: int = 0
    datapoints: int = 0
    last_metric_ts: int = 0
    checked_at: int = 0
    thresholds: Dict[str, Any] = Field(default_factory=dict)


class InstanceMonitoringIngestOut(BaseModel):
    instance_id: str
    ts: int
    health_status: str
    stored: bool = True


# -- Auto-restart policy (GAP-0230, INFRA-008) --

class RestartPolicyIn(BaseModel):
    auto_restart_enabled: Optional[bool] = None
    max_restarts: Optional[int] = Field(default=None, ge=0, le=10)


class RestartPolicyOut(BaseModel):
    instance_id: str
    resource_type: str = "ec2"  # "ec2" | "k8s"
    auto_restart_enabled: bool = False
    max_restarts: int = 3
    restart_count: int = 0
    last_restart_at: int = 0


# -- Lifecycle event timeline (GAP-0231, INFRA-008) --

class TimelineEventOut(BaseModel):
    event_id: str
    event_type: str
    ts: int
    detail: Dict[str, Any] = Field(default_factory=dict)


class InstanceTimelineOut(BaseModel):
    instance_id: str
    resource_type: str = "ec2"  # "ec2" | "k8s"
    events: List[TimelineEventOut] = Field(default_factory=list)
# -- Consumer Tax Documents (FIN-004) --

class SpendingCategoryOut(BaseModel):
    category: str
    total_cents: int = 0
    transaction_count: int = 0


class TaxSpendingSummaryOut(BaseModel):
    date_from: int
    date_to: int
    categories: List[SpendingCategoryOut] = Field(default_factory=list)
    grand_total_cents: int = 0
    transaction_count: int = 0
    currency: str = "usd"


class YearComparisonOut(BaseModel):
    current_year: int
    previous_year: int
    current_summary: TaxSpendingSummaryOut
    previous_summary: TaxSpendingSummaryOut
    change_pct: float = 0.0


class TaxDocumentOut(BaseModel):
    doc_id: str
    doc_type: str = "annual_summary"
    year: Optional[int] = None
    date_from: int = 0
    date_to: int = 0
    grand_total_cents: int = 0
    transaction_count: int = 0
    currency: str = "usd"
    created_at: int = 0


class TaxDocumentListOut(BaseModel):
    documents: List[TaxDocumentOut] = Field(default_factory=list)


class GenerateTaxDocumentIn(BaseModel):
    year: int
    regenerate: bool = False


# ── Creator 1099 / Tax-Form Generation (FIN-008) ────────────────────────────
# DISTINCT from consumer tax documents above: this is the platform-issuer side,
# generating annual 1099-NEC earnings forms for CREATORS / payees.

class TaxForm1099Out(BaseModel):
    form_id: str = ""
    user_sub: str = ""
    tax_year: int = 0
    total_earnings_cents: int = 0
    qualifies: bool = False
    status: str = "generated"
    correction_count: int = 0
    generated_at: int = 0
    updated_at: int = 0
    payer_name: str = ""
    payer_tin_last4: str = ""
    download_url: Optional[str] = None


class TaxForm1099ListOut(BaseModel):
    items: List[TaxForm1099Out] = Field(default_factory=list)


class GenerateTaxForm1099In(BaseModel):
    tax_year: int = Field(ge=2020, le=2100)


class TaxForm1099DownloadOut(BaseModel):
    download_url: str


class BatchGenerateTaxForm1099In(BaseModel):
    tax_year: int = Field(ge=2020, le=2100)


class BatchGenerateTaxForm1099Out(BaseModel):
    tax_year: int
    total_creators: int = 0
    qualifying: int = 0
    generated: int = 0
    skipped: int = 0
    errors: int = 0


class W9SubmitIn(BaseModel):
    """W-9 / tax-info submission (GAP-0020 / FIN-008).

    The raw ``tin`` is KMS-encrypted at the service layer and NEVER stored in
    plaintext, logged, or echoed back in any API response.
    """

    legal_name: str = Field(..., min_length=1, max_length=200)
    tin: str = Field(
        ...,
        description="Raw SSN (XXX-XX-XXXX) or EIN (XX-XXXXXXX). Never stored in plaintext.",
        min_length=9,
        max_length=11,
    )
    tin_type: Literal["ssn", "ein"]
    address_line1: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=2, max_length=2)
    zip_code: str = Field(..., min_length=5, max_length=10)
    certified: bool


class W9StatusOut(BaseModel):
    """Safe view of stored tax info — never includes ``tin_encrypted``."""

    legal_name: str = ""
    tin_last4: str = ""
    tin_type: str = ""
    address_line1: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    certified: bool = False
    certified_at: Optional[int] = None
    updated_at: int = 0


class PayoutTaxInfoOut(W9StatusOut):
    """W-9 status for the payouts pre-withdrawal gate (PAY-21).

    on_file tells the app whether a W-9 has been collected. The TIN is always
    masked to tin_last4 — the raw SSN/EIN is never included.
    """

    on_file: bool = False


class TaxInfoAdminOut(W9StatusOut):
    """W9StatusOut extended with the decrypted TIN (GAP-0194 / FIN-008).

    Returned ONLY by the ADMIN/ROOT-gated TIN-reveal endpoint. Every reveal is
    recorded in a queryable TAX_AUDIT trail. Never returned to non-admin callers.
    """

    tin_full: str = Field(..., description="Decrypted full TIN (SSN/EIN). Never cached or logged.")


# ── Admin Ad Platform Management (ADS-018) ──────────────────────────────────

class AdminAdAccountOut(BaseModel):
    """Advertiser account as seen by a platform admin (cross-user view)."""
    account_id: str
    owner_sub: str = ""
    company_name: str = ""
    billing_email: str = ""
    status: str = "pending_review"
    balance_cents: int = 0
    lifetime_spend_cents: int = 0
    created_at: int = 0
    updated_at: int = 0


class AdminAdCampaignOut(BaseModel):
    campaign_id: str
    account_id: str = ""
    name: str = ""
    objective: str = ""
    status: str = "draft"
    budget_cents: int = 0
    lifetime_spent_cents: int = 0
    created_at: int = 0


class AdminAdCreativeOut(BaseModel):
    creative_id: str
    campaign_id: str = ""
    account_id: str = ""
    format: str = ""
    title: str = ""
    status: str = "draft"
    created_at: int = 0


class AdminAdAccountDetailOut(BaseModel):
    account: AdminAdAccountOut
    campaigns: List[AdminAdCampaignOut] = Field(default_factory=list)
    campaign_count: int = 0


class AdminAdModerationAction(BaseModel):
    action: str = Field(pattern=r"^(approve|reject|suspend)$")
    reason: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=1000)


class AdminAdModerationResult(BaseModel):
    ok: bool = True
    item_type: str
    item_id: str
    status: str


class AdminAdModerationEventOut(BaseModel):
    event_id: str
    item_type: str
    item_id: str
    action: str
    admin_sub: str = ""
    reason: str = ""
    notes: str = ""
    prev_status: str = ""
    new_status: str = ""
    created_at: int = 0


class AdminAdPlatformMetricsOut(BaseModel):
    total_spend_cents: int = 0
    platform_revenue_cents: int = 0
    creator_share_cents: int = 0
    revenue_share_percent: float = 0.0
    impressions: int = 0
    clicks: int = 0
    conversions: int = 0
    effective_cpm_cents: int = 0
    account_count: int = 0
    campaign_count: int = 0
    creative_count: int = 0
    accounts_by_status: Dict[str, int] = Field(default_factory=dict)
    campaigns_by_status: Dict[str, int] = Field(default_factory=dict)
    creatives_by_status: Dict[str, int] = Field(default_factory=dict)
    pending_account_reviews: int = 0
    pending_creative_reviews: int = 0


class AdminAdRevenuePoint(BaseModel):
    month: str
    spend_cents: int = 0
    platform_revenue_cents: int = 0
    creator_share_cents: int = 0
    impressions: int = 0
    clicks: int = 0


class AdminAdTopSpenderOut(BaseModel):
    account_id: str
    company_name: str = ""
    owner_sub: str = ""
    spend_cents: int = 0


# ---------------------------------------------------------------------------
# Multi-Hop SSH Bastion (INFRA-011)
# ---------------------------------------------------------------------------

class SshBastionHopIn(BaseModel):
    """A single hop (jump host or target) in a bastion path."""
    hostname: str
    port: conint(ge=1, le=65535) = 22
    username: str
    ssh_key_id: str = ""
    label: str = ""


class SshBastionHopOut(BaseModel):
    hostname: str
    port: int = 22
    username: str = ""
    ssh_key_id: str = ""
    label: str = ""
    is_bastion: bool = False
    hop_number: int = 0


class CreateSshBastionPathIn(BaseModel):
    """Create a multi-hop bastion path: ordered jump hosts -> target."""
    label: str
    description: str = ""
    jump_hops: List[SshBastionHopIn] = Field(default_factory=list)
    target: SshBastionHopIn


class UpdateSshBastionPathIn(BaseModel):
    """Update a bastion path. Supply jump_hops + target together to replace the chain."""
    label: Optional[str] = None
    description: Optional[str] = None
    jump_hops: Optional[List[SshBastionHopIn]] = None
    target: Optional[SshBastionHopIn] = None


class SshBastionPathOut(BaseModel):
    path_id: str
    label: str
    description: str = ""
    hops: List[SshBastionHopOut] = Field(default_factory=list)
    total_hops: int = 0
    created_at: int = 0
    updated_at: int = 0


class SshBastionPathListOut(BaseModel):
    paths: List[SshBastionPathOut] = Field(default_factory=list)
    total: int = 0


class SshBastionResolvedOut(BaseModel):
    path_id: str
    label: str = ""
    chain: List[SshBastionHopOut] = Field(default_factory=list)
    jump_hops: List[SshBastionHopOut] = Field(default_factory=list)
    target: SshBastionHopOut
    total_hops: int = 0
    proxy_jump: str = ""
    ssh_command: str = ""
    ssh_config: str = ""
# ─── License Compliance (LICENSE-006) ──────────────────────────────────────

class ComplianceFlagIn(BaseModel):
    content_id: str
    reason: str = Field(
        description="One of: unlicensed_music, unlicensed_video, unlicensed_image, "
        "expired_license, copyright_claim, other"
    )
    evidence: str = Field(default="", max_length=2000)
    reporter_type: str = Field(default="viewer", description="viewer or creator")


class ComplianceFlagResolveIn(BaseModel):
    content_id: str = ""
    resolution: str = Field(description="One of: resolved, dismissed, action_required")
    notes: str = Field(default="", max_length=1000)


class ComplianceStatusUpdateIn(BaseModel):
    new_status: str = Field(
        description="One of: compliant, under_review, action_required, removed, resolved"
    )
    notes: str = Field(default="", max_length=1000)


class ComplianceStatusOut(BaseModel):
    content_id: str
    content_type: str = ""
    creator_id: str = ""
    compliance_status: str
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    last_checked_at: Optional[int] = None
    resolved_at: Optional[int] = None
    resolved_by: Optional[str] = None


class LicenseRefOut(BaseModel):
    license_id: str
    license_type: str
    license_status: str = ""
    expires_at: Optional[int] = None
    verified_at: Optional[int] = None


class LicenseRefListOut(BaseModel):
    items: List[LicenseRefOut] = Field(default_factory=list)


class ComplianceFlagOut(BaseModel):
    flag_id: str
    content_id: str = ""
    reporter_id: str = ""
    reporter_type: str = "viewer"
    reason: str = ""
    evidence: str = ""
    status: str = "open"
    created_at: int = 0
    resolved_at: Optional[int] = None
    resolved_by: Optional[str] = None
    resolution_notes: str = ""


class ComplianceFlagListOut(BaseModel):
    items: List[ComplianceFlagOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class ComplianceCheckResultOut(BaseModel):
    content_id: str
    compliance_status: str
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    checked_at: int = 0


class CreatorComplianceItemOut(BaseModel):
    content_id: str
    content_type: str = ""
    compliance_status: str
    issue_count: int = 0
    last_checked_at: Optional[int] = None


class ComplianceSummaryOut(BaseModel):
    total: int = 0
    compliant: int = 0
    expiring_soon: int = 0
    issues: int = 0
    flagged: int = 0


class CreatorComplianceListOut(BaseModel):
    items: List[CreatorComplianceItemOut] = Field(default_factory=list)
    summary: ComplianceSummaryOut = Field(default_factory=ComplianceSummaryOut)
    next_cursor: Optional[str] = None


class AdminComplianceIssueOut(BaseModel):
    content_id: str
    creator_id: str = ""
    creator_display_name: str = ""
    compliance_status: str = ""
    issue_type: str = ""
    severity: str = ""
    created_at: int = 0


class AdminComplianceIssueListOut(BaseModel):
    items: List[AdminComplianceIssueOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class ComplianceScanResultOut(BaseModel):
    checked: int = 0
    issues_found: int = 0
    alerts_sent: int = 0


# ─── Background Job Dashboard (PLATFORM-008) ─────────────────────────

class JobRegistryEntry(BaseModel):
    name: str
    label: str = ""
    source: str = ""
    description: str = ""
    poll_interval_seconds: int = 0
    run_now_safe: bool = False


class JobRegistryOut(BaseModel):
    jobs: List[JobRegistryEntry] = Field(default_factory=list)


class JobRunOut(BaseModel):
    job_name: str
    run_id: str
    status: str
    started_at: int = 0
    finished_at: int = 0
    duration_ms: float = 0
    items_processed: int = 0
    items_failed: int = 0
    error: Optional[str] = None
    triggered_by: str = ""


class JobRunsOut(BaseModel):
    items: List[JobRunOut] = Field(default_factory=list)
    count: int = 0


class JobHealthEntry(BaseModel):
    name: str
    label: str = ""
    description: str = ""
    poll_interval_seconds: int = 0
    run_now_safe: bool = False
    health: str = "unknown"
    last_status: Optional[str] = None
    last_run_at: Optional[int] = None
    last_finished_at: Optional[int] = None
    last_duration_ms: Optional[float] = None
    last_error: Optional[str] = None
    last_items_processed: int = 0
    last_items_failed: int = 0
    next_run_at: Optional[int] = None


class JobHealthOut(BaseModel):
    jobs: List[JobHealthEntry] = Field(default_factory=list)
    timestamp: int = 0


class JobRunNowOut(BaseModel):
    ok: bool = True
    job_name: str
    run: JobRunOut


class JobSeedOut(BaseModel):
    ok: bool = True
    seeded: int = 0
# ---------------------------------------------------------------------------
# Group Advertising & Fundraising (GROUP-003)
# ---------------------------------------------------------------------------


class GroupCreateCampaignIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    daily_budget_cents: int = Field(..., ge=100)
    lifetime_budget_cents: int = Field(..., ge=1000)
    creative_text: Optional[str] = Field(default=None, max_length=500)
    creative_image_url: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("lifetime_budget_cents")
    @classmethod
    def lifetime_gte_daily(cls, v: int, info) -> int:
        daily = info.data.get("daily_budget_cents", 0)
        if daily and v < daily:
            raise ValueError("Lifetime budget must be >= daily budget")
        return v


class GroupUpdateCampaignIn(BaseModel):
    status: Optional[Literal["active", "paused"]] = None
    daily_budget_cents: Optional[int] = Field(default=None, ge=100)


class GroupCampaignOut(BaseModel):
    campaign_id: str
    group_id: str
    name: str
    status: Literal["active", "paused", "completed", "draft"]
    daily_budget_cents: int
    lifetime_budget_cents: int
    spent_cents: int = 0
    impressions: int = 0
    clicks: int = 0
    creative_text: Optional[str] = None
    creative_image_url: Optional[str] = None
    created_at: int


class GroupCampaignListOut(BaseModel):
    campaigns: List[GroupCampaignOut] = Field(default_factory=list)


class GroupCampaignStatsOut(BaseModel):
    campaign_id: str
    impressions: int = 0
    clicks: int = 0
    ctr: float = 0.0
    spent_cents: int = 0
    remaining_cents: int = 0
    daily_spent_cents: int = 0
    daily_budget_cents: int = 0
    status: str = "active"


class GroupCreateFundraiserIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    goal_cents: Optional[int] = Field(default=None, ge=100)
    cover_image_url: Optional[str] = Field(default=None, max_length=2048)
    ends_at: Optional[int] = None

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Title cannot be blank")
        return v


class GroupUpdateFundraiserIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    goal_cents: Optional[int] = Field(default=None, ge=100)
    status: Optional[Literal["active", "paused", "cancelled"]] = None
    ends_at: Optional[int] = None


class GroupFundraiserOut(BaseModel):
    fundraiser_id: str
    group_id: str
    title: str
    description: str = ""
    goal_cents: Optional[int] = None
    raised_cents: int = 0
    donation_count: int = 0
    currency: str = "usd"
    status: Literal["active", "paused", "completed", "cancelled"]
    cover_image_url: Optional[str] = None
    created_at: int
    ends_at: Optional[int] = None


class GroupFundraiserListOut(BaseModel):
    fundraisers: List[GroupFundraiserOut] = Field(default_factory=list)


class GroupPublicFundraiserOut(BaseModel):
    fundraiser_id: str
    group_id: str
    group_name: str
    title: str
    description: str = ""
    goal_cents: Optional[int] = None
    raised_cents: int = 0
    donation_count: int = 0
    currency: str = "usd"
    status: str
    cover_image_url: Optional[str] = None
    ends_at: Optional[int] = None


class GroupDonateIn(BaseModel):
    amount_cents: int = Field(..., ge=100, le=10000000)
    donor_name: Optional[str] = Field(default=None, max_length=100)
    donor_email: Optional[str] = Field(default=None, max_length=254)

    @field_validator("donor_email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != "" and "@" not in v:
            raise ValueError("Invalid email format")
        return v


class GroupDonationOut(BaseModel):
    donation_id: str
    amount_cents: int
    donor_name: Optional[str] = None
    status: Literal["pending", "completed", "failed", "refunded"]
    created_at: int
    is_external: bool = True
    checkout_url: Optional[str] = None


class GroupDonationListOut(BaseModel):
    donations: List[GroupDonationOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    has_more: bool = False


class GroupDonationReceiptOut(BaseModel):
    donation_id: str
    amount_cents: int
    currency: str = "usd"
    donor_name: Optional[str] = None
    group_name: str
    fundraiser_title: str
    created_at: int
    status: str


# ─── Connection Profiles & Quick Connect (INFRA-006) ─────────────────────────

class CreateConnectionProfileIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    protocol: Literal["ssh", "vnc"] = "ssh"
    hostname: Optional[str] = Field(default="", max_length=253)
    instance_id: Optional[str] = Field(default="", max_length=128)
    port: int = Field(default=22, ge=1, le=65535)
    username: Optional[str] = Field(default="", max_length=64)
    auth_method: Literal["key", "key_ref", "password"] = "key_ref"
    # SEC-022: optional plaintext password (KMS-encrypted at rest by the
    # service; never echoed back — responses expose only ``has_password``).
    vnc_password: Optional[str] = Field(default=None, max_length=256)
    ssh_password: Optional[str] = Field(default=None, max_length=256)
    ssh_key_id: Optional[str] = Field(default="", max_length=128)
    bastion_path_id: Optional[str] = Field(default="", max_length=128)
    terminal_cols: int = Field(default=80, ge=40, le=300)
    terminal_rows: int = Field(default=24, ge=10, le=100)
    terminal_font_size: int = Field(default=14, ge=8, le=32)
    terminal_color_scheme: Literal["dark", "light", "monokai", "solarized", "dracula"] = "dark"
    is_favorite: bool = False
    auto_connect: bool = False


class UpdateConnectionProfileIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=200)
    hostname: Optional[str] = Field(default=None, max_length=253)
    instance_id: Optional[str] = Field(default=None, max_length=128)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = Field(default=None, max_length=64)
    auth_method: Optional[Literal["key", "key_ref", "password"]] = None
    # SEC-022: rotate (``password``) or remove (``clear_password``) the stored
    # password. KMS-encrypted at rest; never echoed back.
    password: Optional[str] = Field(default=None, max_length=256)
    clear_password: bool = False
    ssh_key_id: Optional[str] = Field(default=None, max_length=128)
    bastion_path_id: Optional[str] = Field(default=None, max_length=128)
    terminal_cols: Optional[int] = Field(default=None, ge=40, le=300)
    terminal_rows: Optional[int] = Field(default=None, ge=10, le=100)
    terminal_font_size: Optional[int] = Field(default=None, ge=8, le=32)
    terminal_color_scheme: Optional[Literal["dark", "light", "monokai", "solarized", "dracula"]] = None
    is_favorite: Optional[bool] = None
    auto_connect: Optional[bool] = None


class ConnectionProfileOut(BaseModel):
    profile_id: str
    label: str
    protocol: str = "ssh"
    hostname: str = ""
    instance_id: str = ""
    port: int = 22
    username: str = ""
    auth_method: str = "key_ref"
    has_password: bool = False
    ssh_key_id: str = ""
    bastion_path_id: str = ""
    terminal_cols: int = 80
    terminal_rows: int = 24
    terminal_font_size: int = 14
    terminal_color_scheme: str = "dark"
    is_favorite: bool = False
    auto_connect: bool = False
    use_count: int = 0
    created_at: int = 0
    updated_at: int = 0
    last_used_at: int = 0


class ConnectionProfileListOut(BaseModel):
    profiles: List[ConnectionProfileOut]
    total: int


class QuickConnectBastionOut(BaseModel):
    path_id: str
    proxy_jump: str
    ssh_command: str
    total_hops: int


class QuickConnectOut(BaseModel):
    profile_id: str
    label: str
    protocol: str
    hostname: str
    port: int
    username: str
    auth_method: str
    has_password: bool = False
    ssh_key_id: str = ""
    bastion_path_id: str = ""
    bastion: Optional[QuickConnectBastionOut] = None
    terminal_cols: int = 80
    terminal_rows: int = 24
    terminal_font_size: int = 14
    terminal_color_scheme: str = "dark"
    auto_connect: bool = False
    connected_at: int = 0



# ─── BCAST-010: Broadcast Newsfeed Promotion ───────────────────────

class BroadcastPromoLink(BaseModel):
    broadcast_id: str
    post_id: str
    owner_user_id: str
    promoted_at: int
    last_synced_status: str
    removed: bool = False


class BroadcastPromoLiveItem(BaseModel):
    broadcast_id: str
    post_id: str
    title: str
    owner_user_id: str
    promoted_at: int


class BroadcastPromoLinkResponse(BaseModel):
    link: BroadcastPromoLink


class BroadcastPromoLiveResponse(BaseModel):
    items: List[BroadcastPromoLiveItem] = Field(default_factory=list)


class BroadcastPromoDeleteResponse(BaseModel):
    ok: bool = True


# --- Content Boost (ADS-012) ---


class ContentBoostCreate(BaseModel):
    content_type: str = Field(..., description="post | video | broadcast")
    content_id: str = Field(..., min_length=1)
    budget_cents: int = Field(..., ge=1, description="total budget in integer cents")
    duration_seconds: int = Field(..., ge=1, description="boost duration in seconds")


class ContentBoostOut(BaseModel):
    boost_id: str
    owner_sub: str
    content_type: str
    content_id: str
    budget_cents: int
    spent_cents: int
    remaining_cents: int
    duration_seconds: int
    starts_at: int
    ends_at: int
    status: str
    created_at: int


class ContentBoostListOut(BaseModel):
    boosts: List[ContentBoostOut]


class ContentBoostSpendOut(BaseModel):
    boost_id: str
    budget_cents: int
    spent_cents: int
    remaining_cents: int
    status: str


class ContentBoostCancelOut(BaseModel):
    boost_id: str
    status: str
    refunded_cents: int
# ── PLATFORM-013: Theme Customization ────────────────────────────────────────
# Per-user theme configuration persisted in the `user_themes` table via
# app.services.theme_customization. Distinct from the legacy UX-001
# ui_preferences attribute.

class ThemeConfigOut(BaseModel):
    """Full per-user theme configuration (always fully populated)."""

    mode: Literal["light", "dark", "system"] = "system"
    accent_color: Literal[
        "blue", "purple", "green", "orange", "pink", "red", "teal", "custom"
    ] = "blue"
    custom_accent_hex: Optional[str] = None
    font_scale: Literal["small", "default", "large", "xlarge"] = "default"
    density: Literal["compact", "comfortable", "spacious"] = "comfortable"
    preset: Literal["default", "midnight", "sunrise", "forest", "ocean"] = "default"
    high_contrast: bool = False


class ThemeConfigResponse(BaseModel):
    """Envelope returned by GET/PATCH /ui/theme."""

    theme: ThemeConfigOut


class ThemeConfigPatchReq(BaseModel):
    """Partial theme update. All fields optional; only provided keys change."""

    mode: Optional[Literal["light", "dark", "system"]] = None
    accent_color: Optional[
        Literal["blue", "purple", "green", "orange", "pink", "red", "teal", "custom"]
    ] = None
    custom_accent_hex: Optional[str] = Field(default=None, max_length=7)
    font_scale: Optional[Literal["small", "default", "large", "xlarge"]] = None
    density: Optional[Literal["compact", "comfortable", "spacious"]] = None
    preset: Optional[Literal["default", "midnight", "sunrise", "forest", "ocean"]] = None
    high_contrast: Optional[bool] = None

    @field_validator("custom_accent_hex")
    @classmethod
    def _validate_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        raw = v.lstrip("#")
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", raw):
            raise ValueError("custom_accent_hex must be a 6-character hex color")
        return "#" + raw.upper()


# ─── VOD-018: Ad-Supported Viewing Tier ──────────────────────────────────────


class VodAdSupportedStartIn(BaseModel):
    """Request to start an ad-supported viewing session for a video.

    No payment is required — the viewer agrees to watch ad breaks in
    exchange for free playback. The viewer identity comes from the session.
    """

    resume_position_seconds: int = Field(default=0, ge=0)


class VodAdBreak(BaseModel):
    """A single ad break in an ad-supported viewing session's schedule."""

    break_id: str
    slot_type: str  # "pre_roll" | "mid_roll" | "overlay"
    position_seconds: int
    duration_seconds: int
    creative_id: str
    creative_url: str
    creative_type: str  # "video" | "image"
    skip_after_seconds: int
    slot_index: int
    ad_click_id: str = ""
    ctas: List[Dict[str, Any]] = Field(default_factory=list)
    completed: bool = False


class VodAdSupportedSessionOut(BaseModel):
    """State of an ad-supported viewing session."""

    session_id: str
    video_id: str
    status: str  # "active" | "completed" | "abandoned"
    ad_schedule: List[VodAdBreak]
    breaks_total: int
    breaks_completed: int
    next_required_break_id: Optional[str] = None
    playback_unlocked: bool
    ads_free: bool = False
    created_at: int
    updated_at: int


class VodAdSupportedStartOut(BaseModel):
    """Response when an ad-supported viewing session is started.

    Includes the free playback grant plus the ad schedule the viewer must
    watch. Continued playback past a mid-roll position is gated on the
    corresponding ad break being reported complete.
    """

    session_id: str
    video_id: str
    status: str
    ad_schedule: List[VodAdBreak]
    breaks_total: int
    breaks_completed: int
    next_required_break_id: Optional[str] = None
    playback_unlocked: bool
    ads_free: bool = False
    playback_url: str
    manifest_key: str
    mode: str
    thumbnail_url: Optional[str] = None
    token_expires_at: int
    created_at: int
    updated_at: int


class VodAdBreakReportIn(BaseModel):
    """Report that an ad break was viewed/completed (or skipped)."""

    break_id: str
    event_type: str = Field(default="complete", pattern=r"^(impression|complete|skip)$")


class VodAdBreakReportOut(BaseModel):
    """Result of reporting an ad break event."""

    ok: bool
    session_id: str
    video_id: str
    break_id: str
    event_type: str
    completed: bool
    breaks_completed: int
    breaks_total: int
    next_required_break_id: Optional[str] = None
    playback_unlocked: bool
    status: str


# ── Sponsored Content & Creator Partnerships (ADS-013) ──────────────


class SponsorshipDealCreate(BaseModel):
    """Advertiser proposes a sponsorship deal to a creator."""

    advertiser_account_id: str = Field(min_length=1)
    creator_sub: str = Field(min_length=1)
    content_type: str = Field(pattern=r"^(post|video|broadcast)$")
    brief: str = Field(min_length=10, max_length=5000)
    deliverables: List[str] = Field(min_length=1, max_length=10)
    compensation_cents: int = Field(ge=1000)  # min $10
    cpm_bonus_cents: int = Field(default=0, ge=0)
    deadline: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class SponsorshipDealOut(BaseModel):
    """Serialized sponsorship deal."""

    deal_id: str
    advertiser_account_id: str
    advertiser_sub: str
    creator_sub: str
    content_type: str
    brief: str
    deliverables: List[str]
    compensation_cents: int
    cpm_bonus_cents: int
    platform_commission_bps: int
    status: str
    deadline: str
    content_id: Optional[str] = None
    dm_conversation_id: Optional[str] = None
    escrow_hold_id: Optional[str] = None
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None
    cancelled_at: Optional[int] = None
    cancel_reason: Optional[str] = None
    payment_details: Optional[Dict[str, int]] = None


class SponsorshipContentSubmit(BaseModel):
    """Creator links produced content to an accepted deal."""

    content_id: str = Field(min_length=1)


class SponsorshipRejectRequest(BaseModel):
    """Creator rejects a proposed deal."""

    reason: str = Field(default="", max_length=500)


class SponsorshipCounterRequest(BaseModel):
    """Creator counter-offers on a proposed deal."""

    compensation_cents: Optional[int] = Field(default=None, ge=1000)
    note: str = Field(default="", max_length=2000)


class SponsorshipCancelRequest(BaseModel):
    """Either party cancels the deal."""

    reason: str = Field(min_length=1, max_length=500)


class SponsorshipDealEventOut(BaseModel):
    """A single deal lifecycle event."""

    event_id: str
    event_type: str
    actor_sub: str
    details: Dict[str, Any]
    created_at: int


# ---------------------------------------------------------------------------
# Image Optimization (PLATFORM-004)
# ---------------------------------------------------------------------------
class ImageOptimizeRequest(BaseModel):
    """Request on-demand optimization of an already-uploaded image.

    ``source_key`` is the S3 key returned by ``POST /ui/newsfeed/uploads/image``
    (the ``s3_key`` field). ``source_url`` (a ``/uploads/object?s3_key=...`` URL)
    may be supplied instead and the key is extracted from it.
    """

    source_key: Optional[str] = Field(default=None, max_length=2048)
    source_url: Optional[str] = Field(default=None, max_length=4096)
    format: str = Field(default="webp")
    use_cache: bool = Field(default=True)


class ImageOptimizationVariant(BaseModel):
    """A single responsive variant of an optimized image."""

    url: str
    width: int
    height: int
    size_bytes: int
    format: str = "webp"


class ImageOptimizationRecord(BaseModel):
    """Persisted optimization record returned to the client."""

    optimization_id: str
    owner_sub: str
    source_key: str
    source_url: str
    output_format: str = "webp"
    variants: Dict[str, ImageOptimizationVariant] = Field(default_factory=dict)
    cached: bool = False
    created_at: int



# ---------------------------------------------------------------------------
# Syndicate Treasury / Fund Management (SYND-004)
# ---------------------------------------------------------------------------

class SyndicateTreasuryDepositIn(BaseModel):
    amount_cents: int = Field(ge=100, le=1000000)


class SyndicateTreasuryDisburseIn(BaseModel):
    recipient_user_id: str = Field(min_length=1)
    amount_cents: int = Field(ge=1, le=1000000)
    note: str = ""


class SyndicateTreasuryBalanceOut(BaseModel):
    syndicate_id: str
    balance_cents: int = 0
    total_deposited_cents: int = 0
    total_disbursed_cents: int = 0
    currency: str = "usd"
    updated_at: int = 0


class SyndicateTreasuryDepositOut(BaseModel):
    ok: bool = True
    amount_cents: int = 0
    new_personal_balance_cents: int = 0
    new_treasury_balance_cents: int = 0
    treasury_entry_id: str = ""
    user_entry_id: str = ""


class SyndicateTreasuryDisburseOut(BaseModel):
    ok: bool = True
    amount_cents: int = 0
    recipient_user_id: str = ""
    new_treasury_balance_cents: int = 0
    new_recipient_balance_cents: int = 0
    treasury_entry_id: str = ""
    user_entry_id: str = ""


class SyndicateTreasuryLedgerEntryOut(BaseModel):
    entry_id: str
    ts: int = 0
    direction: str = "credit"
    amount_cents: int = 0
    reason: str = ""
    actor_user_id: str = ""
    counterparty_user_id: str = ""
    currency: str = "usd"


class SyndicateTreasuryLedgerOut(BaseModel):
    entries: List[SyndicateTreasuryLedgerEntryOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    has_more: bool = False


class SyndicateTreasuryContributorOut(BaseModel):
    user_id: str
    total_contributed_cents: int = 0
    total_refunded_cents: int = 0
    net_contributed_cents: int = 0
    contribution_count: int = 0
    last_contribution_at: int = 0


# ---------------------------------------------------------------------------
# Syndicate Advertising (SYND-006)
# ---------------------------------------------------------------------------


class SyndicateCampaignCreativeIn(BaseModel):
    headline: str = Field(min_length=1, max_length=100)
    body: str = Field(min_length=1, max_length=500)
    image_url: Optional[str] = None
    cta_text: str = Field(min_length=1, max_length=50)
    cta_url: str = Field(min_length=1, max_length=200)


class SyndicateCampaignTargetingIn(BaseModel):
    audience: str = Field(default="all")
    interests: List[str] = Field(default_factory=list, max_length=10)
    geo: Optional[str] = None
    age_min: Optional[int] = Field(default=None, ge=13, le=100)
    age_max: Optional[int] = Field(default=None, ge=13, le=100)


class SyndicateCampaignCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)
    budget_cents: int = Field(ge=100, le=10_000_000)
    creative: SyndicateCampaignCreativeIn
    targeting: Optional[SyndicateCampaignTargetingIn] = None
    start_date: str = ""
    end_date: Optional[str] = None


class SyndicateCampaignStatusUpdateIn(BaseModel):
    status: str = Field(pattern="^(active|paused|cancelled)$")


class SyndicateCampaignBudgetAddIn(BaseModel):
    additional_cents: int = Field(ge=100, le=10_000_000)


class SyndicateCampaignImpressionIn(BaseModel):
    viewer_user_id: str = ""
    clicked: bool = False


class SyndicateCampaignOut(BaseModel):
    campaign_id: str
    syndicate_id: str
    name: str
    description: str = ""
    status: str
    budget_cents: int = 0
    spent_cents: int = 0
    remaining_cents: int = 0
    creative: Dict[str, Any] = Field(default_factory=dict)
    targeting: Dict[str, Any] = Field(default_factory=dict)
    start_date: str = ""
    end_date: str = ""
    created_by: str = ""
    created_at: int = 0
    updated_at: int = 0
    stats_summary: Dict[str, Any] = Field(default_factory=dict)


class SyndicateCampaignDailyStatsOut(BaseModel):
    date: str
    impressions: int = 0
    clicks: int = 0
    spend_cents: int = 0
    unique_viewers: int = 0


class SyndicateCampaignAnalyticsOut(BaseModel):
    campaign_id: str
    daily: List[SyndicateCampaignDailyStatsOut] = Field(default_factory=list)
    totals: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# KYC-006: Sanctions / PEP Screening models
# ---------------------------------------------------------------------------

KycScreenType = Literal[
    "sanctions_ofac", "sanctions_eu", "sanctions_un", "pep_check", "adverse_media"
]
KycScreeningResultStatus = Literal["clear", "potential_match", "confirmed_match"]
KycScreeningDecision = Literal["clear", "confirm", "escalate"]
KycScreeningTrigger = Literal[
    "submission", "profile_change", "continuous_monitoring", "manual"
]


class KycScreeningMatchDetail(BaseModel):
    """A single match from a sanctions / PEP watchlist."""

    list_name: str
    matched_name: str
    matched_dob: Optional[str] = None
    match_score: float = Field(ge=0.0, le=1.0)
    entity_id: str
    entity_type: Literal["individual", "entity", "vessel", "aircraft"] = "individual"
    listed_since: Optional[str] = None
    source_url: Optional[str] = None


class KycScreeningResultOut(BaseModel):
    """A single screening result for one screen type."""

    screening_id: str
    case_id: Optional[str] = None
    screen_key: Optional[str] = None
    screen_type: KycScreenType
    user_sub: Optional[str] = None
    result: KycScreeningResultStatus
    match_details: List[KycScreeningMatchDetail] = Field(default_factory=list)
    reviewed_by: Optional[str] = None
    review_decision: Optional[KycScreeningDecision] = None
    review_note: Optional[str] = None
    reviewed_at: Optional[int] = None
    trigger: KycScreeningTrigger = "submission"
    provider: str = "mock_screening"
    created_at: int = 0


class KycScreeningResultsListResponse(BaseModel):
    """All screening results for a case."""

    results: List[KycScreeningResultOut] = Field(default_factory=list)


class KycScreeningPendingReviewsResponse(BaseModel):
    """Screening results that need reviewer adjudication."""

    items: List[KycScreeningResultOut] = Field(default_factory=list)
    cursor: Optional[str] = None


class KycScreeningUserHistoryResponse(BaseModel):
    """Screening history for a user across all cases."""

    user_sub: str
    results: List[KycScreeningResultOut] = Field(default_factory=list)
    total: int = 0


class KycScreeningRunRequest(BaseModel):
    """Trigger a screening run for a user / case (admin / reviewer)."""

    user_sub: str = Field(min_length=1, max_length=320)
    case_id: Optional[str] = None
    # Optional injectable identity inputs for deterministic screening.
    name: Optional[str] = Field(default=None, max_length=200)
    dob: Optional[str] = Field(default=None, max_length=32)
    country: Optional[str] = Field(default=None, max_length=64)


class KycScreeningRescreenResponse(BaseModel):
    """Response from triggering a (re-)screen run."""

    ok: bool = True
    case_id: str
    user_sub: str
    results_count: int = 0
    trigger: KycScreeningTrigger = "manual"
    matches_found: int = 0
    results: List[KycScreeningResultOut] = Field(default_factory=list)


class KycScreeningReviewRequest(BaseModel):
    """Reviewer adjudication of a screening match."""

    decision: KycScreeningDecision
    note: str = Field(min_length=1, max_length=2000)


# --------------------------------------------------------------------------- #
#  FIN-018: Billing Configuration UI                                            #
# --------------------------------------------------------------------------- #


class BillingConfigOut(BaseModel):
    """Effective billing configuration (override-or-default)."""

    fee_tips_bps: int = Field(..., ge=0, le=5000, description="Platform fee for tips in basis points")
    fee_unlocks_bps: int = Field(..., ge=0, le=5000, description="Platform fee for unlocks")
    fee_subscriptions_bps: int = Field(..., ge=0, le=5000, description="Platform fee for subscriptions")
    fee_catalog_bps: int = Field(..., ge=0, le=5000, description="Platform fee for catalog purchases")
    fee_ad_revenue_bps: int = Field(..., ge=0, le=5000, description="Platform fee for ad revenue share")
    fee_call_bps: int = Field(..., ge=0, le=5000, description="Platform fee for per-minute calls")
    min_payout_cents: int = Field(..., ge=0, description="Minimum payout threshold in cents")
    payout_fee_cents: int = Field(..., ge=0, description="Per-payout processing fee in cents")
    payout_schedule: str = Field(..., description="Payout frequency: daily, weekly, or monthly")
    auto_payout_enabled: bool = Field(..., description="Whether auto-payout is enabled")
    min_deposit_cents: int = Field(..., ge=0, description="Minimum deposit amount in cents")
    max_deposit_cents: int = Field(..., ge=0, description="Maximum deposit amount in cents")
    deposit_fee_bps: int = Field(..., ge=0, le=5000, description="Deposit fee in basis points")
    default_currency: str = Field(..., description="Default currency (ISO 4217)")
    supported_currencies: List[str] = Field(..., description="List of supported currency codes")
    tax_enabled: bool = Field(..., description="Whether tax collection is active")
    default_tax_rate_bps: int = Field(..., ge=0, le=10000, description="Default tax rate in basis points")
    updated_at: Optional[int] = Field(default=None, description="Last update timestamp")
    updated_by: Optional[str] = Field(default=None, description="Admin who last updated")


class BillingConfigUpdate(BaseModel):
    """Partial update request for billing configuration."""

    fee_tips_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_unlocks_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_subscriptions_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_catalog_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_ad_revenue_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    fee_call_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    min_payout_cents: Optional[int] = Field(default=None, ge=0)
    payout_fee_cents: Optional[int] = Field(default=None, ge=0)
    payout_schedule: Optional[str] = Field(default=None, pattern=r"^(daily|weekly|monthly)$")
    auto_payout_enabled: Optional[bool] = Field(default=None)
    min_deposit_cents: Optional[int] = Field(default=None, ge=0)
    max_deposit_cents: Optional[int] = Field(default=None, ge=0)
    deposit_fee_bps: Optional[int] = Field(default=None, ge=0, le=5000)
    default_currency: Optional[str] = Field(default=None, pattern=r"^[A-Za-z]{3}$")
    supported_currencies: Optional[List[str]] = Field(default=None)
    tax_enabled: Optional[bool] = Field(default=None)
    default_tax_rate_bps: Optional[int] = Field(default=None, ge=0, le=10000)


class BillingConfigResetRequest(BaseModel):
    """Reset one or more config keys to their env/code defaults."""

    keys: Optional[List[str]] = Field(default=None, description="Keys to reset; null = reset all")


class BillingConfigAuditEntry(BaseModel):
    """Single entry in the billing-config audit log."""

    admin_sub: str = Field(..., description="Admin who made the change")
    changes: List[Dict[str, Any]] = Field(
        ..., description="List of field changes: [{field, old_value, new_value}]"
    )
    created_at: int = Field(..., description="Unix timestamp of the change")


class BillingConfigAuditLog(BaseModel):
    """Paginated billing-config audit log."""

    entries: List[BillingConfigAuditEntry] = Field(default_factory=list)
    count: int = 0
    cursor: Optional[str] = Field(default=None)


class BillingConfigPreview(BaseModel):
    """Impact preview for proposed billing-config changes."""

    affected_tx_types: List[str] = Field(..., description="Transaction types affected")
    projected_daily_delta_cents: int = Field(..., description="Projected daily revenue delta in cents")
    sample_before: Dict[str, Any] = Field(..., description="Sample $10 transaction with current fees")
    sample_after: Dict[str, Any] = Field(..., description="Same transaction with proposed fees")



# ─── Ad Creative Affiliate Discounts (ADS-015) ───────────────────────
# Links an ad creative to an affiliate tracking code + promo discount code.
# Reuses promo_codes.py for discount validation and affiliate_links.py for
# click/conversion attribution. MONEY = int cents.


class AdAffiliateDiscountAttachIn(BaseModel):
    """Attach (or replace) an affiliate/promo discount on an ad creative."""

    campaign_id: str = Field(min_length=1, max_length=128)
    affiliate_code: Optional[str] = Field(default=None, max_length=20)
    promo_code: Optional[str] = Field(default=None, max_length=30)
    promo_value_display: Optional[str] = Field(default=None, max_length=50)
    click_through_url: Optional[str] = Field(default=None, max_length=2048)


class AdAffiliateDiscountUpdateIn(BaseModel):
    """Patch mutable fields on an attached affiliate/promo discount."""

    affiliate_code: Optional[str] = Field(default=None, max_length=20)
    promo_code: Optional[str] = Field(default=None, max_length=30)
    promo_value_display: Optional[str] = Field(default=None, max_length=50)
    click_through_url: Optional[str] = Field(default=None, max_length=2048)
    # Pass true to explicitly clear the affiliate or promo code.
    clear_affiliate_code: bool = False
    clear_promo_code: bool = False


class AdAffiliateDiscountOut(BaseModel):
    """An affiliate/promo discount attached to an ad creative."""

    creative_id: str
    campaign_id: str
    owner_sub: str
    affiliate_code: Optional[str] = None
    promo_code: Optional[str] = None
    promo_value_display: Optional[str] = None
    click_through_url: Optional[str] = None
    click_count: int = 0
    redemption_count: int = 0
    created_at: int = 0
    updated_at: int = 0


class AdAffiliateDiscountListOut(BaseModel):
    items: List[AdAffiliateDiscountOut] = Field(default_factory=list)


class AdAffiliateClickResult(BaseModel):
    """Result of an ad-creative click redirect."""

    redirect_url: str
    affiliate_code: Optional[str] = None
    promo_code: Optional[str] = None
    promo_value_display: Optional[str] = None


class AdAffiliateRedeemIn(BaseModel):
    """Validate + record an affiliate-discount redemption at checkout."""

    creative_id: str = Field(min_length=1, max_length=128)
    checkout_type: str = Field(default="shop", max_length=32)
    item_price_cents: int = Field(ge=0)
    creator_user_id: str = Field(min_length=1, max_length=128)
    order_id: Optional[str] = Field(default=None, max_length=128)


class AdAffiliateRedeemOut(BaseModel):
    """Validation / redemption result for an ad-creative discount."""

    valid: bool
    creative_id: str
    promo_code: Optional[str] = None
    affiliate_code: Optional[str] = None
    discount_type: Optional[str] = None
    discount_cents: int = 0
    final_price_cents: int = 0
    message: Optional[str] = None


class AdAffiliateStatsOut(BaseModel):
    """Attribution stats for an ad-creative affiliate discount."""

    creative_id: str
    click_count: int = 0
    redemption_count: int = 0
    total_discount_cents: int = 0


# ── Content-Provider Ad Controls (ADS-010) ──────────────────────────────────


class ContentAdOverrideIn(BaseModel):
    """Per-content ad-control override request (creator-owned content)."""

    content_type: str = Field(default="video", pattern="^(video|post|broadcast)$")
    ad_enabled: Optional[bool] = None
    ad_density: Optional[str] = Field(default=None, pattern="^(low|standard|high)$")
    pre_roll_enabled: Optional[bool] = None
    mid_roll_enabled: Optional[bool] = None
    ads_free_for_subscribers: Optional[bool] = None


class ContentAdOverrideOut(BaseModel):
    content_id: str
    content_type: str = "video"
    owner_sub: Optional[str] = None
    ad_enabled: bool = True
    ad_density: str = "standard"
    pre_roll_enabled: bool = True
    mid_roll_enabled: bool = True
    ads_free_for_subscribers: bool = False
    updated_at: Optional[int] = None


class RevenueShareIn(BaseModel):
    """Creator self-service revenue share in basis points (0-7000 max).

    Capped at the platform ceiling (70%); the platform retains at least a 30% floor.
    """

    revenue_share_bps: int = Field(ge=0, le=7000)


class AdRevenueBreakdownContentOut(BaseModel):
    content_id: str
    revenue_cents: int = 0


class AdRevenueBreakdownOut(BaseModel):
    total_ad_revenue_cents: int = 0
    entry_count: int = 0
    days: int = 30
    revenue_share_bps: int = 7000
    top_content: List[AdRevenueBreakdownContentOut] = Field(default_factory=list)


class AdvertiserTransparencyOut(BaseModel):
    account_id: str
    company_name: str = "Unknown"
    total_impressions: int = 0
    total_clicks: int = 0
    total_revenue_cents: int = 0



# ---------------------------------------------------------------------------
# Syndicate Page & Newsfeed (SYND-005)
# ---------------------------------------------------------------------------

class SyndicateProfileUpdateIn(BaseModel):
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    website_url: Optional[str] = Field(default=None, max_length=200)
    tags: Optional[List[str]] = Field(default=None, max_length=10)
    description: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def at_least_one_field(cls, values):
        if isinstance(values, dict):
            non_none = {k: v for k, v in values.items() if v is not None}
            if not non_none:
                raise ValueError("At least one field must be provided for update")
        return values


class SyndicateProfileOut(BaseModel):
    syndicate_id: str
    name: str
    description: str = ""
    avatar_url: str = ""
    banner_url: str = ""
    website_url: str = ""
    tags: List[str] = Field(default_factory=list)
    admin_user_id: str
    status: str = "active"
    member_count: int = 0
    post_count: int = 0
    members: List[SyndicateMemberOut] = Field(default_factory=list)
    bundle_plans: List[BundlePlanOut] = Field(default_factory=list)
    is_member: bool = False
    created_at: int = 0


class SyndicatePostCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    visibility: str = Field(default="public", pattern="^(public|members_only)$")
    image_url: Optional[str] = None


class SyndicatePostOut(BaseModel):
    post_id: str
    author_id: str
    author_name: str = ""
    author_avatar: str = ""
    text: str = ""
    image_url: str = ""
    syndicate_id: str
    visibility: str = "public"
    created_at: int = 0
    comment_count: int = 0
    reaction_counts: Dict[str, int] = Field(default_factory=dict)
    tip_total_cents: int = 0
    # ADV syndicate-feed ads: optional sponsored-unit fields so an injected
    # standalone sponsored unit serializes through this response model.
    is_sponsored: bool = False
    sponsor_label: str = ""
    headline: Optional[str] = None
    body: str = ""
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    ctas: List[Dict[str, Any]] = Field(default_factory=list)
    image_urls: List[str] = Field(default_factory=list)
    impression_url: Optional[str] = None
    click_url: Optional[str] = None
    creative_id: str = ""
    campaign_id: str = ""
    account_id: str = ""
    ad_click_id: str = ""
    content_owner_id: str = ""


class SyndicateFeedOut(BaseModel):
    posts: List[SyndicatePostOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    is_member: bool = False


# ---------------------------------------------------------------------------
# KYC-007: Enhanced Document Signing — versioned templates + notary stamp
# ---------------------------------------------------------------------------


class SignatureTemplateFieldModel(BaseModel):
    """A field definition within a versioned signature template."""

    id: str = Field(..., min_length=1, max_length=64)
    type: Literal["text", "signature", "initials", "date", "notary_stamp"] = Field(...)
    label: str = Field(default="", max_length=200)
    required: bool = Field(default=True)


class SignatureTemplateVersionOut(BaseModel):
    """A single version of a signature template."""

    template_key: str
    version: int
    display_name: str
    description: str = ""
    fields: List[SignatureTemplateFieldModel] = Field(default_factory=list)
    created_at: int = 0
    created_by: str = ""
    is_active: bool = True


class SignatureTemplateListOut(BaseModel):
    """Latest-version summary for every signature template key."""

    templates: List[SignatureTemplateVersionOut] = Field(default_factory=list)


class SignatureTemplateVersionsOut(BaseModel):
    """All versions of a single signature template, newest first."""

    template_key: str
    versions: List[SignatureTemplateVersionOut] = Field(default_factory=list)


class CreateSignatureTemplateVersionIn(BaseModel):
    """Request body to create the next version of a signature template."""

    template_key: str = Field(..., min_length=1, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    fields: List[SignatureTemplateFieldModel] = Field(..., min_length=1)


class SignatureTemplateMigrationOut(BaseModel):
    """A template pin that has a newer version available (needs re-signing)."""

    template_key: str
    display_name: str
    pinned_version: int
    latest_version: int
    needs_resigning: bool = True


class SignatureTemplateMigrationCheckIn(BaseModel):
    """Request body listing the template versions a set of packets pinned."""

    pins: List["SignatureTemplatePin"] = Field(default_factory=list)


class SignatureTemplatePin(BaseModel):
    template_key: str = Field(..., min_length=1, max_length=128)
    version: int = Field(..., ge=1)


class SignatureTemplateMigrationListOut(BaseModel):
    migrations: List[SignatureTemplateMigrationOut] = Field(default_factory=list)


class NotaryStampFieldValue(BaseModel):
    """Value stored in a notary_stamp signature field."""

    stamp_image_ref: str = Field(..., min_length=1, max_length=512)
    stamp_number: str = Field(..., min_length=1, max_length=128)
    stamp_expiry: str = Field(..., min_length=1, max_length=10, description="YYYY-MM-DD")
    stamped_at: int = Field(default=0)
    stamped_by: str = Field(default="")


SignatureTemplateMigrationCheckIn.model_rebuild()


# ── Ad Performance Optimization (ADS-017) ──────────────────────────────

class OptimizationCreativeStat(BaseModel):
    """Per-creative performance snapshot used to score recommendations."""

    creative_id: str
    impressions: int = 0
    clicks: int = 0
    ctr: float = 0.0
    weight: float = 0.0


class OptimizationRecommendation(BaseModel):
    """A single generated optimization recommendation (persisted)."""

    recommendation_id: str
    campaign_id: str
    account_id: str
    action: str = Field(
        ...,
        description='Suggested action: "pause_creative", "reallocate_budget", "adjust_bid"',
    )
    creative_id: Optional[str] = None
    title: str = ""
    description: str = ""
    impact: str = ""
    severity: str = "info"
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="open", description='"open", "applied", or "dismissed"')
    created_at: int = 0
    updated_at: int = 0
    applied_at: Optional[int] = None
    dismissed_at: Optional[int] = None


class OptimizationGenerateResult(BaseModel):
    """Result of a generate-now run: weights + new recommendations."""

    campaign_id: str
    creative_weights: Dict[str, float] = Field(default_factory=dict)
    creative_stats: List[OptimizationCreativeStat] = Field(default_factory=list)
    underperformers: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[OptimizationRecommendation] = Field(default_factory=list)
    generated_at: int = 0


class OptimizationRecommendationList(BaseModel):
    recommendations: List[OptimizationRecommendation] = Field(default_factory=list)


class ABTestRequest(BaseModel):
    creative_a_id: str
    creative_b_id: str
    confidence_level: float = Field(default=0.95, ge=0.80, le=0.99)


class ABTestResult(BaseModel):
    variant_a_ctr: float
    variant_b_ctr: float
    lift_percent: float
    z_score: float
    p_value: float
    significant: bool
    confidence_level: float
    winner: Optional[str] = None
    sample_size_sufficient: bool


class SuggestedBidOut(BaseModel):
    min_bid_cpm_cents: int
    suggested_bid_cpm_cents: int
    max_bid_cpm_cents: int
    estimated_fill_rate: float
    competition_level: str


class BudgetRecommendationOut(BaseModel):
    estimated_daily_reach: int
    recommended_daily_budget_cents: int
    estimated_cpm_cents: int
    reach_per_dollar: float


class OptimizationConfigUpdate(BaseModel):
    auto_optimize_enabled: Optional[bool] = None
    ctr_threshold: Optional[float] = Field(default=None, ge=0.001, le=0.5)
    auto_pause_min_impressions: Optional[int] = Field(default=None, ge=100)
    roas_threshold: Optional[float] = Field(default=None, ge=0.1)
    budget_pace_alert_ratio: Optional[float] = Field(default=None, ge=1.0, le=3.0)


# FEED-007: Mark Post Interesting (per-viewer "more like this" signal)
class PostInterestingOut(BaseModel):
    ok: bool = True
    post_id: str
    is_interesting: bool


class PostInterestingListOut(BaseModel):
    post_ids: List[str] = Field(default_factory=list)
    count: int = 0


# -- Syndicate Open Licensing (LICENSE-005) --

class SyndicateOpenLicensingTermsIn(BaseModel):
    profit_share_pct: int = Field(default=0, ge=0, le=100)
    fixed_cost_cents: int = Field(default=0, ge=0)
    revenue_share_pct: int = Field(default=0, ge=0, le=100)
    currency: str = Field(default="usd", max_length=3)


class SyndicateOpenLicensingEnableIn(BaseModel):
    terms: SyndicateOpenLicensingTermsIn = Field(default_factory=SyndicateOpenLicensingTermsIn)


class SyndicateOpenLicensingTermsUpdateIn(BaseModel):
    terms: SyndicateOpenLicensingTermsIn


class SyndicateOpenLicensingRegisterIn(BaseModel):
    content_id: str = Field(min_length=1, max_length=200)
    content_type: str = Field(description="One of: video, music, image, post, broadcast, clip")


class SyndicateOpenLicensingConfigOut(BaseModel):
    syndicate_id: str
    open_licensing_enabled: bool = False
    open_licensing_terms: Optional[Dict[str, Any]] = None
    enabled_at: Optional[int] = None
    disabled_at: Optional[int] = None


class SyndicateOpenLicensingEnableOut(BaseModel):
    syndicate_id: str
    open_licensing_enabled: bool = False
    open_licensing_terms: Optional[Dict[str, Any]] = None
    enabled_at: Optional[int] = None
    disabled_at: Optional[int] = None
    licenses_created: int = 0


class SyndicateOpenLicensingContentOut(BaseModel):
    content_id: str
    content_type: str
    creator_id: str
    registered_at: int = 0
    exempt: bool = False


class SyndicateOpenLicensingRegistrationOut(BaseModel):
    content_id: str
    syndicate_id: str
    licenses_created: int = 0


class SyndicateOpenLicensingExemptionOut(BaseModel):
    content_id: str
    syndicate_id: str
    exempt: bool = False
    revoked_count: int = 0
    licenses_created: int = 0


# ── Engagement Rate Calculation (FIN-012) ──────────────────────────


class EngagementRateOut(BaseModel):
    engagement_rate: float = 0.0
    engagement_rate_bps: int = 0
    period_days: int = 30
    total_interactions: int = 0
    follower_count: int = 0
    posts_in_period: int = 0
    likes: int = 0
    comments: int = 0
    shares: int = 0
    tips: int = 0
    trend: str = ""
    trend_delta: float = 0.0


class EngagementTimeSeriesItem(BaseModel):
    date: str
    engagement_rate: float = 0.0
    engagement_rate_bps: int = 0
    interactions: int = 0
    post_count: int = 0


class EngagementTimeSeriesOut(BaseModel):
    items: List[EngagementTimeSeriesItem] = Field(default_factory=list)


class EngagementPublicToggleIn(BaseModel):
    visible: bool


class EngagementPublicOut(BaseModel):
    engagement_rate_30d: float = 0.0
    engagement_rate_7d: float = 0.0
    visible: bool = False


class EngagementBenchmarksOut(BaseModel):
    """Platform-wide engagement benchmarks with the caller's percentile (GAP-0201)."""

    average_rate: float = 0.0
    median_rate: float = 0.0
    p25_rate: float = 0.0
    p75_rate: float = 0.0
    sample_size: int = 0
    my_percentile: Optional[float] = None  # null when caller has no rollup data
    computed_at: int = 0  # Unix timestamp of last benchmark compute
    date: str = ""  # YYYY-MM-DD the benchmark covers




# ─── KYC Webhooks & Notifications (KYC-011) ──────────────────────────────────

class KycWebhookEventType(BaseModel):
    event_type: str
    description: str


class KycWebhookEventTypesOut(BaseModel):
    event_types: List[KycWebhookEventType] = Field(default_factory=list)


class KycWebhookPrefsOut(BaseModel):
    in_app_enabled: bool = True
    email_enabled: bool = True
    events: List[str] = Field(default_factory=list)


class KycWebhookPrefsUpdateRequest(BaseModel):
    in_app_enabled: Optional[bool] = None
    email_enabled: Optional[bool] = None
    events: Optional[List[str]] = Field(default=None, max_length=40)


class KycWebhookNotificationItem(BaseModel):
    alert_id: str
    event: str
    title: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    action_url: Optional[str] = None
    read: bool = False
    created_at: int = 0


class KycWebhookNotificationsOut(BaseModel):
    items: List[KycWebhookNotificationItem] = Field(default_factory=list)
    total: int = 0


class KycWebhookEmitRequest(BaseModel):
    event: str = Field(min_length=1, max_length=80)
    user_sub: str = Field(min_length=1, max_length=256)
    case_id: Optional[str] = Field(default=None, max_length=128)
    data: Optional[Dict[str, Any]] = None


class KycWebhookEmitResult(BaseModel):
    event: str
    user_sub: str
    dispatched: bool = False
    channels: Dict[str, bool] = Field(default_factory=dict)
    alert_id: Optional[str] = None
    webhook_delivery_ids: List[str] = Field(default_factory=list)
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# SOCIAL-007: Snooze Following
# ---------------------------------------------------------------------------

class SnoozeFollowingIn(BaseModel):
    """Request body for POST /ui/social/following/{user_id}/snooze."""
    days: int = Field(..., ge=1, le=90, description="Number of days to snooze (1-90)")


class SnoozeFollowingOut(BaseModel):
    """Response for the snooze endpoint."""
    ok: bool = True
    snoozed_until: int


class UnsnoozeFollowingOut(BaseModel):
    """Response for the unsnooze endpoint."""
    ok: bool = True


class SnoozedFollowingOut(BaseModel):
    """A single snoozed following in the list."""
    following_sub: str
    following_name: Optional[str] = None
    following_avatar_url: Optional[str] = None
    followed_at: int = 0
    snoozed_until: int = 0
    snooze_remaining_hours: Optional[int] = None


class SnoozedFollowingListOut(BaseModel):
    """Response for GET /ui/social/following/snoozed."""
    snoozed: List[SnoozedFollowingOut] = Field(default_factory=list)
    total: int = 0




# ---------------------------------------------------------------------------
# Encrypted one-time share links (FILES-001)
# ---------------------------------------------------------------------------


class CreateShareLinkIn(BaseModel):
    file_node_id: str = Field(..., min_length=1, max_length=2048)
    expiry_hours: int = Field(default=24, ge=1, le=720)
    max_downloads: int = Field(default=1, ge=1, le=100)
    password: Optional[str] = Field(default=None, min_length=4, max_length=128)


class ShareLinkOut(BaseModel):
    link_id: str
    file_node_id: str
    file_name: str
    file_size_bytes: int
    content_type: str
    created_at: int
    expires_at: int
    max_downloads: int
    download_count: int
    has_password: bool = False
    is_revoked: bool = False
    share_url: str


class ShareLinkListOut(BaseModel):
    items: List[ShareLinkOut] = Field(default_factory=list)


class ShareLinkPublicInfoOut(BaseModel):
    file_name: str
    file_size_bytes: int
    content_type: str
    requires_password: bool = False
    is_expired: bool = False
    is_used: bool = False
    is_revoked: bool = False
    remaining_downloads: int = 0


class ShareLinkDownloadIn(BaseModel):
    password: Optional[str] = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# FEED-005: Countdown Posts
# ---------------------------------------------------------------------------
class CreateCountdownPostIn(BaseModel):
    """Request model for creating a countdown post."""

    post_kind: Literal["countdown"] = "countdown"
    countdown_title: str = Field(..., min_length=1, max_length=200)
    target_datetime: int = Field(..., gt=0, description="UTC Unix timestamp (seconds)")
    associated_event_type: Optional[Literal["broadcast", "call", "calendar", "custom"]] = None
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
    body: Optional[str] = Field(default=None, max_length=5000)
    image_urls: Optional[List[str]] = None
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    publish_at: Optional[int] = None

    @model_validator(mode="after")
    def validate_event_link(self):
        if self.associated_event_type and self.associated_event_type != "custom":
            if not self.associated_event_id:
                raise ValueError("associated_event_id required for non-custom events")
        return self


class CountdownPostOut(BaseModel):
    """Response model for countdown post data."""

    post_id: str
    user_id: str
    user_name: Optional[str] = None
    post_kind: Literal["countdown"] = "countdown"
    countdown_title: str
    target_datetime: int
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
    body: Optional[str] = None
    created_at: int = 0
    like_count: int = 0
    comment_count: int = 0
    reactions_counts: Optional[Dict[str, int]] = None




# ─── Instance Templates & Presets (INFRA-007) ────────────────────────────────

class CreateTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    category: Literal["compute", "database", "web", "ml", "custom"] = "custom"
    target: Literal["ec2", "k8s"]
    instance_type: str = Field(default="", max_length=20)
    ami_id: str = Field(default="", max_length=50)
    k8s_image: str = Field(default="", max_length=100)
    k8s_preset: str = Field(default="", max_length=20)
    startup_script: str = Field(default="", max_length=16_384)
    ports: List[int] = Field(default_factory=list)
    env_vars: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    auto_terminate_after: int = Field(default=7200, ge=600, le=86400)


class UpdateTemplateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    category: Optional[Literal["compute", "database", "web", "ml", "custom"]] = None
    instance_type: Optional[str] = Field(default=None, max_length=20)
    ami_id: Optional[str] = Field(default=None, max_length=50)
    k8s_image: Optional[str] = Field(default=None, max_length=100)
    k8s_preset: Optional[str] = Field(default=None, max_length=20)
    startup_script: Optional[str] = Field(default=None, max_length=16_384)
    ports: Optional[List[int]] = None
    env_vars: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    auto_terminate_after: Optional[int] = Field(default=None, ge=600, le=86400)


class CloneTemplateIn(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=100)


class LaunchFromTemplateIn(BaseModel):
    label: str = Field(default="", max_length=100)
    instance_type: Optional[str] = Field(default=None, max_length=20)
    ami_id: Optional[str] = Field(default=None, max_length=50)
    k8s_image: Optional[str] = Field(default=None, max_length=100)
    k8s_preset: Optional[str] = Field(default=None, max_length=20)
    auto_terminate_after: Optional[int] = Field(default=None, ge=600, le=86400)
    ssh_key_id: Optional[str] = None


class TemplateOut(BaseModel):
    template_id: str
    name: str
    description: str = ""
    category: str = "custom"
    target: str = "ec2"
    instance_type: str = ""
    ami_id: str = ""
    k8s_image: str = ""
    k8s_preset: str = ""
    startup_script: str = ""
    ports: List[int] = Field(default_factory=list)
    env_vars: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    auto_terminate_after: int = 7200
    icon: str = ""
    is_system: bool = False
    owner_sub: str = ""
    created_at: int = 0
    updated_at: int = 0
    use_count: int = 0


class TemplateListOut(BaseModel):
    templates: List[TemplateOut] = Field(default_factory=list)
    count: int = 0


class LaunchFromTemplateOut(BaseModel):
    target: str
    template_id: str
    resource_id: str = ""
    instance: Optional[TemplateLaunchInstanceOut] = None
    pod: Optional[TemplateLaunchPodOut] = None


class TemplateLaunchInstanceOut(BaseModel):
    instance_id: str = ""
    label: str = ""
    instance_type: str = ""
    ami_id: str = ""
    status: str = ""
    public_ip: str = ""
    auto_terminate_after: int = 0


class TemplateLaunchPodOut(BaseModel):
    pod_id: str = ""
    label: str = ""
    image: str = ""
    preset: str = ""
    status: str = ""
    pod_ip: str = ""
    ttl_seconds: int = 0


LaunchFromTemplateOut.model_rebuild()


# --------------------------------------------------------------------------- #
# KYC-012: Compliance Reporting & Export                                       #
# --------------------------------------------------------------------------- #
class KycSarRequest(BaseModel):
    """Request body for Suspicious Activity Report generation."""

    user_sub: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=10, max_length=2000)
    transaction_ids: Optional[List[str]] = Field(default=None, max_length=50)


class KycReportExportRequest(BaseModel):
    """Request body for exporting a compliance report as CSV or PDF."""

    format: Literal["csv", "pdf"] = "csv"
    start_date: Optional[int] = Field(default=None, ge=0)
    end_date: Optional[int] = Field(default=None, ge=0)


class KycVolumeReportOut(BaseModel):
    report_type: Literal["volume"] = "volume"
    period_start: int
    period_end: int
    total_cases: int = Field(ge=0)
    counts_by_status: Dict[str, int]
    approval_rate: float = Field(ge=0, le=100)
    rejection_rate: float = Field(ge=0, le=100)
    generated_at: int


class KycScreeningComplianceReportOut(BaseModel):
    report_type: Literal["screening"] = "screening"
    period_start: int
    period_end: int
    total_screenings: int = Field(ge=0)
    total_hits: int = Field(ge=0)
    hit_rate_pct: float = Field(ge=0, le=100)
    resolutions: Dict[str, int]
    false_positive_count: int = Field(ge=0)
    escalated_count: int = Field(ge=0)
    confirmed_count: int = Field(ge=0)
    generated_at: int


class KycProcessingTimeReportOut(BaseModel):
    report_type: Literal["processing_time"] = "processing_time"
    period_start: int
    period_end: int
    total_decided: int = Field(ge=0)
    avg_seconds: int = Field(ge=0)
    p50_seconds: Optional[int] = None
    p90_seconds: Optional[int] = None
    p95_seconds: Optional[int] = None
    min_seconds: Optional[int] = None
    max_seconds: Optional[int] = None
    generated_at: int


class KycOverdueCaseOut(BaseModel):
    case_id: str
    user_sub: str
    status: str
    submitted_at: int
    age_hours: float
    severity: Literal["warning", "critical"]
    assigned_admin: Optional[str] = None


class KycDeadlineReportOut(BaseModel):
    report_type: Literal["deadlines"] = "deadlines"
    warn_after_hours: int
    critical_after_hours: int
    total_overdue: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    cases: List[KycOverdueCaseOut]
    generated_at: int


class KycRetentionInventoryItemOut(BaseModel):
    case_id: str
    user_sub: str
    status: str
    decided_at: int
    retention_days: int
    purge_due_at: int
    purge_overdue: bool
    file_count: int
    has_selfie: bool
    has_id_document: bool
    has_proof_of_address: bool
    purged: bool


class KycRetentionReportOut(BaseModel):
    report_type: Literal["retention"] = "retention"
    policies: Dict[str, str]
    total_records: int = Field(ge=0)
    overdue_purge_count: int = Field(ge=0)
    already_purged_count: int = Field(ge=0)
    inventory: List[KycRetentionInventoryItemOut]
    generated_at: int


class KycAuditEventOut(BaseModel):
    event_name: str
    actor_sub: str
    timestamp: int
    outcome: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class KycAuditTrailOut(BaseModel):
    report_type: Literal["audit_trail"] = "audit_trail"
    user_sub: str
    total_events: int = Field(ge=0)
    events: List[KycAuditEventOut]
    generated_at: int


class KycSarCaseRefOut(BaseModel):
    case_id: str
    status: str
    created_at: int
    decided_at: Optional[int] = None


class KycSarOut(BaseModel):
    sar_id: str = Field(pattern=r"^SAR_[a-f0-9]{12}$")
    generated_at: int
    generated_by: str
    subject_user_sub: str
    reason: str
    kyc_cases: List[KycSarCaseRefOut]
    flagged_transactions: List[Dict[str, Any]]
    audit_trail: List[Dict[str, Any]]


class KycReportExportOut(BaseModel):
    format: Literal["csv", "pdf"]
    content: str = Field(description="CSV content as string (empty if no data)")
    report_type: str




# ===========================================================================
# MSG-008: GIF & Sticker Messages
# ===========================================================================

class GifSearchResult(BaseModel):
    """Single GIF result from the provider."""
    id: str = Field(..., description="Provider-specific GIF ID")
    url: str = Field(..., max_length=2048, description="GIF URL (direct link)")
    alt_text: str = Field(default="", max_length=256, description="GIF alt text")
    width: int = Field(default=0, ge=0, le=4096, description="Width in pixels")
    height: int = Field(default=0, ge=0, le=4096, description="Height in pixels")


class StickerOut(BaseModel):
    """Single sticker within a collection."""
    sticker_id: str = Field(..., max_length=64)
    image_url: str = Field(..., max_length=2048)
    alt_text: str = Field(default="", max_length=256)
    sort_order: int = Field(default=0, ge=0)
    width: int = Field(default=256, ge=0, le=4096)
    height: int = Field(default=256, ge=0, le=4096)


class StickerCollectionOut(BaseModel):
    """Sticker collection metadata."""
    collection_id: str
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    thumbnail_url: Optional[str] = None
    sticker_count: int = Field(default=0, ge=0)
    is_active: bool = True
    created_at: int
    stickers: List[StickerOut] = Field(default_factory=list)


class StickerCollectionListOut(BaseModel):
    """Response for listing sticker collections."""
    collections: List[StickerCollectionOut]


class StickerListOut(BaseModel):
    """Response for listing stickers within a collection."""
    stickers: List[StickerOut]


class StickerFavoriteOut(BaseModel):
    """Response when adding/removing a favorite."""
    ok: bool
    collection_id: str


class StickerSearchResult(BaseModel):
    """A sticker matching a search query."""
    sticker_id: str
    collection_id: str
    image_url: str
    alt_text: str
    collection_name: str


class StickerSearchResponse(BaseModel):
    """Response for sticker search."""
    results: List[StickerSearchResult]


class CreateStickerCollectionOut(BaseModel):
    """Response after creating a sticker collection (admin)."""
    collection_id: str
    name: str
    description: str
    sticker_count: int
    thumbnail_url: Optional[str] = None
    is_active: bool = True
    created_at: int
    stickers: List[StickerOut]


# ===========================================================================
# MSG-007: Custom Emojis
# ===========================================================================


class CustomEmojiOut(BaseModel):
    """A single custom emoji (personal or global)."""
    emoji_id: str
    shortcode: str
    name: str
    image_url: str
    alt_text: str = ""
    category: str = "Uncategorized"
    owner_scope: str
    created_by: str
    created_at: int = 0
    content_type: str = "image/png"
    file_size_bytes: int = 0


class CustomEmojiListOut(BaseModel):
    """Response for listing custom emojis visible to a caller."""
    emojis: List[CustomEmojiOut] = Field(default_factory=list)
    personal_count: int = 0
    global_count: int = 0


class ResolveShortcodesOut(BaseModel):
    """Map of custom shortcode -> image URL."""
    resolved: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of shortcode -> image_url",
    )




# ===========================================================================
# FIN-015: Fraud Detection Dashboard
# ===========================================================================

class FraudFlagOut(BaseModel):
    """Response model for a flagged transaction."""
    flag_id: str = Field(..., description="Unique flag identifier")
    user_id: str = Field(..., description="User who triggered the flag")
    tx_id: str = Field(..., description="Billing ledger entry ID that triggered the flag")
    rule_triggered: str = Field(..., description="Which fraud rule fired")
    risk_score: int = Field(..., ge=0, le=100, description="User's risk score at time of flag")
    amount_cents: int = Field(..., ge=0, description="Transaction amount in cents")
    status: str = Field(..., description="Current flag status")
    reviewed_by: Optional[str] = Field(None, description="Admin who reviewed this flag")
    reviewed_at: Optional[int] = Field(None, description="Unix timestamp of review")
    resolution: Optional[str] = Field(None, description="Resolution outcome")
    notes: Optional[str] = Field(None, description="Admin notes")
    created_at: int = Field(..., description="Unix timestamp when flag was created")


class FraudFlagReview(BaseModel):
    """Request model for reviewing a flagged transaction."""
    action: str = Field(..., pattern=r"^(approve|block|investigate)$", description="Review action")
    notes: str = Field(default="", max_length=1000, description="Optional admin notes")


class FraudFlagQueueOut(BaseModel):
    """Paginated list of flagged transactions."""
    flags: List[FraudFlagOut]
    count: int = Field(..., ge=0, description="Number of flags in this page")
    cursor: Optional[str] = Field(None, description="Pagination cursor for next page")


class UserRiskProfile(BaseModel):
    """Full risk profile for a user."""
    user_id: str
    score: int = Field(..., ge=0, le=100, description="Composite risk score (0-100)")
    components: Dict[str, int] = Field(..., description="Score breakdown by component")
    flagged: bool = Field(..., description="Whether user is currently flagged for review")
    frozen: bool = Field(..., description="Whether user's financial operations are frozen")
    frozen_at: Optional[int] = Field(None, description="Unix timestamp when frozen")
    frozen_by: Optional[str] = Field(None, description="Admin who froze the user")
    tx_count_24h: int = Field(..., ge=0, description="Number of transactions in last 24 hours")
    tx_total_24h: int = Field(..., ge=0, description="Total transaction amount (cents) in last 24h")
    chargeback_count: int = Field(..., ge=0, description="Lifetime chargeback count")
    last_scored_at: int = Field(..., description="Unix timestamp of last score computation")
    recent_flags: Optional[List[FraudFlagOut]] = Field(None, description="Most recent flags")


class HoneytokenMintIn(BaseModel):
    """Request to mint a decoy honeytoken (HNY-004/HNY-007)."""
    kind: str = Field(
        ..., pattern=r"^(api_key|credential_record|canary_row)$",
        description="Honeytoken kind",
    )
    label: str = Field(..., min_length=1, max_length=200, description="Human label / where placed")
    placement: Optional[str] = Field(None, max_length=500, description="Optional placement hint")


class HoneytokenOut(BaseModel):
    """Honeytoken metadata. NEVER includes the stored secret/hash."""
    token_id: str
    kind: str
    label: str = ""
    created_by: str = ""
    created_at: int = 0
    retired: bool = False
    placement: str = ""
    key_id: str = ""
    decoy_username: str = ""
    canary_id: str = ""


class HoneytokenMintOut(BaseModel):
    """Mint response — returns the plaintext secret ONCE (api_key/credential)."""
    token_id: str
    kind: str
    label: str = ""
    created_at: int = 0
    placement: str = ""
    api_key: Optional[str] = None
    key_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    canary_id: Optional[str] = None


class FreezeUserRequest(BaseModel):
    """Request model for freezing a user's financial operations."""
    reason: str = Field(..., min_length=1, max_length=500, description="Reason for freezing")


class FraudCaseCreate(BaseModel):
    """Request model for creating a fraud investigation case."""
    user_id: str = Field(..., description="User ID to investigate")
    flag_ids: List[str] = Field(..., min_length=1, description="Flag IDs to link to this case")
    notes: str = Field(default="", max_length=2000, description="Initial case notes")


class FraudCaseOut(BaseModel):
    """Response model for a fraud investigation case."""
    case_id: str = Field(..., description="Unique case identifier")
    user_id: str = Field(..., description="User under investigation")
    status: str = Field(..., description="Case status")
    assigned_to: Optional[str] = Field(None, description="Admin assigned to the case")
    flags: List[str] = Field(..., description="List of linked flag IDs")
    resolution: Optional[str] = Field(None, description="Resolution outcome when closed")
    notes: Optional[str] = Field(None, description="Case notes")
    created_at: int = Field(..., description="Unix timestamp when case was opened")
    resolved_at: Optional[int] = Field(None, description="Unix timestamp when case was resolved")


class FraudCaseResolve(BaseModel):
    """Request model for resolving a fraud case."""
    resolution: str = Field(
        ..., pattern=r"^(false_positive|confirmed_fraud|inconclusive)$",
        description="Resolution outcome",
    )
    notes: str = Field(default="", max_length=2000, description="Resolution notes")


class FraudConfigOut(BaseModel):
    """Response model for fraud detection configuration."""
    velocity_max_tx_per_hour: int = Field(..., ge=1, le=1000)
    velocity_max_amount_per_hour: int = Field(..., ge=1000)
    large_tx_threshold: int = Field(..., ge=1000)
    new_account_age_days: int = Field(..., ge=1, le=90)
    new_account_high_value: int = Field(..., ge=100)
    chargeback_threshold: int = Field(..., ge=1, le=100)
    flag_score_threshold: int = Field(..., ge=10, le=100)
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class FraudConfigUpdate(BaseModel):
    """Request model for updating fraud detection thresholds."""
    velocity_max_tx_per_hour: Optional[int] = Field(default=None, ge=1, le=1000)
    velocity_max_amount_per_hour: Optional[int] = Field(default=None, ge=1000)
    large_tx_threshold: Optional[int] = Field(default=None, ge=1000)
    new_account_age_days: Optional[int] = Field(default=None, ge=1, le=90)
    new_account_high_value: Optional[int] = Field(default=None, ge=100)
    chargeback_threshold: Optional[int] = Field(default=None, ge=1, le=100)
    flag_score_threshold: Optional[int] = Field(default=None, ge=10, le=100)


class FraudChargebackRecord(BaseModel):
    """Request model for recording a chargeback against a user."""
    user_id: str = Field(..., description="User who initiated the chargeback")
    amount_cents: int = Field(default=0, ge=0, description="Chargeback amount in cents")
    tx_id: str = Field(default="", description="Disputed ledger entry ID")


class FraudStatsOut(BaseModel):
    """Response model for fraud dashboard statistics."""
    pending_flags: int = Field(..., ge=0, description="Number of flags awaiting review")
    open_cases: int = Field(..., ge=0, description="Number of open investigation cases")
    frozen_users: int = Field(..., ge=0, description="Number of currently frozen users")
    flags_resolved_today: int = Field(..., ge=0, description="Flags resolved since midnight UTC")
    avg_resolution_hours: float = Field(..., ge=0, description="Average resolution time (hours)")


# ---------------------------------------------------------------------------
# Find-a-DateTime (MSG-009)
# ---------------------------------------------------------------------------


class BestWindowOut(BaseModel):
    """A computed best overlapping availability window."""
    start: str = Field(..., description="Window start ISO datetime (inclusive)")
    end: str = Field(..., description="Window end ISO datetime (exclusive)")
    count: int = Field(..., ge=0, description="Number of available participants")
    participants: List[str] = Field(default_factory=list, description="Display names of available participants")


class FindDateTimeResultOut(BaseModel):
    """Computed result after closing a Find-a-DateTime poll."""
    computed_at: int
    best_windows: List[BestWindowOut] = Field(default_factory=list)


class AvailabilityOut(BaseModel):
    """A single participant's availability submission."""
    user_sub: str
    user_name: str
    slots: List[str] = Field(default_factory=list)
    submitted_at: int


class FindDateTimeMetaOut(BaseModel):
    """Find-a-DateTime poll metadata."""
    poll_id: str
    conversation_id: str
    message_id: Optional[str] = None
    creator_sub: str
    title: str
    from_date: str
    to_date: str
    start_hour: int
    end_hour: int
    slot_duration_minutes: int
    deadline_at: int
    status: str  # "open" | "closed"
    created_at: int
    participant_count: int


class FindDateTimeFullOut(BaseModel):
    """Complete Find-a-DateTime response: metadata, availabilities, and result."""
    meta: FindDateTimeMetaOut
    availabilities: List[AvailabilityOut] = Field(default_factory=list)
    result: Optional[FindDateTimeResultOut] = None


# ---------------------------------------------------------------------------
# FEED-003: Find-a-DateTime Newsfeed Post
# ---------------------------------------------------------------------------


class CreateFindDateTimePostIn(BaseModel):
    """Request model for creating a Find-a-DateTime newsfeed post (FEED-003)."""
    title: str = Field(min_length=1, max_length=200)
    from_date: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Start date in YYYY-MM-DD format",
    )
    to_date: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="End date in YYYY-MM-DD format",
    )
    start_hour: int = Field(ge=0, le=23, description="Earliest hour of day (0-23)")
    end_hour: int = Field(ge=1, le=24, description="Latest hour of day (1-24)")
    slot_duration_minutes: int = Field(default=30)
    deadline_hours: int = Field(default=48, ge=1, le=336)
    body: str = Field(default="", max_length=5000, description="Optional description text")

    @model_validator(mode="after")
    def _validate_fadt_post(self) -> "CreateFindDateTimePostIn":
        if self.slot_duration_minutes not in (15, 30, 60):
            raise ValueError("slot_duration_minutes must be 15, 30, or 60")
        if self.start_hour >= self.end_hour:
            raise ValueError("start_hour must be less than end_hour")
        return self


class SubmitPostAvailabilityIn(BaseModel):
    """Request model for submitting availability on a FADT post poll (FEED-003)."""
    slots: List[str] = Field(min_length=1, max_length=500)


class FindDateTimePostOut(BaseModel):
    """Response model for a created Find-a-DateTime post (FEED-003)."""
    post_id: str
    user_id: str
    post_kind: Literal["find_datetime"] = "find_datetime"
    find_datetime_id: str
    title: str
    body: str = ""
    from_date: str
    to_date: str
    start_hour: int
    end_hour: int
    slot_duration_minutes: int
    deadline_at: int
    status: str = "open"
    created_at: str = ""
    like_count: int = 0
    comment_count: int = 0


class FindDateTimePostPollOut(BaseModel):
    """Response model for FADT post poll data (FEED-003)."""
    poll_id: str
    post_id: Optional[str] = None
    creator_sub: str
    title: str
    from_date: str
    to_date: str
    start_hour: int
    end_hour: int
    slot_duration_minutes: int
    deadline_at: int
    status: str  # "open" | "closed"
    participant_count: int = 0
    availabilities: List[AvailabilityOut] = Field(default_factory=list)
    best_windows: Optional[List[BestWindowOut]] = None


# --- KYC-014: Facial Comparison (selfie vs ID photo) -----------------------


class FaceComparisonOverrideRequest(BaseModel):
    """Request for an admin to override a face-comparison result."""

    decision: Literal["pass", "fail"] = Field(
        description="Override decision. Must be 'pass' or 'fail'.",
    )
    reason: str = Field(
        min_length=5,
        max_length=500,
        description="Reason for the override decision.",
    )


class AntiSpoofCheckOut(BaseModel):
    """Result of a single anti-spoof check."""

    check: str = Field(description="Check name (file_size, image_format, not_screenshot)")
    passed: bool
    detail: str


class AntiSpoofResultOut(BaseModel):
    """Overall anti-spoof result."""

    passed: bool
    checks: List[AntiSpoofCheckOut]
    total_checks: int = Field(ge=0)
    passed_checks: int = Field(ge=0)


class FaceComparisonAdminOverrideOut(BaseModel):
    """Admin override details attached to a comparison."""

    decision: Literal["pass", "fail"]
    reason: str
    admin_sub: str
    overridden_at: int


class FaceComparisonResultOut(BaseModel):
    """Result of a single face-comparison attempt."""

    comparison_id: str
    confidence_score: int = Field(ge=0, le=100)
    result: Literal["pass", "review", "fail"]
    anti_spoof: AntiSpoofResultOut
    attempt_number: int = Field(ge=1, le=3)
    max_attempts: int = Field(default=3)
    remaining_attempts: int = Field(ge=0, le=3)
    created_at: int
    admin_override: Optional[FaceComparisonAdminOverrideOut] = None


class FaceComparisonListOut(BaseModel):
    """List of face-comparison attempts for a case."""

    comparisons: List[FaceComparisonResultOut]


class FaceComparisonOverrideResultOut(BaseModel):
    """Response after an admin overrides a comparison."""

    comparison_id: str
    original_result: Literal["pass", "review", "fail"]
    original_score: int
    admin_override: FaceComparisonAdminOverrideOut


class KycFaceFileRefOut(BaseModel):
    """File reference for the admin comparison view."""

    file_type: str
    file_node_id: str
    attached_at: int


class BestComparisonOut(BaseModel):
    """Summary of the best comparison for the admin view."""

    comparison_id: str
    confidence_score: int
    result: Literal["pass", "review", "fail"]


class AdminFaceComparisonOut(BaseModel):
    """Admin side-by-side face-comparison view payload."""

    case_id: str
    user_sub: Optional[str] = None
    selfie_file: Optional[KycFaceFileRefOut] = None
    id_front_file: Optional[KycFaceFileRefOut] = None
    selfie_url: Optional[str] = None
    id_front_url: Optional[str] = None
    comparisons: List[FaceComparisonResultOut]
    best_comparison: Optional[BestComparisonOut] = None
    total_attempts: int = Field(ge=0)
    max_attempts: int = Field(default=3)


# -- KYC-022: Electronic Identity Verification (eIDV) -----------------------


class StartEidVerificationIn(BaseModel):
    """Request to start an eID verification session for a case."""

    scheme: str = Field(..., pattern=r"^(eidas|digid|bankid|aadhaar)$", description="eID scheme identifier")


class StartEidVerificationOut(BaseModel):
    """Response after starting an eID verification session."""

    session_id: str
    redirect_url: str
    expires_at: int
    scheme: str


class EidSchemeOut(BaseModel):
    """A single supported eID scheme."""

    id: str
    name: str
    countries: List[str]
    assurance_level: str
    auth_flow: str
    description: str = ""


class EidSchemesListOut(BaseModel):
    """List of supported eID schemes."""

    schemes: List[EidSchemeOut]


class EidVerifiedFieldsOut(BaseModel):
    """Government-verified identity fields extracted from an eID assertion."""

    first_name: str = ""
    last_name: str = ""
    date_of_birth: str = ""
    nationality: str = ""
    document_number: str = ""
    document_type: str = ""
    issuing_country: str = ""


class EidDiscrepancyOut(BaseModel):
    """A discrepancy between eID-verified data and the user's profile."""

    field: str
    profile_value: str
    eid_value: str
    severity: Literal["match", "warning", "critical"]


class EidVerificationOut(BaseModel):
    """The eID verification result for a case."""

    scheme: str
    assertion_id: str
    assurance_level: str
    verified_at: int
    auto_tier_upgrade: bool = False
    discrepancies: List[EidDiscrepancyOut] = Field(default_factory=list)
    verified_fields: Optional[EidVerifiedFieldsOut] = None


class EidStatusOut(BaseModel):
    """eID verification status envelope for a case."""

    eid_verification: Optional[EidVerificationOut] = None


class MockEidRequest(BaseModel):
    """Request body for the mock eID provider endpoint (dev mode only)."""

    session_id: str = Field(..., min_length=1)


class MockEidResponse(BaseModel):
    """Response from the mock eID provider: a base64 assertion + HMAC signature."""

    assertion: str
    signature: str




# ---------------------------------------------------------------------------
# Host Inventory Management (INFRA-001)
# ---------------------------------------------------------------------------

class CreateHostIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    protocol: Literal["ssh", "vnc", "rdp"] = "ssh"
    username: str = Field(default="", max_length=64)
    description: str = Field(default="", max_length=500)
    tags: List[str] = Field(default_factory=list, max_length=20)
    group: str = Field(default="", max_length=50)
    os_type: Literal["linux", "windows", "macos", "unknown"] = "unknown"
    record_sessions: bool = False


class UpdateHostIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Literal["ssh", "vnc", "rdp"]] = None
    username: Optional[str] = Field(default=None, max_length=64)
    description: Optional[str] = Field(default=None, max_length=500)
    tags: Optional[List[str]] = Field(default=None, max_length=20)
    group: Optional[str] = Field(default=None, max_length=50)
    os_type: Optional[Literal["linux", "windows", "macos", "unknown"]] = None
    is_pinned: Optional[bool] = None
    record_sessions: Optional[bool] = None


class HostOut(BaseModel):
    host_id: str
    label: str
    hostname: str
    port: int
    protocol: str
    username: str = ""
    description: str = ""
    tags: List[str] = []
    group: str = ""
    os_type: str = "unknown"
    created_at: int
    updated_at: int
    last_connected_at: int = 0
    connection_count: int = 0
    status: str = "unknown"
    is_pinned: bool = False
    source: str = "manual"
    record_sessions: bool = False


class HostListOut(BaseModel):
    hosts: List[HostOut]
    count: int
    cursor: Optional[str] = None


class HostConnectionEventOut(BaseModel):
    connected_at: int
    protocol: str


class HostHistoryOut(BaseModel):
    host_id: str
    connection_count: int
    last_connected_at: int
    events: List[HostConnectionEventOut]


class ImportHostsCsvIn(BaseModel):
    csv_content: str = Field(..., max_length=100_000)


class ImportResultOut(BaseModel):
    imported: int
    skipped: int
    errors: List[str]


class HostGroupListOut(BaseModel):
    groups: List[str]


class HostQuickConnectOut(BaseModel):
    host_id: str
    protocol: str
    hostname: str
    port: int
    username: str = ""
    label: str = ""
    # For VNC, a target_id the VNC session system can resolve via the
    # user host inventory ("user:{host_id}"); empty for non-VNC.
    target_id: str = ""
    ws_url: str = ""
    # Frontend route to navigate to with these params pre-filled.
    connect_path: str = ""


# KYC-015: KYC for Business / Corporate Accounts (KYB) models

CompanyTypeLiteral = Literal[
    "llc", "corp", "partnership", "sole_prop", "nonprofit", "cooperative", "trust"
]
DirectorRoleLiteral = Literal["director", "secretary", "ceo", "cfo", "coo", "treasurer"]
KybDocumentTypeLiteral = Literal[
    "certificate_of_incorporation",
    "articles_of_association",
    "shareholder_register",
    "financial_statements",
    "board_resolution",
    "proof_of_address_registered",
    "proof_of_address_trading",
]
KybAddressTypeLiteral = Literal["registered", "trading"]


class KybCreateRequest(BaseModel):
    legal_name: str = Field(min_length=2, max_length=200)
    trading_name: Optional[str] = Field(default=None, max_length=200)
    registration_number: str = Field(min_length=1, max_length=50)
    jurisdiction: str = Field(min_length=2, max_length=10)
    company_type: CompanyTypeLiteral
    incorporation_date: Optional[str] = Field(default=None, max_length=20)
    tax_id: Optional[str] = Field(default=None, max_length=50)
    website: Optional[str] = Field(default=None, max_length=200)
    industry: Optional[str] = Field(default=None, max_length=100)
    org_id: Optional[str] = Field(default=None, max_length=100)


class KybCompanyPatchRequest(BaseModel):
    expected_version: int = Field(ge=1)
    legal_name: Optional[str] = Field(default=None, min_length=2, max_length=200)
    trading_name: Optional[str] = Field(default=None, max_length=200)
    registration_number: Optional[str] = Field(default=None, min_length=1, max_length=50)
    jurisdiction: Optional[str] = Field(default=None, min_length=2, max_length=10)
    company_type: Optional[CompanyTypeLiteral] = None
    incorporation_date: Optional[str] = Field(default=None, max_length=20)
    tax_id: Optional[str] = Field(default=None, max_length=50)
    website: Optional[str] = Field(default=None, max_length=200)
    industry: Optional[str] = Field(default=None, max_length=100)


class KybUboAddRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    date_of_birth: Optional[str] = Field(default=None, max_length=20)
    nationality: Optional[str] = Field(default=None, max_length=3)
    ownership_percentage: float = Field(gt=0, le=100)
    personal_kyc_case_id: Optional[str] = Field(default=None, max_length=80)


class KybUboLinkRequest(BaseModel):
    personal_kyc_case_id: str = Field(min_length=1, max_length=80)


class KybDirectorAddRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    role: DirectorRoleLiteral = "director"
    date_of_birth: Optional[str] = Field(default=None, max_length=20)
    nationality: Optional[str] = Field(default=None, max_length=3)
    personal_kyc_case_id: Optional[str] = Field(default=None, max_length=80)


class KybDocumentRequest(BaseModel):
    document_type: KybDocumentTypeLiteral
    file_node_id: str = Field(min_length=1, max_length=200)
    file_name: Optional[str] = Field(default=None, max_length=300)


class KybAddressRequest(BaseModel):
    address_type: KybAddressTypeLiteral
    line1: str = Field(min_length=1, max_length=200)
    line2: Optional[str] = Field(default=None, max_length=200)
    city: str = Field(min_length=1, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    postal_code: str = Field(min_length=1, max_length=20)
    country: str = Field(min_length=2, max_length=3)


class KybSubmitRequest(BaseModel):
    expected_version: int = Field(ge=1)


class KybAdminDecisionRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason_codes: List[str] = Field(default_factory=list)
    note: Optional[str] = Field(default=None, max_length=2000)


class KybCaseEnvelope(BaseModel):
    case: Dict[str, Any]


class KybCaseListEnvelope(BaseModel):
    cases: List[Dict[str, Any]]


class KybUboEnvelope(BaseModel):
    ubo: Dict[str, Any]


class KybUboListEnvelope(BaseModel):
    ubos: List[Dict[str, Any]]


class KybDirectorEnvelope(BaseModel):
    director: Dict[str, Any]


class KybDirectorListEnvelope(BaseModel):
    directors: List[Dict[str, Any]]


class KybDocumentEnvelope(BaseModel):
    document: Dict[str, Any]


class KybAddressEnvelope(BaseModel):
    address: Dict[str, Any]


class KybScreeningEnvelope(BaseModel):
    case_id: str
    any_hit: bool
    screened: List[Dict[str, Any]]


class KybAdminQueueEnvelope(BaseModel):
    cases: List[Dict[str, Any]]


# ── KYC-021: Third-Party Partner API ─────────────────────────────────

class KycPartnerApplicantAddress(BaseModel):
    street: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(default="", max_length=100)
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)  # ISO 3166-1 alpha-2


class KycPartnerApplicantIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    date_of_birth: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    email: str = Field(..., max_length=254)
    phone: Optional[str] = Field(default=None, max_length=20)
    address: Optional[KycPartnerApplicantAddress] = None

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v.lower().strip()


class KycPartnerApplicationCreateIn(BaseModel):
    external_id: str = Field(..., min_length=1, max_length=128)
    applicant: KycPartnerApplicantIn
    tier: str = Field(default="tier_1", pattern=r"^tier_[123]$")
    metadata: Optional[Dict[str, Any]] = None


class KycPartnerApplicationOut(BaseModel):
    application_id: str
    external_id: str
    status: str
    decision: Optional[str] = None
    reason_codes: List[str] = Field(default_factory=list)
    applicant: Dict[str, Any] = Field(default_factory=dict)
    documents: List[Dict[str, Any]] = Field(default_factory=list)
    tier: str = "tier_1"
    created_at: int = 0
    updated_at: int = 0
    sandbox: bool = False


class KycPartnerApplicationResultOut(BaseModel):
    decision: str  # "approved" | "rejected"
    decided_at: int = 0
    reason_codes: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = None
    verified_fields: Dict[str, Any] = Field(default_factory=dict)


class KycPartnerWebhookRegisterIn(BaseModel):
    url: str = Field(..., min_length=10, max_length=2048)
    events: List[str] = Field(..., min_length=1)
    secret: str = Field(..., min_length=16, max_length=128)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if not v.startswith(("https://", "http://localhost")):
            raise ValueError("Webhook URL must use HTTPS (or http://localhost in dev)")
        return v

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: List[str]) -> List[str]:
        allowed = {"status_changed", "decision_made", "document_uploaded"}
        for event in v:
            if event not in allowed:
                raise ValueError(f"Invalid event: {event}. Allowed: {', '.join(sorted(allowed))}")
        return v


class KycPartnerWebhookOut(BaseModel):
    webhook_id: str
    url: str
    events: List[str] = Field(default_factory=list)
    created_at: int = 0




# ── KYC Ongoing Monitoring & Periodic Review (KYC-016) ──────────────────────


class KycTriggerEventRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class KycCompleteReviewRequest(BaseModel):
    new_risk_tier: Optional[Literal["low", "medium", "high", "critical"]] = None
    case_id: Optional[str] = None


class KycReviewScheduleEnvelope(BaseModel):
    schedule: Optional[Dict[str, Any]] = None


class KycTriggerEventListEnvelope(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class KycMonitoringDashboardEnvelope(BaseModel):
    generated_at: int
    upcoming_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    overdue_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    needs_review_count: int = 0


class KycReviewCheckResult(BaseModel):
    checked_at: int
    dry_run: bool
    entered_grace_period: int = 0
    auto_downgraded: int = 0


class KycRescreeningResult(BaseModel):
    screened_at: int
    dry_run: bool
    total_screened: int = 0
    matches_found: int = 0
    triggers_created: int = 0
    skipped: Optional[bool] = None
    reason: Optional[str] = None




# ── KYC-019: Case Assignment & Workload Management ──────────────────


class KycAdminAvailabilityIn(BaseModel):
    on_duty: bool = Field(..., description="Whether admin is available for new assignments")
    expertise_tiers: List[str] = Field(default_factory=list, max_length=5)
    languages: List[str] = Field(default_factory=list, max_length=10)
    max_cases: int = Field(default=20, ge=1, le=100)
    seniority_level: int = Field(default=0, ge=0, le=3)


class KycAdminAvailabilityOut(BaseModel):
    admin_sub: str
    on_duty: bool = False
    current_case_count: int = 0
    avg_processing_hours: float = 0.0
    expertise_tiers: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)
    seniority_level: int = 0
    max_cases: int = 20
    last_assigned_at: Optional[int] = None
    updated_at: Optional[int] = None


class KycAutoAssignIn(BaseModel):
    applicant_language: str = Field(default="en", min_length=2, max_length=8)


class KycAutoAssignOut(BaseModel):
    assigned_admin_sub: Optional[str] = None
    score: float = 0.0
    tier: str = ""
    reason: str = ""


class KycAutoAssignBatchIn(BaseModel):
    case_ids: List[str] = Field(..., min_length=1, max_length=100)
    applicant_language: str = Field(default="en", min_length=2, max_length=8)


class KycAutoAssignBatchOut(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)


class KycReassignIn(BaseModel):
    new_admin_sub: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=3, max_length=500)


class KycReassignOut(BaseModel):
    ok: bool = True
    previous_admin_sub: Optional[str] = None
    new_admin_sub: str = ""
    reason: str = ""


class KycClaimOut(BaseModel):
    ok: bool = True
    assigned_admin_sub: Optional[str] = None
    previous_admin_sub: Optional[str] = None


class KycSlaConfigEnvelope(BaseModel):
    sla_config: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class KycSlaConfigUpdateIn(BaseModel):
    target_hours: int = Field(..., ge=1, le=720)
    warning_pct: int = Field(..., ge=50, le=99)


class KycSlaConfigOut(BaseModel):
    tier: str
    target_hours: int
    warning_pct: int
    escalation_pct: int = 100
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class KycAssignmentEventOut(BaseModel):
    event_type: str
    from_admin: Optional[str] = None
    to_admin: Optional[str] = None
    reason: str = ""
    actor_sub: Optional[str] = None
    escalation_level: Optional[int] = None
    created_at: int = 0


class KycAssignmentHistoryOut(BaseModel):
    events: List[KycAssignmentEventOut] = Field(default_factory=list)


class KycMyAssignedCaseOut(BaseModel):
    kyc_case_id: str
    status: str
    tier: str
    assigned_at: Optional[int] = None
    sla_due_at: Optional[int] = None
    overdue: bool = False
    escalation_level: int = 0


class KycMyAssignedOut(BaseModel):
    cases: List[KycMyAssignedCaseOut] = Field(default_factory=list)


class KycSlaBreachOut(BaseModel):
    kyc_case_id: str
    assigned_admin_sub: Optional[str] = None
    tier: str
    sla_due_at: int
    hours_overdue: float
    escalation_level: int = 0


class KycSlaBreachListOut(BaseModel):
    breaches: List[KycSlaBreachOut] = Field(default_factory=list)


class KycEscalateOut(BaseModel):
    ok: bool = True
    kyc_case_id: str
    escalation_level: int
    previous_admin_sub: Optional[str] = None
    new_admin_sub: Optional[str] = None
    reason: str = ""


class KycWorkloadDashboardOut(BaseModel):
    admins: List[KycAdminAvailabilityOut] = Field(default_factory=list)
    sla_config: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    total_active_cases: int = 0
    total_on_duty_admins: int = 0


# === KYC-018: Address Verification Service =================================


class AddressInput(BaseModel):
    """Structured address input for verification."""

    # Address verification echoes possibly-partial input addresses (and compares
    # profile vs document addresses that may have missing fields), so these are
    # lenient rather than strictly-required to avoid response-model 500s.
    line_1: str = Field(default="", max_length=200)
    line_2: str = Field(default="", max_length=200)
    city: str = Field(default="", max_length=100)
    state: str = Field(default="", max_length=100)
    postal_code: str = Field(default="", max_length=20)
    country: str = Field(default="", max_length=2)


class VerifyAddressRequest(BaseModel):
    """Request body for triggering an address verification."""

    address: AddressInput


class PostalCodeValidationRequest(BaseModel):
    """Request body for standalone postal code validation."""

    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)


class CrossReferenceRequest(BaseModel):
    """Request body for cross-referencing a document address (admin)."""

    document_address: AddressInput


class AddressOverrideRequest(BaseModel):
    """Request body for an admin override of the verification decision."""

    decision: Literal["verified", "needs_review", "failed"]
    note: Optional[str] = Field(default=None, max_length=2000)


class GeocodingOut(BaseModel):
    """Geocoding coordinates."""

    lat: float = Field(..., ge=-90.0, le=90.0)
    lng: float = Field(..., ge=-180.0, le=180.0)


class CrossReferenceOut(BaseModel):
    """Cross-reference result between profile and document addresses."""

    match_score: float = Field(default=0.0, ge=0.0, le=1.0)
    discrepancies: List[str] = Field(default_factory=list)
    field_comparisons: List[Dict[str, Any]] = Field(default_factory=list)


class AddressOverrideOut(BaseModel):
    """Admin override metadata on a verification record."""

    decision: Literal["verified", "needs_review", "failed"]
    reviewer_sub: Optional[str] = None
    note: Optional[str] = None
    decided_at: Optional[int] = None


class AddressVerificationOut(BaseModel):
    """Address verification result for a KYC case."""

    verification_id: Optional[str] = None
    kyc_case_id: Optional[str] = None
    status: Literal[
        "verified", "partial_match", "unverifiable", "pending", "error"
    ] = "pending"
    decision: Literal["verified", "needs_review", "failed"] = "needs_review"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    country: Optional[str] = None
    country_format_valid: bool = False
    postal_format_hint: str = ""
    input_address: Optional[AddressInput] = None
    standardized_address: Optional[AddressInput] = None
    geocoding: Optional[GeocodingOut] = None
    discrepancies: List[str] = Field(default_factory=list)
    cross_reference: Optional[CrossReferenceOut] = None
    override: Optional[AddressOverrideOut] = None
    provider: Optional[str] = None
    verified_at: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0


class AddressVerificationResponse(BaseModel):
    """Envelope returned by verify / get / override endpoints."""

    verification: AddressVerificationOut


class AddressVerificationListResponse(BaseModel):
    """List of verification attempts for a case."""

    attempts: List[AddressVerificationOut] = Field(default_factory=list)


class PostalCodeValidationOut(BaseModel):
    """Postal code validation result."""

    valid: bool = False
    format_hint: str = ""
    normalized: str = ""


class CrossReferenceResponse(BaseModel):
    """Envelope returned by the cross-reference endpoint."""

    cross_reference: CrossReferenceOut




# ── KYC-017: Document Signing Template Library ──────────────────────────

KycTemplateTier = Literal["none", "tier_1", "tier_2", "tier_3"]
KycTemplateStatus = Literal["active", "inactive", "archived"]


class KycDocumentTemplateCreateIn(BaseModel):
    """Request to create a new document signing template."""

    slug: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z0-9_-]+$",
        description="URL-safe, unique slug (lowercase, digits, _ or -).",
    )
    display_name: str = Field(min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    required_tier: KycTemplateTier = "tier_1"
    placeholder_fields: List[str] = Field(default_factory=list, max_length=20)


class KycDocumentTemplateUploadIn(BaseModel):
    """JSON-mode upload of a base64-encoded PDF for a template version."""

    pdf_base64: str = Field(min_length=1, description="Base64-encoded PDF bytes.")


class KycDocumentTemplateVersionOut(BaseModel):
    """One version row of a document template."""

    template_id: str
    version: int = Field(ge=0)
    slug: str
    display_name: Optional[str] = None
    required_tier: KycTemplateTier = "tier_1"
    status: KycTemplateStatus = "active"
    s3_key: str = ""
    pdf_uploaded: bool = False
    placeholder_fields: List[str] = Field(default_factory=list)
    created_by: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class KycDocumentTemplateOut(BaseModel):
    """A document template (metadata) with its version history."""

    template_id: str
    slug: str
    display_name: str
    description: str = ""
    required_tier: KycTemplateTier = "tier_1"
    status: KycTemplateStatus = "active"
    placeholder_fields: List[str] = Field(default_factory=list)
    latest_version: int = 0
    s3_key: str = ""
    created_by: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0
    versions: List[KycDocumentTemplateVersionOut] = Field(default_factory=list)


class KycDocumentTemplateListOut(BaseModel):
    """List of document templates."""

    items: List[KycDocumentTemplateOut] = Field(default_factory=list)
    total: int = 0


class KycRequiredTemplatesOut(BaseModel):
    """Active templates required for a given tier."""

    tier: KycTemplateTier
    items: List[KycDocumentTemplateVersionOut] = Field(default_factory=list)


class KycTemplateRenderForCaseIn(BaseModel):
    """Request to render all required templates for a KYC case."""

    case_id: str = Field(min_length=1, max_length=100)


class KycRenderedTemplateOut(BaseModel):
    """One rendered+instantiated template for a case."""

    slug: str
    template_id: str
    version: int
    rendered_s3_key: str
    packet_id: Optional[str] = None
    fields_populated: int = 0
    fields_fallback: int = 0


class KycTemplateRenderForCaseOut(BaseModel):
    """Result of rendering required templates for a case."""

    case_id: str
    rendered: List[KycRenderedTemplateOut] = Field(default_factory=list)


# ── KYC Multi-Language Support (KYC-020) ─────────────────────────────────────


class KycTranslationIn(BaseModel):
    """Request model for creating/updating a KYC translation."""

    value: str = Field(..., min_length=1, max_length=10000, description="Translated string value")
    context: str = Field(default="", max_length=500, description="Usage context hint for translators")
    status: str = Field(default="published", pattern=r"^(published|draft|needs_review)$")


class KycTranslationOut(BaseModel):
    """Response model for a single KYC translation entry."""

    language_code: str
    key: str
    value: str
    context: str = ""
    status: str = "published"
    updated_by: Optional[str] = None
    updated_at: Optional[int] = None


class KycTranslationListOut(BaseModel):
    """Response model for listing KYC translations (admin)."""

    items: List[KycTranslationOut] = Field(default_factory=list)
    coverage: Optional[Dict[str, Any]] = None
    total: int = 0


class KycTranslationBundleOut(BaseModel):
    """Response model for a locale translation bundle (user-facing)."""

    language: str
    rtl: bool = False
    translations: Dict[str, str] = Field(default_factory=dict)


class KycSupportedLocaleOut(BaseModel):
    """A single supported locale descriptor."""

    code: str
    name: str
    native_name: str = ""
    rtl: bool = False


class KycSupportedLocalesOut(BaseModel):
    """Response model for the list of supported KYC locales."""

    default: str = "en"
    locales: List[KycSupportedLocaleOut] = Field(default_factory=list)


class KycTranslationCoverageOut(BaseModel):
    """Response model for KYC translation coverage of one language."""

    language_code: str
    total_keys: int = 0
    translated_keys: int = 0
    missing_keys: int = 0
    coverage_pct: float = 0.0


class KycCoverageReportOut(BaseModel):
    """Response model for multi-language KYC coverage report."""

    languages: Dict[str, KycTranslationCoverageOut] = Field(default_factory=dict)


class KycLocalizedQuestionnaireOut(BaseModel):
    """Response model for a localized questionnaire."""

    questionnaire: Dict[str, Any] = Field(default_factory=dict)
    language: str = "en"
    rtl: bool = False
    fallback_keys: List[str] = Field(default_factory=list)


class KycLocalizedLegalNoticeOut(BaseModel):
    """Response model for a localized legal notice."""

    text: str
    language: str
    version: str
    is_fallback: bool = False
    rtl: bool = False


class KycTranslationBulkImportIn(BaseModel):
    """Request model for bulk KYC translation import."""

    translations: Dict[str, str] = Field(..., description="Map of key -> value", max_length=500)
    status: str = Field(default="draft", pattern=r"^(published|draft|needs_review)$")


class KycTranslationBulkImportOut(BaseModel):
    """Response model for bulk import results."""

    imported: int = 0
    skipped: int = 0
    errors: List[str] = Field(default_factory=list)


class KycTranslationExportOut(BaseModel):
    """Response model for exporting translations for a language."""

    language: str
    translations: Dict[str, str] = Field(default_factory=dict)
# ── KYC Analytics & Funnel Dashboard (KYC-024) ──────────────────────────────


class FunnelStepOut(BaseModel):
    step: str
    count: int = 0
    percentage: float = 0.0
    drop_off_count: int = 0
    drop_off_pct: float = 0.0


class FunnelResponse(BaseModel):
    funnel: List[FunnelStepOut] = Field(default_factory=list)
    conversion_rate: float = 0.0


class TrendPointOut(BaseModel):
    period: str
    started: int = 0
    submitted: int = 0
    approved: int = 0
    rejected: int = 0


class TrendsResponse(BaseModel):
    trends: List[TrendPointOut] = Field(default_factory=list)


class HistogramBucketOut(BaseModel):
    bucket_label: str
    count: int = 0


class PercentilesOut(BaseModel):
    p50: float = 0.0
    p75: float = 0.0
    p90: float = 0.0
    p99: float = 0.0


class ProcessingTimesResponse(BaseModel):
    histogram: List[HistogramBucketOut] = Field(default_factory=list)
    percentiles: PercentilesOut = Field(default_factory=PercentilesOut)


class RejectionReasonsResponse(BaseModel):
    reasons: Dict[str, int] = Field(default_factory=dict)


class ScreeningHitPointOut(BaseModel):
    period: str
    total_screened: int = 0
    hits: int = 0
    hit_rate: float = 0.0


class ScreeningHitsResponse(BaseModel):
    trends: List[ScreeningHitPointOut] = Field(default_factory=list)


class CountryStatsOut(BaseModel):
    country: str
    count: int = 0
    approved: int = 0
    rejected: int = 0
    approval_rate: float = 0.0


class GeographicResponse(BaseModel):
    countries: List[CountryStatsOut] = Field(default_factory=list)


class DropOffStepOut(BaseModel):
    from_step: str
    to_step: str
    continued: int = 0
    dropped: int = 0
    drop_rate: float = 0.0
    avg_time_in_step_hours: float = 0.0


class DropOffResponse(BaseModel):
    steps: List[DropOffStepOut] = Field(default_factory=list)


class AnalyticsSnapshotOut(BaseModel):
    period_start: int = 0
    period_end: int = 0
    total_applications: int = 0
    approved_count: int = 0
    rejected_count: int = 0
    pending_count: int = 0
    conversion_rate: float = 0.0
    avg_processing_hours: float = 0.0
    processing_time_distribution: PercentilesOut = Field(default_factory=PercentilesOut)
    funnel: List[FunnelStepOut] = Field(default_factory=list)
    rejection_reasons: Dict[str, int] = Field(default_factory=dict)
    geographic_distribution: List[CountryStatsOut] = Field(default_factory=list)
    tier_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class SnapshotResponse(BaseModel):
    snapshot: AnalyticsSnapshotOut


class DeltasOut(BaseModel):
    conversion_rate_delta: float = 0.0
    volume_delta: int = 0
    volume_delta_pct: float = 0.0
    approved_delta: int = 0
    rejected_delta: int = 0
    avg_processing_hours_delta: float = 0.0


class CompareResponse(BaseModel):
    current: AnalyticsSnapshotOut
    previous: AnalyticsSnapshotOut
    deltas: DeltasOut


# ---------------------------------------------------------------------------
# Affiliate analytics (FIN-010 / GAP-0197)
# ---------------------------------------------------------------------------


class AffiliateSummaryOut(BaseModel):
    total_links: int
    active_links: int
    total_clicks: int
    unique_clicks: int
    total_conversions: int
    total_revenue_cents: int
    total_commission_cents: int
    overall_conversion_rate_pct: float


class AffiliateClickBucket(BaseModel):
    bucket: str
    clicks: int


class AffiliateClickTimeSeriesOut(BaseModel):
    items: List[AffiliateClickBucket]
    interval: str


class AffiliateEarningsItem(BaseModel):
    link_id: str
    target_name: str
    target_type: str
    commission_earned_cents: int
    revenue_cents: int
    conversions: int


class AffiliateEarningsBreakdownOut(BaseModel):
    items: List[AffiliateEarningsItem]
    total_commission_cents: int


class AffiliateTopProductItem(BaseModel):
    link_id: str
    target_name: str
    target_id: str
    click_count: int
    conversion_count: int
    commission_earned_cents: int


# ─── Knowledge Base (KB-001..KB-011) ─────────────────────────────────────────


class KbArticleOut(BaseModel):
    article_id: str
    title: str
    body_html: str = ""
    excerpt: str = ""
    status: str = "draft"          # "draft" | "published" | "expired"
    category_id: Optional[str] = None
    category: Optional[str] = None
    author_sub: str = ""
    tags: List[str] = []
    created_at: int = 0
    updated_at: int = 0
    published_at: Optional[int] = None
    expires_at: Optional[int] = None
    expired_at: Optional[int] = None
    expiry_reason: Optional[str] = None
    view_count: int = 0
    helpful_count: int = 0
    not_helpful_count: int = 0
    attachments: List[dict] = []


class KbArticleSummaryOut(BaseModel):
    article_id: str
    title: str
    excerpt: str = ""
    status: str = "draft"
    category_id: Optional[str] = None
    category: Optional[str] = None
    author_sub: str = ""
    tags: List[str] = []
    created_at: int = 0
    updated_at: int = 0
    published_at: Optional[int] = None
    view_count: int = 0
    helpful_count: int = 0
    not_helpful_count: int = 0


class KbArticleCreateIn(BaseModel):
    title: str
    body_html: str = ""
    excerpt: str = ""
    category_id: Optional[str] = None
    tags: List[str] = []
    expires_at: Optional[int] = None


class KbArticleUpdateIn(BaseModel):
    title: Optional[str] = None
    body_html: Optional[str] = None
    excerpt: Optional[str] = None
    category_id: Optional[str] = None
    tags: Optional[List[str]] = None
    expires_at: Optional[int] = None


class KbExpireReq(BaseModel):
    reason: str = ""


class KbRateReq(BaseModel):
    helpful: bool


class KbRateOut(BaseModel):
    ok: bool = True
    already_rated: bool = False
    helpful_count: int = 0
    not_helpful_count: int = 0


class KbAttachmentOut(BaseModel):
    attachment_id: str
    article_id: str
    filename: str
    content_type: str
    size_bytes: int
    url: str = ""
    uploaded_by: str
    created_at: int


class KbCategoryIn(BaseModel):
    name: str
    parent_id: Optional[str] = None
    description: str = ""
    sort_order: int = 0


class KbCategoryOut(BaseModel):
    category_id: str
    name: str
    parent_id: Optional[str] = None
    path: str = ""
    description: str = ""
    sort_order: int = 0
    created_at: int = 0
    updated_at: int = 0
    children: List[dict] = []


class KbArticleListOut(BaseModel):
    items: List[KbArticleSummaryOut]
    cursor: Optional[str] = None
    total: int = 0


class KbCategoryListOut(BaseModel):
    categories: List[KbCategoryOut]


class KbTagStats(BaseModel):
    tag: str
    article_count: int = 0


class KbTagListOut(BaseModel):
    tags: List[KbTagStats]


class KbSearchOut(BaseModel):
    items: List[KbArticleSummaryOut]
    query: str = ""
    cursor: Optional[str] = None


class AffiliateTopProductsOut(BaseModel):
    items: List[AffiliateTopProductItem]


# ---------------------------------------------------------------------------
# BRAND-001 — Platform branding (decision D6)
# ---------------------------------------------------------------------------

class BrandingOut(BaseModel):
    """Read/update response for the platform branding entity.

    ``platform_name`` (not ``name``) is the output key so downstream consumers
    and merge-tag users access it as ``get_branding().platform_name`` or
    ``BrandingOut.platform_name`` (matching the ``{{platform_name}}`` template
    variable name).
    """
    platform_name: str
    logo_url: str = ""
    support_email: str = ""
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None


class BrandingUpdateIn(BaseModel):
    """PUT payload for updating platform branding; all fields optional (partial update).

    ``name`` is the input key (matches the stored DDB attribute and the D6
    shape); the output exposes it as ``platform_name``.
    """
    name: Optional[str] = None
    logo_url: Optional[str] = None
    support_email: Optional[str] = None
# ─── Party / CRM Enums (PTY-003) ─────────────────────────────────────────────


class CrmPartyType(str, Enum):
    PERSON = "PERSON"
    PARTY_GROUP = "PARTY_GROUP"


class CrmPartyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    MERGED = "MERGED"


class CrmPartyRoleType(str, Enum):
    CUSTOMER = "CUSTOMER"
    SUPPLIER = "SUPPLIER"
    EMPLOYEE = "EMPLOYEE"
    ORG_ADMIN = "ORG_ADMIN"
    BILL_TO = "BILL_TO"
    SHIP_TO = "SHIP_TO"
    CONTACT = "CONTACT"


class CrmRelationshipType(str, Enum):
    EMPLOYMENT = "EMPLOYMENT"
    GROUP_MEMBER = "GROUP_MEMBER"
    CONTACT_REL = "CONTACT_REL"
    OWNER = "OWNER"


class CrmContactMechType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    POSTAL = "POSTAL"


class CrmContactMechPurpose(str, Enum):
    PRIMARY_EMAIL = "PRIMARY_EMAIL"
    BILLING = "BILLING"
    SHIPPING = "SHIPPING"
    WORK = "WORK"
    HOME = "HOME"


# ─── Party / CRM Domain Models (PTY-003) ──────────────────────────────────────


class CrmParty(BaseModel):
    party_id: str
    party_type: CrmPartyType
    status: CrmPartyStatus = CrmPartyStatus.ACTIVE
    user_sub: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class CrmPartyRole(BaseModel):
    party_id: str
    role_type: CrmPartyRoleType
    created_at: int = 0


class CrmPartyRelationship(BaseModel):
    from_party_id: str
    to_party_id: str
    relationship_type: CrmRelationshipType
    created_at: int = 0


class CrmContactMech(BaseModel):
    mech_id: str
    party_id: str
    mech_type: CrmContactMechType
    value: str
    purposes: List[CrmContactMechPurpose] = Field(default_factory=list)
    verified: bool = False
    created_at: int = 0
    updated_at: int = 0


# ─── Party / CRM Request (In) Models (PTY-003) ────────────────────────────────


class CrmPartyIn(BaseModel):
    party_type: CrmPartyType
    user_sub: Optional[str] = None  # PERSON only; ignored for PARTY_GROUP
    correlation_id: Optional[str] = Field(default=None, max_length=128)


class CrmPartyStatusIn(BaseModel):
    status: CrmPartyStatus


class CrmAddRoleIn(BaseModel):
    role_type: CrmPartyRoleType


# Alias retained for PTY-011 router import compatibility.
CrmPartyRoleIn = CrmAddRoleIn


class CrmRelationshipIn(BaseModel):
    from_party_id: str = Field(..., min_length=1, max_length=64)
    to_party_id: str = Field(..., min_length=1, max_length=64)
    relationship_type: CrmRelationshipType

    @model_validator(mode="after")
    def _parties_differ(self) -> "CrmRelationshipIn":
        if self.from_party_id == self.to_party_id:
            raise ValueError("from_party_id and to_party_id must differ")
        return self


class CrmContactMechIn(BaseModel):
    mech_type: CrmContactMechType
    value: Optional[str] = None  # for EMAIL and PHONE
    postal_address: Optional[AddressIn] = None  # for POSTAL
    purposes: List[CrmContactMechPurpose] = Field(default_factory=list)
    correlation_id: Optional[str] = Field(default=None, max_length=128)
    verified: bool = False

    @model_validator(mode="after")
    def _normalize_and_validate(self) -> "CrmContactMechIn":
        if self.mech_type == CrmContactMechType.EMAIL:
            if not self.value:
                raise ValueError("value is required for EMAIL contact mechs")
            try:
                self.value = normalize_email(self.value)
            except Exception as exc:
                raise ValueError("Invalid email") from exc
        elif self.mech_type == CrmContactMechType.PHONE:
            if not self.value:
                raise ValueError("value is required for PHONE contact mechs")
            try:
                self.value = normalize_phone(self.value)
            except Exception as exc:
                raise ValueError("Invalid phone") from exc
        elif self.mech_type == CrmContactMechType.POSTAL:
            if self.postal_address is None:
                raise ValueError("postal_address is required for POSTAL contact mechs")
            import hashlib
            import json as _json

            _addr = {
                k: v
                for k, v in self.postal_address.model_dump().items()
                if v is not None
            }
            _canon = _json.dumps(_addr, sort_keys=True)
            self.value = hashlib.sha256(_canon.encode()).hexdigest()[:16]
        return self


# Alias retained for PTY-011 router import compatibility.
CrmContactMechUpdateIn = None  # replaced below after class definition


class CrmUpdateContactMechIn(BaseModel):
    purposes: Optional[List[CrmContactMechPurpose]] = None
    verified: Optional[bool] = None


CrmContactMechUpdateIn = CrmUpdateContactMechIn


# ─── Party / CRM Response (Out) Models (PTY-003) ──────────────────────────────


class CrmPartyOut(BaseModel):
    party_id: str
    party_type: CrmPartyType
    status: CrmPartyStatus
    user_sub: Optional[str] = None
    created_at: int
    updated_at: int


class CrmPartyRoleOut(BaseModel):
    party_id: str
    role_type: CrmPartyRoleType
    created_at: int


class CrmRelationshipOut(BaseModel):
    from_party_id: str
    to_party_id: str
    relationship_type: CrmRelationshipType
    created_at: int


class CrmContactMechOut(BaseModel):
    mech_id: str
    party_id: str
    mech_type: CrmContactMechType
    value: str
    postal_address: Optional[AddressIn] = None
    purposes: List[CrmContactMechPurpose]
    verified: bool
    created_at: int
    updated_at: int


# ─── Party / CRM List-Wrapper Models (PTY-005/006/007) ────────────────────────


class CrmRoleListOut(BaseModel):
    roles: List[CrmPartyRoleOut]
    count: int


class CrmPartyByRoleOut(BaseModel):
    roles: List[CrmPartyRoleOut]
    count: int


class CrmRelationshipListOut(BaseModel):
    relationships: List[CrmRelationshipOut]
    next_cursor: Optional[str] = None
    count: int


class CrmContactMechListOut(BaseModel):
    mechs: List[CrmContactMechOut]
    count: int


# ─── Party / CRM B2B Org-Account Models (PTY-003 / PTY-008) ───────────────────
#
# Cross-ticket reconciliation: the canonical CRM-org read model is CrmOrgOut
# (org_party_id + owner_user_sub). CrmOrgAccountOut is retained as the legacy
# name and aligned to the same field set so PTY-003/PTY-008/PTY-013 agree.


class CrmOrgOut(BaseModel):
    org_party_id: str
    name: str
    status: CrmPartyStatus
    owner_user_sub: Optional[str] = None
    roles: List[CrmPartyRoleOut] = Field(default_factory=list)
    member_count: int = 0
    created_at: int
    updated_at: int


# Legacy alias: same shape, kept so existing references resolve.
CrmOrgAccountOut = CrmOrgOut


class CrmCreateOrgAccountIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    owner_user_sub: Optional[str] = Field(default=None, min_length=1)
    correlation_id: Optional[str] = Field(default=None, max_length=128)


class CrmOrgMemberIn(BaseModel):
    member_party_id: str = Field(..., min_length=1, max_length=64)
    role_type: str = Field(default="member", pattern=r"^(member|admin|org_admin)$")




# ── ATS Candidates (CND-001) ─────────────────────────────────────────────────

CANDIDATE_STATUSES = frozenset({
    "active",
    "qualified",
    "submitted",
    "interviewing",
    "placed",
    "on_hold",
    "not_in_search",
    "archived",
})

CANDIDATE_SOURCES = frozenset({
    "direct",
    "referral",
    "job_board",
    "linkedin",
    "agency",
    "career_portal",
    "import",
    "other",
})

CANDIDATE_RESUME_CONTENT_TYPES = frozenset({
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/rtf",
    "text/plain",
    "application/vnd.oasis.opendocument.text",
})


class CandidateCreateIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=200)
    last_name: str = Field(..., min_length=1, max_length=200)
    email: str = Field(..., max_length=254)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=500)
    title: Optional[str] = Field(default=None, max_length=500)
    source: Optional[str] = Field(
        default=None,
        pattern=r"^(direct|referral|job_board|linkedin|agency|career_portal|import|other)$",
    )
    owner_sub: Optional[str] = Field(default=None, max_length=200)
    status: Optional[str] = Field(
        default=None,
        pattern=r"^(active|qualified|submitted|interviewing|placed|on_hold|not_in_search|archived)$",
    )
    # ATS delta fields
    current_pay: Optional[str] = Field(default=None, max_length=500)
    desired_pay: Optional[str] = Field(default=None, max_length=500)
    key_skills: Optional[str] = Field(default=None, max_length=4000)
    date_available: Optional[str] = Field(default=None, max_length=10)  # "YYYY-MM-DD"
    can_relocate: bool = False
    linkedin_url: Optional[str] = Field(default=None, max_length=500)
    web_url: Optional[str] = Field(default=None, max_length=500)
    address: Optional[str] = Field(default=None, max_length=500)
    city: Optional[str] = Field(default=None, max_length=200)
    state: Optional[str] = Field(default=None, max_length=200)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    country: Optional[str] = Field(default=None, max_length=200)


class CandidateUpdateIn(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    email: Optional[str] = Field(default=None, max_length=254)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=500)
    title: Optional[str] = Field(default=None, max_length=500)
    source: Optional[str] = Field(
        default=None,
        pattern=r"^(direct|referral|job_board|linkedin|agency|career_portal|import|other)$",
    )
    status: Optional[str] = Field(
        default=None,
        pattern=r"^(active|qualified|submitted|interviewing|placed|on_hold|not_in_search|archived)$",
    )
    current_pay: Optional[str] = Field(default=None, max_length=500)
    desired_pay: Optional[str] = Field(default=None, max_length=500)
    key_skills: Optional[str] = Field(default=None, max_length=4000)
    date_available: Optional[str] = Field(default=None, max_length=10)
    can_relocate: Optional[bool] = None
    linkedin_url: Optional[str] = Field(default=None, max_length=500)
    web_url: Optional[str] = Field(default=None, max_length=500)
    address: Optional[str] = Field(default=None, max_length=500)
    city: Optional[str] = Field(default=None, max_length=200)
    state: Optional[str] = Field(default=None, max_length=200)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    country: Optional[str] = Field(default=None, max_length=200)


class CandidateResumeOut(BaseModel):
    attachment_id: str
    candidate_id: str
    filename: str
    filename_original: str
    content_type: str
    size_bytes: int
    url: str              # presigned (prod) or /mock/s3/... (dev)
    source: str           # "upload" | "file_manager"
    is_primary: bool
    node_path: Optional[str] = None   # only for source="file_manager"
    created_at: int
    uploaded_by: str


class CandidateOut(BaseModel):
    candidate_id: str
    first_name: str
    last_name: str
    email: str
    email_raw: str
    phone: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    source: str
    owner_sub: str
    status: str
    # ATS delta
    current_pay: Optional[str] = None
    desired_pay: Optional[str] = None
    key_skills: Optional[str] = None
    date_available: Optional[str] = None
    can_relocate: bool
    linkedin_url: Optional[str] = None
    web_url: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    primary_resume_id: Optional[str] = None
    created_by: str
    created_at: int
    updated_at: int
    deleted_at: Optional[int] = None
    resumes: List[CandidateResumeOut] = Field(default_factory=list)


# ── ATS Candidates change history (CND-004) ──────────────────────────────────

class CandidateHistoryOut(BaseModel):
    event_id: str            # activity_id
    candidate_id: str
    change_type: str
    summary: str
    actor_sub: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: int


# ── ATS Candidates router models (CND-005) ───────────────────────────────────

class SetOwnerIn(BaseModel):
    owner_sub: str = Field(..., min_length=1, max_length=128)


class CandidateListOut(BaseModel):
    candidates: List[CandidateOut]
    cursor: Optional[str] = None
    total_hint: Optional[int] = None


class CandidateHistoryPage(BaseModel):
    events: List[CandidateHistoryOut]
    cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# ATS — Job Order constants and models (JOB-001)
# ---------------------------------------------------------------------------

JOB_ORDER_TYPES: Tuple[str, ...] = (
    "hire",             # Direct / permanent placement
    "contract",         # Contract-only
    "contract_to_hire", # Contract-to-hire (C2H)
    "referral",         # Referral / non-fee
)
JOB_ORDER_STATUSES: Tuple[str, ...] = (
    "active",           # Open and accepting candidates
    "on_hold",          # Temporarily paused
    "full",             # Openings filled / placed_count == openings
    "closed",           # Manually closed — terminal
    "canceled",         # Canceled by client — terminal
    "lead",             # Pre-sale / not yet confirmed
    "upcoming",         # Future start, not yet active
)
JOB_ORDER_TERMINAL: Tuple[str, ...] = ("closed", "canceled")


class JobOrderCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., description="One of JOB_ORDER_TYPES")
    status: str = Field(default="active", description="One of JOB_ORDER_STATUSES")
    openings: int = Field(default=1, ge=0, le=10_000)
    client_company_id: str = Field(..., min_length=1, max_length=128)
    client_contact_id: Optional[str] = Field(None, max_length=128)
    recruiter_subs: List[str] = Field(default_factory=list, max_length=25)
    hot: bool = False
    public: bool = False
    pay_rate_cents: Optional[int] = Field(None, ge=0)
    bill_rate_cents: Optional[int] = Field(None, ge=0)
    duration: Optional[str] = Field(None, max_length=120)
    city: Optional[str] = Field(None, max_length=120)
    state: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = Field(None, max_length=20_000)

    @model_validator(mode="after")
    def _validate_enums(self) -> "JobOrderCreateIn":
        if self.type not in JOB_ORDER_TYPES:
            raise ValueError(f"type must be one of {JOB_ORDER_TYPES}")
        if self.status not in JOB_ORDER_STATUSES:
            raise ValueError(f"status must be one of {JOB_ORDER_STATUSES}")
        return self


class JobOrderUpdateIn(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[str] = None
    status: Optional[str] = None
    openings: Optional[int] = Field(None, ge=0, le=10_000)
    client_company_id: Optional[str] = Field(None, max_length=128)
    client_contact_id: Optional[str] = Field(None, max_length=128)
    recruiter_subs: Optional[List[str]] = Field(None, max_length=25)
    hot: Optional[bool] = None
    public: Optional[bool] = None
    pay_rate_cents: Optional[int] = Field(None, ge=0)
    bill_rate_cents: Optional[int] = Field(None, ge=0)
    duration: Optional[str] = Field(None, max_length=120)
    city: Optional[str] = Field(None, max_length=120)
    state: Optional[str] = Field(None, max_length=120)
    description: Optional[str] = Field(None, max_length=20_000)

    @model_validator(mode="after")
    def _validate_enums(self) -> "JobOrderUpdateIn":
        if self.type is not None and self.type not in JOB_ORDER_TYPES:
            raise ValueError(f"type must be one of {JOB_ORDER_TYPES}")
        if self.status is not None and self.status not in JOB_ORDER_STATUSES:
            raise ValueError(f"status must be one of {JOB_ORDER_STATUSES}")
        return self


class JobOrderOut(BaseModel):
    job_id: str
    title: str
    type: str
    status: str
    openings: int
    placed_count: int           # 0 until PIPE-* ships; JOB-005 adds adjust_placed_count
    openings_remaining: int     # max(openings - placed_count, 0), derived not stored
    client_company_id: str
    client_contact_id: Optional[str]
    recruiter_subs: List[str]
    hot: bool
    public: bool
    pay_rate_cents: Optional[int]
    bill_rate_cents: Optional[int]
    duration: Optional[str]
    city: Optional[str]
    state: Optional[str]
    description: Optional[str]
    created_by: str
    created_at: int
    updated_at: int


class JobOrderListOut(BaseModel):
    items: List[JobOrderOut]
    next_cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# Property management (open-property vertical, PROP-001..PROP-005)
# ---------------------------------------------------------------------------

class PropertyAddress(BaseModel):
    line1: str
    line2: Optional[str] = None
    city: str
    region: str
    postal_code: str
    country: str


class PropertyIn(BaseModel):
    name: str
    property_type: Literal["single_family", "multi_family", "apartment", "commercial"]
    address: PropertyAddress
    color_tags: List[str] = []


class PropertyOut(BaseModel):
    property_id: str
    owner_sub: str
    name: str
    property_type: str
    address: PropertyAddress
    color_tags: List[str]
    occupancy_status: Literal["vacant", "partial", "occupied"]
    unit_count: int
    status: Literal["active", "archived"]
    created_at: int
    updated_at: int


class PropertyUpdateIn(BaseModel):
    name: Optional[str] = None
    property_type: Optional[Literal["single_family", "multi_family", "apartment", "commercial"]] = None
    address: Optional[PropertyAddress] = None
    color_tags: Optional[List[str]] = None


class UnitIn(BaseModel):
    label: str
    bedrooms: int = Field(ge=0)
    bathrooms: float = Field(ge=0)
    square_footage: int = Field(ge=0)
    market_rent_cents: int = Field(ge=0)
    occupancy_status: Literal["vacant", "occupied", "turnover", "unavailable"] = "vacant"


class UnitOut(BaseModel):
    property_id: str
    unit_id: str
    label: str
    bedrooms: int
    bathrooms: float
    square_footage: int
    market_rent_cents: int
    occupancy_status: Literal["vacant", "occupied", "turnover", "unavailable"]
    created_at: int
    updated_at: int


class UnitUpdateIn(BaseModel):
    label: Optional[str] = None
    bedrooms: Optional[int] = Field(default=None, ge=0)
    bathrooms: Optional[float] = Field(default=None, ge=0)
    square_footage: Optional[int] = Field(default=None, ge=0)
    market_rent_cents: Optional[int] = Field(default=None, ge=0)
    occupancy_status: Optional[Literal["vacant", "occupied", "turnover", "unavailable"]] = None


class PropertyOccupancyOut(BaseModel):
    property_id: str
    total: int
    occupied: int
    vacant: int
    turnover: int
    unavailable: int
    occupancy_status: Literal["vacant", "partial", "occupied"]
    occupancy_rate: float


class PortfolioOccupancyOut(BaseModel):
    property_count: int
    unit_count: int
    occupied: int
    vacant: int
    turnover: int
    unavailable: int
    occupancy_rate: float


class PropertyListOut(BaseModel):
    properties: List[PropertyOut]
    count: int
    cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# QloApps hotel-PMS vertical (HTL-001..HTL-004)
# ---------------------------------------------------------------------------

class HotelAddress(BaseModel):
    line1: str
    line2: Optional[str] = None
    city: str
    region: str
    postal_code: str
    country: str


class HotelPolicies(BaseModel):
    cancellation_text: str = ""
    pet_policy: str = ""
    smoking: bool = False
    children: bool = True


class HotelContact(BaseModel):
    phone: str = ""
    email: str = ""
    website: str = ""


class HotelIn(BaseModel):
    name: str
    description: str = ""
    star_rating: int = Field(ge=1, le=5)
    address: HotelAddress
    check_in_time: str = "15:00"
    check_out_time: str = "11:00"
    policies: HotelPolicies = HotelPolicies()
    contact: HotelContact = HotelContact()
    photo_urls: List[str] = []

    @field_validator("check_in_time", "check_out_time")
    @classmethod
    def _valid_time(cls, v: str) -> str:
        import re
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("must be HH:MM 24h")
        return v


class HotelOut(BaseModel):
    hotel_id: str
    owner_sub: str
    name: str
    description: str
    star_rating: int
    address: HotelAddress
    check_in_time: str
    check_out_time: str
    policies: HotelPolicies
    contact: HotelContact
    photo_urls: List[str]
    status: Literal["active", "archived"]
    created_at: int
    updated_at: int


class HotelUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    star_rating: Optional[int] = Field(default=None, ge=1, le=5)
    address: Optional[HotelAddress] = None
    check_in_time: Optional[str] = None
    check_out_time: Optional[str] = None
    policies: Optional[HotelPolicies] = None
    contact: Optional[HotelContact] = None
    photo_urls: Optional[List[str]] = None

    @field_validator("check_in_time", "check_out_time")
    @classmethod
    def _valid_time(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import re
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("must be HH:MM 24h")
        return v


class AmenityIn(BaseModel):
    name: str
    category: Literal[
        "connectivity", "wellness", "parking",
        "dining", "family", "accessibility", "general",
    ]
    icon: Optional[str] = None


class AmenityOut(BaseModel):
    amenity_id: str
    name: str
    category: str
    icon: Optional[str] = None
    created_at: int


class AmenityAttachIn(BaseModel):
    target_type: Literal["hotel", "room_type"]
    target_id: str
    amenity_id: str


class AmenityAssociationOut(BaseModel):
    amenity_id: str
    name: str
    category: str
    icon: Optional[str] = None
    target_type: Literal["hotel", "room_type"]
    created_at: int




# ───────────────────────────────────────────────────────────────────────────
# OpenBankProject — Banking accounts (ACC-001..ACC-004)
# ───────────────────────────────────────────────────────────────────────────


class AccountAttributeIn(BaseModel):
    name: str
    type: str  # "STRING" | "INTEGER" | "DOUBLE" | "BOOLEAN" | "DATE"
    value: str  # always string-encoded


class BankOut(BaseModel):
    bank_id: str
    name: str
    short_name: str
    logo_url: Optional[str] = None
    website: Optional[str] = None


class BankListOut(BaseModel):
    banks: List[BankOut]


class AccountOut(BaseModel):
    account_id: str
    bank_id: str
    label: str
    account_type: str
    product_code: str
    currency: str
    owners: List[str]
    is_default: bool
    wallet_backed: bool
    iban: Optional[str] = None
    routing_number: Optional[str] = None
    account_number_masked: Optional[str] = None
    attributes: List[AccountAttributeIn] = []
    created_at: int
    updated_at: int


class AccountListOut(BaseModel):
    accounts: List[AccountOut]


class AccountCreateIn(BaseModel):
    bank_id: str
    label: str
    account_type: str  # "SAVINGS" | "EXTERNAL"
    product_code: str = "default"
    currency: str = "usd"
    attributes: List[AccountAttributeIn] = []
    iban: Optional[str] = None
    routing_number: Optional[str] = None
    account_number_masked: Optional[str] = None


class AccountUpdateIn(BaseModel):
    label: Optional[str] = None
    attributes: Optional[List[AccountAttributeIn]] = None
    iban: Optional[str] = None
    routing_number: Optional[str] = None
    account_number_masked: Optional[str] = None


class AccountBalanceOut(BaseModel):
    currency: str
    current: float  # dollars (not cents)
    available: float  # dollars; == current (no holds in this tier)


# ACC-002 — transaction projection over the billing ledger


class TransactionAmountOut(BaseModel):
    currency: str
    value: str  # decimal string, e.g. "12.50" (cents / 100)


class TransactionOut(BaseModel):
    transaction_id: str
    account_id: str
    type: str
    amount: TransactionAmountOut
    status: str
    posted_at: int
    description: str
    provider: Optional[str] = None
    new_balance: TransactionAmountOut
    # ACC-003 additive fields
    has_metadata: bool = False
    metadata: Optional["TransactionMetadataOut"] = None


class TransactionListOut(BaseModel):
    transactions: List[TransactionOut]
    cursor: Optional[str] = None


# ACC-003 — transaction metadata


class NarrativeOut(BaseModel):
    text: str
    author_sub: str
    updated_at: int


class GeotagOut(BaseModel):
    lat: float
    lon: float
    label: Optional[str] = None
    author_sub: str
    updated_at: int


class TransactionImageOut(BaseModel):
    image_id: str
    url: str
    author_sub: str
    created_at: int


class TransactionTagOut(BaseModel):
    tag_id: str
    value: str
    author_sub: str
    created_at: int


class TransactionCommentOut(BaseModel):
    comment_id: str
    text: str
    author_sub: str
    created_at: int


class TransactionMetadataOut(BaseModel):
    narrative: Optional[NarrativeOut] = None
    geotag: Optional[GeotagOut] = None
    image: Optional[TransactionImageOut] = None
    tags: List[TransactionTagOut] = []
    comments: List[TransactionCommentOut] = []


class PutNarrativeIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class PutGeotagIn(BaseModel):
    lat: float = Field(ge=-90.0, le=90.0)
    lon: float = Field(ge=-180.0, le=180.0)
    label: Optional[str] = Field(default=None, max_length=200)


class AddTagIn(BaseModel):
    value: str = Field(min_length=1, max_length=100)


class AddCommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=1000)


# ACC-004 — account-holder co-access


class AccountHolderOut(BaseModel):
    user_sub: str
    added_at: int
    is_primary_owner: bool


class AccountHoldersOut(BaseModel):
    holders: List[AccountHolderOut]


class AddAccountHolderIn(BaseModel):
    user_sub: str


TransactionOut.model_rebuild()


# ---------------------------------------------------------------------------
# QUO-001 — AOS Sales Quotes
# ---------------------------------------------------------------------------


class QuoteAddressIn(BaseModel):
    street: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""


class QuoteLineItemIn(BaseModel):
    catalog_item_id: str = ""
    description: str
    qty: int = Field(ge=1)
    unit_price_cents: int = Field(ge=0)
    discount_bps: int = Field(default=0, ge=0, le=10000)
    tax_rate_bps: int = Field(default=0, ge=0, le=10000)


class QuoteCreateIn(BaseModel):
    title: str
    valid_until: Optional[int] = None
    assigned_user_sub: str = ""
    account_id: str = ""
    contact_id: str = ""
    currency: str = "usd"
    billing_address: QuoteAddressIn = Field(default_factory=QuoteAddressIn)
    shipping_address: QuoteAddressIn = Field(default_factory=QuoteAddressIn)
    notes: str = ""
    line_items: List[QuoteLineItemIn]

    @field_validator("line_items")
    @classmethod
    def _non_empty_line_items(cls, v: List[QuoteLineItemIn]) -> List[QuoteLineItemIn]:
        if not v:
            raise ValueError("at least one line item is required")
        return v


class QuotePatchIn(BaseModel):
    title: Optional[str] = None
    valid_until: Optional[int] = None
    assigned_user_sub: Optional[str] = None
    account_id: Optional[str] = None
    contact_id: Optional[str] = None
    currency: Optional[str] = None
    billing_address: Optional[QuoteAddressIn] = None
    shipping_address: Optional[QuoteAddressIn] = None
    notes: Optional[str] = None
    line_items: Optional[List[QuoteLineItemIn]] = None


class QuoteStageIn(BaseModel):
    stage: str


class QuoteLineItemOut(BaseModel):
    catalog_item_id: str = ""
    description: str = ""
    qty: int = 1
    unit_price_cents: int = 0
    discount_bps: int = 0
    tax_rate_bps: int = 0
    line_total_cents: int = 0


class QuoteOut(BaseModel):
    quote_id: str
    quote_number: str
    title: str
    stage: str
    valid_until: Optional[int] = None
    assigned_user_sub: str = ""
    account_id: str = ""
    contact_id: str = ""
    currency: str = "usd"
    billing_address: Dict[str, Any] = Field(default_factory=dict)
    shipping_address: Dict[str, Any] = Field(default_factory=dict)
    notes: str = ""
    line_items: List[QuoteLineItemOut] = Field(default_factory=list)
    subtotal_cents: int = 0
    discount_cents: int = 0
    tax_cents: int = 0
    total_cents: int = 0
    converted_to_invoice_number: str = ""
    converted_to_contract_id: str = ""
    created_at: int = 0
    updated_at: int = 0


class QuoteListOut(BaseModel):
    quotes: List[QuoteOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# QUO-004 — AOS CRM Contracts
# ---------------------------------------------------------------------------


class ContractAddressIn(BaseModel):
    street: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""


class ContractCreateIn(BaseModel):
    title: str
    start_date: int
    end_date: Optional[int] = None
    value_cents: int = Field(default=0, ge=0)
    currency: str = "usd"
    description: str = ""
    account_id: str = ""
    contact_id: str = ""
    renewal_notice_days: int = Field(default=30, ge=1, le=365)
    billing_address: ContractAddressIn = Field(default_factory=ContractAddressIn)
    shipping_address: ContractAddressIn = Field(default_factory=ContractAddressIn)


class ContractPatchIn(BaseModel):
    title: Optional[str] = None
    end_date: Optional[int] = None
    value_cents: Optional[int] = None
    currency: Optional[str] = None
    description: Optional[str] = None
    renewal_notice_days: Optional[int] = None
    billing_address: Optional[ContractAddressIn] = None
    shipping_address: Optional[ContractAddressIn] = None


class ContractStageTransitionIn(BaseModel):
    stage: str


class ContractOut(BaseModel):
    contract_id: str
    contract_number: str
    title: str
    stage: str
    account_id: str = ""
    contact_id: str = ""
    aos_quote_id: str = ""
    start_date: int = 0
    end_date: Optional[int] = None
    value_cents: int = 0
    currency: str = "usd"
    description: str = ""
    renewal_notice_days: int = 30
    renewal_notified_at: Optional[int] = None
    billing_address: Dict[str, Any] = Field(default_factory=dict)
    shipping_address: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0
    updated_at: int = 0


class ContractListOut(BaseModel):
    contracts: List[ContractOut] = Field(default_factory=list)
    count: int = 0
    next_cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# QUO-005 — Standalone invoice lifecycle (manual B2B + payment)
# ---------------------------------------------------------------------------


class ManualInvoiceLineItemIn(BaseModel):
    description: str = Field(min_length=1, max_length=512)
    quantity: int = Field(default=1, ge=1, le=10000)
    unit_price_cents: int = Field(ge=0)
    tax_rate_bps: int = Field(default=0, ge=0, le=10000)


class ManualInvoiceBillingAddressIn(BaseModel):
    street: str = Field(default="", max_length=256)
    city: str = Field(default="", max_length=128)
    state: str = Field(default="", max_length=128)
    postal_code: str = Field(default="", max_length=32)
    country: str = Field(default="", max_length=64)


class ManualInvoiceCreateIn(BaseModel):
    buyer_user_sub: str = Field(default="", max_length=256)
    buyer_name: str = Field(min_length=1, max_length=256)
    buyer_email: str = Field(min_length=1, max_length=256)
    billing_address: ManualInvoiceBillingAddressIn = Field(
        default_factory=ManualInvoiceBillingAddressIn
    )
    line_items: List[ManualInvoiceLineItemIn] = Field(min_length=1)
    currency: str = Field(default="usd", max_length=8)
    payment_terms_days: int = Field(default=30, ge=1, le=365)
    notes: str = Field(default="", max_length=4096)


class ManualPayInvoiceIn(BaseModel):
    payment_ref: str = Field(default="", max_length=256)


class RecordExternalPaymentIn(BaseModel):
    # D5: admin record offline/manual payment (no provider charge).
    amount_cents: int = Field(ge=1)
    method: Literal["external"] = "external"
    reference: str = Field(default="", max_length=256)
    reason: str = Field(default="", max_length=512)
    user_sub: str = Field(min_length=1, max_length=256)  # invoice owner




# ── Sales Pipeline (OPP-001..OPP-006) ────────────────────────────────────────

OPPORTUNITY_STAGES = (
    "prospecting",
    "qualification",
    "needs_analysis",
    "value_proposition",
    "id_decision_makers",
    "proposal_price_quote",
    "negotiation_review",
    "closed_won",
    "closed_lost",
)

LEAD_SOURCE_CHOICES = (
    "cold_call",
    "existing_customer",
    "self_generated",
    "employee",
    "partner",
    "public_relations",
    "direct_mail",
    "conference",
    "trade_show",
    "web_site",
    "word_of_mouth",
    "email",
    "campaign",
    "other",
)


class OpportunityCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    stage: str = Field(..., description="One of OPPORTUNITY_STAGES")
    amount_cents: int = Field(..., ge=0)
    close_date: int = Field(..., description="Unix timestamp integer seconds")
    probability: int = Field(0, ge=0, le=100)
    lead_source: Optional[str] = None
    description: Optional[str] = Field(None, max_length=4096)
    account_party_id: Optional[str] = Field(None, max_length=128)
    contact_party_id: Optional[str] = Field(None, max_length=128)

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: str) -> str:
        if v not in OPPORTUNITY_STAGES:
            raise ValueError(
                f"Unknown stage {v!r}. Valid choices: {', '.join(OPPORTUNITY_STAGES)}"
            )
        return v

    @field_validator("lead_source")
    @classmethod
    def _validate_lead_source(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in LEAD_SOURCE_CHOICES:
            raise ValueError(
                f"Unknown lead_source {v!r}. Valid choices: {', '.join(LEAD_SOURCE_CHOICES)}"
            )
        return v


class OpportunityUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    stage: Optional[str] = None
    amount_cents: Optional[int] = Field(None, ge=0)
    close_date: Optional[int] = None
    probability: Optional[int] = Field(None, ge=0, le=100)
    lead_source: Optional[str] = None
    description: Optional[str] = Field(None, max_length=4096)
    account_party_id: Optional[str] = Field(None, max_length=128)
    contact_party_id: Optional[str] = Field(None, max_length=128)

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in OPPORTUNITY_STAGES:
            raise ValueError(
                f"Unknown stage {v!r}. Valid choices: {', '.join(OPPORTUNITY_STAGES)}"
            )
        return v

    @field_validator("lead_source")
    @classmethod
    def _validate_lead_source(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in LEAD_SOURCE_CHOICES:
            raise ValueError(
                f"Unknown lead_source {v!r}. Valid choices: {', '.join(LEAD_SOURCE_CHOICES)}"
            )
        return v


class OppContactRoleOut(BaseModel):
    opp_id: str
    contact_ref: str
    contact_role: str
    owner_sub: str
    created_at: int


class OpportunityOut(BaseModel):
    opp_id: str
    owner_sub: str
    name: str
    stage: str
    amount_cents: int
    weighted_amount_cents: int
    close_date: int
    probability: int
    lead_source: Optional[str] = None
    description: Optional[str] = None
    account_party_id: Optional[str] = None
    contact_party_id: Optional[str] = None
    created_at: int
    updated_at: int
    contact_roles: List["OppContactRoleOut"] = Field(default_factory=list)


class OppContactRoleIn(BaseModel):
    contact_ref: str = Field(..., min_length=1, max_length=255)
    contact_role: str = Field(..., description="One of CONTACT_ROLES")

    @field_validator("contact_role")
    @classmethod
    def validate_contact_role(cls, v: str) -> str:
        from app.services.opportunities import CONTACT_ROLES  # lazy import to avoid circular
        if v not in CONTACT_ROLES:
            raise ValueError(f"Unknown contact_role '{v}'. Valid values: {CONTACT_ROLES}")
        return v


# OPP-003 Stage config models
class StageConfigItemIn(BaseModel):
    stage_key: str = Field(..., min_length=1, max_length=80)
    label: str = Field(..., min_length=1, max_length=80)
    probability_default: int = Field(default=0, ge=0, le=100)
    order: int = Field(default=0, ge=0)
    is_won: bool = False
    is_lost: bool = False
    color: Optional[str] = Field(None, max_length=7)  # "#RRGGBB"


class StageConfigIn(BaseModel):
    stages: List[StageConfigItemIn]


class StageConfigItemOut(BaseModel):
    stage_key: str
    label: str
    probability_default: int
    order: int
    is_won: bool
    is_lost: bool
    color: Optional[str] = None


class StageConfigOut(BaseModel):
    stages: List[StageConfigItemOut]
    updated_at: Optional[int] = None
    updated_by_sub: Optional[str] = None


# OPP-005 Quota / Forecast models
PERIOD_TYPE_CHOICES = ("monthly", "quarterly", "annual")


class SalesQuotaIn(BaseModel):
    user_sub: str = Field(..., min_length=1)
    period_type: str = Field(..., description="monthly | quarterly | annual")
    period_key: str = Field(..., min_length=4, max_length=16)
    target_amount_cents: int = Field(..., ge=0)

    @field_validator("period_type")
    @classmethod
    def _validate_period_type(cls, v: str) -> str:
        if v not in PERIOD_TYPE_CHOICES:
            raise ValueError(f"period_type must be one of {PERIOD_TYPE_CHOICES}")
        return v


class SalesQuotaOut(BaseModel):
    user_sub: str
    period_type: str
    period_key: str
    target_amount_cents: int
    created_at: int
    updated_at: int
    set_by_sub: str


class SalesQuotaListOut(BaseModel):
    items: List[SalesQuotaOut]
    next_cursor: Optional[str] = None


class ForecastWorksheetIn(BaseModel):
    committed_cents: int = Field(..., ge=0)
    best_case_cents: int = Field(..., ge=0)
    pipeline_cents: int = Field(..., ge=0)
    notes: Optional[str] = Field(None, max_length=4096)


class ForecastWorksheetOut(BaseModel):
    user_sub: str
    period_key: str
    committed_cents: int
    best_case_cents: int
    pipeline_cents: int
    closed_cents: int
    quota_cents: int
    attainment_pct: int
    notes: Optional[str] = None
    created_at: int
    updated_at: int


# OPP-006 Pipeline report models
class PipelineStageMetric(BaseModel):
    stage: str
    label: str
    count: int
    total_amount_cents: int
    weighted_amount_cents: int
    avg_close_date: Optional[int] = None


class PipelineReportOut(BaseModel):
    stages: List[PipelineStageMetric]
    total_amount_cents: int
    total_weighted_cents: int
    generated_at: int




# ── CRM Leads (LED-002) ──────────────────────────────────────────────────────

LEAD_STATUSES: frozenset = frozenset({
    "new", "assigned", "in_process", "converted", "recycled", "dead"
})

LEAD_SOURCES: frozenset = frozenset({
    "web_site", "cold_call", "email", "campaign", "trade_show",
    "word_of_mouth", "other", "internal",
})

_LEAD_SOURCE_PATTERN = (
    r"^(web_site|cold_call|email|campaign|trade_show|word_of_mouth|other|internal)$"
)


class LeadCreateIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=120)
    last_name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=254)
    phone: Optional[str] = None
    company: Optional[str] = Field(default=None, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    lead_source: str = Field(default="other", pattern=_LEAD_SOURCE_PATTERN)
    description: Optional[str] = Field(default=None, max_length=4000)
    assigned_to: Optional[str] = None
    website: Optional[str] = Field(default=None, max_length=500)
    attribution_code: Optional[str] = Field(default=None, max_length=200)
    campaign_id: Optional[str] = Field(default=None, max_length=200)


class LeadUpdateIn(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    email: Optional[str] = Field(default=None, min_length=3, max_length=254)
    phone: Optional[str] = None
    company: Optional[str] = Field(default=None, max_length=200)
    title: Optional[str] = Field(default=None, max_length=200)
    lead_source: Optional[str] = Field(default=None, pattern=_LEAD_SOURCE_PATTERN)
    description: Optional[str] = Field(default=None, max_length=4000)
    assigned_to: Optional[str] = None
    status: Optional[str] = None  # transition enforced by service layer (LED-003)
    website: Optional[str] = Field(default=None, max_length=500)
    score: Optional[int] = None   # only written by scoring engine (LED-011)


class LeadOut(BaseModel):
    lead_id: str
    first_name: str
    last_name: str
    email: str
    phone: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    lead_source: str = "other"
    description: Optional[str] = None
    status: str = "new"
    assigned_to: Optional[str] = None
    score: int = 0
    website: Optional[str] = None
    attribution_code: Optional[str] = None
    campaign_id: Optional[str] = None
    created_by: str = ""
    created_at: int = 0
    updated_at: int = 0
    converted_at: Optional[int] = None
    converted_party_id: Optional[str] = None
    converted_org_id: Optional[str] = None
    origin_questionnaire_id: Optional[str] = None
    origin_response_session_id: Optional[str] = None
    linked_entity_id: Optional[str] = None  # opaque PTY linkage (soft, LED-006)


class ProspectCreateIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    first_name: Optional[str] = Field(default=None, max_length=120)
    last_name: Optional[str] = Field(default=None, max_length=120)
    phone: Optional[str] = None
    company: Optional[str] = Field(default=None, max_length=200)


class ProspectOut(BaseModel):
    prospect_id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    suppressed: bool = False
    created_at: int = 0
    updated_at: int = 0


class ProspectUpdateIn(BaseModel):
    first_name: Optional[str] = Field(default=None, max_length=120)
    last_name: Optional[str] = Field(default=None, max_length=120)
    phone: Optional[str] = None
    company: Optional[str] = Field(default=None, max_length=200)


class LeadConversionIn(BaseModel):
    create_account: bool = False
    account_name: Optional[str] = Field(default=None, max_length=200)
    create_opportunity: bool = False
    opportunity_name: Optional[str] = Field(default=None, max_length=300)
    opportunity_amount_cents: Optional[int] = Field(default=None, ge=0)


class OpportunityStubOut(BaseModel):
    opportunity_id: str
    name: str
    amount_cents: int
    currency: str
    stage: str
    created_at: int


class LeadConversionOut(BaseModel):
    lead_id: str
    status: str = "converted"
    converted_party_id: str = ""
    converted_org_id: Optional[str] = None
    opportunity: Optional[OpportunityStubOut] = None
    converted_at: int = 0
    pty_path_used: bool = False


class LeadScoreRuleIn(BaseModel):
    """A single scoring rule definition (LED-011)."""
    field: str = Field(..., max_length=100)
    operator: str = Field(..., max_length=50)
    value: str = Field(..., max_length=500)
    points: int


class LeadScoreRulesIn(BaseModel):
    rules: List[LeadScoreRuleIn]
    max_score: int = Field(default=100, ge=0)


class LeadScoreRulesOut(BaseModel):
    rules: List[LeadScoreRuleIn]
    max_score: int
    updated_at: int = 0


class LeadScoreHistoryEntry(BaseModel):
    score: int
    trigger: str
    computed_at: int
    lead_id: str


class LeadScoreHistoryOut(BaseModel):
    lead_id: str
    entries: List[LeadScoreHistoryEntry]
    cursor: Optional[str] = None


class LeadActivityOut(BaseModel):
    activity_id: str
    lead_id: str
    activity_type: str
    subject: Optional[str] = None
    description: Optional[str] = None
    actor_sub: str = ""
    created_at: int = 0
    metadata: Optional[Dict] = None




# ---------------------------------------------------------------------------
# CRM Reports & Dashboards (RPT-001..RPT-009)
# ---------------------------------------------------------------------------

class ReportCondition(BaseModel):
    field: str = Field(..., min_length=1, max_length=100)
    operator: str = Field(
        ...,
        pattern=r"^(eq|neq|contains|gt|lt|gte|lte|is_empty|not_empty)$"
    )
    value: Optional[str] = Field(None, max_length=500)


class AggregateSpec(BaseModel):
    field: str = Field(..., min_length=1, max_length=100, description="Field name or '*' for COUNT(*)")
    function: str = Field(..., pattern=r"^(SUM|AVG|COUNT|MIN|MAX)$")


class ChartConfig(BaseModel):
    chart_type: str = Field(..., pattern=r"^(bar|line|pie)$")
    x_field: str = Field(..., min_length=1, max_length=100)
    y_field: str = Field(..., min_length=1, max_length=100)


class ReportCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    module: str = Field(
        ...,
        pattern=r"^(tickets|contacts|billing_ledger|orders|subscriptions|questionnaire_responses)$"
    )
    fields: List[str] = Field(..., min_length=1, max_length=20)
    conditions: List[ReportCondition] = Field(default_factory=list)
    # RPT-003 additions
    group_by: Optional[str] = Field(None, min_length=1, max_length=100)
    aggregates: List[AggregateSpec] = Field(default_factory=list)
    # RPT-005 addition
    chart: Optional[ChartConfig] = None

    @model_validator(mode="after")
    def _check_group_by_aggregates(self) -> "ReportCreateIn":
        if self.group_by and not self.aggregates:
            raise ValueError("aggregates must be non-empty when group_by is set")
        if not self.group_by and self.aggregates:
            raise ValueError("aggregates requires group_by to be set")
        if len(self.aggregates) > 10:
            raise ValueError("maximum 10 aggregates per report")
        # Check for duplicate (field, function) pairs
        seen = set()
        for agg in self.aggregates:
            pair = (agg.field, agg.function)
            if pair in seen:
                raise ValueError(f"Duplicate aggregate: {pair}")
            seen.add(pair)
        return self


class ReportUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    fields: Optional[List[str]] = Field(None, min_length=1, max_length=20)
    conditions: Optional[List[ReportCondition]] = None
    group_by: Optional[str] = Field(None, min_length=1, max_length=100)
    aggregates: Optional[List[AggregateSpec]] = None
    chart: Optional[ChartConfig] = None


class ReportOut(BaseModel):
    report_id: str
    name: str
    description: Optional[str] = None
    module: str
    fields: List[str]
    conditions: List[ReportCondition]
    group_by: Optional[str] = None
    aggregates: List[AggregateSpec] = Field(default_factory=list)
    chart: Optional[ChartConfig] = None
    owner_sub: str
    created_at: int
    updated_at: int


class ReportRunOut(BaseModel):
    report_id: str
    run_id: str
    run_at: int
    status: str
    row_count: int
    columns: List[str]
    rows: List[List[Any]]
    error_msg: Optional[str] = None
    chart: Optional[ChartConfig] = None


# RPT-004: schedule models

class ReportScheduleCreateIn(BaseModel):
    cadence: str = Field(..., pattern=r"^(daily|weekly|monthly)$")
    recipients: List[str] = Field(..., min_length=1, max_length=50)
    format: str = Field("csv", pattern=r"^(csv|json)$")

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, v: List[str]) -> List[str]:
        for email in v:
            if "@" not in email:
                raise ValueError(f"Invalid email address: {email}")
        return v


class ReportScheduleUpdateIn(BaseModel):
    cadence: Optional[str] = Field(None, pattern=r"^(daily|weekly|monthly)$")
    recipients: Optional[List[str]] = Field(None, min_length=1, max_length=50)
    format: Optional[str] = Field(None, pattern=r"^(csv|json)$")
    enabled: Optional[bool] = None

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        for email in v:
            if "@" not in email:
                raise ValueError(f"Invalid email address: {email}")
        return v


class ReportScheduleOut(BaseModel):
    schedule_id: str
    report_id: str
    owner_sub: str
    cadence: str
    recipients: List[str]
    format: str
    enabled: bool
    created_at: int
    next_run_at: int
    last_run_at: Optional[int] = None
    last_run_id: Optional[str] = None


class ReportScheduleListOut(BaseModel):
    schedules: List[ReportScheduleOut]
    cursor: Optional[str] = None


# RPT-006: dashboard models

class DashletConfig(BaseModel):
    dashlet_type: str = Field(
        ...,
        pattern=r"^(recent_tickets|calendar_today|my_contacts|billing_summary|report|saved_search)$"
    )
    title: str = Field(..., min_length=1, max_length=120)
    config: Dict[str, Any] = Field(default_factory=dict)


class DashletConfigOut(BaseModel):
    dashlet_id: str
    dashlet_type: str
    title: str
    config: Dict[str, Any] = Field(default_factory=dict)


class DashboardOut(BaseModel):
    dashboard_id: str
    name: str
    owner_sub: str
    dashlets: List[DashletConfigOut]
    created_at: int
    updated_at: int


class DashboardUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    dashlets: Optional[List[DashletConfig]] = None


class DashletAddIn(BaseModel):
    dashlet_type: str = Field(
        ...,
        pattern=r"^(recent_tickets|calendar_today|my_contacts|billing_summary|report|saved_search)$"
    )
    title: str = Field(..., min_length=1, max_length=120)
    config: Dict[str, Any] = Field(default_factory=dict)


class DashletReorderIn(BaseModel):
    dashlet_ids: List[str] = Field(..., min_length=1)


# RPT-008: saved search models

class SavedSearchCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    module: str = Field(
        ...,
        pattern=r"^(tickets|contacts|billing_ledger|orders|subscriptions|questionnaire_responses)$"
    )
    filters: List[ReportCondition] = Field(default_factory=list, max_length=20)


class SavedSearchUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    filters: Optional[List[ReportCondition]] = Field(None, max_length=20)


class SavedSearchOut(BaseModel):
    saved_search_id: str
    name: str
    module: str
    filters: List[Dict[str, Any]]
    owner_sub: str
    created_at: int
    updated_at: int


class SavedSearchRunOut(BaseModel):
    saved_search_id: str
    module: str
    columns: List[str]
    rows: List[Dict[str, Any]]
    row_count: int
    ran_at: int




# ---------------------------------------------------------------------------
# CRM Workflow & Process Automation (WFL-001 / WFL-002 / WFL-006 / WFL-008 / WFL-009)
# ---------------------------------------------------------------------------

class WorkflowConditionIn(BaseModel):
    field: str
    operator: str  # eq|neq|contains|gt|lt|is_empty|is_not_empty
    value: Optional[str] = None


class WorkflowActionIn(BaseModel):
    action_type: str  # modify_field|create_record|send_email|drip_sequence
    config: dict = {}


class WorkflowRuleCreateIn(BaseModel):
    name: str = Field(..., max_length=200)
    description: str = Field(default="", max_length=2000)
    target_module: str
    trigger_type: str
    trigger_config: dict = {}
    conditions: List[WorkflowConditionIn] = []
    actions: List[WorkflowActionIn] = []
    enabled: bool = True


class WorkflowRuleUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    trigger_config: Optional[dict] = None
    conditions: Optional[List[WorkflowConditionIn]] = None
    actions: Optional[List[WorkflowActionIn]] = None


class WorkflowRuleOut(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    target_module: str
    trigger_type: str
    trigger_config: dict
    conditions: List[dict]
    actions: List[dict]
    enabled: bool
    created_by: str
    created_at: int
    updated_at: int


class WorkflowRuleListOut(BaseModel):
    rules: List[WorkflowRuleOut] = []
    cursor: Optional[str] = None


class WorkflowActionFiredOut(BaseModel):
    action_type: str
    result: str  # "ok" | "skipped" | "error:<msg>"
    error: Optional[str] = None


class WorkflowRunOut(BaseModel):
    run_id: str
    rule_id: str
    target_module: str
    record_id: str
    trigger_type: str
    outcome: str  # "matched" | "error" | "skipped"
    actions_fired: List[dict] = []
    started_at: int
    finished_at: Optional[int] = None
    error_message: Optional[str] = None


class WorkflowRunListOut(BaseModel):
    runs: List[WorkflowRunOut] = []
    cursor: Optional[str] = None


class DripStageIn(BaseModel):
    stage_number: int = Field(..., ge=1)
    delay_hours: int = Field(..., ge=0)
    template_id: str
    to_field: str


class DripSequenceCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    stages: List[DripStageIn] = Field(..., min_length=1)


class DripSequenceUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    stages: Optional[List[DripStageIn]] = None


class DripSequenceOut(BaseModel):
    sequence_id: str
    name: str
    description: str
    stages: List[dict]
    created_by: str
    created_at: int
    updated_at: int


class DripSequenceListOut(BaseModel):
    sequences: List[DripSequenceOut] = []
    cursor: Optional[str] = None


class DripEnrolmentOut(BaseModel):
    sequence_id: str
    module: str
    record_id: str
    current_stage: int
    enrolled_at: int
    last_stage_sent_at: Optional[int] = None
    completed: bool
    stopped: bool




# ---------------------------------------------------------------------------
# CAS-007 — Ticket watchers / CC list
# ---------------------------------------------------------------------------
class TicketWatcherOut(BaseModel):
    ticket_id: str
    watcher_sub: str
    added_by_sub: Optional[str] = None
    created_at: int


class TicketWatcherListOut(BaseModel):
    watchers: List[TicketWatcherOut]


class AddWatcherReq(BaseModel):
    watcher_sub: str


# ---------------------------------------------------------------------------
# CAS-011 — Case-to-case relationship links
# ---------------------------------------------------------------------------
class TicketLinkOut(BaseModel):
    ticket_id: str
    related_ticket_id: str
    link_type: Literal["duplicate", "blocks", "relates_to"]
    created_by_sub: Optional[str] = None
    created_at: int


class TicketLinkListOut(BaseModel):
    links: List[TicketLinkOut]


class CreateTicketLinkReq(BaseModel):
    related_ticket_id: str
    link_type: Literal["duplicate", "blocks", "relates_to"]




# ---------------------------------------------------------------------------
# STU-002: CRM ACL Role matrix models
# ---------------------------------------------------------------------------

class CrmAclPermissionMatrix(BaseModel):
    """Seven per-module boolean permission flags."""
    model_config = ConfigDict(populate_by_name=True)

    create: bool = False
    read: bool = False
    update: bool = False
    delete: bool = False
    export: bool = False
    import_: bool = Field(False, alias="import")
    mass_update: bool = False


class CrmAclRoleCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = ""
    permissions: Dict[str, CrmAclPermissionMatrix] = {}


class CrmAclRoleUpdateIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    permissions: Optional[Dict[str, CrmAclPermissionMatrix]] = None


class CrmAclRoleOut(BaseModel):
    role_id: str
    name: str
    description: str
    permissions: Dict[str, Any]
    created_at: int
    created_by_sub: str
    updated_at: Optional[int] = None
    updated_by_sub: Optional[str] = None


class CrmAclAssignmentIn(BaseModel):
    user_sub: str


class CrmAclAssignmentOut(BaseModel):
    role_id: str
    user_sub: str
    assigned_by_sub: str
    assigned_at: int


class CrmEffectivePermissionsOut(BaseModel):
    user_sub: str
    permissions: Dict[str, Any]


# STU-003: Group assignment models

class CrmAclGroupAssignmentIn(BaseModel):
    group_key: str = Field(..., min_length=1, max_length=100)


class CrmAclGroupAssignmentOut(BaseModel):
    role_id: str
    group_key: str
    assigned_by_sub: str
    assigned_at: int


class CrmAclRoleAssignmentsOut(BaseModel):
    role_id: str
    user_assignments: List[Dict[str, Any]]
    group_assignments: List[CrmAclGroupAssignmentOut]


# ---------------------------------------------------------------------------
# STU-004: CRM Security Groups models
# ---------------------------------------------------------------------------

class CrmSecurityGroupCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=512)
    is_global: bool = False


class CrmSecurityGroupMemberAddIn(BaseModel):
    user_sub: str
    can_edit: bool = False


class CrmSecurityGroupRecordAssignIn(BaseModel):
    entity_type: str = Field(..., min_length=1)
    record_id: str = Field(..., min_length=1)


class CrmSecurityGroupOut(BaseModel):
    group_id: str
    name: str
    description: str
    owner_sub: str
    created_at: int
    is_global: bool
    member_count: int = 0
    record_count: int = 0


class CrmSecurityGroupMemberOut(BaseModel):
    user_sub: str
    added_by_sub: str
    added_at: int
    can_edit: bool


class CrmSecurityGroupRecordOut(BaseModel):
    entity_type: str
    record_id: str
    record_ref: str
    assigned_by_sub: str
    created_at: int


class CrmSecurityGroupDetailOut(BaseModel):
    group: CrmSecurityGroupOut
    members: List[CrmSecurityGroupMemberOut]
    records: List[CrmSecurityGroupRecordOut]


# ---------------------------------------------------------------------------
# STU-011: Studio custom fields models
# ---------------------------------------------------------------------------

class StudioFieldCreateIn(BaseModel):
    field_key: str = Field(..., pattern=r"^[a-z][a-z0-9_]{2,49}$")
    label: str = Field(..., min_length=1, max_length=255)
    field_type: Literal["text", "integer", "decimal", "boolean", "date", "picklist", "multi_picklist"]
    required: bool = False
    default_value: Any = None
    picklist_name: Optional[str] = None
    max_length: int = Field(1000, ge=1, le=65535)
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    sort_order: int = 0


class StudioFieldUpdateIn(BaseModel):
    label: Optional[str] = Field(None, min_length=1, max_length=255)
    required: Optional[bool] = None
    default_value: Any = None
    max_length: Optional[int] = Field(None, ge=1, le=65535)
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    sort_order: Optional[int] = None
    reactivate: Optional[bool] = None


class StudioFieldOut(BaseModel):
    entity_type: str
    field_key: str
    label: str
    field_type: str
    required: bool
    default_value: Any
    picklist_name: Optional[str]
    max_length: int
    min_value: Optional[float]
    max_value: Optional[float]
    sort_order: int
    is_active: bool
    created_by_sub: str
    created_at: int
    updated_by_sub: str
    updated_at: int


class StudioFieldListOut(BaseModel):
    fields: List[StudioFieldOut]
    next_cursor: Optional[str]
    total_count: Optional[int] = None




# ---------------------------------------------------------------------------
# CRM Project Management (PRJ-001 through PRJ-009)
# ---------------------------------------------------------------------------


class CrmProjectStatus(str, Enum):
    draft = "draft"
    in_review = "in_review"
    underway = "underway"
    completed = "completed"
    deferred = "deferred"


class CrmProjectCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: CrmProjectStatus = CrmProjectStatus.draft
    priority: int = Field(default=0, ge=0, le=4)
    start_date: Optional[int] = None  # Unix ts (seconds)
    end_date: Optional[int] = None
    assigned_user_sub: Optional[str] = None
    account_id: Optional[str] = None


class CrmProjectUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[CrmProjectStatus] = None
    priority: Optional[int] = Field(default=None, ge=0, le=4)
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    assigned_user_sub: Optional[str] = None
    account_id: Optional[str] = None


class CrmProjectOut(BaseModel):
    id: str
    owner_sub: str
    name: str
    description: Optional[str] = None
    status: CrmProjectStatus
    priority: int
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    assigned_user_sub: Optional[str] = None
    account_id: Optional[str] = None
    created_at: int
    updated_at: int


class CrmProjectListResp(BaseModel):
    items: List[CrmProjectOut]
    cursor: Optional[str] = None


# PRJ-003: Task models
class CrmProjectResourceType(str, Enum):
    user = "user"
    contact = "contact"


class CrmProjectTaskCreateReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    task_order: int = Field(default=0, ge=0)  # 0 = auto-assign
    duration_days: int = Field(default=1, ge=1)
    start_date: Optional[int] = None  # Unix ts
    end_date: Optional[int] = None
    percent_complete: int = Field(default=0, ge=0, le=100)
    is_milestone: bool = False
    assigned_user_sub: Optional[str] = None
    predecessor_task_ids: List[str] = Field(default_factory=list, max_length=50)
    project_resource_type: Optional[CrmProjectResourceType] = None
    linked_contact_id: Optional[str] = None


class CrmProjectTaskUpdateReq(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    task_order: Optional[int] = Field(default=None, ge=0)
    duration_days: Optional[int] = Field(default=None, ge=1)
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    percent_complete: Optional[int] = Field(default=None, ge=0, le=100)
    is_milestone: Optional[bool] = None
    assigned_user_sub: Optional[str] = None
    predecessor_task_ids: Optional[List[str]] = Field(default=None, max_length=50)
    project_resource_type: Optional[CrmProjectResourceType] = None
    linked_contact_id: Optional[str] = None


class CrmProjectTaskReorderReq(BaseModel):
    task_ids: List[str] = Field(..., min_length=1)


class CrmProjectTaskModel(BaseModel):
    id: str
    project_id: str
    owner_sub: str
    name: str
    description: Optional[str] = None
    task_order: int
    duration_days: int
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    percent_complete: int
    is_milestone: bool
    assigned_user_sub: Optional[str] = None
    predecessor_task_ids: List[str]
    project_resource_type: CrmProjectResourceType = CrmProjectResourceType.user
    linked_contact_id: Optional[str] = None
    created_at: int
    updated_at: int


class CrmProjectTaskListResp(BaseModel):
    items: List[CrmProjectTaskModel]
    cursor: Optional[str] = None


# PRJ-004: Workload models
class CrmTaskWorkloadEntry(BaseModel):
    assignee_key: str
    resource_type: CrmProjectResourceType
    assigned_id: str
    task_count: int
    overdue_count: int


class CrmProjectWorkloadResp(BaseModel):
    project_id: str
    entries: List[CrmTaskWorkloadEntry]


# PRJ-005: Milestone models
class CrmMilestoneSummaryItem(BaseModel):
    id: str
    project_id: str
    name: str
    task_order: int
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    percent_complete: int
    on_track: bool
    overdue: bool
    created_at: int
    updated_at: int


class CrmMilestoneSummaryResp(BaseModel):
    items: List[CrmMilestoneSummaryItem]
    cursor: Optional[str] = None
    total_milestones: int
    overdue_count: int
    on_track_count: int
    no_date_count: int


# PRJ-006: Template models
class CrmTemplateTaskDef(BaseModel):
    template_task_id: str
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    task_order: int = Field(..., ge=0)
    duration_days: int = Field(default=1, ge=1)
    is_milestone: bool = False
    predecessor_template_task_ids: List[str] = Field(default_factory=list)


class CrmProjectTemplateModel(BaseModel):
    id: str
    owner_sub: str
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    task_defs: List[CrmTemplateTaskDef] = Field(default_factory=list)
    created_at: int
    updated_at: int


class CrmTemplateCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    task_defs: List[CrmTemplateTaskDef] = Field(default_factory=list)


class CrmTemplateFromProjectIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)


class CrmTemplateInstantiateIn(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=120)
    start_date: Optional[int] = None  # Unix timestamp; None → no start_date


class CrmTemplateListOut(BaseModel):
    items: List[CrmProjectTemplateModel] = Field(default_factory=list)
    cursor: Optional[str] = None


# PRJ-007: Member models
class CrmProjectMemberRole(str, Enum):
    owner = "owner"
    member = "member"
    viewer = "viewer"


class CrmProjectMemberOut(BaseModel):
    project_id: str
    user_sub: str
    role: CrmProjectMemberRole
    added_by: str
    added_at: int


class CrmProjectMemberListResp(BaseModel):
    items: List[CrmProjectMemberOut]
    cursor: Optional[str] = None


class CrmProjectAddMemberIn(BaseModel):
    user_sub: str
    role: CrmProjectMemberRole = CrmProjectMemberRole.member


class CrmProjectUpdateMemberIn(BaseModel):
    role: CrmProjectMemberRole


# PRJ-009: Status history model
class CrmProjectStatusHistoryEntry(BaseModel):
    project_id: str
    from_status: Optional[str] = None
    to_status: str
    changed_by: str
    changed_at: int
    event_id: str


class CrmProjectStatusHistoryResp(BaseModel):
    items: List[CrmProjectStatusHistoryEntry]
    cursor: Optional[str] = None


# PRJ-010: Contact links model
class CrmProjectContactLinkOut(BaseModel):
    project_id: str
    linked_entity_id: str
    linked_entity_type: str
    added_by: str
    added_at: int
    note: Optional[str] = None


class CrmProjectContactLinkListResp(BaseModel):
    items: List[CrmProjectContactLinkOut]
    cursor: Optional[str] = None


class CrmProjectAddContactLinkIn(BaseModel):
    linked_entity_id: str
    linked_entity_type: str = "contact_party"
    note: Optional[str] = Field(default=None, max_length=500)




# ─── Hotel PMS / Availability (QloApps vertical, HTL-010..HTL-013) ───────────

class AvailabilityDayOut(BaseModel):
    """One (room_type, date) row — mirrors the hotel_availability DATE# row.

    ``available`` is derived: total_rooms + overbooking_allowance - booked - held.
    It is never stored; the service recomputes it on every read/mutation.
    """
    hotel_id: str
    room_type_id: str
    date: str                           # YYYY-MM-DD
    total_rooms: int
    booked: int
    held: int
    overbooking_allowance: int
    min_availability: int
    max_availability: Optional[int] = None
    available: int                      # derived
    updated_at: int


class AvailabilitySetIn(BaseModel):
    """Date-range seed/set payload for set_total_rooms."""
    hotel_id: str
    room_type_id: str
    start_date: str                     # YYYY-MM-DD inclusive
    end_date: str                       # YYYY-MM-DD inclusive
    total_rooms: int = Field(ge=0)


class AvailabilityDayIn(BaseModel):
    """Single-date set payload."""
    hotel_id: str
    room_type_id: str
    date: str                           # YYYY-MM-DD
    total_rooms: int = Field(ge=0)


class HoldRoomsIn(BaseModel):
    """Request body for hold_rooms (HTL-011)."""
    hotel_id: str
    room_type_id: str
    checkin: str                        # YYYY-MM-DD inclusive
    checkout: str                       # YYYY-MM-DD exclusive
    quantity: int = Field(ge=1)
    ttl_seconds: Optional[int] = Field(default=None, ge=1)


class HoldOut(BaseModel):
    """Response for a hold (HTL-011)."""
    hold_id: str
    hotel_id: str
    room_type_id: str
    checkin: str
    checkout: str
    dates: List[str]
    quantity: int
    status: str                         # "active" | "released" | "expired"
    user_sub: str
    created_at: int
    expires_at: int


class OverbookingSetIn(BaseModel):
    """Request body for set_overbooking_allowance (HTL-011)."""
    hotel_id: str
    room_type_id: str
    start_date: str
    end_date: str
    allowance: int = Field(ge=0)


class MinMaxSetIn(BaseModel):
    """Request body for set_min_max_availability (HTL-011)."""
    hotel_id: str
    room_type_id: str
    start_date: str
    end_date: str
    min_availability: Optional[int] = Field(default=None, ge=0)
    max_availability: Optional[int] = Field(default=None, ge=0)




# ─────────────────── Hotel Rate Plans (HTL-014..HTL-016) ────────────────────


class RatePlanIn(BaseModel):
    room_type_id: str
    name: str = Field(min_length=1, max_length=200)
    base_nightly_rate_cents: Optional[int] = Field(default=None, ge=0)  # None → default from room type
    base_occupancy: int = Field(default=2, ge=1)
    currency: str = Field(default="USD", min_length=3, max_length=3)


class RatePlanOut(BaseModel):
    rate_plan_id: str
    hotel_id: str
    room_type_id: str
    name: str
    base_nightly_rate_cents: int
    base_occupancy: int
    currency: str
    active: bool
    created_at: int
    updated_at: int
    created_by: str


class RatePlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    base_nightly_rate_cents: Optional[int] = Field(default=None, ge=0)
    base_occupancy: Optional[int] = Field(default=None, ge=1)
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    active: Optional[bool] = None


class RatePlanRuleIn(BaseModel):
    kind: Literal["season", "occupancy", "los", "advance", "weekend"]
    rule_config: dict  # validated per-kind in the service
    priority: int = Field(default=500, ge=0)


class RatePlanRuleOut(BaseModel):
    rule_id: str
    kind: str
    rule_config: dict
    priority: int
    created_at: int
    updated_at: int
    created_by: str


class NightLineOut(BaseModel):
    date: str                     # "YYYY-MM-DD" — the night's calendar date (inclusive)
    base_cents: int               # base_nightly_rate_cents at the start of this night
    season_delta_cents: int       # signed; net effect of season rules
    weekend_delta_cents: int      # signed; net effect of weekend rules
    occupancy_cents: int          # >= 0; extra-adult + extra-child surcharge
    night_total_cents: int        # >= 0; floored final per-night charge (one room)


class StayPriceResult(BaseModel):
    nights: int
    per_night: List[NightLineOut]
    stay_subtotal_cents: int      # sum(night_total_cents); ONE room, pre whole-stay mods
    los_discount_cents: int       # >= 0; LOS discount applied to the subtotal
    advance_modifier_cents: int   # signed; advance modifier (negative = discount)
    rooms: int
    total_cents: int              # final: (subtotal - los + advance) * rooms, floored >= 0
    currency: str
    applied_rule_ids: List[str]


class StayQuoteIn(BaseModel):
    checkin: str                  # "YYYY-MM-DD" inclusive (first night)
    checkout: str                 # "YYYY-MM-DD" exclusive (departure day, not a night)
    adults: int = Field(ge=1)
    children: int = Field(default=0, ge=0)
    rooms: int = Field(default=1, ge=1)
    advance_days: Optional[int] = Field(default=None, ge=0)


class StayQuoteOut(BaseModel):   # serialization of HTL-015's StayPriceResult
    nights: int
    per_night: List[NightLineOut]
    stay_subtotal_cents: int
    los_discount_cents: int
    advance_modifier_cents: int   # signed: negative = discount
    rooms: int
    total_cents: int              # final, all rules applied, × rooms, floored >= 0
    currency: str
    applied_rule_ids: List[str]




# ---------------------------------------------------------------------------
# PRD-003 / PRD-006 / PRD-007 / PRD-012  — OFBiz Catalog Depth models
# All models are ADDITIVE; CatalogItemOut above is unchanged.
# ---------------------------------------------------------------------------

class ProductTypeEnum(str, Enum):
    virtual    = "virtual"
    variant    = "variant"
    standalone = "standalone"
    bundle     = "bundle"
    kit        = "kit"
    digital    = "digital"


class PriceTypeEnum(str, Enum):
    LIST         = "LIST"
    DEFAULT      = "DEFAULT"
    PROMO        = "PROMO"
    COMPETITIVE  = "COMPETITIVE"
    MINIMUM      = "MINIMUM"
    AVERAGE_COST = "AVERAGE_COST"


# --- Feature categories / values ---

class FeatureCategoryCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=500)
    feature_category_id: Optional[str] = Field(default=None, max_length=64)


class FeatureValueCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    price_delta_cents: int = Field(default=0, ge=-10_000_000_00, le=10_000_000_00)
    position: int = Field(default=0, ge=0, le=9999)


class FeatureValueOut(BaseModel):
    feature_value_id: str
    feature_category_id: str
    name: str
    price_delta_cents: int = 0
    position: int = 0


class FeatureCategoryOut(BaseModel):
    feature_category_id: str
    name: str
    description: Optional[str] = None
    creator_id: str
    created_at: int
    values: List[FeatureValueOut] = Field(default_factory=list)


class AttachFeatureCategoryIn(BaseModel):
    feature_category_id: str


# --- PRD-006: Per-item feature categories & values (OFBiz Catalog Depth) ---

class ProductFeatureCategoryCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)  # e.g. "Color", "Size"
    position: int = Field(default=0, ge=0)


class ProductFeatureCategoryOut(BaseModel):
    feature_category_id: str
    name: str
    position: int
    item_id: str  # the product it's attached to
    created_at: int


class ProductFeatureValueCreateIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=100)  # e.g. "Red", "XL"
    price_delta_cents: int = Field(default=0)
    position: int = Field(default=0, ge=0)


class ProductFeatureValueOut(BaseModel):
    feature_value_id: str
    feature_category_id: str
    value: str
    price_delta_cents: int
    position: int
    created_at: int


class ProductFeaturesOut(BaseModel):
    item_id: str
    feature_categories: List[ProductFeatureCategoryOut]
    values: List[ProductFeatureValueOut]


# --- Variants ---

class VariantCreateIn(BaseModel):
    feature_values: Dict[str, str]  # {feature_category_id: feature_value_id}
    sku_override: Optional[str] = None


class VariantOut(BaseModel):
    variant_id: str
    parent_item_id: str
    sku: str
    feature_values: Dict[str, str]
    price_delta_cents: int
    effective_price_cents: int
    creator_id: str
    created_at: int


class VariantListOut(BaseModel):
    item_id: str
    variants: List["VariantOut"]
    count: int


# --- Price components ---

class ProductPriceComponentIn(BaseModel):
    price_type: PriceTypeEnum
    amount_cents: int = Field(ge=0, le=10_000_000_00)
    currency: str = "USD"
    effective_at: int = Field(ge=0)
    expires_at: Optional[int] = Field(default=None, ge=0)


class ProductPriceComponentOut(BaseModel):
    price_component_id: str
    item_id: str
    price_type: str
    amount_cents: int
    currency: str
    effective_at: int
    expires_at: Optional[int] = None
    is_active: bool = False


class PriceResolution(BaseModel):
    amount_cents: int
    currency: str = "USD"
    price_component_id: Optional[str] = None
    source: str  # "price_component" | "scalar_fallback"


class SetPriceComponentsIn(BaseModel):
    price_type: PriceTypeEnum
    components: List[ProductPriceComponentIn] = Field(default_factory=list)




# ── Order Lifecycle (ORD-004) ─────────────────────────────────────────────────


class OrderLifecycleStatus(str, Enum):
    CREATED = "created"
    APPROVED = "approved"
    ALLOCATED = "allocated"
    PICKING = "picking"
    PACKED = "packed"
    SHIPPED = "shipped"
    COMPLETED = "completed"
    HELD = "held"
    BACKORDER = "backorder"
    CANCELLED = "cancelled"
    RETURNED = "returned"


class OrderAdjustmentType(str, Enum):
    DISCOUNT = "discount"
    SURCHARGE = "surcharge"
    TAX = "tax"
    SHIPPING = "shipping"
    PROMOTION = "promotion"


class OrderStatusHistoryEntry(BaseModel):
    event_id: str = Field(min_length=1, max_length=32)
    from_status: Optional[str] = None  # None for the initial "created" event
    to_status: str
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(default="", max_length=500)
    ts: int = Field(ge=0)  # Unix seconds (now_ts())


class ShipGroup(BaseModel):
    ship_group_id: str = Field(min_length=1, max_length=64)
    ship_method: str = Field(default="", max_length=128)
    address_id: Optional[str] = Field(default=None, max_length=128)
    item_ids: List[str] = Field(default_factory=list)
    ship_status: OrderLifecycleStatus = OrderLifecycleStatus.CREATED
    ship_date_bucket: Optional[str] = Field(default=None, max_length=10)  # YYYY-MM-DD
    ship_ts: Optional[int] = Field(default=None, ge=0)
    tracking_number: Optional[str] = Field(default=None, max_length=256)
    tracking_url: Optional[str] = Field(default=None, max_length=2048)
    created_at: int = Field(default=0, ge=0)
    updated_at: int = Field(default=0, ge=0)


class OrderAdjustment(BaseModel):
    adjustment_id: str = Field(min_length=1, max_length=64)
    adj_type: OrderAdjustmentType
    amount_cents: int = Field(..., ge=0)  # always non-negative; sign conveyed by adj_type
    currency: str = Field(default="USD", min_length=3, max_length=8)
    label: str = Field(default="", max_length=255)
    taxable: bool = False
    source_rule_ref: Optional[str] = Field(default=None, max_length=128)
    created_at: int = Field(default=0, ge=0)


class OrderTransitionRequest(BaseModel):
    target_status: OrderLifecycleStatus
    reason: str = Field(default="", max_length=500)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


class OrderLineItemOut(BaseModel):
    item_id: str
    sku: str = Field(default="", max_length=256)
    name: str = Field(default="", max_length=512)
    quantity: int = Field(default=1, ge=1)
    unit_price_cents: int = Field(default=0, ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=8)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OrderLifecycleOut(BaseModel):
    # ── Core fields (mirror of DDB order_record written by create_order) ──
    order_id: str
    status: str  # legacy mirror
    created_at: str  # ISO string
    updated_at: str  # ISO string
    source_system: str
    correlation_id: str
    amount_cents: int = Field(ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=8)
    line_item_count: int = Field(default=0, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # ── Lifecycle fields (populated only when ORDER_LIFECYCLE_ENABLED is on) ──
    lifecycle_status: Optional[OrderLifecycleStatus] = None
    updated_ts: Optional[int] = Field(default=None, ge=0)
    pre_hold_status: Optional[str] = None

    # ── Enriched collections (None = not fetched; [] = fetched but empty) ──
    adjustments: Optional[List[OrderAdjustment]] = None
    ship_groups: Optional[List[ShipGroup]] = None
    status_history: Optional[List[OrderStatusHistoryEntry]] = None

    # ── Derived from TRANSITIONS graph; populated by get_order_lifecycle ──
    allowed_transitions: Optional[List[str]] = None

    # ── Joined order items; populated by get_order_lifecycle ──
    line_items: Optional[List["OrderLineItemOut"]] = None


class OrderTransitionResult(BaseModel):
    order: "OrderLifecycleOut"
    event_id: str
    from_status: Optional[str] = None
    to_status: str


# ── Order Lifecycle router-layer request shapes (ORD-011) ──


class OrderAdjustmentIn(BaseModel):
    adj_type: OrderAdjustmentType
    amount_cents: int = Field(..., ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=8)
    label: str = Field(default="", max_length=255)
    taxable: bool = False
    source_rule_ref: Optional[str] = Field(default=None, max_length=128)


class ShipGroupCreateIn(BaseModel):
    ship_method: str = Field(default="", max_length=128)
    address_id: Optional[str] = Field(default=None, max_length=128)
    item_ids: List[str] = Field(default_factory=list)
    ship_date_bucket: Optional[str] = Field(default=None, max_length=10)


class ShipGroupAssignIn(BaseModel):
    item_ids: List[str] = Field(min_length=1)


class OrderCancelIn(BaseModel):
    reason: str = Field(default="", max_length=500)
    refund: bool = False


OrderLifecycleOut.model_rebuild()
OrderTransitionResult.model_rebuild()


# ── ORD-008: order adjustments response models ────────────────────────────────

class OrderAdjustmentOut(BaseModel):
    adjustment_id: str
    order_id: str
    adj_type: str  # discount|surcharge|tax|shipping
    description: str
    amount_cents: int
    percentage: Optional[float] = None
    created_at: int
    created_by: str


class OrderAdjustmentListOut(BaseModel):
    order_id: str
    adjustments: List[OrderAdjustmentOut]
    total_adjustments_cents: int
    base_amount_cents: int
    total_cents: int


class OrderAdjustmentAddIn(BaseModel):
    adj_type: str
    description: str = Field(..., min_length=1, max_length=500)
    amount_cents: int
    percentage: Optional[float] = None


# ── ORD-009: ship group response models ───────────────────────────────────────

class ShipGroupCreateBodyIn(BaseModel):
    ship_to: Dict[str, Any] = Field(..., min_length=1)
    carrier: Optional[str] = Field(default=None, max_length=128)
    ship_method: str = Field(default="standard", max_length=64)
    item_ids: List[str] = Field(default_factory=list)
    estimated_ship_date: Optional[str] = Field(default=None, max_length=10)


class ShipGroupUpdateIn(BaseModel):
    tracking_number: Optional[str] = Field(default=None, max_length=256)
    status: Optional[str] = Field(default=None, max_length=64)
    carrier: Optional[str] = Field(default=None, max_length=128)
    estimated_ship_date: Optional[str] = Field(default=None, max_length=10)


class ShipGroupFullOut(BaseModel):
    ship_group_id: str
    order_id: str
    ship_to: Dict[str, Any]
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    ship_method: str
    estimated_ship_date: Optional[str] = None
    item_ids: List[str]
    status: str
    created_at: int
    updated_at: int


class ShipGroupListOut(BaseModel):
    order_id: str
    ship_groups: List[ShipGroupFullOut]


# ---------------------------------------------------------------------------
# ATS Pipeline (PIP-001..PIP-006)
# ---------------------------------------------------------------------------

class PipelineEntryCreateIn(BaseModel):
    job_order_id: str
    candidate_id: str
    status: Optional[str] = None  # defaults to "100_no_contact" in service


class PipelineEntryOut(BaseModel):
    pipeline_id: str
    job_order_id: str
    candidate_id: str
    owner_sub: str
    status: str
    status_rank: int
    rating: int
    created_at: int
    updated_at: int


class PipelineStatusChangeIn(BaseModel):
    new_status: str = Field(..., min_length=1, max_length=80)
    note: Optional[str] = Field(None, max_length=500)


class PipelineRatingIn(BaseModel):
    rating: int = Field(
        ..., ge=0, le=5,
        description="1–5 star rating; 0 clears the rating (unrated).",
    )


class PipelineStatusItemIn(BaseModel):
    status_key: str = Field(..., min_length=1, max_length=80)
    label: str = Field(..., min_length=1, max_length=80)
    rank: int = Field(..., ge=0)
    order: int = Field(ge=0, default=0)
    is_submitted: bool = False
    is_placed: bool = False
    is_terminal: bool = False
    color: Optional[str] = Field(None, max_length=7)  # "#RRGGBB"


class PipelineStatusConfigIn(BaseModel):
    statuses: List[PipelineStatusItemIn]

    @model_validator(mode="after")
    def _validate_constraints(self) -> "PipelineStatusConfigIn":
        keys = [s.status_key for s in self.statuses]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate_status_key")
        placed_count = sum(1 for s in self.statuses if s.is_placed)
        if placed_count != 1:
            raise ValueError("exactly_one_is_placed_required")
        submitted_count = sum(1 for s in self.statuses if s.is_submitted)
        if submitted_count > 1:
            raise ValueError("at_most_one_is_submitted_allowed")
        if not (1 <= len(self.statuses) <= 20):
            raise ValueError("statuses_count_out_of_range")
        return self


class PipelineStatusItemOut(BaseModel):
    status_key: str
    label: str
    rank: int
    order: int
    is_submitted: bool
    is_placed: bool
    is_terminal: bool
    color: Optional[str]


class PipelineStatusConfigOut(BaseModel):
    statuses: List[PipelineStatusItemOut]
    updated_at: Optional[int]
    updated_by_sub: Optional[str]


class PlacementIn(BaseModel):
    start_date: int = Field(..., description="Unix epoch seconds for the candidate's start date")
    fee_cents: int = Field(..., ge=0, description="Placement fee in integer cents; 0 = pro-bono")
    notes: Optional[str] = Field(None, max_length=2000)


class PlacementOut(BaseModel):
    placement_id: str
    job_order_id: str
    candidate_id: str
    owner_sub: str
    start_date: int
    fee_cents: int
    status_at_placement: str
    notes: Optional[str]
    created_at: int




# ─── Property Management — Tenants (TEN-001..TEN-003) ──────────────────────


class CreateTenantIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    email: Optional[str] = None
    phone: Optional[str] = None
    party_id: Optional[str] = None
    correlation_id: Optional[str] = None


class UpdateTenantIn(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=200)
    email: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[str] = None  # "prospect" | "active" | "past"


class PropertyTenantOut(BaseModel):
    """Named PropertyTenantOut (not TenantOut) to avoid collision with ENTERPRISE-001
    class TenantOut at app/models.py:4158."""

    tenant_id: str
    owner_id: str
    party_id: str = ""
    display_name: str = ""
    email: Optional[str] = None
    phone: Optional[str] = None
    status: str = "prospect"
    active_unit_id: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class TenantListOut(BaseModel):
    tenants: List[PropertyTenantOut]
    count: int
    next_cursor: Optional[str] = None


class EmploymentIn(BaseModel):
    employer_name: Optional[str] = None
    job_title: Optional[str] = None
    employment_type: Optional[str] = None
    start_date: Optional[str] = None
    employer_phone: Optional[str] = None


class IncomeIn(BaseModel):
    annual_income_cents: Optional[int] = None
    income_currency: str = "usd"
    pay_frequency: Optional[str] = None


class EmergencyContactIn(BaseModel):
    ec_id: Optional[str] = None
    name: str
    relationship: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None


class TenantProfileIn(BaseModel):
    employment: Optional[EmploymentIn] = None
    income: Optional[IncomeIn] = None
    emergency_contacts: Optional[List[EmergencyContactIn]] = None


class TenantProfileOut(BaseModel):
    employment: dict = {}
    income: dict = {}
    emergency_contacts: List[dict] = []
    updated_at: Optional[int] = None


class IncomeDocOut(BaseModel):
    doc_id: str
    tenant_id: str
    file_node_path: str
    file_name: str
    content_type: str
    size_bytes: int
    doc_kind: str
    uploaded_at: int
    uploaded_by: str


class IncomeDocListOut(BaseModel):
    docs: List[IncomeDocOut]
    next_cursor: Optional[str] = None
    count: int


class ActiveUnitIn(BaseModel):
    property_id: Optional[str] = None
    unit_id: Optional[str] = None


class SetIncomeVerificationIn(BaseModel):
    status: str  # unverified | pending | verified | rejected


class TenantLeaseSummaryOut(BaseModel):
    lease_id: str
    unit_id: str
    status: str
    start_date: int
    end_date: Optional[int] = None
    monthly_rent_cents: int
    security_deposit_cents: int
    currency: str
    lease_number: Optional[str] = None


class TenantLeaseListOut(BaseModel):
    leases: List[TenantLeaseSummaryOut]
    count: int
    next_cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# QloApps Hotel-PMS models — HTL-005 (Room Types)
# ---------------------------------------------------------------------------

class RoomTypeIn(BaseModel):
    name: str
    description: str = ""
    base_occupancy_adults: int = Field(ge=0)
    base_occupancy_children: int = Field(default=0, ge=0)
    max_occupancy: int = Field(ge=1)
    bed_type: Literal["single", "twin", "double", "queen", "king", "suite"]
    size_sqft: int = Field(default=0, ge=0)
    base_nightly_rate_cents: int = Field(ge=0)
    photo_urls: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_occupancy(self) -> "RoomTypeIn":
        if self.max_occupancy < self.base_occupancy_adults + self.base_occupancy_children:
            raise ValueError(
                "max_occupancy must be >= base_occupancy_adults + base_occupancy_children"
            )
        return self


class RoomTypeOut(BaseModel):
    hotel_id: str
    room_type_id: str
    name: str
    description: str
    base_occupancy_adults: int
    base_occupancy_children: int
    max_occupancy: int
    bed_type: Literal["single", "twin", "double", "queen", "king", "suite"]
    size_sqft: int
    base_nightly_rate_cents: int
    photo_urls: List[str]
    status: Literal["active", "archived"]
    created_at: int
    updated_at: int


class RoomTypeUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    base_occupancy_adults: Optional[int] = Field(default=None, ge=0)
    base_occupancy_children: Optional[int] = Field(default=None, ge=0)
    max_occupancy: Optional[int] = Field(default=None, ge=1)
    bed_type: Optional[Literal["single", "twin", "double", "queen", "king", "suite"]] = None
    size_sqft: Optional[int] = Field(default=None, ge=0)
    base_nightly_rate_cents: Optional[int] = Field(default=None, ge=0)
    photo_urls: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# QloApps Hotel-PMS models — HTL-006 (Individual Rooms)
# ---------------------------------------------------------------------------

class RoomIn(BaseModel):
    room_type_id: str
    room_number: str
    floor: int
    status: Literal["available", "out_of_service"] = "available"


class RoomOut(BaseModel):
    hotel_id: str
    room_id: str
    room_type_id: str
    room_number: str
    floor: int
    status: Literal["available", "out_of_service"]
    housekeeping_status: Literal["clean", "dirty", "inspected", "out_of_service"]
    created_at: int
    updated_at: int


class RoomUpdateIn(BaseModel):
    room_type_id: Optional[str] = None
    room_number: Optional[str] = None
    floor: Optional[int] = None
    status: Optional[Literal["available", "out_of_service"]] = None


# ---------------------------------------------------------------------------
# QloApps Hotel-PMS models — HTL-007 (Housekeeping)
# ---------------------------------------------------------------------------

class HousekeepingStatusIn(BaseModel):
    housekeeping_status: Literal["clean", "dirty", "inspected", "out_of_service"]


class HkTaskIn(BaseModel):
    room_id: str
    assignee_sub: str = ""
    due_at: int = Field(default=0, ge=0)
    notes: str = ""


class HkTaskOut(BaseModel):
    hotel_id: str
    task_id: str
    room_id: str
    assignee_sub: str
    status: Literal["open", "in_progress", "done"]
    due_at: int
    notes: str
    created_at: int
    updated_at: int
    completed_at: int


class HkTaskAssignIn(BaseModel):
    assignee_sub: str


class HkTaskUpdateIn(BaseModel):
    status: Optional[Literal["open", "in_progress", "done"]] = None
    notes: Optional[str] = None
    due_at: Optional[int] = Field(default=None, ge=0)




# ---------------------------------------------------------------------------
# Leases (open-property vertical — LSE-001 / LSE-002 / LSE-003)
# ---------------------------------------------------------------------------


class LeaseCreateIn(BaseModel):
    tenant_id: str
    property_id: str
    unit_id: str
    start_date: int                                     # Unix ts; required
    end_date: Optional[int] = None                      # Unix ts; None = month-to-month
    monthly_rent_cents: int = Field(ge=0)
    security_deposit_cents: int = Field(default=0, ge=0)
    rent_due_day: int = Field(ge=1, le=28)
    late_fee_type: str = "none"                         # none | flat | percent
    late_fee_cents: int = Field(default=0, ge=0)
    late_fee_percent_bps: int = Field(default=0, ge=0, le=10000)
    late_fee_grace_days: int = Field(default=0, ge=0)
    currency: str = "usd"
    notes: str = ""
    renewal_notice_days: int = Field(default=30, ge=1, le=365)
    force_draft: bool = False


class LeasePatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    end_date: Optional[int] = None
    monthly_rent_cents: Optional[int] = Field(default=None, ge=0)
    security_deposit_cents: Optional[int] = Field(default=None, ge=0)
    rent_due_day: Optional[int] = Field(default=None, ge=1, le=28)
    late_fee_type: Optional[str] = None
    late_fee_cents: Optional[int] = Field(default=None, ge=0)
    late_fee_percent_bps: Optional[int] = Field(default=None, ge=0, le=10000)
    late_fee_grace_days: Optional[int] = Field(default=None, ge=0)
    currency: Optional[str] = None
    notes: Optional[str] = None
    renewal_notice_days: Optional[int] = Field(default=None, ge=1, le=365)


class LeaseStatusTransitionIn(BaseModel):
    status: str  # upcoming | active | ended


class LeaseOut(BaseModel):
    lease_id: str
    lease_number: str
    user_sub: str
    tenant_id: str
    property_id: str
    unit_id: str
    status: str
    start_date: int
    end_date: Optional[int] = None
    monthly_rent_cents: int
    security_deposit_cents: int
    rent_due_day: int
    late_fee_type: str
    late_fee_cents: int
    late_fee_percent_bps: int
    late_fee_grace_days: int
    currency: str
    notes: str
    renewal_notice_days: int
    renewal_notified_at: Optional[int] = None
    created_at: int
    updated_at: int


class LeaseListOut(BaseModel):
    leases: List[LeaseOut]
    count: int
    next_cursor: Optional[str] = None




# ── ATS Skills (RSK-001) ──────────────────────────────────────────────────────

class SkillOut(BaseModel):
    skill_id: str
    name: str
    usage_count: int = 0
    weight: Optional[int] = None          # 1-5, candidate proficiency
    required: Optional[bool] = None       # job_order required flag
    created_at: int = 0


class SkillAssignmentIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    weight: Optional[int] = Field(None, ge=1, le=5)
    required: Optional[bool] = None


class EntitySkillsOut(BaseModel):
    entity_type: str
    entity_id: str
    skills: List[SkillOut]


# ── ATS Résumé Search (RSK-002/RSK-003) ─────────────────────────────────────

class ResumeExtractionOut(BaseModel):
    candidate_id: str
    attachment_id: str
    extraction_status: str      # "ok" | "unsupported" | "error" | "disabled"
    char_count: int
    extracted_at: Optional[int] = None


class ResumeSearchResultItem(BaseModel):
    candidate_id: str
    name_snippet: str
    owner_sub: str
    updated_at: int


class ResumeSearchOut(BaseModel):
    items: List[ResumeSearchResultItem]
    query: str
    total_estimate: int
    has_more: bool


# ── ATS Skill Search (RSK-004) ───────────────────────────────────────────────

class CandidateMatchOut(BaseModel):
    candidate_id: str
    name: str
    email: Optional[str] = None
    matched_skill_ids: List[str]
    match_score: float
    owner_sub: Optional[str] = None


class JobOrderMatchOut(BaseModel):
    job_order_id: str
    title: str
    status: str
    matched_skill_ids: List[str]
    match_score: float


class SkillSearchResultsOut(BaseModel):
    items: List[Union[CandidateMatchOut, JobOrderMatchOut]]
    total: int
    query_skill_ids: List[str]
    match: str




# ---------------------------------------------------------------------------
# QloApps Hotel PMS — Stay-Search + Reservation Lifecycle (HTL-017..HTL-021)
# ---------------------------------------------------------------------------


class StaySearchIn(BaseModel):
    """HTL-017 stay-search request payload."""
    hotel_id: Optional[str] = None   # one of hotel_id | city required (else 422)
    city: Optional[str] = None
    checkin: str                     # "YYYY-MM-DD" (inclusive — first night)
    checkout: str                    # "YYYY-MM-DD" (exclusive — departure day)
    adults: int = Field(ge=1)
    children: int = Field(default=0, ge=0)
    rooms: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _check_target(self) -> "StaySearchIn":
        if not (self.hotel_id or self.city):
            raise ValueError("one of hotel_id or city is required")
        return self


class StayRoomTypeResult(BaseModel):
    """HTL-017 — one available room type in a stay-search result."""
    hotel_id: str
    room_type_id: str
    name: str
    available: bool                   # always True for a surviving result
    min_remaining: int
    rooms: int
    per_night: List[Any] = []        # List[NightLineOut] — typed as Any until HTL-015 merges
    total_cents: int
    currency: str
    applied_rule_ids: List[str] = []


class StaySearchResult(BaseModel):
    """HTL-017 — full stay-search response."""
    checkin: str
    checkout: str
    nights: int
    adults: int
    children: int
    rooms: int
    results: List[StayRoomTypeResult]
    result_count: int


class ReservationCreateIn(BaseModel):
    """HTL-018 — reservation creation payload."""
    hotel_id: str
    guest_party_id: str
    room_type_id: str
    checkin: str                      # "YYYY-MM-DD"
    checkout: str                     # "YYYY-MM-DD" (exclusive)
    adults: int = Field(ge=1)
    children: int = Field(ge=0, default=0)
    rooms: int = Field(ge=1, default=1)
    deposit_cents: int = Field(ge=0, default=0)


class StayReservationOut(BaseModel):
    """HTL-018 — full reservation read response (named StayReservationOut to avoid
    collision with the live inventory ReservationOut at app/models.py:618)."""
    reservation_id: str
    hotel_id: str
    guest_party_id: str
    room_type_id: str
    assigned_room_ids: List[str]
    checkin: str
    checkout: str
    nights: int
    adults: int
    children: int
    rooms: int
    total_cents: int
    deposit_cents: int
    currency: str
    status: Literal["confirmed", "checked_in", "checked_out", "cancelled", "no_show"]
    hold_id: str
    version: int
    created_at: int
    updated_at: int


class ReservationTransitionIn(BaseModel):
    """HTL-019 — lifecycle transition request."""
    target_status: Literal["checked_in", "checked_out", "cancelled", "no_show"]
    reason: str = ""
    assigned_room_ids: Optional[List[str]] = None   # required by the service on → checked_in


class ReservationActionIn(BaseModel):
    """HTL-019 — body for the dedicated literal lifecycle endpoints
    (check-in / check-out / cancel / no-show). The target status is implied by
    the route, so ``target_status`` is NOT required here — only the optional
    ``reason`` and (for check-in) ``assigned_room_ids``."""
    reason: str = ""
    assigned_room_ids: Optional[List[str]] = None


class ReservationModifyIn(BaseModel):
    """HTL-019 — modify-reservation request (all fields optional; None = keep current)."""
    checkin: Optional[str] = None
    checkout: Optional[str] = None
    room_type_id: Optional[str] = None
    adults: Optional[int] = Field(default=None, ge=1)
    children: Optional[int] = Field(default=None, ge=0)
    rooms: Optional[int] = Field(default=None, ge=1)


class ReservationHistoryEntry(BaseModel):
    """HTL-019 — one append-only HIST# child row."""
    event_id: str
    from_status: str
    to_status: str
    actor: str
    reason: str
    ts: int




# ---------------------------------------------------------------------------
# EML-002: Admin email settings
# ---------------------------------------------------------------------------

class EmailSettingsOut(BaseModel):
    from_email: str
    reply_to_email: Optional[str] = None
    ses_enabled: bool
    smtp_enabled: bool
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None
    source: str  # "ddb_override" | "env_fallback"


class EmailSettingsUpdate(BaseModel):
    from_email: Optional[str] = None
    reply_to_email: Optional[str] = None
    ses_enabled: Optional[bool] = None
    smtp_enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# EML-003: Per-user email account connections
# ---------------------------------------------------------------------------

class EmailAccountCreateIn(BaseModel):
    label: str = Field(..., max_length=100)
    imap_host: str
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_use_ssl: bool = True
    smtp_host: str
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_use_tls: bool = True
    username: str
    password: str = Field(..., min_length=1)
    is_default: bool = False


class EmailAccountUpdateIn(BaseModel):
    label: Optional[str] = Field(default=None, max_length=100)
    imap_host: Optional[str] = None
    imap_port: Optional[int] = Field(default=None, ge=1, le=65535)
    imap_use_ssl: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = Field(default=None, ge=1, le=65535)
    smtp_use_tls: Optional[bool] = None
    username: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=1)
    is_default: Optional[bool] = None


class EmailAccountOut(BaseModel):
    account_id: str
    label: str
    imap_host: str
    imap_port: int
    imap_use_ssl: bool
    smtp_host: str
    smtp_port: int
    smtp_use_tls: bool
    username: str
    is_default: bool
    created_at: int
    updated_at: int
    status: str
    last_error: Optional[str] = None


# ---------------------------------------------------------------------------
# EML-004: IMAP inbox sync
# ---------------------------------------------------------------------------

class SyncInboxIn(BaseModel):
    folder: str = "INBOX"
    max_fetch: Optional[int] = Field(default=None, ge=1, le=500)


class SyncInboxOut(BaseModel):
    synced: int
    folder: str
    last_uid: int


class EmailMessageOut(BaseModel):
    uid: int
    message_id: str
    in_reply_to: Optional[str] = None
    references: List[str] = []
    thread_id: str
    subject: str
    from_addr: str
    to_addrs: List[str] = []
    cc_addrs: List[str] = []
    date_ts: int
    folder: str
    flags: List[str] = []
    snippet: str
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    body_html_url: Optional[str] = None
    has_attachments: bool = False
    synced_at: int


class EmailMessageListOut(BaseModel):
    items: List[EmailMessageOut]
    next_cursor: Optional[str] = None


class EmailThreadOut(BaseModel):
    thread_id: str
    messages: List[EmailMessageOut]


# ---------------------------------------------------------------------------
# EML-007: Email archiving
# ---------------------------------------------------------------------------

class ArchiveEmailIn(BaseModel):
    account_id: str
    uid: int
    entity_type: Literal["contact", "ticket"]
    entity_id: str


class ArchivedEmailOut(BaseModel):
    pk: str
    sk: str
    entity_type: str
    entity_id: str
    user_sub: str
    account_id: str
    uid: int
    message_id: str
    message_id_hash: str
    subject: str
    from_addr: str
    snippet: str
    date_ts: int
    archived_at: int


# ---------------------------------------------------------------------------
# EML-009: Campaign email template models
# ---------------------------------------------------------------------------

class CampaignEmailTemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=50_000)
    campaign_id: Optional[str] = Field(default=None, max_length=64)
    merge_fields: List[str] = Field(default_factory=list)

    @field_validator("body", mode="before")
    @classmethod
    def _strip_scripts(cls, v):
        if isinstance(v, str):
            return re.sub(
                r"<script[^>]*>.*?</script>", "", v,
                flags=re.DOTALL | re.IGNORECASE
            )
        return v

    @field_validator("merge_fields", mode="before")
    @classmethod
    def _validate_merge_fields(cls, v):
        if not isinstance(v, list):
            return v
        for f in v:
            if not re.fullmatch(r"[a-zA-Z0-9_]{1,64}", str(f)):
                raise ValueError(f"Invalid merge field name: {f!r}")
        return v


class CampaignEmailTemplateUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    subject: Optional[str] = Field(default=None, max_length=200)
    body: Optional[str] = Field(default=None, max_length=50_000)
    campaign_id: Optional[str] = Field(default=None, max_length=64)
    merge_fields: Optional[List[str]] = None
    active: Optional[bool] = None

    @field_validator("body", mode="before")
    @classmethod
    def _strip_scripts(cls, v):
        if isinstance(v, str):
            return re.sub(
                r"<script[^>]*>.*?</script>", "", v,
                flags=re.DOTALL | re.IGNORECASE
            )
        return v


class CampaignEmailTemplateOut(NotificationTemplateOut):
    campaign_id: Optional[str] = None
    merge_fields: List[str] = Field(default_factory=list)


class CampaignEmailTemplatePreviewOut(NotificationTemplatePreviewOut):
    merge_fields: List[str] = Field(default_factory=list)




# ---------------------------------------------------------------------------
# OBP Transaction Requests + Step-Up SCA (TXR-001..TXR-005)
# ---------------------------------------------------------------------------


class TxnRequestType(str, Enum):
    WALLET_TRANSFER = "WALLET_TRANSFER"
    COUNTERPARTY = "COUNTERPARTY"
    PAYOUT = "PAYOUT"
    REFUND = "REFUND"
    FREE_FORM = "FREE_FORM"


class TxnRequestCreateIn(BaseModel):
    type: TxnRequestType
    amount_cents: int = Field(..., gt=0, description="Amount in cents, must be > 0")
    currency: str = Field(default="usd", min_length=3, max_length=3)
    target: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


class TxnRequestOut(BaseModel):
    request_id: str
    type: TxnRequestType
    amount_cents: int
    currency: str
    target: Dict[str, Any]
    # INITIATED | PENDING | IN_FLIGHT (transient) | COMPLETED | FAILED
    status: str
    sca_challenge_id: Optional[str] = None
    required_factors: Optional[List[str]] = None
    sca_required_factors: Optional[List[str]] = None
    ledger_refs: List[str] = []
    created_at: int
    updated_at: int
    failure_reason: Optional[str] = None


class TxnRequestListOut(BaseModel):
    items: List[TxnRequestOut]
    next_cursor: Optional[str] = None


class InvoiceAddressOut(BaseModel):
    """INV-001: invoice billing/shipping address (additive)."""
    street: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""


class TaxBreakdownEntry(BaseModel):
    """INV-006: one entry per distinct per-line tax rate on an invoice."""
    name: str = ""
    rate_bps: int = 0
    tax_cents: int = 0


    unit_price_cents: int = 0  # INV-001
    tax_rate_bps: int = 0      # INV-006
    tax_cents: int = 0         # INV-006
    invoice_type: str  # tip, unlock, subscription, shop, deposit, b2b
    # QUO-005 standalone-lifecycle fields (additive; default to safe values).
    aos_quote_id: str = ""
    payment_terms_days: Optional[int] = None
    due_date: Optional[int] = None
    voided_at: Optional[int] = None
    # INV-001: extended AOS invoice fields.
    billing_address: Optional[InvoiceAddressOut] = None
    shipping_address: Optional[InvoiceAddressOut] = None
    discount_cents: int = 0
    shipping_cents: int = 0
    # INV-003: currency conversion snapshot.
    original_currency: str = ""
    original_amount_cents: int = 0
    usd_amount_cents: int = 0
    exchange_rate_snapshot: Optional[float] = None
    # INV-006: per-line tax breakdown.
    tax_breakdown: List[TaxBreakdownEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# INV-002 / INV-005: CRM currency + tax-rate registries
# ---------------------------------------------------------------------------
from decimal import Decimal as _InvDecimal  # noqa: E402


class CurrencyCreateIn(BaseModel):
    iso_code: str = Field(..., min_length=3, max_length=3)
    name: str = Field(..., min_length=1, max_length=64)
    symbol: str = Field(..., min_length=1, max_length=8)
    rate_to_usd: _InvDecimal = Field(..., gt=_InvDecimal("0"))
    decimal_places: int = Field(default=2, ge=0, le=4)
    is_active: bool = True


class CurrencyPatchIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=64)
    symbol: Optional[str] = Field(default=None, max_length=8)
    rate_to_usd: Optional[_InvDecimal] = Field(default=None, gt=_InvDecimal("0"))
    decimal_places: Optional[int] = Field(default=None, ge=0, le=4)
    is_active: Optional[bool] = None


class CurrencyOut(BaseModel):
    iso_code: str
    name: str
    symbol: str
    rate_to_usd: float
    decimal_places: int = 2
    is_active: bool = True
    is_default: bool = False
    created_at: int = 0
    updated_at: int = 0


class CurrencyListOut(BaseModel):
    currencies: List[CurrencyOut] = Field(default_factory=list)


class TaxRateCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    rate_bps: int = Field(..., ge=0, le=10000)
    jurisdiction: str = Field(..., min_length=1, max_length=20)
    description: str = Field(default="", max_length=500)


class TaxRatePatchIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    rate_bps: Optional[int] = Field(default=None, ge=0, le=10000)
    jurisdiction: Optional[str] = Field(default=None, min_length=1, max_length=20)
    description: Optional[str] = Field(default=None, max_length=500)
    is_active: Optional[bool] = None


class TaxRateOut(BaseModel):
    tax_rate_id: str
    name: str
    rate_bps: int
    jurisdiction: str
    description: str = ""
    is_active: bool = True
    created_by: str = ""
    created_at: int = 0
    updated_at: int = 0


class TaxRateListOut(BaseModel):
    tax_rates: List[TaxRateOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# Rent Ledger (open-property vertical, RNT-001..RNT-006). Additive.
# ---------------------------------------------------------------------------
class RentChargeOut(BaseModel):
    """Response shape for a posted rent_charge ledger row."""
    pk: str
    sk: str
    entry_id: str
    ts: int
    type: Literal["rent_charge"]
    state: str
    amount_cents: int
    reason: str
    ledger_date: str
    lease_id: str
    property_id: str = ""
    unit_id: str = ""
    tenant_id: str = ""
    period: str
    rent_kind: Literal["charge"]
    currency: str
    signed_amount_cents: Optional[int] = None


class RentChargeSkipOut(BaseModel):
    skipped: bool
    reason: Literal["already_charged"]
    period: str


class RentPaymentIn(BaseModel):
    amount_cents: int = Field(ge=1)
    method: Literal["cash", "check", "bank_transfer", "card_external", "other"]
    paid_on: Optional[int] = Field(default=None)
    reference: Optional[str] = Field(default="", max_length=256)
    period: Optional[str] = Field(default=None, pattern=r"^\d{4}-(?:0[1-9]|1[0-2])$")
    notes: Optional[str] = Field(default="", max_length=1024)


class RentLedgerRowOut(BaseModel):
    sk: str
    ts: int
    type: str
    rent_kind: str
    amount_cents: int
    state: str
    reason: str
    period: Optional[str] = None
    lease_id: Optional[str] = None
    property_id: Optional[str] = None
    unit_id: Optional[str] = None
    tenant_id: Optional[str] = None
    currency: Optional[str] = None
    signed_amount_cents: Optional[int] = None
    status: Optional[str] = None
    method: Optional[str] = None
    reference: Optional[str] = None
    paid_on: Optional[int] = None
    ledger_date: Optional[str] = None


class RentPaymentOut(BaseModel):
    ledger_sk: str
    period: str
    amount_cents: int
    method: str
    reference: str
    paid_on: Optional[int] = None
    charge_status: Optional[str] = None


class RentChargeListOut(BaseModel):
    lease_id: str
    charges: List[RentLedgerRowOut]
    as_of_ts: int


class RentHistoryOut(BaseModel):
    rows: List[RentLedgerRowOut]
    count: int
    next_cursor: Optional[str] = None


class RentVoidIn(BaseModel):
    reason: str = ""


class RentVoidOut(BaseModel):
    ok: bool
    ledger_sk: str
    state: str


class RentAgingOut(BaseModel):
    current_cents: int
    days_30_cents: int
    days_60_cents: int
    days_90_plus_cents: int
    total_open_cents: int
    open_item_count: int
    source: str


class RentPeriodSummaryOut(BaseModel):
    period: str
    scope: str
    charged_cents: int
    collected_cents: int
    outstanding_cents: int
    overdue_cents: int
    due_settled_cents_all_time: int
    charge_count: int
    payment_count: int
    lease_count: int
    aging: Optional[RentAgingOut] = None


class RentPeriodsOut(BaseModel):
    periods: List[str]
    count: int


class RentRunTriggerIn(BaseModel):
    period: Optional[str] = None


class RentRunResultOut(BaseModel):
    period: str
    charged: int
    skipped: int
    lease_count: int




# ── OFBiz Facility/Fulfillment (FAC-003) ─────────────────────────────────────
# Pydantic models for facility CRUD, stock transfers, inbound receiving,
# pick/pack/ship lifecycle, and optional lot/serial tracking.
# All Out models coerce DynamoDB Decimal → int via field_validator(mode="before").
# Importable unconditionally; flag gate enforced at service layer (FAC-004+).


class FacilityIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    facility_type: str = Field(
        default="warehouse",
        pattern="^(warehouse|retail|virtual|drop_ship)$",
    )
    description: Optional[str] = Field(default=None, max_length=1000)
    # address stored as DDB Map (M) per FAC-001/002 authoritative schema.
    address: Optional[dict] = Field(default=None)
    owner_sub: Optional[str] = Field(default=None, max_length=256)
    idempotency_key: Optional[str] = Field(default=None, max_length=256)


class FacilityOut(BaseModel):
    facility_id: str
    name: str
    facility_type: str = "warehouse"
    description: Optional[str] = None
    address: Optional[dict] = None
    owner_sub: Optional[str] = None
    status: str = "active"  # active | archived
    created_at: int = 0
    updated_at: int = 0

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class FacilityLocationIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    location_type: str = Field(
        default="bulk",
        pattern="^(bulk|bin|aisle|shelf|staging|receiving|shipping)$",
    )
    description: Optional[str] = Field(default=None, max_length=500)
    parent_location_id: Optional[str] = Field(default=None, max_length=128)


class FacilityLocationOut(BaseModel):
    facility_id: str
    location_id: str
    name: str
    location_type: str = "bulk"
    description: Optional[str] = None
    parent_location_id: Optional[str] = None
    status: str = "active"  # active | archived
    created_at: int = 0

    @field_validator("created_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class FacilityListOut(BaseModel):
    facilities: List[FacilityOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class FacilityLocationListOut(BaseModel):
    locations: List[FacilityLocationOut] = Field(default_factory=list)


# Transfer models

class TransferItemIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    quantity: int = Field(ge=1, le=10_000_000)


class TransferIn(BaseModel):
    from_facility_id: str = Field(min_length=1, max_length=128)
    from_location_id: str = Field(min_length=1, max_length=128)
    to_facility_id: str = Field(min_length=1, max_length=128)
    to_location_id: str = Field(min_length=1, max_length=128)
    lines: List[TransferItemIn] = Field(min_length=1, max_length=500)
    notes: Optional[str] = Field(default=None, max_length=1000)
    idempotency_key: Optional[str] = Field(default=None, max_length=256)


class TransferItemOut(BaseModel):
    sku: str
    quantity: int = 0
    picked_quantity: int = 0  # units physically moved
    status: str = "pending"  # pending | moved | short

    @field_validator("quantity", "picked_quantity", mode="before")
    @classmethod
    def _coerce_qty(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class TransferOut(BaseModel):
    transfer_id: str
    from_facility_id: str
    from_location_id: str
    to_facility_id: str
    to_location_id: str
    status: str  # requested | in_transit | completed | cancelled
    notes: Optional[str] = None
    lines: List[TransferItemOut] = Field(default_factory=list)
    created_by: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0
    completed_at: Optional[int] = None

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)

    @field_validator("completed_at", mode="before")
    @classmethod
    def _coerce_opt_ts(cls, v: Any) -> Optional[int]:
        return None if v is None else int(v)


class TransferListOut(BaseModel):
    transfers: List[TransferOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# Receiving models

class ReceiveLineIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    quantity: int = Field(ge=1, le=10_000_000)
    unit_cost_cents: Optional[int] = Field(default=None, ge=0, le=1_000_000_000)
    lot_label: Optional[str] = Field(default=None, max_length=128)
    serials: List[str] = Field(default_factory=list, max_length=10_000)


class ReceiveIn(BaseModel):
    facility_id: str = Field(min_length=1, max_length=128)
    location_id: str = Field(min_length=1, max_length=128)
    lines: List[ReceiveLineIn] = Field(min_length=1, max_length=500)
    po_id: Optional[str] = Field(default=None, max_length=128)
    notes: Optional[str] = Field(default=None, max_length=1000)
    # Required to enforce idempotency: sha256(correlation_id) → receipt_id.
    correlation_id: str = Field(min_length=1, max_length=256)


class ReceiptLineOut(BaseModel):
    sku: str
    ordered_quantity: int = 0  # from linked PO line; 0 if no PO
    received_quantity: int = 0
    unit_cost_cents: int = 0
    receipt_status: str = "received"  # received | short | over
    lot_id: Optional[str] = None

    @field_validator("ordered_quantity", "received_quantity", "unit_cost_cents", mode="before")
    @classmethod
    def _coerce_qty(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class ReceiptOut(BaseModel):
    receipt_id: str
    facility_id: str
    location_id: str
    po_id: Optional[str] = None
    correlation_id: str
    status: str  # received | partial | over | cancelled
    notes: Optional[str] = None
    lines: List[ReceiptLineOut] = Field(default_factory=list)
    received_by: Optional[str] = None
    created_at: int = 0

    @field_validator("created_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class ReceiptListOut(BaseModel):
    receipts: List[ReceiptOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# Pick / pack / ship models

class PickLineOut(BaseModel):
    line_id: str  # e.g. "LINE#1"
    order_line_id: str
    sku: str
    requested_quantity: int = 0
    picked_quantity: int = 0
    from_facility_id: str = ""
    from_location_id: str = ""
    reservation_id: Optional[str] = None
    status: str = "pending"  # pending | picked | short | cancelled

    @field_validator("requested_quantity", "picked_quantity", mode="before")
    @classmethod
    def _coerce_qty(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class PicklistOut(BaseModel):
    picklist_id: str
    order_id: str
    status: str  # pending | picking | picked | packed | cancelled
    lines: List[PickLineOut] = Field(default_factory=list)
    created_by: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0
    packed_at: Optional[int] = None

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)

    @field_validator("packed_at", mode="before")
    @classmethod
    def _coerce_opt_ts(cls, v: Any) -> Optional[int]:
        return None if v is None else int(v)


class PackageLineIn(BaseModel):
    order_line_id: str = Field(min_length=1, max_length=128)
    sku: str = Field(min_length=1, max_length=256)
    quantity: int = Field(ge=1, le=10_000_000)


class PackageIn(BaseModel):
    weight_grams: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    length_mm: Optional[int] = Field(default=None, ge=0)
    width_mm: Optional[int] = Field(default=None, ge=0)
    height_mm: Optional[int] = Field(default=None, ge=0)
    contents: List[PackageLineIn] = Field(min_length=1, max_length=500)
    notes: Optional[str] = Field(default=None, max_length=500)


class PackageOut(BaseModel):
    package_id: str  # e.g. "1" (PKG# prefix stripped by service layer)
    weight_grams: int = 0
    length_mm: int = 0
    width_mm: int = 0
    height_mm: int = 0
    contents: List[PackageLineIn] = Field(default_factory=list)
    notes: Optional[str] = None

    @field_validator("weight_grams", "length_mm", "width_mm", "height_mm", mode="before")
    @classmethod
    def _coerce_dim(cls, v: Any) -> int:
        return 0 if v is None else int(v)


class FulfillmentShipmentIn(BaseModel):
    picklist_id: str = Field(min_length=1, max_length=128)
    carrier: str = Field(min_length=1, max_length=100)
    tracking_number: str = Field(min_length=1, max_length=200)
    service_level: Optional[str] = Field(default=None, max_length=100)
    packages: List[PackageIn] = Field(min_length=1, max_length=500)
    notes: Optional[str] = Field(default=None, max_length=1000)
    idempotency_key: Optional[str] = Field(default=None, max_length=256)


class FulfillmentShipmentOut(BaseModel):
    shipment_id: str
    order_id: str
    picklist_id: str
    status: str  # draft | packed | shipped | delivered | cancelled
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    service_level: Optional[str] = None
    packages: List[PackageOut] = Field(default_factory=list)
    notes: Optional[str] = None
    created_by: Optional[str] = None
    created_at: int = 0
    shipped_at: Optional[int] = None
    delivered_at: Optional[int] = None

    @field_validator("created_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)

    @field_validator("shipped_at", "delivered_at", mode="before")
    @classmethod
    def _coerce_opt_ts(cls, v: Any) -> Optional[int]:
        return None if v is None else int(v)


class ShipmentListOut(BaseModel):
    shipments: List[ShipmentOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# Lot / serial models (FAC-014, optional; defined here to prevent a second models.py PR)

class LotSummaryOut(BaseModel):
    """Simplified lot view owned by FAC-003. FAC-014 adds the full LotOut."""
    sku: str
    lot_id: str
    quantity: int = 0
    received_at: int = 0
    expires_at: Optional[int] = None
    receipt_id: Optional[str] = None
    notes: Optional[str] = None

    @field_validator("quantity", "received_at", mode="before")
    @classmethod
    def _coerce_int(cls, v: Any) -> int:
        return 0 if v is None else int(v)

    @field_validator("expires_at", mode="before")
    @classmethod
    def _coerce_opt_int(cls, v: Any) -> Optional[int]:
        return None if v is None else int(v)


class SerialOut(BaseModel):
    sku: str
    serial: str
    lot_id: Optional[str] = None
    status: str = "on_hand"  # on_hand | picked | shipped | returned
    receipt_id: Optional[str] = None
    shipment_id: Optional[str] = None
    received_at: int = 0

    @field_validator("received_at", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> int:
        return 0 if v is None else int(v)




# ── Hotel Front Desk (HTL-022..024) ─────────────────────────────────────────
# Additive read-only and action models for the QloApps hotel front-desk
# console.  No existing model is modified; these are appended at the end
# per CLAUDE.md "APPEND new Pydantic models at END of app/models.py".


class FrontDeskRow(BaseModel):
    """A reservation projection for a front-desk console row (HTL-022)."""
    reservation_id: str
    hotel_id: str
    room_type_id: str
    guest_name: str
    guest_sub: str
    checkin: str              # "YYYY-MM-DD"
    checkout: str             # "YYYY-MM-DD"
    status: Literal["confirmed", "checked_in", "checked_out", "cancelled", "no_show"]
    nights: int
    occupancy_adults: int
    occupancy_children: int
    assigned_room_ids: List[str] = []
    total_cents: int


class FrontDeskListOut(BaseModel):
    """Paginated list envelope for the front-desk console (HTL-022)."""
    rows: List[FrontDeskRow]
    count: int
    cursor: Optional[str] = None


class OccupancySnapshotOut(BaseModel):
    """Live occupancy snapshot for a hotel on a given date (HTL-022)."""
    hotel_id: str
    date: str                 # "YYYY-MM-DD"
    rooms_total: int
    rooms_occupied: int
    rooms_available: int
    rooms_out_of_service: int
    occupancy_rate: float     # rooms_occupied / max(rooms_total, 1); 0.0..1.0
    arrivals_count: int
    departures_count: int
    in_house_count: int


class WalkInBookingIn(BaseModel):
    """Walk-in create+check-in request body (HTL-023)."""
    room_type_id: str
    checkin: str              # "YYYY-MM-DD"
    checkout: str             # "YYYY-MM-DD"
    occupancy_adults: int = Field(default=1, ge=1)
    occupancy_children: int = Field(default=0, ge=0)
    guest_name: str
    guest_sub: Optional[str] = None
    assigned_room_ids: Optional[List[str]] = None
    total_cents: Optional[int] = Field(default=None, ge=0)


class AssignRoomIn(BaseModel):
    """Assign / change room request body (HTL-023)."""
    assigned_room_ids: List[str]
    version: int = Field(ge=0)


class RoomMoveIn(BaseModel):
    """Room-move request body (HTL-023)."""
    from_room_id: str
    to_room_id: str
    version: int = Field(ge=0)


class FrontDeskActionOut(BaseModel):
    """Action response: updated reservation row + affected room rows (HTL-023)."""
    reservation: FrontDeskRow
    affected_rooms: List[dict] = []




# ── ATS Career Portal (PRT-001..PRT-005) ─────────────────────────────────────

class CareerPortalConfigIn(BaseModel):
    portal_name: str = Field(..., min_length=1, max_length=120)
    intro_copy: str = Field(default="", max_length=4000)
    logo_file_path: Optional[str] = Field(default=None)
    primary_color: Optional[str] = Field(
        default=None,
        pattern=r"^#[0-9a-fA-F]{6}$",
    )
    support_email: Optional[str] = Field(default=None, max_length=254)


class CareerPortalConfigOut(BaseModel):
    portal_name: str
    intro_copy: str
    logo_file_path: Optional[str] = None
    logo_url: Optional[str] = None          # resolved at read time; None when no logo
    primary_color: Optional[str] = None
    support_email: Optional[str] = None
    updated_at: Optional[int] = None        # None when no row persisted yet (default config)
    updated_by: Optional[str] = None


class CareerJobSummaryOut(BaseModel):
    job_order_id: str
    slug: str
    title: str
    location: Optional[str] = None
    employment_type: Optional[str] = None   # "full_time"|"part_time"|"contract"|"temp"|"referral"
    posted_at: int = 0                      # Unix timestamp
    openings: int = 1


class CareerJobDetailOut(CareerJobSummaryOut):
    public_description: Optional[str] = None
    screening_questionnaire_slug: Optional[str] = None  # non-None → PRT-005 applies
    apply_path: str = ""                    # "/public/careers/jobs/{slug}/apply"


class CareerJobListOut(BaseModel):
    items: List[CareerJobSummaryOut]
    cursor: Optional[str] = None           # opaque HMAC-signed cursor; None = no more pages
    total_estimate: Optional[int] = None   # always None (DynamoDB GSI queries don't count)


# PRT-004: Self-apply

class CareerApplyIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=120)
    last_name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., max_length=254)
    phone: Optional[str] = Field(None, max_length=30)
    cover_note: Optional[str] = Field(None, max_length=4000)
    # Bot-trap: non-empty → silent fake-success, no DDB write (CMP-006 §5.1).
    # No max_length so arbitrarily long bot values still hit honeypot, not 422.
    honeypot: Optional[str] = None
    # PRT-005 extensions (backward-compatible optional fields)
    resume_ticket_id: Optional[str] = Field(None, max_length=64)
    screening_response_session_id: Optional[str] = Field(None, max_length=64)


class CareerApplyOut(BaseModel):
    application_id: str
    candidate_id: Optional[str] = None
    status: str  # always "received" on success


# PRT-005: Résumé presign

class CareerResumePresignIn(BaseModel):
    filename: str = Field(..., min_length=1, max_length=260)
    content_type: str = Field(..., max_length=120)
    size_bytes: int = Field(..., ge=1)
    # Bot-trap: identical honeypot semantics to CareerApplyIn (CMP-006 §5.1).
    honeypot: Optional[str] = None


class CareerResumePresignOut(BaseModel):
    upload_url: str          # /mock/s3/... in dev; presigned PUT URL in prod
    ticket_id: str
    key: str                 # S3 object key
    path: str                # file-manager path: /career-portal/resumes/{job_order_id}/{uuid}.ext
    content_type: str



# ---------------------------------------------------------------------------
# OAU-001 / OAU-005: OAuth consumer-app registry models
# ---------------------------------------------------------------------------

class CreateConsumerReq(BaseModel):
    name: str
    description: str = ""
    redirect_uris: List[str]
    allowed_scopes: List[str]
    is_confidential: bool = True


class UpdateConsumerReq(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None


class ConsumerOut(BaseModel):
    client_id: str
    client_secret_prefix: str
    owner_sub: str
    name: str
    description: str = ""
    redirect_uris: List[str] = []
    allowed_scopes: List[str] = []
    is_confidential: bool = True
    enabled: bool = True
    created_at: int = 0
    updated_at: int = 0
    secret_rotated_at: int = 0


class CreateConsumerOut(ConsumerOut):
    client_secret: str  # present only at creation/rotation; omitted on subsequent reads


# OAU-002: OAuth2 token models
class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None


class OAuthErrorResponse(BaseModel):
    error: str
    error_description: Optional[str] = None



    freq: Literal["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]


# ─── CRM Activities (ACT-002): Calendar RSVP ─────────────────────────────────

class EventAttendeeRsvpStatus(str, Enum):
    accepted = "accepted"
    declined = "declined"
    tentative = "tentative"
    no_response = "no_response"


class EventAttendeeOut(BaseModel):
    user_sub: str
    rsvp_status: EventAttendeeRsvpStatus = EventAttendeeRsvpStatus.no_response
    responded_at: Optional[int] = None   # Unix epoch; None when no_response


class EventRsvpUpdateIn(BaseModel):
    status: EventAttendeeRsvpStatus


class EventAttendeeListOut(BaseModel):
    attendees: List[EventAttendeeOut]


class UserRsvpListOut(BaseModel):
    items: List[dict]
    next_cursor: Optional[str] = None


# ─── CRM Activities (ACT-004): Event Reminders/Alarms ───────────────────────

class EventReminderMethod(str, Enum):
    email = "email"
    in_app = "in_app"


class EventReminderIn(BaseModel):
    minutes_before: int = Field(ge=1, le=10080)   # 1 min to 1 week
    method: EventReminderMethod = EventReminderMethod.in_app


class EventRemindersSetIn(BaseModel):
    reminders: List[EventReminderIn] = Field(default_factory=list, max_length=5)


class EventReminderOut(BaseModel):
    reminder_id: str
    calendar_id: str
    event_id: str
    user_sub: str
    minutes_before: int
    method: EventReminderMethod
    fire_at: int
    fired: bool
    created_at: int


class EventRemindersOut(BaseModel):
    reminders: List[EventReminderOut]
    count: int


# ─── CRM Activities (ACT-006/ACT-007): CRM Call Logging ─────────────────────

class CallOutcome(str, Enum):
    connected = "connected"
    not_connected = "not_connected"
    left_message = "left_message"
    wrong_number = "wrong_number"
    busy = "busy"


class CallLogCreateIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    direction: Literal["inbound", "outbound"]
    duration_seconds: int = Field(default=0, ge=0)
    outcome: CallOutcome
    call_type: Literal["audio", "video", "phone"] = "phone"
    contact_user_sub: Optional[str] = None
    # ACT-007: entity link (opaque, PTY will resolve once shipped)
    linked_entity_type: Optional[Literal["contact", "lead", "account", "opportunity"]] = None
    linked_entity_id: Optional[str] = Field(default=None, max_length=200)


class CallLogUpdateIn(BaseModel):
    subject: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    outcome: Optional[CallOutcome] = None


class CallLogOut(BaseModel):
    call_id: str
    user_sub: str
    subject: str
    description: str
    direction: str
    duration_seconds: int
    outcome: str
    call_type: str
    contact_user_sub: Optional[str] = None
    linked_entity_type: Optional[str] = None
    linked_entity_id: Optional[str] = None
    created_at: int
    updated_at: int


class CallLogListResponse(BaseModel):
    items: List[CallLogOut]
    next_cursor: Optional[str] = None


# ─── CRM Activities (ACT-008): CRM Tasks ────────────────────────────────────

class CrmTaskStatus(str, Enum):
    not_started = "not_started"
    in_progress = "in_progress"
    completed = "completed"
    deferred = "deferred"
    waiting = "waiting"


class CrmTaskPriority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    urgent = "urgent"


class CrmTaskCreateIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    status: CrmTaskStatus = CrmTaskStatus.not_started
    priority: CrmTaskPriority = CrmTaskPriority.medium
    due_date_ts: Optional[int] = None   # Unix epoch seconds
    assignee_sub: Optional[str] = None
    linked_entity_type: Optional[Literal["contact", "lead", "account", "opportunity"]] = None
    linked_entity_id: Optional[str] = Field(default=None, max_length=200)


class CrmTaskUpdateIn(BaseModel):
    subject: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    status: Optional[CrmTaskStatus] = None
    priority: Optional[CrmTaskPriority] = None
    due_date_ts: Optional[int] = None
    assignee_sub: Optional[str] = None


class CrmTaskOut(BaseModel):
    task_id: str
    user_sub: str
    subject: str
    description: str
    status: str
    priority: str
    due_date_ts: Optional[int] = None
    assignee_sub: Optional[str] = None
    linked_entity_type: Optional[str] = None
    linked_entity_id: Optional[str] = None
    created_at: int
    updated_at: int


class CrmTaskListOut(BaseModel):
    items: List[CrmTaskOut]
    next_cursor: Optional[str] = None
    count: int = 0


# ─── CRM Activities (ACT-009): CRM Activity Timeline ────────────────────────

class CrmActivityOut(BaseModel):
    activity_id: str
    entity_type: str
    entity_id: str
    activity_type: str   # call | task | note | calendar_event | email
    user_sub: str
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: int


class CrmActivityTimelineOut(BaseModel):
    entity_type: str
    entity_id: str
    items: List[CrmActivityOut]
    next_cursor: Optional[str] = None


# ─── CRM Activities (ACT-010): CRM Notes ────────────────────────────────────

class CrmNoteCreateIn(BaseModel):
    body: str = Field(default="", max_length=20_000)
    linked_entity_type: Optional[Literal["contact", "lead", "account", "opportunity"]] = None
    linked_entity_id: Optional[str] = Field(default=None, max_length=200)


class CrmNoteUpdateIn(BaseModel):
    body: str = Field(max_length=20_000)


class CrmNoteOut(BaseModel):
    note_id: str
    user_sub: str
    body: str
    linked_entity_type: Optional[str] = None
    linked_entity_id: Optional[str] = None
    attachment_s3_key: Optional[str] = None
    attachment_filename: Optional[str] = None
    attachment_content_type: Optional[str] = None
    attachment_url: Optional[str] = None
    created_at: int
    updated_at: int


class CrmNoteListOut(BaseModel):
    notes: List[CrmNoteOut]
    next_cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# Maintenance Work Orders (WOV-001..WOV-004)
# ---------------------------------------------------------------------------

class MaintenanceOrderIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    priority: str = Field("normal")
    property_id: str
    unit_id: Optional[str] = None
    scheduled_for: Optional[int] = None
    correlation_id: Optional[str] = None
    amount_cents: Optional[int] = None  # WOV-003 escrow; ignored when sub-flag off


class MaintenanceOrderOut(BaseModel):
    work_order_id: str
    property_id: str
    unit_id: Optional[str] = None
    vendor_id: Optional[str] = None
    assignee_sub: Optional[str] = None
    title: str
    description: Optional[str] = None
    priority: str
    wo_status: str
    scheduled_for: Optional[int] = None
    cost_cents: Optional[int] = None
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None
    correlation_id: str
    actor_sub: str
    escrow_amount_cents: Optional[int] = None  # WOV-003
    escrow_status: Optional[str] = None         # WOV-003


class MaintenanceOrderTransitionIn(BaseModel):
    property_id: str = Field(..., min_length=1, max_length=64)
    target_status: Literal["assigned", "in_progress", "completed", "cancelled"]
    cost_cents: Optional[int] = Field(default=None, ge=0)
    assignee_sub: Optional[str] = None
    vendor_id: Optional[str] = None


class MaintenanceOrderAssignIn(BaseModel):
    property_id: str = Field(..., min_length=1, max_length=64)
    vendor_id: Optional[str] = None
    unit_id: Optional[str] = None
    assignee_sub: Optional[str] = None


class MaintenanceOrderScheduleIn(BaseModel):
    property_id: str = Field(..., min_length=1, max_length=64)
    scheduled_for: int = Field(..., ge=1)


class WoListOut(BaseModel):
    items: List[MaintenanceOrderOut]
    count: int
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# Maintenance Vendors (WOV-004)
# ---------------------------------------------------------------------------

class VendorCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    trade_category: str
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: str = "USD"
    payment_terms_days: int = Field(default=30, ge=0, le=365)
    user_sub: Optional[str] = None  # WOV-003/D2: link to platform account


class VendorPatchIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    trade_category: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: Optional[str] = None
    payment_terms_days: Optional[int] = Field(default=None, ge=0, le=365)
    user_sub: Optional[str] = None  # "" clears link; None leaves unchanged


class VendorStatusIn(BaseModel):
    status: str


class VendorOut(BaseModel):
    vendor_id: str
    name: str
    status: str
    trade_category: str
    source: str
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: str
    payment_terms_days: int
    user_sub: Optional[str] = None  # WOV-003/D2: linked platform account
    created_by: str
    created_at: int
    updated_at: int


class VendorListOut(BaseModel):
    vendors: List[VendorOut]
    cursor: Optional[str] = None
    count: int





# ---------------------------------------------------------------------------
# VEW-001 — Account Views models
# ---------------------------------------------------------------------------

class ViewGrantsMatrix(BaseModel):
    """Per-field boolean grants — all default False (deny-by-default)."""
    can_see_balance: bool = False
    can_see_available_balance: bool = False
    can_see_transaction_list: bool = False
    can_see_transaction_amount: bool = False
    can_see_transaction_description: bool = False
    can_see_counterparty: bool = False
    can_see_counterparty_name: bool = False
    can_see_owners: bool = False
    can_see_account_label: bool = False
    can_see_payout_destination_masked: bool = False
    can_add_comment: bool = False
    can_add_tag: bool = False
    can_add_narrative: bool = False
    can_delete_comment: bool = False


class ViewCreateIn(BaseModel):
    name: str
    grants: ViewGrantsMatrix
    preset: Optional[str] = None
    description: str = ""
    metadata_visibility: str = ""


class ViewUpdateIn(BaseModel):
    name: Optional[str] = None
    grants: Optional[ViewGrantsMatrix] = None
    description: Optional[str] = None
    metadata_visibility: Optional[str] = None


class ViewOut(BaseModel):
    view_id: str
    resource_type: str
    resource_id: str
    owner_sub: str
    name: str
    description: str
    is_system_alias: bool
    grants: Dict[str, bool]
    preset: Optional[str]
    metadata_visibility: str
    created_at: int
    updated_at: int


class ViewGrantCatalogOut(BaseModel):
    fields: List[str]
    presets: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# VEW-002 — Grant models
# ---------------------------------------------------------------------------

class ViewGrantIn(BaseModel):
    grantee_sub: str


class ViewGrantRespondIn(BaseModel):
    accept: bool


class ViewGrantOut(BaseModel):
    grant_id: str
    view_id: str
    grantee_sub: str
    owner_sub: str
    resource_type: str
    resource_id: str
    status: str
    invited_at: int
    accepted_at: int
    updated_at: int


class ViewGrantListOut(BaseModel):
    grants: List[ViewGrantOut]
    next_cursor: Optional[str] = None


class PublicViewLinkIn(BaseModel):
    ttl_days: Optional[int] = None


class PublicViewLinkOut(BaseModel):
    url: str
    token: str
    expires_at: int


class PublicViewDataOut(BaseModel):
    resource_type: str
    resource_id: str
    data: Dict[str, Any]
    expires_at: Optional[int] = None


# ---------------------------------------------------------------------------
# VEW-003 — Projection models
# ---------------------------------------------------------------------------

class ViewProvenanceOut(BaseModel):
    view_id: str
    view_name: str
    preset: Optional[str]
    granted_fields: List[str]


class ViewedResourceOut(BaseModel):
    resource_type: str
    resource_id: str
    data: Dict[str, Any]
    view: ViewProvenanceOut = Field(alias="_view")
    model_config = ConfigDict(populate_by_name=True)


# ---------------------------------------------------------------------------
# VEW-004 — Entitlement-request models
# ---------------------------------------------------------------------------

class EntitlementRequestCreateIn(BaseModel):
    entitlement_kind: str = Field(..., pattern="^(acl_role|admin_scope)$")
    target_ref: str = Field(..., min_length=1, max_length=200)
    justification: str = Field(..., min_length=10, max_length=2000)


class EntitlementDecisionIn(BaseModel):
    reason: str = Field(default="", max_length=1000)


class EntitlementRequestOut(BaseModel):
    request_id: str
    requester_sub: str
    entitlement_kind: str
    target_ref: str
    justification: str
    status: str
    claimed_by_sub: Optional[str]
    claimed_at: Optional[int]
    decided_by_sub: Optional[str]
    decided_at: Optional[int]
    decision_reason: Optional[str]
    grant_pending_acl: bool
    created_at: int
    updated_at: int


class EntitlementAuditEventOut(BaseModel):
    event_type: str
    actor_sub: str
    from_status: Optional[str]
    to_status: Optional[str]
    reason: str
    created_at: int


class EntitlementQueueOut(BaseModel):
    requests: List[EntitlementRequestOut]
    next_cursor: Optional[str] = None




# ---------------------------------------------------------------------------
# QloApps Booking-Engine Storefront (HTL-025 .. HTL-027)
# Public, unauthenticated, storefront-safe projections.
# These are append-only additions; no existing model is modified.
# ---------------------------------------------------------------------------

class HotelAddress(BaseModel):
    """HTL-025: Storefront-safe hotel address (mirrors HTL-001 HotelAddress)."""
    line1: str
    line2: Optional[str] = None
    city: str
    region: str
    postal_code: str
    country: str


class HotelPolicies(BaseModel):
    """HTL-025: Storefront-safe hotel policies (mirrors HTL-001 HotelPolicies)."""
    cancellation_text: str = ""
    pet_policy: str = ""
    smoking: bool = False
    children: bool = True


class HotelContact(BaseModel):
    """HTL-025: Storefront-safe hotel contact (mirrors HTL-001 HotelContact)."""
    phone: str = ""
    email: str = ""
    website: str = ""


class PublicHotelOut(BaseModel):
    """HTL-025: Storefront-safe hotel projection (no owner_sub, no status, no internal fields)."""
    hotel_id: str
    name: str
    description: str = ""
    star_rating: int
    check_in_time: str
    check_out_time: str
    address: HotelAddress
    amenities: List[str] = []
    photos: List[str] = []
    policies: HotelPolicies
    contact: HotelContact


class PublicRoomTypeOut(BaseModel):
    """HTL-025: Storefront-safe room-type projection."""
    room_type_id: str
    name: str
    description: str = ""
    occupancy_adults: int
    occupancy_children: int
    max_occupancy: int
    bed_type: str
    size_sqft: int
    amenities: List[str] = []
    photos: List[str] = []
    base_rate_cents: int
    currency: str = "usd"


class PublicRoomTypeListOut(BaseModel):
    """HTL-025: Storefront-safe list of room types."""
    room_types: List[PublicRoomTypeOut]
    count: int


class PerNightAvailOut(BaseModel):
    """HTL-026: Per-night availability + rate line in a stay quote."""
    date: str
    rooms_available: int
    rate_cents: int


class StayQuoteResultOut(BaseModel):
    """HTL-026: One available room type's availability + total in a stay quote."""
    room_type: PublicRoomTypeOut
    available_rooms: int
    per_night: List[PerNightAvailOut]
    total_price_cents: int
    currency: str


class BookingStayQuoteOut(BaseModel):
    """HTL-026: Full stay-search quote envelope (public booking-engine response)."""
    hotel_id: str
    checkin: str
    checkout: str
    nights: int
    adults: int
    children: int
    rooms: int
    results: List[StayQuoteResultOut]
    currency: str


class AddRoomToCartIn(BaseModel):
    """HTL-027: Add a room-night selection to the booking cart."""
    hotel_id: str
    room_type_id: str
    checkin: str
    checkout: str
    adults: int = Field(ge=1, default=1)
    children: int = Field(ge=0, default=0)
    rooms: int = Field(ge=1, default=1)


class GuestDetailsIn(BaseModel):
    """HTL-027: Guest snapshot for set_guest_details."""
    name: str
    email: str
    phone: str
    address: Optional[HotelAddress] = None


class BookingCheckoutIn(BaseModel):
    """HTL-027: Checkout payload."""
    payment_method_token: Optional[str] = None
    idempotency_key: Optional[str] = None


class BookingCartLineOut(BaseModel):
    """HTL-027: A single room-night line in the booking cart projection."""
    room_type_id: str
    room_type_name: str
    checkin: str
    checkout: str
    nights: int
    adults: int
    children: int
    rooms: int
    unit_price_cents: int
    line_total_cents: int
    currency: str


class GuestSnapshotOut(BaseModel):
    """HTL-027: Guest snapshot in the booking cart projection."""
    name: str
    email: str
    phone: str
    address: Optional[HotelAddress] = None


class BookingCartOut(BaseModel):
    """HTL-027: Storefront-safe booking cart projection."""
    booking_cart_id: str
    hotel_id: str
    status: str
    currency: str
    lines: List[BookingCartLineOut]
    total_cents: int
    guest: Optional[GuestSnapshotOut] = None
    created_at: str


class BookingCheckoutResult(BaseModel):
    """HTL-027: Checkout response."""
    reservation_ids: List[str]
    order_id: str
    total_price_cents: int
    currency: str
    confirmation: dict




# ── Shipping / Logistics (SHP-003, Phase 8 Module H) ────────────────────────

class CarrierIn(BaseModel):
    carrier_code: str = Field(pattern=r"^(ups|fedex|usps|dhl|manual)$")
    display_name: str = Field(min_length=1, max_length=100)


class CarrierOut(BaseModel):
    carrier_id: str
    carrier_code: str
    display_name: str
    online_tracking: bool
    enabled: bool
    created_at: int
    updated_at: int


class ShipmentMethodIn(BaseModel):
    method_code: str = Field(pattern=r"^(ground|express|overnight|economy|flat_rate)$")
    method_label: str = Field(min_length=1, max_length=100)
    base_rate_cents: int = Field(ge=0)
    currency: str = Field(default="usd", min_length=3, max_length=3)
    transit_days_min: Optional[int] = Field(default=None, ge=0)
    transit_days_max: Optional[int] = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _transit_days_order(self) -> "ShipmentMethodIn":
        if self.transit_days_min is not None and self.transit_days_max is not None:
            if self.transit_days_min > self.transit_days_max:
                raise ValueError("transit_days_min must be <= transit_days_max")
        return self


class ShipmentMethodOut(BaseModel):
    carrier_id: str
    carrier_code: str
    method_code: str
    method_label: str
    base_rate_cents: int
    currency: str
    transit_days_min: Optional[int] = None
    transit_days_max: Optional[int] = None
    enabled: bool = True


class ShippingRateRequest(BaseModel):
    carrier_code: str = Field(pattern=r"^(ups|fedex|usps|dhl|manual)$")
    method_code: str = Field(pattern=r"^(ground|express|overnight|economy|flat_rate)$")
    weight_oz: int = Field(ge=0)
    destination_zip: str = Field(min_length=1, max_length=20)
    origin_zip: Optional[str] = Field(default=None, max_length=20)


class ShippingRateOption(BaseModel):
    carrier_code: str
    method_code: str
    rate_cents: int
    currency: str
    transit_days_min: Optional[int] = None
    transit_days_max: Optional[int] = None
    estimated_delivery: Optional[str] = None


class ShippingRateQuote(BaseModel):
    request_id: str
    options: List["ShippingRateOption"]
    currency: str
    generated_at: int


class ShipGroupIn(BaseModel):
    ship_to_address: Dict[str, Any] = Field(min_length=1)
    ship_method_id: Optional[str] = None
    carrier_code: Optional[str] = Field(default=None, pattern=r"^(ups|fedex|usps|dhl|manual)$")
    method_code: Optional[str] = Field(default=None, pattern=r"^(ground|express|overnight|economy|flat_rate)$")


class ShipGroupOut(BaseModel):
    ship_to_address: Dict[str, Any]
    ship_method_id: Optional[str] = None
    carrier_code: Optional[str] = None
    method_code: Optional[str] = None


class ShipmentPackageContentIn(BaseModel):
    item_id: str
    sku: Optional[str] = None
    quantity: int = Field(ge=1)


class ShipmentPackageIn(BaseModel):
    weight_oz: int = Field(ge=0)
    length_in: Optional[float] = Field(default=None, ge=0)
    width_in: Optional[float] = Field(default=None, ge=0)
    height_in: Optional[float] = Field(default=None, ge=0)
    contents: List[Dict[str, Any]] = Field(default_factory=list)


class ShipmentPackageOut(BaseModel):
    package_seq: str
    weight_oz: int
    length_in: Optional[float] = None
    width_in: Optional[float] = None
    height_in: Optional[float] = None
    contents: List[Dict[str, Any]] = Field(default_factory=list)
    billed_weight_oz: Optional[int] = None


class ShipmentItemOut(BaseModel):
    item_id: str
    sku: Optional[str] = None
    quantity: int
    order_id: Optional[str] = None


class ShipmentIn(BaseModel):
    order_id: str = Field(min_length=1, max_length=128)
    carrier_code: str = Field(pattern=r"^(ups|fedex|usps|dhl|manual)$")
    method_code: str = Field(pattern=r"^(ground|express|overnight|economy|flat_rate)$")
    ship_to_address: Dict[str, Any]
    line_items: List[Dict[str, Any]] = Field(min_length=1)
    packages: List[ShipmentPackageIn] = Field(default_factory=list)
    correlation_id: Optional[str] = None
    ship_group_seq: int = Field(default=1, ge=1)
    purchase_txn_id: Optional[str] = None


class ShipmentOut(BaseModel):
    shipment_id: str
    order_id: str
    user_id: str
    status: str
    carrier_code: str
    method_code: str
    ship_method_id: Optional[str] = None
    tracking_number: Optional[str] = None
    tracking_url: Optional[str] = None
    ship_to_address: Dict[str, Any]
    ship_group_seq: int = 1
    estimated_delivery: Optional[str] = None
    shipped_at: Optional[int] = None
    delivered_at: Optional[int] = None
    created_at: int
    updated_at: int
    version: int = 1
    items: List[ShipmentItemOut] = Field(default_factory=list)
    packages: List[ShipmentPackageOut] = Field(default_factory=list)


class ShipmentTrackingUpdateIn(BaseModel):
    tracking_number: str = Field(min_length=1, max_length=100)
    carrier_code: Optional[str] = Field(default=None, pattern=r"^(ups|fedex|usps|dhl|manual)$")


class ShipmentAdvanceIn(BaseModel):
    target_status: str = Field(min_length=1, max_length=50)
    reason: Optional[str] = None


class ShipmentCancelIn(BaseModel):
    reason: str = Field(default="cancelled", min_length=1, max_length=500)
    refund_shipping: bool = False




# ---------------------------------------------------------------------------
# CUS-001: Customer entity models
# ---------------------------------------------------------------------------

class CustomerCreateIn(BaseModel):
    legal_name: str
    date_of_birth: Optional[str] = None
    mobile_phone: Optional[str] = None
    email: Optional[str] = None
    branch_id: Optional[str] = None


class CustomerPatchIn(BaseModel):
    legal_name: Optional[str] = None
    date_of_birth: Optional[str] = None
    mobile_phone: Optional[str] = None
    email: Optional[str] = None
    branch_id: Optional[str] = None
    kyc_status: Optional[str] = None
    expected_version: int


class CustomerOut(BaseModel):
    customer_id: str
    customer_number: str
    legal_name: str
    date_of_birth: Optional[str] = None
    mobile_phone: Optional[str] = None
    email: Optional[str] = None
    kyc_status: str
    branch_id: Optional[str] = None
    created_at: int
    updated_at: int
    version: int


class CustomerAttributeSetIn(BaseModel):
    name: str
    type: Literal["STRING", "INTEGER", "DOUBLE", "DATE_WITH_DAY"]
    value: str


class CustomerAttributeOut(BaseModel):
    attribute_id: str
    name: str
    type: str
    value: str
    created_at: int


class CustomerListOut(BaseModel):
    customers: List[CustomerOut]
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# CUS-002: User-link + customer message models
# ---------------------------------------------------------------------------

class CustomerLinkIn(BaseModel):
    user_sub: str


class CustomerLinkOut(BaseModel):
    customer_id: str
    user_sub: str
    linked_at: int
    linked_by: str


class CustomerMessageCreateIn(BaseModel):
    body: str = Field(max_length=10_000)


class CustomerMessageOut(BaseModel):
    message_id: str
    author_sub: str
    author_role: Literal["STAFF", "CUSTOMER"]
    body: str
    created_at: int


class CustomerMessageListOut(BaseModel):
    messages: List[CustomerMessageOut]
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# CUS-003: Card resource models
# ---------------------------------------------------------------------------

class CardOut(BaseModel):
    card_id: str
    brand: Optional[str] = None
    last4: Optional[str] = None
    exp_month: Optional[int] = None
    exp_year: Optional[int] = None
    label: Optional[str] = None
    is_default: bool
    card_status: str
    card_version: int
    created_at: Optional[int] = None


class CardStatusUpdateIn(BaseModel):
    status: str
    expected_version: int


class CardAttributeSetIn(BaseModel):
    name: str
    type: Literal["STRING", "INTEGER", "DOUBLE", "DATE_WITH_DAY"]
    value: str


class CardAttributeOut(BaseModel):
    attribute_id: str
    name: str
    type: str
    value: str
    created_at: Optional[int] = None


class CardListOut(BaseModel):
    cards: List[CardOut]


# ---------------------------------------------------------------------------
# CUS-004: Financial Products + Collections models
# ---------------------------------------------------------------------------

class FinancialProductCreateIn(BaseModel):
    product_code: str = Field(pattern=r"^[a-zA-Z0-9_\-]{1,64}$")
    name: str
    parent_product_code: Optional[str] = None
    category: Optional[str] = None
    family: Optional[str] = None
    super_family: Optional[str] = None
    more_info_url: Optional[str] = None
    description: Optional[str] = None


class FinancialProductPatchIn(BaseModel):
    name: Optional[str] = None
    parent_product_code: Optional[str] = None
    category: Optional[str] = None
    family: Optional[str] = None
    super_family: Optional[str] = None
    more_info_url: Optional[str] = None
    description: Optional[str] = None
    expected_version: int


class FinancialProductOut(BaseModel):
    product_code: str
    name: str
    parent_product_code: Optional[str] = None
    category: Optional[str] = None
    family: Optional[str] = None
    super_family: Optional[str] = None
    more_info_url: Optional[str] = None
    description: Optional[str] = None
    created_at: int
    updated_at: int
    version: int


class FinancialProductListOut(BaseModel):
    items: List[FinancialProductOut]
    cursor: Optional[str] = None


class ProductAttributeSetIn(BaseModel):
    name: str
    type: Literal["STRING", "INTEGER", "DOUBLE", "DATE_WITH_DAY"]
    value: str = Field(max_length=2048)


class ProductAttributeOut(BaseModel):
    attribute_id: str
    name: str
    type: str
    value: str
    created_at: int


class ProductAttributeListOut(BaseModel):
    attributes: List[ProductAttributeOut]


class ProductCollectionUpsertIn(BaseModel):
    name: str
    product_codes: List[str]


class ProductCollectionOut(BaseModel):
    collection_code: str
    name: str
    product_codes: List[str]
    updated_at: int


class ProductCollectionListOut(BaseModel):
    items: List[ProductCollectionOut]
    cursor: Optional[str] = None


class ProductCollectionMemberIn(BaseModel):
    product_code: str




# ---------------------------------------------------------------------------
# PMD-001 — Rent-policy models
# ---------------------------------------------------------------------------

class RentPolicyUpdateIn(BaseModel):
    rent_due_day: int = Field(..., ge=1, le=28,
        description="Day of month rent is due (1-28; 29-31 excluded for Feb safety)")
    late_fee_cents: int = Field(..., ge=0,
        description="Flat late fee in cents applied after grace period")
    grace_period_days: int = Field(..., ge=0,
        description="Days after due_day before late fee applies")
    currency: str = Field(..., min_length=3, max_length=3,
        description="3-letter ISO 4217 currency code, case-insensitive")

    @field_validator("currency")
    @classmethod
    def _currency_alpha(cls, v: str) -> str:
        v = v.strip()
        if not v.isalpha():
            raise ValueError("currency must be 3 alphabetic characters")
        return v.lower()


class RentPolicyOut(BaseModel):
    rent_due_day: int
    late_fee_cents: int
    grace_period_days: int
    currency: str
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None
    is_default: bool


class RentPolicyAuditEntryOut(BaseModel):
    actor_sub: str
    before: Optional[Dict[str, Any]] = None
    after: Dict[str, Any]
    created_at: int


class RentPolicyAuditOut(BaseModel):
    entries: List[RentPolicyAuditEntryOut]
    count: int
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# PMD-002 — Property document link models
# ---------------------------------------------------------------------------

class PropertyDocumentLinkIn(BaseModel):
    record_type: str = Field(..., description="One of: property, unit, lease, tenant")
    record_id: str = Field(..., min_length=1, max_length=200)
    doc_id: str = Field(..., min_length=1, max_length=200)
    file_path: str = Field("", max_length=500)
    crm_category: str = Field("", max_length=200)
    crm_description: str = Field("", max_length=1000)


class PropertyDocumentUnlinkIn(BaseModel):
    record_type: str
    record_id: str
    doc_id: str


class PropertyDocumentLinkOut(BaseModel):
    doc_id: str
    record_type: str
    record_id: str
    file_path: str
    crm_category: str
    crm_description: str
    linked_at: Optional[int] = None
    owner_sub: str


class PropertyDocumentListOut(BaseModel):
    items: List[PropertyDocumentLinkOut]
    count: int
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# PMD-003 — Portfolio dashboard KPI models
# ---------------------------------------------------------------------------

class PortfolioKpisOut(BaseModel):
    occupancy_rate: float
    unit_count: int
    occupied_units: int
    active_lease_count: int
    outstanding_rent_cents: int
    open_work_order_count: int
    computed_at: int


class RentSnapshotOut(BaseModel):
    year: int
    month: int
    charged_cents: int
    collected_cents: int
    outstanding_cents: int
    overdue_cents: int
    rent_due_day: int
    grace_period_days: int
    computed_at: int


class PriorityItemOut(BaseModel):
    kind: str
    # Lease-expiring fields (Optional)
    lease_id: Optional[str] = None
    lease_number: Optional[str] = None
    unit_id: Optional[str] = None
    property_id: Optional[str] = None
    tenant_id: Optional[str] = None
    end_date: Optional[int] = None
    monthly_rent_cents: Optional[int] = None
    # Work-order / ticket fields (Optional)
    work_order_id: Optional[str] = None
    ticket_id: Optional[str] = None
    subject: Optional[str] = None
    title: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    updated_at: Optional[int] = None


class PriorityItemsOut(BaseModel):
    upcoming_expirations: List[PriorityItemOut]
    open_work_orders: List[PriorityItemOut]
    items: List[PriorityItemOut]
    count: int


class PortfolioSummaryData(BaseModel):
    """Dashlet payload for RPT-007 portfolio_summary dashlet."""
    occupancy_rate: float
    unit_count: int
    occupied_units: int
    active_lease_count: int
    outstanding_rent_cents: int
    open_work_order_count: int
    computed_at: int




# ---------------------------------------------------------------------------
# Hotel Guest Folio + Payments (HTL-029..HTL-032)
# ---------------------------------------------------------------------------


class FolioLineIn(BaseModel):
    line_type: Literal["room_night", "addon", "tax", "fee"]
    description: str
    quantity: int = Field(ge=1, default=1)
    unit_price_cents: int = Field(ge=0)
    sku: str = ""


class FolioLineOut(BaseModel):
    line_id: str
    line_type: Literal["room_night", "addon", "tax", "fee"]
    description: str
    quantity: int
    unit_price_cents: int
    amount_cents: int
    sku: str
    created_at: int


class FolioOut(BaseModel):
    reservation_id: str
    folio_id: str
    hotel_id: str
    guest_sub: str
    currency: str
    status: Literal["open", "closed"]
    charges_total_cents: int
    payments_total_cents: int
    deposit_held_cents: int = 0
    deposit_policy_kind: Literal["none", "pct", "fixed"] = "none"
    deposit_pct_bps: int = 0                  # set when deposit_policy_kind == "pct"
    deposit_fixed_cents: int = 0             # set when deposit_policy_kind == "fixed"
    balance_due_cents: int                   # computed: charges - payments
    balance_due_on_arrival_cents: int = 0    # HTL-031: charges - payments - deposit_held
    line_items: List[FolioLineOut]
    closed_at: Optional[int] = None
    created_at: int
    updated_at: int


class FolioAddonIn(BaseModel):
    sku: str
    quantity: int = Field(default=1, ge=1)


class DepositPolicyIn(BaseModel):
    kind: Literal["none", "pct", "fixed"] = "none"
    pct_bps: int = Field(ge=0, le=10_000, default=0)
    fixed_cents: int = Field(ge=0, default=0)


class TakeDepositIn(BaseModel):
    amount_cents: Optional[int] = Field(default=None, ge=1)


class FolioPaymentIn(BaseModel):
    amount_cents: int = Field(ge=1)
    method: Literal["wallet", "card_external", "cash", "check", "bank_transfer", "deposit_applied"]
    reference: str = ""




# ── Purchasing / SCM (PUR-001..PUR-012) ──────────────────────────────────────

class SupplierCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: str = "USD"
    payment_terms_days: int = Field(default=30, ge=0, le=365)


class SupplierPatchIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: Optional[str] = None
    payment_terms_days: Optional[int] = Field(default=None, ge=0, le=365)


class SupplierStatusIn(BaseModel):
    status: str  # "active" | "inactive"


class SupplierOut(BaseModel):
    supplier_id: str
    name: str
    status: str
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    default_currency: str
    payment_terms_days: int
    created_by: str
    created_at: int
    updated_at: int


class SupplierListOut(BaseModel):
    suppliers: List[SupplierOut]
    cursor: Optional[str] = None


class SupplierProductUpsertIn(BaseModel):
    unit_cost_cents: int = Field(ge=0, le=10_000_000_00)
    currency: str = "USD"
    lead_time_days: int = Field(default=0, ge=0, le=3650)
    min_order_qty: int = Field(default=1, ge=1, le=10_000_000)
    supplier_sku: Optional[str] = Field(default=None, max_length=256)
    preferred: bool = False


class SupplierProductOut(BaseModel):
    supplier_id: str
    sku: str
    supplier_sku: Optional[str] = None
    unit_cost_cents: int
    currency: str
    lead_time_days: int
    min_order_qty: int
    preferred: bool
    updated_at: int


class SupplierProductListOut(BaseModel):
    products: List[SupplierProductOut]


class PurchaseOrderLineIn(BaseModel):
    sku: str = Field(min_length=1, max_length=256)
    quantity_ordered: int = Field(ge=1, le=10_000_000)
    unit_cost_cents: Optional[int] = Field(default=None, ge=0)


class PurchaseOrderLineOut(BaseModel):
    line_no: int
    sku: str
    quantity_ordered: int
    quantity_received: int
    unit_cost_cents: int
    line_total_cents: int


class PurchaseOrderCreateIn(BaseModel):
    supplier_id: str
    lines: List[PurchaseOrderLineIn] = Field(min_length=1)
    currency: str = "USD"
    expected_delivery_date: Optional[str] = None
    correlation_id: Optional[str] = None


class PurchaseOrderOut(BaseModel):
    po_id: str
    supplier_id: str
    status: str
    currency: str
    subtotal_cents: int
    expected_delivery_date: Optional[str] = None
    created_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[int] = None
    rejected_by: Optional[str] = None
    rejected_reason: Optional[str] = None
    ledger_entry_sk: Optional[str] = None
    paid_at: Optional[int] = None
    correlation_id: str
    created_at: int
    updated_at: int
    lines: List[PurchaseOrderLineOut] = Field(default_factory=list)


class PurchaseOrderListOut(BaseModel):
    purchase_orders: List[PurchaseOrderOut]
    cursor: Optional[str] = None


class PoTransitionIn(BaseModel):
    reason: Optional[str] = None
    rejected_reason: Optional[str] = None


class PoReceiveLineIn(BaseModel):
    line_no: int = Field(ge=1)
    quantity: int = Field(ge=1, le=10_000_000)


class PoReceiveIn(BaseModel):
    lines: List[PoReceiveLineIn] = Field(min_length=1)
    receipt_correlation_id: Optional[str] = None


class PoReceiptOut(BaseModel):
    receipt_id: str
    po_id: str
    received_by: str
    lines: List[Dict[str, Any]]
    created_at: int


class PoReceiveOut(BaseModel):
    receipt: PoReceiptOut
    po: PurchaseOrderOut


class ReorderSuggestionOut(BaseModel):
    sku: str
    available: int
    reorder_point: int
    suggested_qty: int
    supplier_id: Optional[str] = None
    supplier_name: Optional[str] = None
    unit_cost_cents: Optional[int] = None
    lead_time_days: Optional[int] = None
    warning: Optional[str] = None


class ReorderSuggestionListOut(BaseModel):
    suggestions: List[ReorderSuggestionOut]
    no_supplier_skus: List[str] = Field(default_factory=list)


class ReorderCreatePoIn(BaseModel):
    skus: List[str] = Field(min_length=1)


class ApPayableOut(BaseModel):
    po_id: str
    entry_id: str
    amount_cents: int
    state: str
    ledger_date: str
    supplier_id: str
    ts: int


class PoSettlePaymentIn(BaseModel):
    payment_ref: str
    provider: str = "internal"




# ---------------------------------------------------------------------------
# CSN-001 / CSN-002: PSD2 AIS/PIS Consents
# ---------------------------------------------------------------------------

class ConsentCreateIn(BaseModel):
    consumer_ref: str = Field(..., max_length=256)
    consent_type: Literal["AIS", "PIS"] = "AIS"
    account_refs: List[str] = Field(default_factory=list)
    view_refs: List[str] = Field(default_factory=lambda: ["owner"])
    payment_ref: Optional[str] = None
    valid_until: Optional[int] = None
    recurring: bool = True
    reason: Optional[str] = Field(None, max_length=512)


class ConsentOut(BaseModel):
    consent_id: str
    owner_sub: str
    consumer_ref: str
    consent_type: str
    account_refs: List[str]
    view_refs: List[str]
    status: str
    valid_from: int
    valid_until: int
    sca_challenge_id: Optional[str]
    recurring: bool
    reason: Optional[str]
    created_at: int
    updated_at: int
    revoked_at: Optional[int]


class ConsentListOut(BaseModel):
    consents: List[ConsentOut]
    cursor: Optional[str]
    count: int


class ConsentScaOut(BaseModel):
    challenge_id: str
    required_factors: List[str]
    consent_id: str
    status: str


# ---------------------------------------------------------------------------
# CSN-003: Dynamic Entities
# ---------------------------------------------------------------------------

class DynamicEntityRegisterIn(BaseModel):
    entity_name: str
    json_schema: dict
    description: Optional[str] = None
    expected_version: Optional[int] = None


class DynamicEntityDefOut(BaseModel):
    entity_name: str
    json_schema: dict
    description: Optional[str]
    version: int
    created_by: str
    created_at: int
    updated_at: int


class DynamicEntityRowIn(BaseModel):
    data: dict


class DynamicEntityRowOut(BaseModel):
    entity_name: str
    row_id: str
    owner_sub: str
    data: dict
    created_at: int
    updated_at: int


class DynamicEntityListDefsOut(BaseModel):
    defs: List[DynamicEntityDefOut]
    cursor: Optional[str] = None


class DynamicEntityListRowsOut(BaseModel):
    rows: List[DynamicEntityRowOut]
    cursor: Optional[str] = None


# ---------------------------------------------------------------------------
# CSN-004: Dynamic Endpoints
# ---------------------------------------------------------------------------

class DynamicEndpointCreateIn(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE"]
    path: str
    connector_kind: Literal["static_response", "dynamic_entity_proxy"]
    connector_config: dict
    openapi_spec: Optional[dict] = None


class DynamicEndpointOut(BaseModel):
    endpoint_id: str
    method: str
    path: str
    connector_kind: str
    connector_config: dict
    openapi_spec: dict
    created_by: str
    created_at: int
    updated_at: int


class DynamicEndpointListOut(BaseModel):
    endpoints: List[DynamicEndpointOut]
    cursor: Optional[str] = None


class DynamicEndpointsOpenApiOut(BaseModel):
    paths: dict


# ---------------------------------------------------------------------------
# CSN-005: Open Data (Branches + ATMs)
# ---------------------------------------------------------------------------

class OpeningHours(BaseModel):
    day: Literal["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    opens: str
    closes: str

    @field_validator("opens", "closes")
    @classmethod
    def _validate_time(cls, v: str) -> str:
        if not re.match(r"^\d{2}:\d{2}$", v):
            raise ValueError("must be HH:MM format")
        return v

    @model_validator(mode="after")
    def _opens_before_closes(self) -> "OpeningHours":
        if self.opens >= self.closes:
            raise ValueError("opens must be before closes")
        return self


class OpenDataAddressIn(BaseModel):
    line1: str
    line2: Optional[str] = None
    city: str
    region: Optional[str] = None
    country: str
    postcode: str

    @field_validator("country")
    @classmethod
    def _validate_country(cls, v: str) -> str:
        if not re.match(r"^[A-Z]{2}$", v):
            raise ValueError("must be ISO 3166-1 alpha-2 (2 uppercase letters)")
        return v


class LocationIn(BaseModel):
    lat: float = Field(..., ge=-90, le=90)
    lng: float = Field(..., ge=-180, le=180)


class BranchIn(BaseModel):
    name: str
    address: OpenDataAddressIn
    location: LocationIn
    opening_hours: List[OpeningHours] = Field(default_factory=list)
    accessibility: List[str] = Field(default_factory=list)
    phone: Optional[str] = None
    is_active: bool = True


class BranchOut(BaseModel):
    branch_id: str
    name: str
    address: OpenDataAddressIn
    location: LocationIn
    opening_hours: List[OpeningHours]
    accessibility: List[str]
    phone: Optional[str]
    is_active: bool
    created_at: int
    updated_at: int


class AtmIn(BaseModel):
    name: str
    address: OpenDataAddressIn
    location: LocationIn
    is_active: bool = True
    has_deposit: bool = False
    is_accessible: bool = False


class AtmOut(BaseModel):
    atm_id: str
    name: str
    address: OpenDataAddressIn
    location: LocationIn
    is_active: bool
    has_deposit: bool
    is_accessible: bool
    created_at: int
    updated_at: int


class OpenDataListOut(BaseModel):
    items: List[Any]
    next_cursor: Optional[str]




# ── EVT-002: CRM Event invitee management ──────────────────────────────────

class CrmEventCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    calendar_event_id: Optional[str] = Field(default=None, max_length=200)
    max_attendance: Optional[int] = Field(default=None, ge=1)


class CrmEventOut(BaseModel):
    event_id: str
    owner_sub: str
    name: str
    description: str
    calendar_event_id: Optional[str]
    max_attendance: Optional[int]
    created_at: int
    updated_at: int


class CrmInviteeAddIn(BaseModel):
    invitee_sub: str = Field(min_length=1, max_length=128)


class CrmInviteeBulkImportIn(BaseModel):
    user_subs: List[str] = Field(min_length=1, max_length=500)

    @field_validator("user_subs")
    @classmethod
    def validate_subs(cls, v: List[str]) -> List[str]:
        for sub in v:
            if not sub or len(sub) > 128:
                raise ValueError("Each user_sub must be 1-128 characters")
        return v


class CrmInviteeOut(BaseModel):
    event_id: str
    invitee_sub: str
    invite_status: str
    invited_at: int
    responded_at: Optional[int]
    display_name: Optional[str]


class CrmInviteeListOut(BaseModel):
    invitees: List[CrmInviteeOut]
    cursor: Optional[str]


class CrmSendInvitationsOut(BaseModel):
    sent: int
    skipped: int
    failed: int


# ── EVT-003: CRM Event registration/RSVP ──────────────────────────────────

class CrmRegistrationOut(BaseModel):
    event_id: str
    registrant_sub: str
    status: str
    registered_at: int
    responded_at: Optional[int]
    checked_in_at: Optional[int]
    waitlist_position: Optional[int]
    invited: Optional[bool]


class CrmRegistrationListOut(BaseModel):
    registrations: List[CrmRegistrationOut]
    cursor: Optional[str]


class CrmRespondIn(BaseModel):
    new_status: str = Field(pattern="^(accepted|declined)$")


# ── EVT-004: CRM Event capacity / waitlist ────────────────────────────────

class CrmCapacityOut(BaseModel):
    event_id: str
    max_attendance: Optional[int]
    accepted_count: int
    waitlisted_count: int
    available_spots: Optional[int]


# ── EVT-008: Survey distribution ──────────────────────────────────────────

class DistributeSurveyReq(BaseModel):
    recipients: List[str] = Field(min_length=1, max_length=500)
    subject: str = Field(default="You've been invited to complete a survey", max_length=120)
    message: Optional[str] = Field(default=None, max_length=2000)
    contact_list_id: Optional[str] = Field(default=None, min_length=1, max_length=120)


class DistributeSurveyResp(BaseModel):
    sent: int
    skipped: int
    failed: int


class DistributionSummaryResp(BaseModel):
    total_sent: int
    total_responses: int
    response_rate: float


# ── EVT-014: CRM Contact SMS ──────────────────────────────────────────────

class CrmContactSmsSendIn(BaseModel):
    body: str = Field(min_length=1, max_length=1600)


class CrmContactSmsOut(BaseModel):
    sms_id: str
    contact_id: str
    contact_phone: str
    status: str
    message_id: str
    sent_at_ts: int


class CrmContactSmsLogListOut(BaseModel):
    items: List[CrmContactSmsOut]
    cursor: Optional[str]


# ── EVT-015: Audit Log Browse ─────────────────────────────────────────────

class AuditLogBrowseOut(BaseModel):
    items: List[dict]
    cursor: Optional[str]
    total_scanned: int
    category: str
    from_ts: int
    to_ts: int


class ApiKeyRateLimitOverrides(BaseModel):
    """PLT-001: Per-key rate-limit overrides (None = use account default)."""
    minute: Optional[int] = Field(None, ge=0)
    hour: Optional[int] = Field(None, ge=0)
    day: Optional[int] = Field(None, ge=0)
    week: Optional[int] = Field(None, ge=0)
    month: Optional[int] = Field(None, ge=0)


    rate_limit_overrides: Optional[ApiKeyRateLimitOverrides] = None  # PLT-001


# ---------------------------------------------------------------------------
# PLT-002: Metrics Leaderboard
# ---------------------------------------------------------------------------

class LeaderboardItem(BaseModel):
    rank: int
    id: str
    user_sub: str
    calls_total: int
    billable_calls_total: int
    request_units_total: int
    cost_subtotal_micros: int
    unit_price_micros: int = 0


class LeaderboardResponse(BaseModel):
    period_id: str
    dimension: Literal["consumers", "endpoints"]
    metric: Literal["calls_total", "cost_subtotal_micros", "request_units_total"]
    top_n: int
    scope: Literal["platform", "user"]
    items: List[LeaderboardItem]
    total_rows_scanned: int


# ---------------------------------------------------------------------------
# PLT-003: Glossary
# ---------------------------------------------------------------------------

class GlossaryTermOut(BaseModel):
    term_id: str
    term: str
    definition: str
    tags: List[str] = []
    created_at: int
    updated_at: int
    updated_by: str


class GlossaryListOut(BaseModel):
    terms: List[GlossaryTermOut]
    next_cursor: Optional[str] = None
    count: int


class GlossaryCreateIn(BaseModel):
    term: str = Field(..., min_length=1, max_length=200)
    definition: str = Field(..., min_length=1, max_length=4096)
    tags: Optional[List[str]] = None


class GlossaryPatchIn(BaseModel):
    term: Optional[str] = Field(default=None, min_length=1, max_length=200)
    definition: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    tags: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# PLT-004: Sandbox JSON import
# ---------------------------------------------------------------------------

class SandboxCustomerIn(BaseModel):
    user_sub: Optional[str] = None
    email: str
    full_name: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None


class SandboxAccountIn(BaseModel):
    user_sub: str
    initial_balance_cents: int = Field(default=0, ge=0)
    currency: str = "usd"


class SandboxTransactionIn(BaseModel):
    user_sub: str
    entry_type: Literal["credit", "debit", "adjustment"]
    amount_cents: int = Field(ge=0)
    state: str = "settled"
    reason: str
    currency: str = "usd"


class SandboxImportIn(BaseModel):
    customers: List[SandboxCustomerIn] = []
    accounts: List[SandboxAccountIn] = []
    transactions: List[SandboxTransactionIn] = []


class SandboxRowError(BaseModel):
    section: str
    index: int
    code: str
    message: str


class SandboxImportResult(BaseModel):
    customers_created: int
    accounts_created: int
    transactions_created: int
    errors: List[SandboxRowError]
    ok: bool


# ---------------------------------------------------------------------------
# PLT-005: Wallet threshold (account/ledger webhooks)
# ---------------------------------------------------------------------------

class SetWalletThresholdReq(BaseModel):
    threshold_cents: int = Field(ge=0, description="0 = disable threshold")


class WalletBalanceOut(BaseModel):
    wallet_balance_cents: int
    currency: str
    updated_at: int
    threshold_cents: Optional[int] = None
    threshold_active: Optional[bool] = None


# ---------------------------------------------------------------------------
# Hotel PMS — Cancellation + KPI Reports (HTL-033..HTL-036)
# ---------------------------------------------------------------------------


class CancellationPolicyIn(BaseModel):
    """Input for PUT /ui/hotels/{hotel_id}/cancellation-policy (HTL-034)."""
    free_until_days_before: int = Field(default=0, ge=0)
    penalty_pct: int = Field(default=0, ge=0, le=100)
    penalty_fixed_cents: int = Field(default=0, ge=0)
    no_show_fee_cents: int = Field(default=0, ge=0)


class CancellationPolicyOut(BaseModel):
    """Response for GET/PUT /ui/hotels/{hotel_id}/cancellation-policy (HTL-034)."""
    hotel_id: str
    policy_id: str
    scope: str = "default"
    free_until_days_before: int = 0
    penalty_pct: int = 0
    penalty_fixed_cents: int = 0
    no_show_fee_cents: int = 0
    created_at: int = 0
    updated_at: int = 0


class HotelKpisOut(BaseModel):
    """Response for GET /ui/hotels/{hotel_id}/reports/kpis (HTL-035)."""
    hotel_id: str
    from_ts: int
    to_ts: int
    rooms_available: int
    rooms_sold: int
    occupancy_pct: float
    room_revenue_cents: int
    adr_cents: int
    revpar_cents: int
    arrivals: int
    departures: int
    currency: str


# ---------------------------------------------------------------------------
# MFG-003: Manufacturing / MRP models (additive; visible when flag is off but
# no endpoint exposes them).
# ---------------------------------------------------------------------------

class BomComponentIn(BaseModel):
    """One component line in a new Bill of Materials."""
    component_sku: str = Field(..., min_length=1, max_length=256)
    quantity_per: float = Field(..., gt=0)
    scrap_pct: float = Field(default=0.0, ge=0.0, lt=1.0)
    unit_of_measure: str = Field(default="each", max_length=64)


class BomCreateIn(BaseModel):
    product_sku: str = Field(..., min_length=1, max_length=256)
    name: str = Field(..., min_length=1, max_length=256)
    output_quantity: int = Field(default=1, ge=1)
    components: List[BomComponentIn] = Field(default_factory=list)
    correlation_id: Optional[str] = None


class BomUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    status: Optional[str] = None


class BomComponentOut(BaseModel):
    component_sku: str
    quantity_per: float
    scrap_pct: float
    unit_of_measure: str
    seq: int


class BomOut(BaseModel):
    bom_id: str
    product_sku: str
    name: str
    output_quantity: int
    status: str
    created_at: int
    updated_at: int
    created_by: str
    components: List[BomComponentOut] = Field(default_factory=list)


class ExplodedComponentOut(BaseModel):
    component_sku: str
    required_qty: float
    depth: int


class BomExplosionOut(BaseModel):
    bom_id: str
    build_qty: int
    components: List[ExplodedComponentOut]


# Work-center models

class WorkCenterCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    capacity_per_hour: int = Field(default=0, ge=0)
    cost_per_hour_cents: int = Field(default=0, ge=0)
    correlation_id: Optional[str] = None


class WorkCenterUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    capacity_per_hour: Optional[int] = Field(default=None, ge=0)
    cost_per_hour_cents: Optional[int] = Field(default=None, ge=0)
    status: Optional[str] = None


class WorkCenterOut(BaseModel):
    work_center_id: str
    name: str
    capacity_per_hour: int
    cost_per_hour_cents: int
    status: str
    created_at: int
    updated_at: int


# Routing-task models (MFG-005) — per-BOM ordered operations

class RoutingTaskIn(BaseModel):
    work_center_id: str = Field(..., min_length=1, max_length=256)
    sequence: int = Field(..., ge=0, le=999)
    setup_minutes: int = Field(default=0, ge=0, le=100_000)
    run_minutes_per_unit: int = Field(default=0, ge=0, le=100_000)
    description: str = Field(default="", max_length=512)


class RoutingTaskOut(BaseModel):
    bom_id: str
    sequence: int
    work_center_id: str
    description: str
    setup_minutes: int
    run_minutes_per_unit: int
    created_at: int = 0
    updated_at: int = 0


class RoutingCostTaskOut(BaseModel):
    sequence: int
    work_center_id: str
    task_minutes: int
    cost_per_hour_cents: int
    task_cost_cents: int


class RoutingCostOut(BaseModel):
    bom_id: str
    quantity: int
    total_setup_minutes: int
    total_run_minutes: int
    total_minutes: int
    total_labor_cost_cents: int
    tasks: List[RoutingCostTaskOut] = Field(default_factory=list)


# Work-order models

class WorkOrderCreateIn(BaseModel):
    product_sku: str = Field(..., min_length=1, max_length=256)
    quantity: int = Field(..., ge=1)
    bom_id: Optional[str] = None
    work_center_id: Optional[str] = None
    correlation_id: Optional[str] = None
    # MFG-013: optional catalog link for finished-goods stock mirror
    catalog_category_id: Optional[str] = Field(default=None, max_length=256)
    catalog_item_id: Optional[str] = Field(default=None, max_length=256)


class IssueRowOut(BaseModel):
    component_sku: str
    required_quantity: float
    issued_quantity: float
    location_id: str
    issued_at: int


class WorkOrderOut(BaseModel):
    work_order_id: str
    product_sku: str
    quantity: int
    produced_qty: int
    bom_id: str
    work_center_id: str
    status: str
    correlation_id: str
    issues_guard: str
    produce_guard: str
    created_at: int
    updated_at: int
    user_sub: str
    issues: List[IssueRowOut] = Field(default_factory=list)
    # MFG-013: catalog link (empty string when not catalog-linked)
    catalog_category_id: str = ""
    catalog_item_id: str = ""


class WorkOrderCompleteIn(BaseModel):
    produced_qty: Optional[int] = Field(default=None, ge=1)
    location_id: str = Field(default="warehouse")


class WorkOrderCatalogStockOut(BaseModel):
    work_order_id: str
    product_sku: str
    inventory_available: Optional[int] = None
    inventory_on_hand: Optional[int] = None
    catalog_stock_count: Optional[int] = None
    in_sync: Optional[bool] = None


class WorkOrderCancelIn(BaseModel):
    reason: Optional[str] = None


# MRP models

class MrpRunIn(BaseModel):
    horizon_days: Optional[int] = Field(default=None, ge=1, le=365)
    location_id: str = Field(default="warehouse")
    correlation_id: Optional[str] = None


class MrpRequirementOut(BaseModel):
    sku: str
    gross_requirement: int
    on_hand_available: int
    scheduled_receipts: int
    net_requirement: int
    suggested_action: str
    suggested_quantity: int
    depth: int = 0
    bom_id: str = ""


class MrpRunOut(BaseModel):
    mrp_run_id: str
    status: str
    horizon_days: int
    location_id: str
    created_at: int
    completed_at: int
    requirement_count: int
    user_sub: str
    requirements: List[MrpRequirementOut] = Field(default_factory=list)


# ── Human Resources (HRM-003) — Phase M OFBiz HR models ──────────────────────


class Position(BaseModel):
    position_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1, max_length=200)
    department: Optional[str] = Field(default=None, max_length=100)
    status: Literal["OPEN", "FILLED", "CLOSED"]
    created_at: int
    updated_at: int


PositionOut = Position


class CreatePositionIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    department: Optional[str] = Field(default=None, max_length=100)
    correlation_id: Optional[str] = Field(default=None, max_length=64)


class UpdatePositionStatusIn(BaseModel):
    status: Literal["OPEN", "FILLED", "CLOSED"]


class Employment(BaseModel):
    employment_id: str = Field(..., min_length=1)
    party_id: str = Field(..., min_length=1)
    position_id: str = Field(..., min_length=1)
    org_party_id: str = Field(..., min_length=1)
    status: Literal["ACTIVE", "TERMINATED", "ON_LEAVE"]
    start_date: int
    end_date: Optional[int] = None
    pay_rate_cents: int = Field(..., ge=0)
    pay_period: Literal["MONTHLY", "BIWEEKLY", "WEEKLY", "HOURLY"]
    currency: str = Field(..., min_length=3, max_length=3)
    created_at: int
    updated_at: int


EmploymentOut = Employment


class CreateEmploymentIn(BaseModel):
    party_id: str = Field(..., min_length=1)
    position_id: str = Field(..., min_length=1)
    org_party_id: str = Field(..., min_length=1)
    start_date: int = Field(..., ge=0)
    end_date: Optional[int] = Field(default=None, ge=0)
    pay_rate_cents: int = Field(..., ge=0)
    pay_period: Literal["MONTHLY", "BIWEEKLY", "WEEKLY", "HOURLY"]
    currency: str = Field(..., min_length=3, max_length=3)
    correlation_id: Optional[str] = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _check_dates(self) -> "CreateEmploymentIn":
        if self.end_date is not None and self.end_date < self.start_date:
            raise ValueError("end_date must be >= start_date")
        return self


class TerminateEmploymentIn(BaseModel):
    end_date: int = Field(..., ge=0)
    note: Optional[str] = Field(default=None, max_length=500)


class PayrollLine(BaseModel):
    employment_id: str = Field(..., min_length=1)
    party_id: str = Field(..., min_length=1)
    gross_cents: int = Field(..., ge=0)
    currency: str = Field(..., min_length=3, max_length=3)


PayrollLineOut = PayrollLine


class PayrollRun(BaseModel):
    payroll_run_id: str = Field(..., min_length=1)
    period_start: int
    period_end: int
    status: Literal["DRAFT", "APPROVED", "POSTED"]
    lines: List[PayrollLine] = Field(default_factory=list)
    created_at: int
    updated_at: int
    approved_by: Optional[str] = None
    posted_at: Optional[int] = None


PayrollRunOut = PayrollRun


class CreatePayrollRunIn(BaseModel):
    period_start: int = Field(..., ge=0)
    period_end: int = Field(..., ge=0)
    currency: str = Field(default="usd", min_length=3, max_length=3)
    correlation_id: Optional[str] = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _check_period(self) -> "CreatePayrollRunIn":
        if self.period_end < self.period_start:
            raise ValueError("period_end must be >= period_start")
        return self


# ---------------------------------------------------------------------------
# OFBiz Fixed Assets — FXA-004 Pydantic models
# ---------------------------------------------------------------------------

class FixedAssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    asset_class: str = Field(min_length=1, max_length=50)
    acquisition_cost_cents: int = Field(gt=0)
    salvage_value_cents: int = Field(ge=0)
    useful_life_months: int = Field(ge=1, le=1200)
    acquired_at: int  # Unix timestamp
    depreciation_method: Literal["straight_line"] = "straight_line"
    correlation_id: Optional[str] = None
    gl_asset_account_id: Optional[str] = None
    gl_accum_depr_account_id: Optional[str] = None
    gl_depr_expense_account_id: Optional[str] = None
    gl_gain_account_id: Optional[str] = None
    gl_loss_account_id: Optional[str] = None

    @model_validator(mode="after")
    def salvage_below_cost(self) -> "FixedAssetIn":
        if self.salvage_value_cents >= self.acquisition_cost_cents:
            raise ValueError("salvage_value_cents must be less than acquisition_cost_cents")
        return self


class FixedAssetPatchIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    asset_class: Optional[str] = None
    gl_asset_account_id: Optional[str] = None
    gl_accum_depr_account_id: Optional[str] = None
    gl_depr_expense_account_id: Optional[str] = None
    gl_gain_account_id: Optional[str] = None
    gl_loss_account_id: Optional[str] = None


class FixedAssetOut(BaseModel):
    asset_id: str
    owner_sub: str
    name: str
    asset_class: str
    acquisition_cost_cents: int
    salvage_value_cents: int
    useful_life_months: int
    acquired_at: int
    depreciation_method: str
    status: str  # active / fully_depreciated / disposed
    accumulated_depreciation_cents: int
    net_book_value_cents: int  # computed: cost - accumulated, floor = salvage
    gl_asset_account_id: Optional[str]
    gl_accum_depr_account_id: Optional[str]
    gl_depr_expense_account_id: Optional[str]
    gl_gain_account_id: Optional[str]
    gl_loss_account_id: Optional[str]
    created_at: int
    updated_at: int
    correlation_id: Optional[str]


class FixedAssetDisposeIn(BaseModel):
    disposal_reason: Optional[str] = Field(default=None, max_length=500)
    proceeds_payment_intent_id: Optional[str] = None
    proceeds_amount_cents: Optional[int] = Field(default=None, ge=0)
    correlation_id: Optional[str] = None


class DepreciationPeriodOut(BaseModel):
    period: int
    period_start_ts: int
    period_end_ts: int
    amount_cents: int
    schedule_status: str  # scheduled / posted / cancelled
    journal_entry_id: Optional[str]
    posted_at: Optional[int]


class DepreciationScheduleOut(BaseModel):
    asset_id: str
    periods: List[DepreciationPeriodOut]
    total_periods: int
    posted_periods: int
    remaining_periods: int


class AssetMaintenanceOrderIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    assignee_sub: Optional[str] = None
    scheduled_for: Optional[int] = None  # Unix timestamp
    correlation_id: Optional[str] = None


class AssetMaintenanceOrderTransitionIn(BaseModel):
    target_status: Literal["in_progress", "completed", "cancelled"]
    cost_cents: Optional[int] = Field(default=None, ge=0)
    assignee_sub: Optional[str] = None


class AssetMaintenanceOrderOut(BaseModel):
    work_order_id: str
    asset_id: str
    title: str
    description: Optional[str]
    wo_status: str
    assignee_sub: Optional[str]
    cost_cents: Optional[int]
    scheduled_for: Optional[int]
    created_at: int
    completed_at: Optional[int]
    correlation_id: Optional[str]


# ── POS — Point of Sale (POS-001..POS-NNN) ───────────────────────────────────

class RegisterConfig(BaseModel):
    register_id: Optional[str] = None
    label: str = Field(min_length=1, max_length=128)
    location_id: str = Field(min_length=1, max_length=128)
    default_currency: str = Field(default="USD", min_length=3, max_length=3)
    created_at: int = 0
    updated_at: int = 0
    created_by: Optional[str] = None


class RegisterCreateIn(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    location_id: str = Field(min_length=1, max_length=128)
    default_currency: str = Field(default="USD", min_length=3, max_length=3)


class TenderKind(str, Enum):
    cash = "cash"
    card = "card"
    wallet = "wallet"


class TenderOut(BaseModel):
    kind: str                          # cash | card | wallet
    amount_cents: int = 0
    change_due_cents: int = 0          # only meaningful for kind=cash
    payment_method_id: Optional[str] = None  # card/wallet
    card_ref: Optional[str] = None     # opaque processor ref


class RegisterSessionOut(BaseModel):
    session_id: str
    register_id: str
    cashier_sub: str
    status: str                        # open | closed
    opening_float_cents: int = 0
    closing_float_cents: Optional[int] = None
    expected_cash_cents: Optional[int] = None
    counted_cash_cents: Optional[int] = None
    over_short_cents: Optional[int] = None    # signed: positive = over
    opened_at: int = 0
    closed_at: Optional[int] = None


class PosTransactionOut(BaseModel):
    txn_id: str
    session_id: str
    cart_id: Optional[str] = None
    order_id: Optional[str] = None
    status: str                        # draft | tendered | voided | refunded
    subtotal_cents: int = 0
    discount_cents: int = 0
    tax_cents: int = 0
    total_cents: int = 0
    tenders: List[TenderOut] = Field(default_factory=list)
    receipt_id: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class OpenSessionIn(BaseModel):
    register_id: str = Field(min_length=1, max_length=128)
    opening_float_cents: int = Field(default=0, ge=0, le=100_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=256)


class CloseSessionIn(BaseModel):
    counted_cash_cents: int = Field(ge=0, le=100_000_000)


class TenderIn(BaseModel):
    kind: Literal["cash", "card", "wallet"]
    amount_cents: int = Field(ge=0, le=100_000_000)
    change_due_cents: int = Field(default=0, ge=0, le=100_000_000)
    payment_method_id: Optional[str] = Field(default=None, max_length=256)
    card_ref: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def card_wallet_needs_pm(self) -> "TenderIn":
        if self.kind in ("card", "wallet") and not self.payment_method_id:
            raise ValueError("'payment_method_id' is required for card/wallet tenders")
        return self


class TenderRequestIn(BaseModel):
    tenders: List[TenderIn] = Field(min_length=1)
    idempotency_key: str = Field(min_length=1, max_length=256)

    def total_tendered_cents(self) -> int:
        """Sum of all tender amounts minus change given back."""
        return sum(t.amount_cents - t.change_due_cents for t in self.tenders)

    def validates_against_total(self, transaction_total_cents: int) -> bool:
        """Returns True iff net tender covers (equals) the transaction total."""
        return self.total_tendered_cents() == transaction_total_cents


class RefundTxnIn(BaseModel):
    txn_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=500)


class AddLineItemIn(BaseModel):
    sku: Optional[str] = Field(default=None, min_length=1, max_length=128)
    category_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    item_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    quantity: int = Field(default=1, ge=1, le=1000)

    @model_validator(mode="after")
    def sku_or_item_id(self) -> "AddLineItemIn":
        has_sku = bool(self.sku)
        has_item = bool(self.item_id)
        if has_sku == has_item:  # both set or neither
            raise ValueError("Provide exactly one of 'sku' or 'item_id'")
        if has_item and not self.category_id:
            raise ValueError("'category_id' is required when 'item_id' is provided")
        return self


class PosAddLineItemIn(BaseModel):
    # Catalog path: provide item_id (category_id optional)
    item_id: Optional[str] = Field(default=None, max_length=128)
    category_id: Optional[str] = Field(default=None, max_length=128)
    # Raw-SKU path: provide sku + name + unit_price_cents
    sku: Optional[str] = Field(default=None, min_length=1, max_length=128)
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    unit_price_cents: Optional[conint(ge=0, le=100_000_000)] = None  # type: ignore[valid-type]
    quantity: conint(ge=1, le=1000) = 1  # type: ignore[valid-type]

    @model_validator(mode="after")
    def _either_catalog_or_sku(self) -> "PosAddLineItemIn":
        has_catalog = bool(self.item_id)
        has_sku = bool(self.sku)
        if has_catalog == has_sku:
            raise ValueError("Provide exactly one of item_id or sku")
        if has_sku and (self.name is None or self.unit_price_cents is None):
            raise ValueError("name and unit_price_cents required for raw-SKU add")
        return self


class PosSetLineQtyIn(BaseModel):
    quantity: conint(ge=0, le=1000) = 0  # type: ignore[valid-type]


class PosTxnDraftOut(BaseModel):
    txn_id: str
    session_id: str
    cashier_sub: str
    status: str        # "draft" before settlement; "tendered" / "voided" / "refunded" after
    cart_id: str
    subtotal_cents: int
    tax_cents: int = 0
    discount_cents: int = 0
    total_cents: int = 0
    created_at: int = 0
    updated_at: int = 0


class PosBindTxnIn(BaseModel):
    correlation_id: str = Field(min_length=1, max_length=256)


class PosCashTenderIn(BaseModel):
    amount_tendered_cents: int = Field(ge=0, le=100_000_000)
    idempotency_key: str = Field(min_length=1, max_length=256)


class PosCardTenderIn(BaseModel):
    # POS-007 — card tender. Charge routes through the shared billing layer.
    amount_tendered_cents: int = Field(ge=1, le=100_000_000)
    payment_method_id: str = Field(min_length=1, max_length=256)
    idempotency_key: str = Field(min_length=1, max_length=256)
    # Display-only card provenance (NO PAN). card_kind="visa", last4="4242".
    card_kind: Optional[str] = Field(default=None, max_length=64)
    last4: Optional[str] = Field(default=None, min_length=2, max_length=4)


class PosWalletTenderIn(BaseModel):
    # POS-007 — wallet tender. Debits the cashier-user's in-platform wallet.
    amount_tendered_cents: int = Field(ge=1, le=100_000_000)
    idempotency_key: str = Field(min_length=1, max_length=256)


class PosTxnVoidIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class PosSessionReportOut(BaseModel):
    session_id: str
    register_id: str
    cashier_sub: str
    status: str
    opening_float_cents: int
    closing_float_cents: Optional[int] = None
    expected_cash_cents: Optional[int] = None
    counted_cash_cents: Optional[int] = None
    over_short_cents: Optional[int] = None
    opened_at: int
    closed_at: Optional[int] = None
    transaction_count: int = 0
    total_sales_cents: int = 0
    total_cash_tendered_cents: int = 0
    total_change_given_cents: int = 0


# ── POS-010: X/Z till-summary report models ──────────────────────────────────


class TenderBreakdownItem(BaseModel):
    kind: str                       # "cash" | "card" | "wallet"
    gross_cents: int = 0
    refund_cents: int = 0
    net_cents: int = 0              # gross_cents - refund_cents
    transaction_count: int = 0


class SessionReportCashSection(BaseModel):
    opening_float_cents: int = 0
    cash_in_cents: int = 0
    change_out_cents: int = 0
    expected_cash_cents: int = 0
    counted_cash_cents: Optional[int] = None   # null for X report
    over_short_cents: Optional[int] = None     # null for X report


class SessionReportOut(BaseModel):
    report_kind: str                # "x" or "z"
    session_id: str
    register_id: str
    cashier_sub: str
    opened_at: int = 0
    closed_at: Optional[int] = None
    generated_at: int = 0
    z_report_printed_at: Optional[int] = None   # null for X; null if Z not finalized

    gross_sales_cents: int = 0
    discount_cents: int = 0
    tax_cents: int = 0
    net_sales_cents: int = 0        # gross - discount (before tax)
    refund_total_cents: int = 0
    void_count: int = 0
    transaction_count: int = 0      # count of settled transactions

    tender_breakdown: List[TenderBreakdownItem] = Field(default_factory=list)
    cash: SessionReportCashSection


# ── ECM-003: Store integration Pydantic models ──────────────────────────────


class StorefrontAvailabilityOut(BaseModel):
    """Reservation-adjusted availability projection for one SKU/location pair.

    - available: on_hand − reserved (may be negative if oversold)
    - low_stock: True when available > 0 AND available <= reorder_point
    - stock_status: mirrors existing catalog vocabulary (in_stock|low_stock|out_of_stock)
    """
    available: int
    on_hand: int
    reserved: int
    low_stock: bool
    stock_status: str


class StorefrontVariantOut(BaseModel):
    """A single product variant (SKU, option selections, per-variant effective price)."""
    variant_id: str
    sku: str
    option_selections: Dict[str, Any]
    price_cents: int = Field(ge=0)
    availability: Optional[StorefrontAvailabilityOut] = None


class AppliedPricingRuleLineOut(BaseModel):
    """One rule line from the pricing-rules engine applied to this cart."""
    rule_id: str
    rule_name: str
    discount_type: str
    discount_cents: int = Field(ge=0)
    applies_to_skus: List[str] = Field(default_factory=list)


class CartPricingBreakdownOut(BaseModel):
    """Itemised pricing breakdown for a cart."""
    cart_id: str
    subtotal_cents: int
    applied_rules: List[AppliedPricingRuleLineOut] = Field(default_factory=list)
    discount_cents: int = Field(default=0, ge=0)
    final_total_cents: int
    currency: str = "USD"

    @model_validator(mode="after")
    def _check_invariant(self) -> "CartPricingBreakdownOut":
        expected = self.subtotal_cents - self.discount_cents
        if expected < 0:
            # Clamp: over-discount reduces final to 0
            object.__setattr__(self, "discount_cents", self.subtotal_cents)
            object.__setattr__(self, "final_total_cents", 0)
        elif self.final_total_cents != expected:
            raise ValueError(
                f"final_total_cents ({self.final_total_cents}) must equal "
                f"subtotal_cents ({self.subtotal_cents}) - discount_cents ({self.discount_cents})"
            )
        return self


class ShipGroupFulfillmentOut(BaseModel):
    """Fulfillment status for one ship group within an order."""
    ship_group_id: str
    status: str
    items: List[str] = Field(default_factory=list)
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    shipped_at: Optional[int] = None
    estimated_delivery: Optional[str] = None


class OrderFulfillmentStatusOut(BaseModel):
    """Post-purchase order state: lifecycle phase, ship groups, and tracking numbers."""
    order_id: str
    lifecycle_status: Optional[str] = None
    fulfillment_status: Optional[str] = None
    ship_groups: List[ShipGroupFulfillmentOut] = Field(default_factory=list)
    tracking_numbers: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Marketing Campaigns module (MKT-003)
# ---------------------------------------------------------------------------

VALID_SEGMENT_ATTRIBUTES: frozenset = frozenset({
    "subscription_tier", "total_spend_cents", "profile_country", "profile_city",
    "display_name", "first_name", "last_name", "gender", "location", "locale",
    "birthday", "has_active_subscription", "subscription_status",
    "order_count", "total_paid_cents", "last_order_at",
})

VALID_SEGMENT_OPERATORS: frozenset = frozenset({
    "eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in",
})


class SegmentPredicate(BaseModel):
    attribute: str
    operator: str
    value: Any

    @field_validator("attribute")
    @classmethod
    def _validate_attribute(cls, v: str) -> str:
        if v not in VALID_SEGMENT_ATTRIBUTES:
            raise ValueError(f"Unknown segment attribute: {v!r}. Must be one of {sorted(VALID_SEGMENT_ATTRIBUTES)}")
        return v

    @field_validator("operator")
    @classmethod
    def _validate_operator(cls, v: str) -> str:
        if v not in VALID_SEGMENT_OPERATORS:
            raise ValueError(f"Unknown segment operator: {v!r}. Must be one of {sorted(VALID_SEGMENT_OPERATORS)}")
        return v


class MarketingCampaignCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., pattern=r"^(awareness|traffic|conversions|retention)$")
    budget_cents: int = Field(..., ge=0)
    ad_campaign_id: Optional[str] = None
    promo_code_ids: List[str] = []
    contact_list_ids: List[str] = []
    segment_ids: List[str] = []
    tracking_code: Optional[str] = None
    start_date: Optional[int] = None
    end_date: Optional[int] = None


class MarketingCampaignUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    objective: Optional[str] = Field(default=None, pattern=r"^(awareness|traffic|conversions|retention)$")
    budget_cents: Optional[int] = Field(default=None, ge=0)
    status: Optional[str] = None
    ad_campaign_id: Optional[str] = None
    promo_code_ids: Optional[List[str]] = None
    contact_list_ids: Optional[List[str]] = None
    segment_ids: Optional[List[str]] = None
    tracking_code: Optional[str] = None
    start_date: Optional[int] = None
    end_date: Optional[int] = None


class MarketingCampaignOut(BaseModel):
    campaign_id: str
    owner_id: str
    name: str
    objective: str
    status: str
    budget_cents: int = 0
    ad_campaign_id: Optional[str] = None
    ad_account_id: Optional[str] = None
    promo_code_ids: List[str] = []
    contact_list_ids: List[str] = []
    segment_ids: List[str] = []
    tracking_code: Optional[str] = None
    start_date: Optional[int] = None
    end_date: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0


class CampaignTransitionIn(BaseModel):
    target_status: str


class ContactListCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None


class ContactListUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None


class ContactListOut(BaseModel):
    list_id: str
    owner_id: str
    name: str
    description: Optional[str] = None
    member_count: int = 0
    created_at: int = 0
    updated_at: int = 0


class ContactListMemberIn(BaseModel):
    party_id: str


class ContactListMemberOut(BaseModel):
    list_id: str
    party_id: str
    joined_at: int = 0
    suppressed: bool = False
    display_name: Optional[str] = None


class PartySegmentCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    predicates: List[SegmentPredicate] = Field(..., min_length=1)
    candidate_source: Optional[str] = None


class PartySegmentUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    predicates: Optional[List[SegmentPredicate]] = None
    candidate_source: Optional[str] = None


class PartySegmentOut(BaseModel):
    segment_id: str
    owner_id: str
    name: str
    description: Optional[str] = None
    predicates: List[SegmentPredicate] = []
    candidate_source: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class SegmentMemberOut(BaseModel):
    segment_id: str
    party_id: str
    snap_id: str = ""
    snap_ts: int = 0
    opted_out: bool = False
    snapped_at: int = 0


class TrackingCodeCreateIn(BaseModel):
    code_slug: str = Field(..., pattern=r"^[A-Za-z0-9_-]{3,50}$")
    campaign_id: str


class TrackingCodeOut(BaseModel):
    code_slug: str
    campaign_id: str
    owner_id: str
    visit_count: int = 0
    order_count: int = 0
    created_at: int = 0


class CampaignAttributionOut(BaseModel):
    campaign_id: str
    ad_spend_cents: int = 0
    promo_discount_cents: int = 0
    promo_redemptions: int = 0
    tracking_visits: int = 0
    tracking_orders: int = 0
    as_of: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# OBP PAY cluster — Counterparties, Standing Orders, Direct-Debit Mandates, FX
# (PAY-001..PAY-004). Additive, flag-gated default-OFF. Money-out is NEVER done
# here — standing orders / mandates emit COUNTERPARTY Transaction Requests (TXR).
# ─────────────────────────────────────────────────────────────────────────────


class CounterpartyRouting(BaseModel):
    scheme: Literal["IBAN", "ACCOUNT_SORT_CODE", "ACCOUNT_NUMBER", "BANK"]
    iban: Optional[str] = None
    account_number: Optional[str] = None
    sort_code: Optional[str] = None
    bank_code: Optional[str] = None
    bank_name: Optional[str] = None
    account_holder: Optional[str] = None
    currency: str = "usd"


class CounterpartyCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_beneficiary: bool = True
    routing: CounterpartyRouting
    description: Optional[str] = None
    bespoke: Optional[Dict[str, Any]] = None


class CounterpartyUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    is_beneficiary: Optional[bool] = None
    description: Optional[str] = None
    bespoke: Optional[Dict[str, Any]] = None


class CounterpartyRoutingOut(BaseModel):
    scheme: str
    iban_last4: Optional[str] = None
    account_number_last4: Optional[str] = None
    sort_code: Optional[str] = None
    bank_code: Optional[str] = None
    bank_name: Optional[str] = None
    account_holder: Optional[str] = None
    currency: str = "usd"


class CounterpartyOut(BaseModel):
    counterparty_id: str
    name: str
    is_beneficiary: bool
    routing: CounterpartyRoutingOut
    description: Optional[str] = None
    bespoke: Optional[Dict[str, Any]] = None
    created_at: int
    updated_at: int


class StandingOrderCreateIn(BaseModel):
    counterparty_id: str
    amount_cents: int = Field(gt=0)
    currency: str = "usd"
    cadence: Literal["weekly", "biweekly", "monthly"]
    start_at: int
    end_at: Optional[int] = None
    reason: Optional[str] = None


class StandingOrderUpdateIn(BaseModel):
    amount_cents: Optional[int] = Field(default=None, gt=0)
    cadence: Optional[Literal["weekly", "biweekly", "monthly"]] = None
    end_at: Optional[int] = None
    paused: Optional[bool] = None


class StandingOrderOut(BaseModel):
    standing_order_id: str
    counterparty_id: str
    amount_cents: int
    currency: str
    cadence: str
    status: str
    next_run_at: Optional[int] = None
    last_run_at: Optional[int] = None
    runs_count: int
    created_at: int
    updated_at: int


class MandateCreateIn(BaseModel):
    counterparty_id: str
    max_amount_cents: int = Field(gt=0)
    currency: str = "usd"
    cadence: Literal["weekly", "monthly"]
    start_at: int
    end_at: Optional[int] = None
    reference: Optional[str] = None


class MandateOut(BaseModel):
    mandate_id: str
    counterparty_id: str
    max_amount_cents: int
    currency: str
    cadence: str
    status: str
    next_run_at: Optional[int] = None
    last_run_at: Optional[int] = None
    pulled_this_window_cents: int
    runs_count: int
    created_at: int
    updated_at: int


class FxRateSetIn(BaseModel):
    source_currency: str = Field(min_length=2, max_length=8)
    target_currency: str = Field(min_length=2, max_length=8)
    rate: float = Field(gt=0)
    source: Literal["admin", "fetched"] = "admin"


class FxRateOut(BaseModel):
    pair: str
    source_currency: str
    target_currency: str
    rate: float
    source: str
    as_of: int
    set_by: str


class FxConvertOut(BaseModel):
    source_currency: str
    target_currency: str
    source_amount_cents: int
    target_amount_cents: int
    rate: float
    as_of: int


# ---------------------------------------------------------------------------
# EVT-005: CRM Geocoding models
# ---------------------------------------------------------------------------

class GeocodedAddressOut(BaseModel):
    """A single geocoded address item (EVT-005)."""
    address_id: str
    lat: float
    lng: float
    geocoded_at: int
    line1: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None


class GeocodedAddressListOut(BaseModel):
    """List of geocoded addresses with count (EVT-005)."""
    addresses: List[GeocodedAddressOut]
    count: int


# ---------------------------------------------------------------------------
# EVT-006: CRM Proximity Search models
# ---------------------------------------------------------------------------

class ProximityResultItem(BaseModel):
    """A single result item from the proximity search (EVT-006)."""
    entity_type: str
    entity_id: str
    name: str
    lat: float
    lng: float
    distance_km: float
    address_id: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None


class ProximitySearchOut(BaseModel):
    """Proximity search response envelope (EVT-006)."""
    results: List[ProximityResultItem]
    count: int
    center_lat: float
    center_lng: float
    radius_km: float
    entity_type: str


# ---------------------------------------------------------------------------
# EVT-007: CRM Map Feature Flags model
# ---------------------------------------------------------------------------

class CrmMapFeatureFlagsOut(BaseModel):
    """Feature flags and map defaults served to the frontend (EVT-007)."""
    crm_geocoding_enabled: bool
    default_lat: float
    default_lng: float
    default_radius_km: float
    max_radius_km: float
    max_pins: int


# ---------------------------------------------------------------------------
# ATI (OpenCATS ATS Integration) — cross-link bridge models (ATI-owned).
# Additive, append-only. These describe the ATI-owned link rows that bridge
# the ATS pipeline (candidate / job_order) to the CRM (contact / opportunity).
# All ATI link rows live in T.ats_integration_links; the link records are
# opaque-id pointers only — no sibling schema is duplicated here.
# ---------------------------------------------------------------------------


class AtsCandidateContactLinkIn(BaseModel):
    candidate_id: str = Field(..., min_length=1, max_length=128)
    contact_id: Optional[str] = Field(default=None, max_length=128)


class AtsCandidateContactLinkOut(BaseModel):
    link_id: str
    link_type: Literal["candidate_contact"] = "candidate_contact"
    candidate_id: str
    contact_id: str
    owner_sub: str
    synced: bool = False
    degraded: bool = False
    degraded_reason: Optional[str] = None
    created_at: int
    updated_at: int


class AtsJobOpportunityLinkIn(BaseModel):
    job_order_id: str = Field(..., min_length=1, max_length=128)
    opportunity_id: Optional[str] = Field(default=None, max_length=128)


class AtsJobOpportunityLinkOut(BaseModel):
    link_id: str
    link_type: Literal["job_opportunity"] = "job_opportunity"
    job_order_id: str
    opportunity_id: str
    owner_sub: str
    synced: bool = False
    degraded: bool = False
    degraded_reason: Optional[str] = None
    created_at: int
    updated_at: int


class AtsIntegrationLinksOut(BaseModel):
    candidate_contact_links: List[AtsCandidateContactLinkOut] = Field(default_factory=list)
    job_opportunity_links: List[AtsJobOpportunityLinkOut] = Field(default_factory=list)
    count: int = 0


# ---------------------------------------------------------------------------
# CCT-001..CCT-006 — SuiteCRM Contacts Extra (party CRM extension)
# ---------------------------------------------------------------------------

class CctPartyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    MERGED = "MERGED"
    ARCHIVED = "ARCHIVED"


class CctPartyType(str, Enum):
    PERSON = "PERSON"
    PARTY_GROUP = "PARTY_GROUP"


class CctRelationshipType(str, Enum):
    EMPLOYMENT = "EMPLOYMENT"
    GROUP_MEMBER = "GROUP_MEMBER"
    CONTACT_REL = "CONTACT_REL"
    OWNER = "OWNER"
    PARENT_ORG = "PARENT_ORG"    # CCT-002: org hierarchy
    REPORTS_TO = "REPORTS_TO"    # CCT-003: manager chain


class CctPartyRoleOut(BaseModel):
    role_type: str
    org_party_id: Optional[str] = None
    granted_at: int


class CctRelationshipOut(BaseModel):
    rel_id: str
    from_party_id: str
    to_party_id: str
    relationship_type: str
    created_at: int
    meta: Optional[Dict[str, Any]] = None


class CctContactMechOut(BaseModel):
    mech_id: str
    mech_type: str   # EMAIL / PHONE / POSTAL
    value: str
    purpose: Optional[str] = None
    created_at: int


class CctPartyOut(BaseModel):
    party_id: str
    party_type: CctPartyType
    status: CctPartyStatus
    name: str
    display_name: Optional[str] = None
    owner_user_sub: str
    created_at: int
    updated_at: int
    merged_into_party_id: Optional[str] = None
    manager_party_id: Optional[str] = None        # CCT-003
    direct_report_count: int = 0                  # CCT-003


class CctOrgAccountOut(BaseModel):
    party_id: str
    name: str
    status: CctPartyStatus
    roles: List[CctPartyRoleOut] = Field(default_factory=list)
    member_count: int = 0
    created_at: int
    updated_at: int
    # CCT-001: business metadata fields
    industry: Optional[str] = None
    website: Optional[str] = None
    phone: Optional[str] = None
    employee_count: Optional[int] = None
    annual_revenue_cents: Optional[int] = None
    # CCT-002: hierarchy
    parent_org_party_id: Optional[str] = None
    child_org_count: int = 0


class CctCreatePartyIn(BaseModel):
    party_type: CctPartyType
    name: str
    display_name: Optional[str] = None
    correlation_id: Optional[str] = None  # idempotency


class CctCreateOrgAccountIn(BaseModel):
    name: str
    correlation_id: Optional[str] = None
    # CCT-001 optional business fields
    industry: Optional[str] = None
    website: Optional[str] = None
    phone: Optional[str] = None
    employee_count: Optional[int] = Field(default=None, ge=0)
    annual_revenue_cents: Optional[int] = Field(default=None, ge=0)


class CctOrgAccountUpdateIn(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    website: Optional[str] = None
    phone: Optional[str] = None
    employee_count: Optional[int] = Field(default=None, ge=0)
    annual_revenue_cents: Optional[int] = Field(default=None, ge=0)


class CctSetParentOrgIn(BaseModel):
    parent_org_party_id: str


class CctSetManagerIn(BaseModel):
    manager_party_id: str


class CctAddContactMechIn(BaseModel):
    mech_type: str    # EMAIL / PHONE / POSTAL
    value: str
    purpose: Optional[str] = None   # WORK / HOME / etc.
    postal_address: Optional[Dict[str, Any]] = None   # for POSTAL mechs


class CctDuplicateCandidateOut(BaseModel):
    party_a_id: str
    party_b_id: str
    score: float
    match_signals: List[str]


class CctDuplicateCandidateListOut(BaseModel):
    items: List[CctDuplicateCandidateOut]
    cursor: Optional[str] = None


class CctMergePartyIn(BaseModel):
    winner_party_id: str
    loser_party_id: str


class CctHierarchyOut(BaseModel):
    ancestors: List[CctRelationshipOut] = Field(default_factory=list)
    children: List[CctRelationshipOut] = Field(default_factory=list)


class CctReportsToOut(BaseModel):
    direction: str
    chain: List[CctRelationshipOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# CMP-001..CMP-008 — SuiteCRM Campaigns-Extra (campaign waves, templates, etc.)
# ---------------------------------------------------------------------------

CAMPAIGN_TYPES = {"email", "phone", "mail", "fax", "sms"}

# CMP-001: campaign type + channel support
class CrmCampaignCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: Optional[str] = Field(default=None, max_length=500)
    budget_cents: int = Field(default=0, ge=0)
    ad_campaign_id: Optional[str] = None
    promo_code_ids: List[str] = Field(default_factory=list)
    contact_list_ids: List[str] = Field(default_factory=list)
    segment_ids: List[str] = Field(default_factory=list)
    tracking_code: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    campaign_type: str = Field(default="email", pattern=r"^(email|phone|mail|fax|sms)$")
    email_template_id: Optional[str] = None
    questionnaire_id: Optional[str] = None
    variants: Optional[List[Dict[str, Any]]] = None

class CrmCampaignUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    objective: Optional[str] = Field(default=None, max_length=500)
    budget_cents: Optional[int] = Field(default=None, ge=0)
    contact_list_ids: Optional[List[str]] = None
    segment_ids: Optional[List[str]] = None
    tracking_code: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    campaign_type: Optional[str] = Field(default=None, pattern=r"^(email|phone|mail|fax|sms)$")
    email_template_id: Optional[str] = None
    questionnaire_id: Optional[str] = None
    variants: Optional[List[Dict[str, Any]]] = None

class CrmCampaignOut(BaseModel):
    campaign_id: str
    owner_id: str
    name: str
    status: str = "draft"
    objective: Optional[str] = None
    budget_cents: int = 0
    contact_list_ids: List[str] = Field(default_factory=list)
    segment_ids: List[str] = Field(default_factory=list)
    tracking_code: Optional[str] = None
    email_template_id: Optional[str] = None
    questionnaire_id: Optional[str] = None
    questionnaire_url: Optional[str] = None
    campaign_type: str = "email"
    variants: Optional[List[Dict[str, Any]]] = None
    created_at: int = 0
    updated_at: int = 0

class MarketingCampaignListOut(BaseModel):
    campaigns: List[CrmCampaignOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    count: int = 0

class MarketingCampaignSendIn(BaseModel):
    dry_run: bool = False
    snapshot_ts: Optional[int] = None

class MarketingCampaignSendOut(BaseModel):
    campaign_id: str
    total_resolved: int = 0
    total_sent: int = 0
    total_skipped: int = 0
    dry_run: bool = False
    send_id: Optional[str] = None

class MarketingCampaignAttributionOut(BaseModel):
    campaign_id: str
    total_sent: int = 0
    email_sent: int = 0
    open_count: int = 0
    open_rate: float = 0.0
    click_count: int = 0
    click_rate: float = 0.0

# CMP-002: HTML email templates
class MarketingEmailTemplateCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    subject_template: str = Field(..., min_length=1, max_length=500)
    body_html_template: str = Field(..., min_length=1, max_length=50000)

class MarketingEmailTemplateUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    subject_template: Optional[str] = Field(default=None, min_length=1, max_length=500)
    body_html_template: Optional[str] = Field(default=None, min_length=1, max_length=50000)
    status: Optional[str] = Field(default=None, pattern=r"^(draft|active)$")

class MarketingEmailTemplateOut(BaseModel):
    template_id: str
    owner_id: str
    name: str
    subject_template: str
    body_html_template: str
    variables: List[str] = Field(default_factory=list)
    status: str = "draft"
    created_at: int = 0
    updated_at: int = 0

class MarketingEmailTemplateListOut(BaseModel):
    templates: List[MarketingEmailTemplateOut] = Field(default_factory=list)
    cursor: Optional[str] = None
    count: int = 0

class MarketingEmailTemplatePreviewIn(BaseModel):
    sample_vars: Dict[str, str] = Field(default_factory=dict)

class MarketingEmailTemplatePreviewOut(BaseModel):
    subject: str
    body_html: str
    variables: List[str] = Field(default_factory=list)
    missing_vars: List[str] = Field(default_factory=list)

# CMP-006: web-to-lead capture
class WebLeadCaptureIn(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=1, max_length=200)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=200)
    message: Optional[str] = Field(default=None, max_length=2000)
    campaign_id: Optional[str] = None
    honeypot: Optional[str] = Field(default=None, description="Bot trap — must be empty")
    contact_list_id: Optional[str] = None

class WebLeadCaptureOut(BaseModel):
    capture_id: str
    ok: bool = True

class WebLeadListOut(BaseModel):
    leads: List[Dict[str, Any]] = Field(default_factory=list)
    cursor: Optional[str] = None
    count: int = 0

# CMP-004: unsubscribe
class MarketingUnsubscribeOut(BaseModel):
    ok: bool = True
    message: str = "You have been unsubscribed from marketing emails."

# CMP-007: A/B test results
class MarketingAbVariantStats(BaseModel):
    variant_id: str
    label: str = ""
    sent: int = 0
    opens: int = 0
    clicks: int = 0
    open_rate: float = 0.0
    click_rate: float = 0.0

class MarketingAbResultsOut(BaseModel):
    campaign_id: str
    variant_stats: List[MarketingAbVariantStats] = Field(default_factory=list)
    significance: Optional[Dict[str, Any]] = None

# CMP-008: merge-tag preview
class MarketingEmailPreviewIn(BaseModel):
    sample_party_id: Optional[str] = None
    sample_vars: Dict[str, str] = Field(default_factory=dict)

class MarketingEmailPreviewOut(BaseModel):
    subject: str
    body_text: str
    body_html: Optional[str] = None
    merge_vars_used: Dict[str, str] = Field(default_factory=dict)
    merge_vars_missing: List[str] = Field(default_factory=list)


# ===========================================================================
# Follow-up 1 — ORD: server-side order list (GET /ui/orders)
# ===========================================================================

class OrderListItem(BaseModel):
    """Compact order-header projection for the list view."""
    order_id: str
    user_id: str
    status: str  # legacy mirror (also the GSI_STATUS partition)
    lifecycle_status: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    source_system: str = ""
    correlation_id: str = ""
    amount_cents: int = Field(default=0, ge=0)
    currency: str = "USD"
    line_item_count: int = Field(default=0, ge=0)


class OrderListOut(BaseModel):
    orders: List[OrderListItem] = Field(default_factory=list)
    next_cursor: Optional[str] = None


# ===========================================================================
# Follow-up 2 — CRM events: list / get-single / update
# ===========================================================================

class CrmEventListOut(BaseModel):
    events: List["CrmEventOut"] = Field(default_factory=list)
    cursor: Optional[str] = None


class CrmEventUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    calendar_event_id: Optional[str] = Field(default=None, max_length=200)
    max_attendance: Optional[int] = Field(default=None, ge=1)


# ===========================================================================
# Follow-up 3 — PRD: product-bundle membership
# ===========================================================================

class BundleComponentIn(BaseModel):
    component_item_id: str = Field(min_length=1, max_length=128)
    quantity: int = Field(default=1, ge=1, le=100000)


class BundleComponentOut(BaseModel):
    parent_item_id: str
    component_item_id: str
    quantity: int = Field(default=1, ge=1)
    component_sku: Optional[str] = None
    component_name: Optional[str] = None
    component_price_cents: Optional[int] = None
    created_at: int = 0


class BundleComponentListOut(BaseModel):
    parent_item_id: str
    components: List[BundleComponentOut] = Field(default_factory=list)
    count: int = 0
