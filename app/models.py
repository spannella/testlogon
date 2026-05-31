from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

import re
from enum import Enum
from datetime import datetime, timezone

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    conint,
    field_validator,
    model_validator,
)

from app.core.normalize import normalize_phone

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
    push_event_types: List[str] = Field(default_factory=list)

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
    reviewer: Optional[str] = None


class CatalogReviewOut(BaseModel):
    item_id: str
    review_id: str
    rating: int
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: str


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


class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None
    promo_code_id: Optional[str] = None


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
    freq: Literal["DAILY", "WEEKLY", "MONTHLY"]
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
    """Customer-initiated dispute (e.g. a chargeback claim) for a transaction."""
    transaction_entry_id: Optional[str] = Field(default=None, max_length=200)
    amount_cents: int = Field(ge=1)
    currency: str = "USD"
    reason: str = Field(min_length=10, max_length=2000)
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
    resolution: str = Field(pattern="^(won|lost|accepted)$")
    notes: Optional[str] = Field(default=None, max_length=2000)


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
        if v.startswith("javascript:") or v.startswith("data:"):
            raise ValueError("Invalid content URL scheme")
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


class PayoutStatsOut(BaseModel):
    total_requested: int = 0
    total_requested_amount_cents: int = 0
    total_approved: int = 0
    total_processing: int = 0


class PayoutRejectIn(BaseModel):
    reason: str = Field(default="", max_length=1000)


class PayoutMarkPaidIn(BaseModel):
    reference: str = Field(default="", max_length=500)


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
    checkout_type: Literal["subscription", "vod", "shop"]
    item_price_cents: int = 0
    creator_user_id: str


class PromoValidateOut(BaseModel):
    valid: bool
    code_id: Optional[str] = None
    discount_type: Optional[str] = None
    discount_cents: int = 0
    final_price_cents: int = 0
    free_trial_days: int = 0
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
    provider: str = Field(..., pattern=r"^(openai|anthropic|deepseek|gemini|custom)$")
    label: str = Field(..., min_length=1, max_length=200)
    api_key: str = Field(..., min_length=8, max_length=500)
    base_url: str = Field(default="", max_length=500)
    model_preference: str = Field(default="", max_length=200)
    rate_limit_rpm: int = Field(default=60, ge=1, le=10000)
    monthly_budget_cents: int = Field(default=0, ge=0)


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


class LlmProviderListOut(BaseModel):
    providers: List[LlmProviderInfo]
# --- Advertiser Accounts & Campaigns (ADS-001) ---

class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=5, max_length=254)


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
# ── Advertiser Accounts & Campaigns (ADS-001) ──────────────────────
# ── Ad Accounts & Campaigns (ADS-001) ─────────────────────────────────────


class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=1, max_length=320)


class AdAccountReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None
# -- Ad Accounts & Campaigns (ADS-001) --

class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=3, max_length=320)


class CampaignCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    objective: str = Field(..., pattern=r"^(awareness|traffic|conversions)$")
    budget_cents: int = Field(..., ge=100)  # Minimum $1
    budget_type: str = Field(..., pattern=r"^(daily|lifetime)$")
    start_date: Optional[int] = None  # Unix timestamp
    end_date: Optional[int] = None    # Unix timestamp


class CampaignUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    budget_cents: Optional[int] = Field(default=None, ge=100)
    budget_type: Optional[str] = Field(default=None, pattern=r"^(daily|lifetime)$")
    status: Optional[str] = Field(default=None, pattern=r"^(draft|active|paused|archived)$")
    start_date: Optional[int] = None
    end_date: Optional[int] = None


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


class CampaignReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject)$")
    notes: Optional[str] = Field(default=None, max_length=1000)
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

class CreativeCreateIn(BaseModel):
    format: str = Field(..., pattern=r"^(image|video|native_post)$")
    title: str = Field(..., min_length=1, max_length=200)
    headline: Optional[str] = Field(default=None, max_length=100)
    body_text: Optional[str] = Field(default=None, max_length=300)
    cta_text: Optional[str] = Field(default=None, max_length=25)
    cta_url: Optional[str] = Field(default=None, max_length=1024)
    alt_text: Optional[str] = Field(default=None, max_length=200)
    width: Optional[int] = Field(default=None, ge=100, le=4096)
    height: Optional[int] = Field(default=None, ge=100, le=4096)
    duration_seconds: Optional[int] = Field(default=None, ge=5, le=60)
    skip_after_seconds: Optional[int] = Field(default=5, ge=0, le=30)
    objective: str = Field(default="awareness")
    budget_cents: int = Field(..., ge=100)
    budget_type: str = Field(default="lifetime", pattern="^(lifetime|daily)$")
    budget_cents: int = Field(..., ge=100)
    budget_type: str = Field(..., pattern=r"^(daily|lifetime)$")
    objective: str = Field(default="awareness")
    budget_cents: int = Field(..., ge=100)
    budget_type: str = Field(default="lifetime")
    start_date: Optional[int] = None
    end_date: Optional[int] = None


class CampaignUpdateIn(BaseModel):
    name: Optional[str] = None
    objective: Optional[str] = None
    budget_cents: Optional[int] = None
    budget_type: Optional[str] = None
    status: Optional[str] = None
    bid_cpm_cents: Optional[int] = None


class CampaignReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None


# ── Ad Creatives (ADS-002) ──────────────────────────────────────────
# ── Ad Creatives (ADS-002) ─────────────────────────────────────────────


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

class CreativeUpdateIn(BaseModel):
    title: Optional[str] = None
    headline: Optional[str] = None
    body_text: Optional[str] = None
    cta_text: Optional[str] = None
    cta_url: Optional[str] = None
    rotation_weight: Optional[int] = None
    skip_after_seconds: Optional[int] = None


class CreativeReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None


# ── Ad Targeting (ADS-003) ──────────────────────────────────────────


class TargetingCreateIn(BaseModel):
    name: str = Field(default="Default targeting")
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


class CreatorAdSettingsIn(BaseModel):
    allow_ads: Optional[bool] = None
    allowed_ad_categories: Optional[List[str]] = None
    min_cpm_cents: Optional[int] = None


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
# ── Ad Targeting (ADS-003) ──────────────────────────────────────────────────
# ── Ad Serving (ADS-004) ─────────────────────────────────────────────


class AdServeRequestIn(BaseModel):
    surface: str = Field(..., pattern="^(newsfeed|broadcast|vod)$")
    content_type: str = Field(default="")
    creator_id: str = Field(..., min_length=1)
    content_id: str = Field(..., min_length=1)
    slot_type: str = Field(default="sponsored_post",
                           pattern="^(pre_roll|mid_roll|overlay|sponsored_post|broadcast_preroll|broadcast_midroll)$")
    user_context: Optional[Dict[str, Any]] = None


class AdTrackEventIn(BaseModel):
    event: str = Field(..., pattern="^(impression|click|skip|complete)$")
    creative_id: str = Field(..., min_length=1)
    campaign_id: str = Field(..., min_length=1)
    account_id: str = Field(..., min_length=1)
    surface: str = Field(..., min_length=1)
    slot_type: str = Field(..., min_length=1)
    content_id: str = Field(..., min_length=1)
    creator_id: str = Field(..., min_length=1)


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


class CreativeReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approve|reject)$")
    notes: Optional[str] = Field(default=None, max_length=1000)
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
    last_activity_at: int = 0
    auto_terminate_after: int = 7200


class Ec2InstanceListOut(BaseModel):
    instances: List[Ec2InstanceOut]
    count: int


class Ec2InstanceTypeInfo(BaseModel):
    instance_type: str
    vcpu: int = 0
    memory_gb: float = 0.0
    description: str = ""


# -- Agent Worker Provisioning (AGENT-002) --

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
    terminated_at: int = 0
    ttl_seconds: int
    expires_at: int
    last_activity_at: int = 0


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

class GroupMemberListOut(BaseModel):
    members: List[GroupMemberOut] = Field(default_factory=list)
    count: int = 0


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
class AdBlockIn(BaseModel):
    account_id: str
    reason: str = ""
    startup_seconds: int


class ComputeOptionListOut(BaseModel):
    options: List[ComputeOption]
    start_date: Optional[int] = None
    end_date: Optional[int] = None


# -- Ad Billing (ADS-007) --

class AdDepositIn(BaseModel):
    """Request body for POST /ui/ads/accounts/{id}/deposit."""
    amount_cents: int = Field(..., ge=5000, le=10000000,
                              description="Deposit amount in cents ($50 minimum, $100k maximum)")
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


class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=3, max_length=320)
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


class EligibleTicketOut(BaseModel):
    ticket_id: str
    subject: str = ""
    labels: List[str] = Field(default_factory=list)
    complexity: Optional[str] = None
    estimated_effort_hours: Optional[int] = None
    created_at: int = 0


class EligibleTicketsOutCoder(BaseModel):
    tickets: List[EligibleTicketOut] = Field(default_factory=list)
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


class ReportOut(BaseModel):
    report_id: str
    report_type: str = "daily"
    content: str = ""
    metrics_snapshot: Dict[str, Any] = Field(default_factory=dict)
    created_at: int = 0


class ReportListOut(BaseModel):
    reports: List[ReportOut] = Field(default_factory=list)
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


class CapacityOut(BaseModel):
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


class ComplianceStatusOut(BaseModel):
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
# FIN-001: Invoice / Receipt PDF models
# ---------------------------------------------------------------------------

class InvoiceLineItemOut(BaseModel):
    description: str
    quantity: int = 1
    amount_cents: int


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
