from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

import re
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


class AdAccountCreateIn(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    billing_email: str = Field(..., min_length=1, max_length=320)


class AdAccountReviewIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")
    notes: Optional[str] = None


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


class AdTrackEventOut(BaseModel):
    """Response from POST /ui/ads/track."""
    ok: bool
    event_id: str = ""
# ─── EC2 Instance Launcher (INFRA-003) ────────────────────────────────────────

class Ec2LaunchIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    instance_type: str = Field(..., min_length=1)
    ami_id: str = Field(..., min_length=1)
    ssh_key_id: Optional[str] = None
    auto_terminate_after: int = Field(default=7200, ge=600, le=86400)
    startup_script: str = Field(default="", max_length=16_384)
    template_id: Optional[str] = None


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
    vcpu: int
    memory_gb: float
    cost_cents_per_min: float


class Ec2InstanceTypeListOut(BaseModel):
    types: List[Ec2InstanceTypeInfo]


class Ec2AmiInfo(BaseModel):
    ami_id: str
    name: str
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
