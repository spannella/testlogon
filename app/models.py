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

class RevokeApiKeyReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))

class ApiKeyIpRulesReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))
    allow_cidrs: List[str] = Field(default_factory=list)
    deny_cidrs: List[str] = Field(default_factory=list)

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


class PurchaseShippingIn(BaseModel):
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    shipped_at: Optional[int] = None
    delivered_at: Optional[int] = None
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


class CatalogItemPatchIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price_cents: Optional[int] = Field(default=None, ge=0, le=10_000_000_00)
    currency: Optional[str] = None
    image_urls: Optional[List[str]] = None
    attributes: Optional[Dict[str, Any]] = None


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


class CatalogItemListOut(CatalogPageOut):
    items: List[CatalogItemOut]


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


class ShoppingCartPurchaseOut(BaseModel):
    cart_id: str
    order_id: str
    purchased_at: str
    purchased_total_cents: int
    currency: str = "USD"
    buyer: Optional[ShoppingCartBuyer] = None
    purchase_txn_id: Optional[str] = None


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


class CalendarUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    timezone: str | None = Field(default=None, max_length=64)
    conflict_detection: bool | None = None
    working_hours: Dict[str, List[WorkingHoursWindow]] | None = None
    buffer_before_minutes: int | None = None
    buffer_after_minutes: int | None = None


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


class ProfilePatchReq(ProfileBase):
    pass


class ProfilePutReq(ProfileBase):
    pass


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
