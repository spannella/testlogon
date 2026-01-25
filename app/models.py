from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, conint

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

class CreateApiKeyReq(BaseModel):
    label: Optional[str] = None

class RevokeApiKeyReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))

class ApiKeyIpRulesReq(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    key_id: str = Field(validation_alias=AliasChoices("key_id", "api_key_id"))
    allow_cidrs: List[str] = Field(default_factory=list)
    deny_cidrs: List[str] = Field(default_factory=list)

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

class AlertEmailBeginReq(BaseModel):
    email: str

class AlertEmailConfirmReq(BaseModel):
    challenge_id: str
    code: str


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


class CalendarCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    timezone: str = Field(default="UTC", max_length=64)


class CalendarOut(BaseModel):
    calendar_id: str
    name: str
    timezone: str
    owner_user_id: str
    created_at_utc: str


class EventCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    timezone: str | None = Field(default=None, max_length=64)
    start_utc: str | None = None
    end_utc: str | None = None
    all_day: bool = False
    all_day_date: str | None = None


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
    created_at_utc: str


class OpeningsOut(BaseModel):
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

class VerifyMicrodepositsReq(BaseModel):
    setup_intent_id: str
    amounts: Optional[List[int]] = None
    descriptor_code: Optional[str] = None

class AddChargeReq(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"


class AccountStatusReq(BaseModel):
    reason: Optional[str] = None
