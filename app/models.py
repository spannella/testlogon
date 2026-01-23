from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

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


class MailingAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None


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

class VerifyMicrodepositsReq(BaseModel):
    setup_intent_id: str
    amounts: Optional[List[int]] = None
    descriptor_code: Optional[str] = None

class AddChargeReq(BaseModel):
    amount_cents: int = Field(ge=1)
    state: str = Field(pattern="^(pending|settled)$")
    reason: str = "usage"
