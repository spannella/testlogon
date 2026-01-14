from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class UiSessionStartReq(BaseModel):
    # You can include client metadata; auth is handled separately.
    # For example: challenge_context could include risk signals.
    challenge_context: Dict[str, Any] = Field(default_factory=dict)

class UiSessionStartResp(BaseModel):
    status: str
    challenge_id: str
    required_factors: List[str]

class UiSessionFinalizeReq(BaseModel):
    challenge_id: str

class UiSessionFinalizeResp(BaseModel):
    status: str
    session_id: Optional[str] = None
    required_factors: List[str] = Field(default_factory=list)
    passed: Dict[str, bool] = Field(default_factory=dict)

class TotpVerifyReq(BaseModel):
    challenge_id: str
    code: str

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
    challenge_id: str
    code: str
    factor: str = "totp"  # totp|sms|email

class CreateApiKeyReq(BaseModel):
    label: str = ""
    ip_rules: List[str] = Field(default_factory=list)

class RevokeApiKeyReq(BaseModel):
    api_key_id: str

class ApiKeyIpRulesReq(BaseModel):
    api_key_id: str
    ip_rules: List[str] = Field(default_factory=list)

class RevokeSessionReq(BaseModel):
    session_id: str

class MarkReadReq(BaseModel):
    alert_ids: List[str] = Field(default_factory=list)

class AlertPrefsReq(BaseModel):
    event_types: List[str] = Field(default_factory=list)

class AlertContactBeginReq(BaseModel):
    email: Optional[str] = None
    phone_e164: Optional[str] = None

class AlertContactConfirmReq(BaseModel):
    token: str  # out-of-band confirmation token / code

class TotpDeviceBeginReq(BaseModel):
    label: Optional[str] = None

class TotpDeviceConfirmReq(BaseModel):
    device_id: str
    code: str

class SmsDeviceBeginReq(BaseModel):
    phone_e164: str
    label: Optional[str] = None

class SmsDeviceConfirmReq(BaseModel):
    sms_device_id: str

class SmsDeviceRemoveBeginReq(BaseModel):
    sms_device_id: str

class SmsDeviceRemoveConfirmReq(BaseModel):
    sms_device_id: str

class EmailDeviceBeginReq(BaseModel):
    email: str
    label: Optional[str] = None

class EmailDeviceConfirmReq(BaseModel):
    email_device_id: str

class EmailDeviceRemoveBeginReq(BaseModel):
    email_device_id: str

class EmailDeviceRemoveConfirmReq(BaseModel):
    email_device_id: str
