from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator

EntitlementStatus = Literal["pending_payment", "active", "expired", "revoked", "consumed"]
ProductType = Literal["file_bundle", "api_package", "internal_api_package"]


class EntitlementModel(BaseModel):
    entitlement_id: str
    user_id: str
    sku: str
    product_type: ProductType
    status: EntitlementStatus
    scope: Dict[str, Any] = Field(default_factory=dict)
    starts_at: datetime
    ends_at: Optional[datetime] = None
    usage_limit: int = 0
    usage_consumed: int = 0
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None

    @field_validator("starts_at", "ends_at", "created_at", "updated_at", mode="before")
    @classmethod
    def _validate_utc_datetime(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


class EntitlementResponse(BaseModel):
    entitlement: EntitlementModel


class EntitlementTransitionRequest(BaseModel):
    status: EntitlementStatus
    reason: Optional[str] = None
