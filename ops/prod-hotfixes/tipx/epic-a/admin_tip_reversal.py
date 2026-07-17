"""Admin tip reversal router (TIPX-A2).

Makes the (previously unreachable) tip reversal/refund engine reachable:

    POST /v1/admin/tips/{tip_payment_id}/reverse

Admin/root only. Idempotent -- reversing an already-reversed tip returns the
stored reversal receipt (no double clawback / double refund). The reversal writes
ledger entries with type != "credit" so earnings are never inflated, flips the
original credit to state="reversed" (dropping it from earnings + the reversed-
excluded leaderboard), and best-effort refunds the processor charge.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/tips", tags=["admin-tips"])


class TipReverseIn(BaseModel):
    # The ledger is partitioned by user, so the tipper is required to locate the
    # tip cheaply. The recipient is derived from the debit row when omitted.
    tipper_id: str = Field(..., min_length=1, max_length=200)
    recipient_id: Optional[str] = Field(default=None, max_length=200)
    reason: str = Field(default="admin_reversal", max_length=200)


class TipReverseOut(BaseModel):
    ok: bool
    tip_payment_id: str
    refunded_cents: int
    clawback_cents: int
    reversal_entry_id: str
    refund_entry_id: str
    idempotent_replay: bool


@router.post("/{tip_payment_id}/reverse", response_model=TipReverseOut)
def reverse_tip_admin(
    tip_payment_id: str,
    body: TipReverseIn,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Reverse (refund) a tip by its ``tip_payment_id``. Admin/root only."""
    from app.services.tips import reverse_tip_by_payment_id

    try:
        result = reverse_tip_by_payment_id(
            tip_payment_id=tip_payment_id,
            tipper_id=body.tipper_id,
            recipient_id=body.recipient_id,
            reason=body.reason,
            actor=admin.sub,
        )
    except HTTPException:
        raise
    except Exception:
        logger.warning("admin tip reversal failed for %s", tip_payment_id, exc_info=True)
        raise HTTPException(500, {"code": "reversal_failed", "message": "Tip reversal failed."})

    return TipReverseOut(
        ok=True,
        tip_payment_id=result.tip_payment_id,
        refunded_cents=result.refunded_cents,
        clawback_cents=result.clawback_cents,
        reversal_entry_id=result.reversal_entry_id,
        refund_entry_id=result.refund_entry_id,
        idempotent_replay=result.idempotent_replay,
    )
