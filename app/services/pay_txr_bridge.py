"""OBP PAY → TXR money-out bridge (the ONE outbound rail for PAY).

PAY NEVER settles money itself. Standing-order ticks and mandate pulls are realized
as ``type=COUNTERPARTY`` Transaction Requests via the TXR cluster
(``app/services/txn_requests.py``, TXR-001 create + TXR-004 execute). TXR owns the
wallet debit, fraud gate, and SCA hold. This module is the single lazy-import boundary
to TXR so the PAY services never import it at module load (it lives in the integrated
tree, may be absent/flag-OFF here).

RULE-2: every call is guarded on the sibling's flag ``S.txn_requests_enabled`` — siblings
EXIST in the integrated tree but may be flag-OFF; with the flag off this degrades to a
no-op (returns ``None``) and the caller treats the occurrence as not-yet-executed.

Idempotency (money-safety #2): the deterministic ``idempotency_key`` is passed to TXR's
``create_request`` (TXR collapses duplicate creates) so a scheduler retry of the same
occurrence yields at most ONE request → at most one debit.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.settings import S

logger = logging.getLogger(__name__)


def emit_counterparty_request(
    user_sub: str,
    *,
    counterparty_id: str,
    amount_cents: int,
    idempotency_key: str,
    reason: str,
    meta: Optional[Dict[str, Any]] = None,
    execute: bool = True,
) -> Optional[Dict[str, Any]]:
    """Emit (and optionally server-side execute) a COUNTERPARTY Transaction Request.

    Returns the TXR request dict, or ``None`` when TXR is unavailable / flag-OFF
    (RULE-2). NEVER raises on a TXR import/availability problem — the caller decides
    whether to advance the schedule based on a non-None return.
    """
    # RULE-2: guard on the sibling's flag.
    if not getattr(S, "txn_requests_enabled", False):
        logger.debug("PAY→TXR skipped: txn_requests_enabled is off")
        return None
    try:
        from app.services import txn_requests as _txr  # lazy: sibling lives in integrated tree
    except Exception:
        logger.debug("PAY→TXR skipped: txn_requests service unavailable", exc_info=True)
        return None

    payload: Dict[str, Any] = {
        "type": "COUNTERPARTY",
        "amount_cents": int(amount_cents),
        "currency": "usd",  # money-safety #5 — ledger stays single-currency usd
        "target": {"counterparty_ref": counterparty_id},
        "reason": reason,
        "idempotency_key": idempotency_key,
        "meta": dict(meta or {}),
    }
    try:
        created = _txr.create_request(user_sub, payload)
    except Exception:
        logger.exception("PAY→TXR create_request failed (idempotency_key=%s)", idempotency_key)
        return None

    request_id = ""
    if isinstance(created, dict):
        request_id = str(created.get("request_id") or created.get("id") or "")

    if execute and request_id:
        try:
            _txr.execute_request(user_sub, request_id, req=None)
        except Exception:
            # Execution failure (fraud/SCA/insufficient-funds) does NOT roll back the
            # created request — TXR owns its state machine; PAY only emitted it.
            logger.exception("PAY→TXR execute_request failed (request_id=%s)", request_id)
    return created
