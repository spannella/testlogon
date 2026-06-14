"""ATI — OpenCATS ATS Integration cross-link bridge (ATI-001..ATI-005 core).

This module is the ONLY production module ATI owns. It cross-links the ATS
pipeline to the CRM:

  * candidate (CND cluster)  <->  contact (contacts/party cluster)
  * job_order (JOB cluster)  <->  opportunity (OPP cluster)

RULE-1 (absolute): this module NEVER re-creates or overwrites any sibling
service. Every sibling (candidates / job_orders / pipeline / opportunities /
party / contacts / crm_reports / crm_activity_timeline) is referenced via a
LAZY import inside a function, wrapped in try/except, AND guarded on that
sibling's own feature flag (RULE-2). The siblings EXIST in the integrated tree
but are absent (or flag-off) on this stale base — so every call site MUST
degrade gracefully: when a sibling is missing or its flag is off we still
persist the ATI link row (the bridge is the ATI-owned source of truth) and mark
it ``degraded`` with a reason, rather than raising.

The link rows live in the ATI-owned ``T.ats_integration_links`` table (single
table, pk/sk). No sibling table is written by this module.

Master gate: ``S.ats_integration_enabled`` AND ``S.candidates_enabled``
(CND-001 is the authoritative ATS gate; we AND with it per the audit B2-1 note
and never redeclare it).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Link-type discriminators (stored on the row + used as SK prefix).
LINK_CANDIDATE_CONTACT = "candidate_contact"
LINK_JOB_OPPORTUNITY = "job_opportunity"


# ---------------------------------------------------------------------------
# Gating helpers
# ---------------------------------------------------------------------------

def _sibling_flag(name: str) -> bool:
    """Read a sibling's feature flag off the frozen S without redeclaring it.

    Returns False when the flag attribute does not exist on this (stale) base,
    which is exactly the graceful-degrade trigger the tests exercise.
    """
    return bool(getattr(S, name, False))


def ats_integration_active() -> bool:
    """Master ATI gate: our own flag AND the authoritative CND-001 gate."""
    return bool(getattr(S, "ats_integration_enabled", False)) and _sibling_flag(
        "candidates_enabled"
    )


class AtsIntegrationDisabled(Exception):
    """Raised when the ATI master gate is off — routers map this to 503."""


def _require_active() -> None:
    if not ats_integration_active():
        raise AtsIntegrationDisabled("ats_integration_disabled")


# ---------------------------------------------------------------------------
# Lazy sibling resolvers — each returns (callable, None) or (None, reason).
# These NEVER import a sibling at module scope. RULE-1 + RULE-2 in one place.
# ---------------------------------------------------------------------------

def _resolve_candidate_lookup() -> Tuple[Optional[Callable[[str], Optional[dict]]], Optional[str]]:
    """Resolve CND-001's candidate getter, gated on candidates_enabled."""
    if not _sibling_flag("candidates_enabled"):
        return None, "candidates_flag_off"
    try:  # pragma: no cover - exercised via degrade path on stale base
        from app.services import candidates as _cnd  # type: ignore

        fn = getattr(_cnd, "get_candidate", None)
        if fn is None:
            return None, "candidates_api_missing"
        return fn, None
    except Exception:
        return None, "candidates_absent"


def _resolve_contact_upsert() -> Tuple[Optional[Callable[..., Any]], Optional[str]]:
    """Resolve the CRM contact upsert (party PERSON or legacy contacts).

    Prefer the OFBiz party PERSON path (PTY/CCT, gated on party_crm_enabled);
    fall back to the legacy contacts service if the party cluster is absent.
    """
    if _sibling_flag("party_crm_enabled"):
        try:  # pragma: no cover
            from app.services import party as _party  # type: ignore

            fn = getattr(_party, "upsert_person_from_candidate", None) or getattr(
                _party, "create_party", None
            )
            if fn is not None:
                return fn, None
        except Exception:
            pass  # fall through to legacy contacts
    try:  # pragma: no cover
        from app.services import contacts as _contacts  # type: ignore

        fn = getattr(_contacts, "upsert_contact", None) or getattr(
            _contacts, "create_contact", None
        )
        if fn is None:
            return None, "contacts_api_missing"
        return fn, None
    except Exception:
        return None, "contacts_absent"


def _resolve_job_lookup() -> Tuple[Optional[Callable[[str], Optional[dict]]], Optional[str]]:
    """Resolve JOB-001's job-order getter, gated on ats_enabled+job_orders_enabled."""
    if not (_sibling_flag("ats_enabled") and _sibling_flag("job_orders_enabled")):
        return None, "job_orders_flag_off"
    try:  # pragma: no cover
        from app.services import job_orders as _job  # type: ignore

        fn = getattr(_job, "get_job_order", None)
        if fn is None:
            return None, "job_orders_api_missing"
        return fn, None
    except Exception:
        return None, "job_orders_absent"


def _resolve_opportunity_upsert() -> Tuple[Optional[Callable[..., Any]], Optional[str]]:
    """Resolve the OPP cluster opportunity upsert, gated on opportunities_enabled."""
    if not _sibling_flag("opportunities_enabled"):
        return None, "opportunities_flag_off"
    try:  # pragma: no cover
        from app.services import opportunities as _opp  # type: ignore

        fn = getattr(_opp, "upsert_opportunity_from_job", None) or getattr(
            _opp, "create_opportunity", None
        )
        if fn is None:
            return None, "opportunities_api_missing"
        return fn, None
    except Exception:
        return None, "opportunities_absent"


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Fire-and-forget audit via the live alerts.audit_event (lazy, never raises)."""
    try:
        from app.services.alerts import audit_event  # local import; alerts is live

        audit_event(event, user_sub, None, **fields)
    except Exception:  # pragma: no cover - audit must never break the bridge
        logger.debug("ATI audit emit failed for %s", event, exc_info=True)


def _record_activity(entity_type: str, entity_id: str, activity_type: str, user_sub: str, summary: str) -> None:
    """Best-effort ACT-009 timeline write — lazy + flag-guarded + swallowed.

    Bridges ATI activity into the CRM activity timeline when ACT-009 is present
    and enabled; a no-op (no raise) otherwise. This is the ATI-002/ATI-003
    "activity bridge" surface kept inert when the sibling is absent.
    """
    if not (_sibling_flag("crm_activities_enabled") and _sibling_flag("crm_activity_timeline_enabled")):
        return
    try:  # pragma: no cover
        from app.services import crm_activity_timeline as _tl  # type: ignore

        fn = getattr(_tl, "record_crm_activity", None)
        if fn is None:
            return
        fn(
            entity_type=entity_type,
            entity_id=entity_id,
            activity_type=activity_type,
            activity_id=uuid.uuid4().hex,
            user_sub=user_sub,
            summary=summary,
            metadata={"source": "ats_integration"},
        )
    except Exception:
        logger.debug("ATI activity bridge failed", exc_info=True)


# ---------------------------------------------------------------------------
# DDB row helpers (ATI-owned table only)
# ---------------------------------------------------------------------------

def _link_pk(owner_sub: str) -> str:
    return f"OWNER#{owner_sub}"


def _link_sk(link_type: str, link_id: str) -> str:
    return f"LINK#{link_type}#{link_id}"


def _deterministic_link_id(link_type: str, primary_id: str) -> str:
    """One link per (owner, link_type, primary ATS id) — deterministic id.

    primary_id is the ATS-side id (candidate_id / job_order_id) so re-linking
    the same candidate is idempotent (upsert overwrites the same row).
    """
    return f"{link_type}:{primary_id}"


def _row_to_candidate_contact(item: dict) -> dict:
    return {
        "link_id": item["link_id"],
        "link_type": LINK_CANDIDATE_CONTACT,
        "candidate_id": item.get("candidate_id", ""),
        "contact_id": item.get("contact_id", ""),
        "owner_sub": item.get("owner_sub", ""),
        "synced": bool(item.get("synced", False)),
        "degraded": bool(item.get("degraded", False)),
        "degraded_reason": item.get("degraded_reason"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _row_to_job_opportunity(item: dict) -> dict:
    return {
        "link_id": item["link_id"],
        "link_type": LINK_JOB_OPPORTUNITY,
        "job_order_id": item.get("job_order_id", ""),
        "opportunity_id": item.get("opportunity_id", ""),
        "owner_sub": item.get("owner_sub", ""),
        "synced": bool(item.get("synced", False)),
        "degraded": bool(item.get("degraded", False)),
        "degraded_reason": item.get("degraded_reason"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


# ---------------------------------------------------------------------------
# ATI-001/004 core: candidate <-> contact sync
# ---------------------------------------------------------------------------

def link_candidate_to_contact(
    owner_sub: str,
    candidate_id: str,
    contact_id: Optional[str] = None,
) -> dict:
    """Link a candidate to a CRM contact, syncing one from the other if needed.

    Behaviour:
      * Master gate off -> AtsIntegrationDisabled (router -> 503).
      * candidate_id is validated against the CND cluster ONLY when that
        cluster is present + flag-on; otherwise we trust the opaque id and
        mark the link ``degraded`` (graceful degrade — the bridge still works).
      * When ``contact_id`` is omitted we attempt to create/sync a CRM contact
        from the candidate via the CRM upsert sibling; if that sibling is
        absent/flag-off we persist the link with an empty contact_id and
        ``degraded=True`` so a later reconcile pass can complete the sync.

    Returns an ``AtsCandidateContactLinkOut``-shaped dict.
    """
    _require_active()
    degraded = False
    reasons: List[str] = []

    # 1) Validate / fetch the candidate (lazy + guarded).
    cand_get, cand_reason = _resolve_candidate_lookup()
    candidate: Optional[dict] = None
    if cand_get is not None:
        try:  # pragma: no cover - real-path only present in integrated tree
            candidate = cand_get(candidate_id)
        except Exception:
            candidate = None
        if candidate is None:
            degraded = True
            reasons.append("candidate_not_found")
    else:
        degraded = True
        reasons.append(cand_reason or "candidates_unavailable")

    # 2) Resolve / create the contact (lazy + guarded).
    resolved_contact_id = contact_id or ""
    synced = False
    if not resolved_contact_id:
        upsert, up_reason = _resolve_contact_upsert()
        if upsert is not None and candidate is not None:
            try:  # pragma: no cover - integrated-tree path
                created = upsert(owner_sub=owner_sub, candidate=candidate)
                resolved_contact_id = (
                    created.get("contact_id")
                    or created.get("party_id")
                    or created.get("id")
                    or ""
                ) if isinstance(created, dict) else str(created or "")
                synced = bool(resolved_contact_id)
            except Exception:
                degraded = True
                reasons.append("contact_sync_failed")
        else:
            degraded = True
            reasons.append(up_reason or "contact_target_unavailable")

    item = {
        "pk": _link_pk(owner_sub),
        "sk": _link_sk(LINK_CANDIDATE_CONTACT, _deterministic_link_id(LINK_CANDIDATE_CONTACT, candidate_id)),
        "link_id": _deterministic_link_id(LINK_CANDIDATE_CONTACT, candidate_id),
        "link_type": LINK_CANDIDATE_CONTACT,
        "candidate_id": candidate_id,
        "contact_id": resolved_contact_id,
        "owner_sub": owner_sub,
        "owner_key": _link_pk(owner_sub),
        "target_key": f"CANDIDATE#{candidate_id}",
        "synced": synced,
        "degraded": degraded,
        "degraded_reason": ",".join(reasons) if reasons else None,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    T.ats_integration_links.put_item(Item=item)
    _audit(
        "ats_integration.candidate_contact_linked",
        owner_sub,
        candidate_id=candidate_id,
        contact_id=resolved_contact_id,
        degraded=degraded,
    )
    _record_activity("candidate", candidate_id, "note", owner_sub, "Linked candidate to CRM contact")
    return _row_to_candidate_contact(item)


# ---------------------------------------------------------------------------
# ATI-002 core: job_order <-> opportunity link
# ---------------------------------------------------------------------------

def link_job_to_opportunity(
    owner_sub: str,
    job_order_id: str,
    opportunity_id: Optional[str] = None,
) -> dict:
    """Link a job order to a CRM opportunity, syncing one from the other.

    Symmetric to ``link_candidate_to_contact`` — same graceful-degrade rules:
    JOB cluster validates the job_order_id only when present+flag-on; OPP
    cluster creates the opportunity only when present+flag-on; otherwise the
    bridge row persists with ``degraded=True``.
    """
    _require_active()
    degraded = False
    reasons: List[str] = []

    job_get, job_reason = _resolve_job_lookup()
    job: Optional[dict] = None
    if job_get is not None:
        try:  # pragma: no cover - integrated-tree path
            job = job_get(job_order_id)
        except Exception:
            job = None
        if job is None:
            degraded = True
            reasons.append("job_order_not_found")
    else:
        degraded = True
        reasons.append(job_reason or "job_orders_unavailable")

    resolved_opp_id = opportunity_id or ""
    synced = False
    if not resolved_opp_id:
        upsert, up_reason = _resolve_opportunity_upsert()
        if upsert is not None and job is not None:
            try:  # pragma: no cover - integrated-tree path
                created = upsert(owner_sub=owner_sub, job_order=job)
                resolved_opp_id = (
                    created.get("opportunity_id")
                    or created.get("id")
                    or ""
                ) if isinstance(created, dict) else str(created or "")
                synced = bool(resolved_opp_id)
            except Exception:
                degraded = True
                reasons.append("opportunity_sync_failed")
        else:
            degraded = True
            reasons.append(up_reason or "opportunity_target_unavailable")

    item = {
        "pk": _link_pk(owner_sub),
        "sk": _link_sk(LINK_JOB_OPPORTUNITY, _deterministic_link_id(LINK_JOB_OPPORTUNITY, job_order_id)),
        "link_id": _deterministic_link_id(LINK_JOB_OPPORTUNITY, job_order_id),
        "link_type": LINK_JOB_OPPORTUNITY,
        "job_order_id": job_order_id,
        "opportunity_id": resolved_opp_id,
        "owner_sub": owner_sub,
        "owner_key": _link_pk(owner_sub),
        "target_key": f"JOB#{job_order_id}",
        "synced": synced,
        "degraded": degraded,
        "degraded_reason": ",".join(reasons) if reasons else None,
        "created_at": now_ts(),
        "updated_at": now_ts(),
    }
    T.ats_integration_links.put_item(Item=item)
    _audit(
        "ats_integration.job_opportunity_linked",
        owner_sub,
        job_order_id=job_order_id,
        opportunity_id=resolved_opp_id,
        degraded=degraded,
    )
    _record_activity("job_order", job_order_id, "note", owner_sub, "Linked job order to CRM opportunity")
    return _row_to_job_opportunity(item)


# ---------------------------------------------------------------------------
# Read / list / unlink
# ---------------------------------------------------------------------------

def _query_owner_links(owner_sub: str) -> List[dict]:
    """Query all ATI link rows for an owner, looping LastEvaluatedKey."""
    items: List[dict] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(_link_pk(owner_sub))
        & Key("sk").begins_with("LINK#"),
    }
    while True:
        resp = T.ats_integration_links.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def list_links(owner_sub: str) -> dict:
    """Return all ATI cross-links for an owner, split by type.

    Returns an ``AtsIntegrationLinksOut``-shaped dict. Master gate off -> 503.
    """
    _require_active()
    cc: List[dict] = []
    jo: List[dict] = []
    for it in _query_owner_links(owner_sub):
        if it.get("link_type") == LINK_CANDIDATE_CONTACT:
            cc.append(_row_to_candidate_contact(it))
        elif it.get("link_type") == LINK_JOB_OPPORTUNITY:
            jo.append(_row_to_job_opportunity(it))
    return {
        "candidate_contact_links": cc,
        "job_opportunity_links": jo,
        "count": len(cc) + len(jo),
    }


def unlink(owner_sub: str, link_type: str, link_id: str) -> bool:
    """Delete an ATI link row. Idempotent (delete of a missing key is a no-op)."""
    _require_active()
    if link_type not in (LINK_CANDIDATE_CONTACT, LINK_JOB_OPPORTUNITY):
        return False
    T.ats_integration_links.delete_item(
        Key={"pk": _link_pk(owner_sub), "sk": _link_sk(link_type, link_id)}
    )
    _audit("ats_integration.unlinked", owner_sub, link_type=link_type, link_id=link_id)
    return True
