"""CRM Leads service — LED-001 through LED-013.

Implements CRUD for Lead and Prospect entities, lead conversion (LED-006),
source attribution (LED-004), web-to-lead capture (LED-005), duplicate
detection (LED-009), round-robin assignment (LED-010), scoring engine (LED-011),
and CRM activity log (LED-012).

All public functions guard on S.leads_enabled first.  No S.dev_mode branches —
SECOPS-007 parity: identical code in dev (moto) and prod (real DDB).
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Local import of audit_event to avoid heavy circular deps at module load time.
def _audit(event: str, user_sub: str, **kwargs: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub, **kwargs)
    except Exception:
        pass


# ── status state machine (LED-003) ────────────────────────────────────────────

LEAD_STATUSES = {"new", "assigned", "in_process", "converted", "recycled", "dead"}

_LEAD_TRANSITIONS: Dict[str, tuple] = {
    "new":        ("assigned", "in_process", "recycled", "dead"),
    "assigned":   ("in_process", "recycled", "dead", "new"),
    "in_process": ("converted", "recycled", "dead", "assigned"),
    "recycled":   ("new", "assigned", "dead"),
    "dead":       ("new",),          # re-open only
    "converted":  (),                # terminal
}

LEAD_SOURCES = {
    "web_site", "cold_call", "email", "campaign", "trade_show",
    "word_of_mouth", "other", "internal",
}

_WELL_KNOWN_QUESTION_IDS = {
    "first_name", "last_name", "email", "phone",
    "company", "title", "website",
}

# ── LED-003: Lead CRUD ────────────────────────────────────────────────────────

def _require_leads() -> None:
    if not S.leads_enabled:
        raise HTTPException(503, "Leads module is not enabled")


def _find_lead_by_email_new_status(email: str) -> Optional[dict]:
    """
    Scan ByStatus GSI for STATUS#new leads matching email.
    Used by create_lead duplicate check (LED-003 §5.2).
    Caps at 10 pages (~5000 leads).
    """
    page = 0
    esk = None
    while page < 10:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatus",
            "KeyConditionExpression": Key("GSI2PK").eq("STATUS#new"),
            "FilterExpression": Attr("email").eq(email),
            "Limit": 500,
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.leads.query(**kwargs)
        for item in resp.get("Items", []):
            if not item.get("deleted_at"):
                return item
        esk = resp.get("LastEvaluatedKey")
        page += 1
        if not esk:
            break
    return None


def create_lead(
    creator_sub: str,
    data: Any,  # LeadCreateIn
    extra: Optional[Dict[str, Any]] = None,
) -> dict:
    """Create a lead, returning existing record if email already in STATUS#new."""
    _require_leads()

    from app.core.normalize import normalize_email, normalize_phone

    email = normalize_email(data.email)
    phone: Optional[str] = None
    if data.phone:
        try:
            phone = normalize_phone(data.phone)
        except HTTPException:
            raise
        except Exception:
            phone = None

    # Idempotent duplicate check
    existing = _find_lead_by_email_new_status(email)
    if existing:
        return existing

    lead_id = "lead_" + uuid.uuid4().hex[:20]
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"LEAD#{lead_id}",
        "sk": "META",
        "lead_id": lead_id,
        "first_name": data.first_name,
        "last_name": data.last_name,
        "email": email,
        "email_raw": data.email,
        "lead_source": data.lead_source or "other",
        "status": "new",
        "score": 0,
        "created_by": creator_sub,
        "created_at": ts,
        "updated_at": ts,
        # GSI keys
        "GSI1PK": f"OWNER#{creator_sub}",
        "GSI1SK": ts,
        "GSI2PK": "STATUS#new",
        "GSI2SK": ts,
        "GSI3PK": f"SOURCE#{data.lead_source or 'other'}",
        "GSI3SK": ts,
    }

    if phone:
        item["phone"] = phone
    if data.company:
        item["company"] = data.company
    if data.title:
        item["title"] = data.title
    if data.description:
        item["description"] = data.description
    if data.assigned_to:
        item["assigned_to"] = data.assigned_to
    if data.website:
        item["website"] = data.website
    if getattr(data, "attribution_code", None):
        item["attribution_code"] = data.attribution_code
    if getattr(data, "campaign_id", None):
        item["campaign_id"] = data.campaign_id
    if extra:
        for k, v in extra.items():
            if v:
                item[k] = v

    T.leads.put_item(Item=item)

    # LED-004: fire-and-forget tracking visit
    if getattr(data, "attribution_code", None):
        try:
            from app.services.tracking_codes import record_visit  # MKT-010, soft dep
            record_visit(data.attribution_code, party_id=None, referrer="lead_create")
        except (ImportError, Exception):
            pass

    _audit(
        "lead.created", creator_sub,
        lead_id=lead_id,
        email=email,
        lead_source=data.lead_source or "other",
        attribution_code=getattr(data, "attribution_code", "") or "",
        campaign_id=getattr(data, "campaign_id", "") or "",
    )
    return item


def get_lead(lead_id: str) -> Optional[dict]:
    """Return lead META dict or None."""
    _require_leads()
    resp = T.leads.get_item(Key={"pk": f"LEAD#{lead_id}", "sk": "META"})
    return resp.get("Item")


def list_leads(
    *,
    owner_sub: str,
    status: Optional[str] = None,
    lead_source: Optional[str] = None,
    assigned_to: Optional[str] = None,
    created_after: Optional[int] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List leads by owner/status/source with pagination."""
    _require_leads()
    limit = max(1, min(limit, 200))

    esk = decode_cursor(cursor) if cursor else None

    if status:
        index = "ByStatus"
        pk_val = f"STATUS#{status}"
        pk_attr = "GSI2PK"
        sk_attr = "GSI2SK"
    elif lead_source:
        index = "BySource"
        pk_val = f"SOURCE#{lead_source}"
        pk_attr = "GSI3PK"
        sk_attr = "GSI3SK"
    else:
        index = "ByOwner"
        pk_val = f"OWNER#{owner_sub}"
        pk_attr = "GSI1PK"
        sk_attr = "GSI1SK"

    kce = Key(pk_attr).eq(pk_val)
    if created_after is not None:
        kce = kce & Key(sk_attr).gte(created_after)

    filter_expr = Attr("deleted_at").not_exists()
    if assigned_to:
        filter_expr = filter_expr & Attr("assigned_to").eq(assigned_to)

    kwargs: Dict[str, Any] = {
        "IndexName": index,
        "KeyConditionExpression": kce,
        "FilterExpression": filter_expr,
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    resp = T.leads.query(**kwargs)
    items = resp.get("Items", [])
    next_esk = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(next_esk) if next_esk else None

    return {"leads": items, "cursor": next_cursor}


def update_lead(
    lead_id: str,
    actor_sub: str,
    data: Any,  # LeadUpdateIn
) -> dict:
    """Update a lead, enforcing status transitions."""
    _require_leads()

    existing = get_lead(lead_id)
    if existing is None:
        raise HTTPException(404, "Lead not found")
    if existing.get("deleted_at"):
        raise HTTPException(410, "Lead has been deleted")

    # Status transition validation
    new_status = data.status
    if new_status is not None and new_status != existing["status"]:
        if new_status not in LEAD_STATUSES:
            raise HTTPException(422, f"Unknown status: {new_status}")
        allowed = _LEAD_TRANSITIONS.get(existing["status"], ())
        if new_status not in allowed:
            raise HTTPException(400, {
                "code": "invalid_status_transition",
                "from": existing["status"],
                "to": new_status,
            })
        if new_status == "converted" and not existing.get("converted_party_id"):
            raise HTTPException(400, "converted_party_id required to transition to converted")

    from app.core.normalize import normalize_email, normalize_phone

    ts = now_ts()
    updated = {**existing}
    updated["updated_at"] = ts

    # Apply non-None fields from data
    if data.first_name is not None:
        updated["first_name"] = data.first_name
    if data.last_name is not None:
        updated["last_name"] = data.last_name
    if data.email is not None:
        updated["email"] = normalize_email(data.email)
        updated["email_raw"] = data.email
    if data.phone is not None:
        updated["phone"] = normalize_phone(data.phone) if data.phone else None
    if data.company is not None:
        updated["company"] = data.company
    if data.title is not None:
        updated["title"] = data.title
    if data.lead_source is not None:
        updated["lead_source"] = data.lead_source
        updated["GSI3PK"] = f"SOURCE#{data.lead_source}"
    if data.description is not None:
        updated["description"] = data.description
    if data.assigned_to is not None:
        updated["assigned_to"] = data.assigned_to
    if data.website is not None:
        updated["website"] = data.website
    if data.score is not None:
        updated["score"] = data.score
    if new_status is not None:
        updated["status"] = new_status
        updated["GSI2PK"] = f"STATUS#{new_status}"
        updated["GSI2SK"] = ts

    # GSI2 key changed → delete + re-put
    T.leads.delete_item(Key={"pk": existing["pk"], "sk": "META"})
    T.leads.put_item(Item=updated)

    _audit("lead.updated", actor_sub, lead_id=lead_id, changes=list(data.model_fields_set))
    return updated


def delete_lead(lead_id: str, actor_sub: str) -> None:
    """Soft-delete a lead."""
    _require_leads()

    existing = get_lead(lead_id)
    if existing is None:
        raise HTTPException(404, "Lead not found")
    if existing.get("deleted_at"):
        return  # idempotent

    ts = now_ts()
    T.leads.update_item(
        Key={"pk": f"LEAD#{lead_id}", "sk": "META"},
        UpdateExpression="SET deleted_at = :da, #st = :dead, updated_at = :ua",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":da": ts, ":dead": "dead", ":ua": ts},
    )
    _audit("lead.deleted", actor_sub, lead_id=lead_id)


def find_lead_by_email(email: str) -> Optional[dict]:
    """Find first active lead with given (pre-normalized) email across STATUS#new."""
    return _find_lead_by_email_new_status(email)


# ── LED-004: source summary ────────────────────────────────────────────────────

def get_lead_source_counts() -> List[Dict[str, Any]]:
    """Return count breakdown of leads by lead_source (using BySource GSI)."""
    _require_leads()
    results = []
    for source in sorted(LEAD_SOURCES):
        total = 0
        esk = None
        page = 0
        while page < 1000:
            kwargs: Dict[str, Any] = {
                "IndexName": "BySource",
                "KeyConditionExpression": Key("GSI3PK").eq(f"SOURCE#{source}"),
                "Select": "COUNT",
            }
            if esk:
                kwargs["ExclusiveStartKey"] = esk
            resp = T.leads.query(**kwargs)
            total += resp.get("Count", 0)
            esk = resp.get("LastEvaluatedKey")
            page += 1
            if not esk:
                break
        results.append({"lead_source": source, "count": total})
    return results


# ── LED-005: web-to-lead capture ──────────────────────────────────────────────

def create_lead_from_submission(
    version: dict,
    answers: dict,
    *,
    response_session_id: str = "",
    user_sub: Optional[str],
) -> Optional[dict]:
    """Best-effort web-to-lead capture from a questionnaire submission.

    Returns the created lead dict, or None if capture is skipped or fails.
    Never raises.
    """
    try:
        if not getattr(S, "leads_enabled", False):
            return None
        if not version.get("capture_as_lead", False):
            return None

        raw_email = str(answers.get("email") or "").strip()
        if not raw_email:
            return None

        from app.core.normalize import normalize_email, normalize_phone
        try:
            normalized_email = normalize_email(raw_email)
        except Exception:
            return None

        first_name = str(answers.get("first_name") or "").strip()[:120] or "Unknown"
        last_name  = str(answers.get("last_name")  or "").strip()[:120] or "Unknown"
        raw_phone  = str(answers.get("phone")      or "").strip()
        company    = str(answers.get("company")    or "").strip()[:200] or None
        title      = str(answers.get("title")      or "").strip()[:200] or None
        website    = str(answers.get("website")    or "").strip()[:500] or None

        phone: Optional[str] = None
        if raw_phone:
            try:
                phone = normalize_phone(raw_phone)
            except Exception:
                phone = None

        lead_source_raw = version.get("lead_source_override") or "web_site"
        if lead_source_raw not in LEAD_SOURCES:
            lead_source_raw = "web_site"

        creator_sub = user_sub or "system_web_lead"

        from app.models import LeadCreateIn
        data = LeadCreateIn(
            first_name=first_name,
            last_name=last_name,
            email=normalized_email,
            phone=phone,
            company=company,
            title=title,
            lead_source=lead_source_raw,
            website=website,
        )

        lead = create_lead(
            creator_sub=creator_sub,
            data=data,
            extra={
                "origin_questionnaire_id": version.get("questionnaire_id", ""),
                "origin_response_session_id": response_session_id,
            },
        )
        return lead
    except Exception:
        return None


# ── LED-006: lead conversion ──────────────────────────────────────────────────

def _create_person_stub(lead: dict, actor_sub: str) -> str:
    person_id = "person_" + uuid.uuid4().hex[:20]
    item: Dict[str, Any] = {
        "pk": f"PERSON#{person_id}",
        "sk": "META",
        "person_id": person_id,
        "first_name": lead["first_name"],
        "last_name": lead["last_name"],
        "email": lead["email"],
        "source": "lead_conversion_stub",
        "lead_id": lead["lead_id"],
        "created_at": now_ts(),
        "_stub": True,
    }
    if lead.get("phone"):
        item["phone"] = lead["phone"]
    T.leads.put_item(Item=item)
    return person_id


def _create_org_stub(lead: dict, data: Any, actor_sub: str) -> str:
    org_id = "org_" + uuid.uuid4().hex[:20]
    name = (
        getattr(data, "account_name", None)
        or lead.get("company")
        or f"{lead['first_name']} {lead['last_name']}"
    )
    T.leads.put_item(Item={
        "pk": f"ORG#{org_id}",
        "sk": "META",
        "org_id": org_id,
        "name": name,
        "source": "lead_conversion_stub",
        "lead_id": lead["lead_id"],
        "created_at": now_ts(),
        "_stub": True,
    })
    return org_id


def _create_opportunity_stub(lead_id: str, actor_sub: str, data: Any, lead: dict) -> str:
    opportunity_id = "opp_" + uuid.uuid4().hex[:20]
    opp_name = (
        getattr(data, "opportunity_name", None)
        or f"Opportunity from {lead['first_name']} {lead['last_name']}"
    )
    T.leads.put_item(Item={
        "pk": f"LEAD#{lead_id}",
        "sk": "OPPORTUNITY#META",
        "opportunity_id": opportunity_id,
        "lead_id": lead_id,
        "name": opp_name,
        "amount_cents": getattr(data, "opportunity_amount_cents", None) or 0,
        "currency": "USD",
        "stage": "prospecting",
        "created_by": actor_sub,
        "created_at": now_ts(),
        "converted_from_lead_id": lead_id,
    })
    return opportunity_id


def _finalize_conversion(
    lead: dict,
    actor_sub: str,
    converted_party_id: str,
    converted_org_id: Optional[str],
    opportunity_id: Optional[str],
) -> dict:
    ts = now_ts()
    updated = {**lead}
    updated["status"] = "converted"
    updated["converted_at"] = ts
    updated["converted_party_id"] = converted_party_id
    updated["updated_at"] = ts
    updated["GSI2PK"] = "STATUS#converted"
    updated["GSI2SK"] = ts
    # soft opaque PTY linkage (LED reconciliation)
    updated["linked_entity_id"] = converted_party_id
    if converted_org_id:
        updated["converted_org_id"] = converted_org_id
    if opportunity_id:
        updated["opportunity_id"] = opportunity_id
    # GSI2 key changed: delete old + re-put
    T.leads.delete_item(Key={"pk": lead["pk"], "sk": "META"})
    T.leads.put_item(Item=updated)
    return updated


def convert_lead(lead_id: str, actor_sub: str, data: Any) -> Any:
    """Convert a lead to Party + Opportunity stub (LED-006)."""
    _require_leads()

    lead = get_lead(lead_id)
    if lead is None:
        raise HTTPException(404, "Lead not found")
    if lead["status"] == "converted":
        raise HTTPException(409, {
            "detail": "Lead already converted",
            "lead_id": lead_id,
            "converted_at": lead.get("converted_at"),
        })
    if lead.get("deleted_at"):
        raise HTTPException(410, "Lead has been deleted")

    # PTY path (when party_crm_enabled)
    pty_used = False
    try:
        from app.services import party as _party_module
        _pty_available = getattr(S, "party_crm_enabled", False)
    except ImportError:
        _pty_available = False

    if _pty_available:
        try:
            matches = _party_module.find_party_by_contact("EMAIL", lead["email"])
            if matches:
                person_party_id = matches[0]["party_id"]
            else:
                person_dict = _party_module.create_party(
                    "PERSON", correlation_id=f"LED:PERSON:{lead_id}"
                )
                person_party_id = person_dict["party_id"]
                _party_module.add_contact_mech(
                    person_party_id, "EMAIL", lead["email"],
                    purposes=["PRIMARY_EMAIL"],
                    correlation_id=f"MECH:EMAIL:LED:{lead_id}",
                )
                if lead.get("phone"):
                    _party_module.add_contact_mech(
                        person_party_id, "PHONE", lead["phone"],
                        purposes=["PRIMARY_PHONE"],
                        correlation_id=f"MECH:PHONE:LED:{lead_id}",
                    )
            org_party_id: Optional[str] = None
            if data.create_account:
                name = (
                    data.account_name
                    or lead.get("company")
                    or f"{lead['first_name']} {lead['last_name']}"
                )
                org_dict = _party_module.create_org_account(
                    name,
                    owner_user_sub=actor_sub,
                    correlation_id=f"LED:ORG:{lead_id}",
                )
                org_party_id = org_dict["party_id"]
            converted_party_id = person_party_id
            converted_org_id = org_party_id
            pty_used = True
        except ImportError:
            _pty_available = False

    if not _pty_available or not pty_used:
        # Stub path
        person_id = _create_person_stub(lead, actor_sub)
        converted_party_id = f"PERSON#{person_id}"
        converted_org_id = None
        if data.create_account:
            org_id = _create_org_stub(lead, data, actor_sub)
            converted_org_id = f"ORG#{org_id}"

    opportunity_id: Optional[str] = None
    opp_stub = None
    if data.create_opportunity:
        opportunity_id = _create_opportunity_stub(lead_id, actor_sub, data, lead)
        opp_item = T.leads.get_item(Key={"pk": f"LEAD#{lead_id}", "sk": "OPPORTUNITY#META"}).get("Item", {})
        from app.models import OpportunityStubOut
        opp_stub = OpportunityStubOut(
            opportunity_id=opp_item.get("opportunity_id", opportunity_id),
            name=opp_item.get("name", ""),
            amount_cents=opp_item.get("amount_cents", 0),
            currency=opp_item.get("currency", "USD"),
            stage=opp_item.get("stage", "prospecting"),
            created_at=opp_item.get("created_at", now_ts()),
        )

    updated = _finalize_conversion(
        lead, actor_sub, converted_party_id, converted_org_id, opportunity_id
    )

    _audit(
        "lead.converted", actor_sub,
        lead_id=lead_id,
        converted_party_id=converted_party_id,
        converted_org_id=converted_org_id or "",
        pty_path=pty_used,
    )

    from app.models import LeadConversionOut
    return LeadConversionOut(
        lead_id=lead_id,
        status="converted",
        converted_party_id=converted_party_id,
        converted_org_id=converted_org_id,
        opportunity=opp_stub,
        converted_at=updated.get("converted_at", now_ts()),
        pty_path_used=pty_used,
    )


# ── LED-007: Prospect CRUD ────────────────────────────────────────────────────

def find_prospect_by_email(normalized_email: str) -> Optional[dict]:
    """Query ByEmail GSI for an active Prospect."""
    esk = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByEmail",
            "KeyConditionExpression": Key("GSI4PK").eq(f"EMAIL#{normalized_email}"),
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.leads.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("pk", "").startswith("PROSPECT#") and not item.get("deleted_at"):
                return item
        esk = resp.get("LastEvaluatedKey")
        if not esk:
            break
    return None


def create_prospect(owner_sub: str, data: Any) -> dict:
    """Create a Prospect (idempotent by email)."""
    _require_leads()

    from app.core.normalize import normalize_email, normalize_phone

    email = normalize_email(data.email)
    phone: Optional[str] = None
    if data.phone:
        try:
            phone = normalize_phone(data.phone)
        except HTTPException:
            raise
        except Exception:
            phone = None

    existing = find_prospect_by_email(email)
    if existing:
        return existing

    # Opt-out check (fail-open)
    suppressed = False
    try:
        from app.services.cart_reminders import is_user_opted_out
        suppressed = is_user_opted_out(email)
    except Exception:
        suppressed = False

    prospect_id = "pros_" + uuid.uuid4().hex[:20]
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"PROSPECT#{prospect_id}",
        "sk": "META",
        "prospect_id": prospect_id,
        "owner_sub": owner_sub,
        "email": email,
        "suppressed": suppressed,
        "created_at": ts,
        "updated_at": ts,
        # GSI keys
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": ts,
        "GSI2PK": "STATUS#prospect",
        "GSI2SK": ts,
        "GSI4PK": f"EMAIL#{email}",
        "GSI4SK": ts,
    }
    if data.first_name:
        item["first_name"] = data.first_name
    if data.last_name:
        item["last_name"] = data.last_name
    if phone:
        item["phone"] = phone
    if data.company:
        item["company"] = data.company

    T.leads.put_item(Item=item)
    _audit("prospect.created", owner_sub, prospect_id=prospect_id, email=email)
    return item


def get_prospect(prospect_id: str) -> Optional[dict]:
    """Return Prospect META dict or None."""
    _require_leads()
    resp = T.leads.get_item(Key={"pk": f"PROSPECT#{prospect_id}", "sk": "META"})
    item = resp.get("Item")
    if item and item.get("deleted_at"):
        return None
    return item


def list_prospects(
    owner_sub: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
    include_suppressed: bool = True,
    include_deleted: bool = False,
) -> dict:
    """List Prospects for an owner, paginated."""
    _require_leads()
    limit = max(1, min(limit, 200))
    esk = decode_cursor(cursor) if cursor else None

    filter_expr = Attr("pk").begins_with("PROSPECT#")
    if not include_deleted:
        filter_expr = filter_expr & Attr("deleted_at").not_exists()
    if not include_suppressed:
        filter_expr = filter_expr & Attr("suppressed").eq(False)

    collected: List[dict] = []
    while len(collected) < limit:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByOwner",
            "KeyConditionExpression": Key("GSI1PK").eq(f"OWNER#{owner_sub}"),
            "FilterExpression": filter_expr,
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.leads.query(**kwargs)
        collected.extend(resp.get("Items", []))
        esk = resp.get("LastEvaluatedKey")
        if not esk:
            break

    next_cursor = encode_cursor(esk) if esk else None
    return {"prospects": collected[:limit], "cursor": next_cursor, "count": len(collected[:limit])}


def update_prospect(prospect_id: str, actor_sub: str, data: Any) -> dict:
    """Update Prospect fields (email is immutable)."""
    _require_leads()

    existing = get_prospect(prospect_id)
    if existing is None:
        raise HTTPException(404, "Prospect not found")

    from app.core.normalize import normalize_phone

    ts = now_ts()
    expr_parts = ["updated_at = :ua"]
    expr_vals: Dict[str, Any] = {":ua": ts}
    expr_names: Dict[str, str] = {}

    if data.first_name is not None:
        expr_parts.append("first_name = :fn")
        expr_vals[":fn"] = data.first_name
    if data.last_name is not None:
        expr_parts.append("last_name = :ln")
        expr_vals[":ln"] = data.last_name
    if data.phone is not None and data.phone != "":
        expr_parts.append("phone = :ph")
        expr_vals[":ph"] = normalize_phone(data.phone)
    if data.company is not None:
        expr_parts.append("company = :co")
        expr_vals[":co"] = data.company

    T.leads.update_item(
        Key={"pk": f"PROSPECT#{prospect_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=expr_vals,
        **({"ExpressionAttributeNames": expr_names} if expr_names else {}),
    )

    _audit("prospect.updated", actor_sub, prospect_id=prospect_id)

    # Re-fetch the updated item to return the fresh state
    resp2 = T.leads.get_item(Key={"pk": f"PROSPECT#{prospect_id}", "sk": "META"})
    return resp2.get("Item", existing)


def delete_prospect(prospect_id: str, actor_sub: str) -> None:
    """Soft-delete a Prospect."""
    _require_leads()
    existing = get_prospect(prospect_id)
    if existing is None:
        return  # idempotent: already deleted or not found
    ts = now_ts()
    T.leads.update_item(
        Key={"pk": f"PROSPECT#{prospect_id}", "sk": "META"},
        UpdateExpression="SET deleted_at = :da, GSI2PK = :gsi2pk, updated_at = :ua",
        ExpressionAttributeValues={":da": ts, ":gsi2pk": "STATUS#deleted", ":ua": ts},
    )
    _audit("prospect.deleted", actor_sub, prospect_id=prospect_id)


def add_prospect_to_contact_list(prospect_id: str, list_id: str) -> None:
    """Soft dependency on MKT-007 marketing_lists.add_member()."""
    try:
        from app.services.marketing_lists import add_member
        prospect = get_prospect(prospect_id)
        if not prospect:
            raise ValueError(f"Prospect {prospect_id} not found")
        add_member(
            list_id=list_id,
            email=prospect["email"],
            suppressed=prospect.get("suppressed", False),
        )
    except ImportError:
        pass


# ── LED-009: duplicate detection & merge ──────────────────────────────────────

def find_duplicates(lead_id: str) -> List[dict]:
    """Return list of potential duplicate leads (same email, not this lead)."""
    _require_leads()
    lead = get_lead(lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    email = lead.get("email", "")
    if not email:
        return []

    # Query ByEmail GSI for leads with same email
    results = []
    esk = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByEmail",
            "KeyConditionExpression": Key("GSI4PK").eq(f"EMAIL#{email}"),
        }
        if esk:
            kwargs["ExclusiveStartKey"] = esk
        resp = T.leads.query(**kwargs)
        for item in resp.get("Items", []):
            if (item.get("pk", "").startswith("LEAD#")
                    and item.get("lead_id") != lead_id
                    and not item.get("deleted_at")):
                results.append(item)
        esk = resp.get("LastEvaluatedKey")
        if not esk:
            break
    return results


def merge_leads(
    primary_lead_id: str,
    secondary_lead_id: str,
    actor_sub: str,
) -> dict:
    """Merge secondary lead into primary, soft-deleting secondary (LED-009)."""
    _require_leads()

    primary = get_lead(primary_lead_id)
    if not primary:
        raise HTTPException(404, f"Primary lead {primary_lead_id} not found")
    secondary = get_lead(secondary_lead_id)
    if not secondary:
        raise HTTPException(404, f"Secondary lead {secondary_lead_id} not found")
    if secondary_lead_id == primary_lead_id:
        raise HTTPException(400, "Cannot merge lead with itself")

    # Merge: fill missing fields from secondary → primary
    fields_to_merge = ["phone", "company", "title", "website", "description"]
    ts = now_ts()
    updated = {**primary, "updated_at": ts}
    for field in fields_to_merge:
        if not primary.get(field) and secondary.get(field):
            updated[field] = secondary[field]

    # Re-put primary with merged fields
    T.leads.put_item(Item=updated)

    # Soft-delete secondary
    T.leads.update_item(
        Key={"pk": f"LEAD#{secondary_lead_id}", "sk": "META"},
        UpdateExpression="SET deleted_at = :da, updated_at = :ua, merged_into = :mi",
        ExpressionAttributeValues={
            ":da": ts, ":ua": ts, ":mi": primary_lead_id
        },
    )

    _audit(
        "lead.merged", actor_sub,
        primary_lead_id=primary_lead_id,
        secondary_lead_id=secondary_lead_id,
    )
    return updated


# ── LED-010: assignment & round-robin ─────────────────────────────────────────

def assign_lead(lead_id: str, assignee_sub: str, actor_sub: str) -> dict:
    """Assign a lead to a user (LED-010)."""
    _require_leads()
    if not S.leads_assignment_enabled:
        raise HTTPException(404, "Lead assignment is not enabled")

    lead = get_lead(lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    if lead.get("deleted_at"):
        raise HTTPException(410, "Lead has been deleted")

    from app.models import LeadUpdateIn
    data = LeadUpdateIn(assigned_to=assignee_sub, status="assigned")
    return update_lead(lead_id, actor_sub, data)


def get_assignment_queue(queue_id: str) -> Optional[dict]:
    """Retrieve assignment queue config row."""
    _require_leads()
    resp = T.leads.get_item(Key={"pk": f"QUEUE#{queue_id}", "sk": "CONFIG"})
    return resp.get("Item")


def upsert_assignment_queue(
    queue_id: str,
    actor_sub: str,
    agent_subs: List[str],
    name: str = "",
) -> dict:
    """Create or update a round-robin assignment queue (LED-010)."""
    _require_leads()
    if not S.leads_assignment_enabled:
        raise HTTPException(404, "Lead assignment is not enabled")

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"QUEUE#{queue_id}",
        "sk": "CONFIG",
        "queue_id": queue_id,
        "name": name,
        "agent_subs": agent_subs,
        "current_index": 0,
        "created_by": actor_sub,
        "updated_at": ts,
    }
    T.leads.put_item(Item=item)
    return item


def auto_assign_round_robin(lead_id: str, queue_id: str, actor_sub: str) -> dict:
    """Auto-assign a lead using round-robin from queue (LED-010)."""
    _require_leads()
    if not S.leads_assignment_enabled:
        raise HTTPException(404, "Lead assignment is not enabled")

    queue = get_assignment_queue(queue_id)
    if not queue:
        raise HTTPException(404, "Assignment queue not found")

    agents = queue.get("agent_subs") or []
    if not agents:
        raise HTTPException(400, "Assignment queue has no agents")

    idx = int(queue.get("current_index", 0)) % len(agents)
    assignee = agents[idx]
    next_idx = (idx + 1) % len(agents)

    # Advance queue index
    T.leads.update_item(
        Key={"pk": f"QUEUE#{queue_id}", "sk": "CONFIG"},
        UpdateExpression="SET current_index = :ci",
        ExpressionAttributeValues={":ci": next_idx},
    )

    return assign_lead(lead_id, assignee, actor_sub)


# ── LED-011: scoring engine ───────────────────────────────────────────────────

def get_scoring_rules() -> dict:
    """Return global scoring rules config (LED-011)."""
    _require_leads()
    resp = T.leads.get_item(Key={"pk": "SCORING_CONFIG", "sk": "RULES"})
    item = resp.get("Item")
    if not item:
        return {"rules": [], "max_score": 100, "updated_at": 0}
    return item


def update_scoring_rules(actor_sub: str, data: Any) -> dict:
    """Persist scoring rules (LED-011). Admin/Root only (enforced at router)."""
    _require_leads()
    if not S.leads_scoring_enabled:
        raise HTTPException(404, "Lead scoring is not enabled")

    ts = now_ts()
    rules_list = [r.model_dump() for r in data.rules]
    item: Dict[str, Any] = {
        "pk": "SCORING_CONFIG",
        "sk": "RULES",
        "rules": rules_list,
        "max_score": data.max_score,
        "updated_at": ts,
        "updated_by": actor_sub,
    }
    T.leads.put_item(Item=item)
    _audit("lead_scoring.rules_updated", actor_sub, rule_count=len(rules_list))
    return item


def _apply_scoring_rules(lead: dict, rules: List[dict], max_score: int) -> int:
    """Apply rules to a lead, returning computed score."""
    score = 0
    for rule in rules:
        field = rule.get("field", "")
        operator = rule.get("operator", "")
        value = str(rule.get("value", ""))
        points = int(rule.get("points", 0))
        lead_val = str(lead.get(field, "") or "")
        match = False
        if operator == "eq":
            match = lead_val == value
        elif operator == "contains":
            match = value.lower() in lead_val.lower()
        elif operator == "not_empty":
            match = bool(lead_val)
        elif operator == "empty":
            match = not bool(lead_val)
        elif operator == "gte" and lead_val.isdigit() and value.isdigit():
            match = int(lead_val) >= int(value)
        elif operator == "lte" and lead_val.isdigit() and value.isdigit():
            match = int(lead_val) <= int(value)
        if match:
            score += points
    return min(max(0, score), max_score)


def compute_lead_score(
    lead_id: str,
    actor_sub: str,
    trigger: str = "manual",
) -> dict:
    """Compute and persist the score for a lead (LED-011)."""
    _require_leads()
    if not S.leads_scoring_enabled:
        raise HTTPException(404, "Lead scoring is not enabled")

    lead = get_lead(lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")

    rules_row = get_scoring_rules()
    rules = rules_row.get("rules", [])
    max_score = rules_row.get("max_score", 100)
    score = _apply_scoring_rules(lead, rules, max_score)

    ts = now_ts()

    # Persist score on lead
    from app.models import LeadUpdateIn
    data = LeadUpdateIn(score=score)
    update_lead(lead_id, actor_sub, data)

    # Append score history row
    history_id = uuid.uuid4().hex[:16]
    T.leads.put_item(Item={
        "pk": f"LEAD#{lead_id}",
        "sk": f"SCORE#{ts:010d}#{history_id}",
        "score": score,
        "trigger": trigger,
        "computed_at": ts,
        "lead_id": lead_id,
    })

    _audit("lead.score_computed", actor_sub, lead_id=lead_id, score=score, trigger=trigger)
    return {"lead_id": lead_id, "score": score, "computed_at": ts, "trigger": trigger}


def get_score_history(lead_id: str, *, cursor: Optional[str] = None, limit: int = 20) -> dict:
    """Return score history for a lead (LED-011 / LED-013). Per-resource ownership enforced at router."""
    _require_leads()
    limit = max(1, min(limit, 100))
    esk = decode_cursor(cursor) if cursor else None

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"LEAD#{lead_id}") & Key("sk").begins_with("SCORE#")
        ),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk
    resp = T.leads.query(**kwargs)
    items = resp.get("Items", [])
    next_esk = resp.get("LastEvaluatedKey")

    entries = [
        {
            "score": int(i.get("score", 0)),
            "trigger": i.get("trigger", ""),
            "computed_at": int(i.get("computed_at", 0)),
            "lead_id": i.get("lead_id", lead_id),
        }
        for i in items
    ]
    return {
        "lead_id": lead_id,
        "entries": entries,
        "cursor": encode_cursor(next_esk) if next_esk else None,
    }


# ── LED-012: CRM activity log on Lead ─────────────────────────────────────────

_CRM_ACTIVITY_TTL_SECONDS = 365 * 24 * 3600  # ~1 year (intentional per spec)


def log_lead_activity(
    lead_id: str,
    actor_sub: str,
    activity_type: str,
    *,
    subject: Optional[str] = None,
    description: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Append a CRM activity log row to a lead (LED-012)."""
    _require_leads()

    lead = get_lead(lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")

    ts = now_ts()
    activity_id = uuid.uuid4().hex[:20]
    item: Dict[str, Any] = {
        "pk": f"LEAD#{lead_id}",
        "sk": f"ACTIVITY#{ts:010d}#{activity_id}",
        "activity_id": activity_id,
        "lead_id": lead_id,
        "activity_type": activity_type,
        "actor_sub": actor_sub,
        "created_at": ts,
        "ttl": ts + _CRM_ACTIVITY_TTL_SECONDS,
    }
    if subject:
        item["subject"] = subject
    if description:
        item["description"] = description
    if metadata:
        item["metadata"] = metadata

    T.leads.put_item(Item=item)
    _audit(
        "lead.activity_logged", actor_sub,
        lead_id=lead_id, activity_type=activity_type, activity_id=activity_id,
    )
    return item


def list_lead_activities(
    lead_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List CRM activity log entries for a lead, newest-first (LED-012)."""
    _require_leads()
    limit = max(1, min(limit, 200))
    esk = decode_cursor(cursor) if cursor else None

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"LEAD#{lead_id}") & Key("sk").begins_with("ACTIVITY#")
        ),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk
    resp = T.leads.query(**kwargs)
    items = resp.get("Items", [])
    next_esk = resp.get("LastEvaluatedKey")

    return {
        "activities": items,
        "cursor": encode_cursor(next_esk) if next_esk else None,
    }
