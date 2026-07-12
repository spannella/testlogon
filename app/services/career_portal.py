"""ATS Career Portal service (PRT-001..PRT-005).

Implements:
  - Portal config admin CRUD (PRT-001)
  - Public job listing + slug detail (PRT-002)
  - RSS 2.0 feed builder (PRT-003)
  - Self-apply endpoint (PRT-004)
  - Résumé upload presign (PRT-005)

All functions are synchronous (no async def). Forward dependencies on
JOB-*, CND-*, PIP-* are lazy-imported inside try/except so this module
compiles and operates whether or not those clusters are deployed.
"""

from __future__ import annotations

import html as _html
import re as _re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ── Constants ──────────────────────────────────────────────────────────────

_CONFIG_PK = "CONFIG"
_CONFIG_SK = "META"

_OPEN_STATUSES = {"open", "active"}

_CAREER_RESUME_ALLOWED_TYPES: set = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

# ── Flag guard ──────────────────────────────────────────────────────────────


def _require_enabled() -> None:
    """Raise 404 when career_portal_enabled is False.

    Mirrors CMP-006 _require_web_lead_enabled and KB-011 flag-gated guard.
    """
    if not S.career_portal_enabled:
        raise HTTPException(status_code=404, detail="Not found")


# ── Logo URL resolution ──────────────────────────────────────────────────────


def _resolve_logo_url(logo_file_path: Optional[str]) -> Optional[str]:
    """Derive a download URL from a file-manager path at read time.

    Uses build_download_url (filemanager.py:2374) so dev returns
    http://localhost:8000/v1/fs/download?path=... and prod a real URL —
    no dev_mode branch here (SECOPS-007).
    """
    if not logo_file_path:
        return None
    try:
        from app.services.filemanager import build_download_url
        return build_download_url(logo_file_path)
    except Exception:
        return None


# ── PRT-001: Admin portal config ─────────────────────────────────────────────


def get_portal_config() -> dict:
    """Return the config row. Returns S-default branding when no row exists (never 500)."""
    _require_enabled()
    item = T.career_portal.get_item(
        Key={"pk": _CONFIG_PK, "sk": _CONFIG_SK}
    ).get("Item") or {}
    return {
        "portal_name": item.get("portal_name", "Careers"),
        "intro_copy": item.get("intro_copy", ""),
        "logo_file_path": item.get("logo_file_path"),
        "logo_url": _resolve_logo_url(item.get("logo_file_path")),
        "primary_color": item.get("primary_color"),
        "support_email": item.get("support_email"),
        "updated_at": int(item["updated_at"]) if item.get("updated_at") else None,
        "updated_by": item.get("updated_by"),
    }


def set_portal_config(data: dict, *, actor_sub: str) -> dict:
    """Persist branding config. Overwrites entire row (last-write-wins)."""
    _require_enabled()
    now = now_ts()
    item: dict = {
        "pk": _CONFIG_PK,
        "sk": _CONFIG_SK,
        "portal_name": data["portal_name"],
        "intro_copy": data.get("intro_copy", ""),
        "updated_at": now,
        "updated_by": actor_sub,
    }
    if data.get("logo_file_path") is not None:
        item["logo_file_path"] = data["logo_file_path"]
    if data.get("primary_color") is not None:
        item["primary_color"] = data["primary_color"]
    if data.get("support_email") is not None:
        item["support_email"] = data["support_email"]
    T.career_portal.put_item(Item=item)
    try:
        from app.services.alerts import audit_event  # local import — SECOPS-007 parity
        audit_event("career_portal.config_updated", actor_sub,
                    portal_name=data["portal_name"])
    except Exception:
        pass
    return get_portal_config()


# ── PRT-002: Public listing + slug detail ─────────────────────────────────────


def get_portal_config_public() -> dict:
    """Public wrapper around get_portal_config — entry point for the /config endpoint."""
    _require_enabled()
    return get_portal_config()


def _to_job_summary(jo: dict) -> dict:
    """Extract only public-safe fields from a job order dict."""
    return {
        "job_order_id": jo["job_order_id"],
        "slug": jo["slug"],
        "title": jo["title"],
        "location": jo.get("location"),
        "employment_type": jo.get("employment_type"),
        "posted_at": int(jo.get("posted_at") or jo.get("created_at", 0)),
        "openings": int(jo.get("openings", 1)),
    }


def list_public_jobs(
    *,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> dict:
    """Return paginated public job listing.

    Delegates to JOB-* list_public_job_orders.
    Graceful degradation: any import or runtime error → empty list.
    """
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor
    esk = decode_cursor(cursor)
    try:
        from app.services.job_orders import list_public_job_orders  # lazy import
        result = list_public_job_orders(limit=limit, exclusive_start_key=esk)
        items = [_to_job_summary(jo) for jo in result.get("items", [])]
        next_cursor = encode_cursor(result.get("last_evaluated_key"))
    except Exception:
        items = []
        next_cursor = None
    return {"items": items, "cursor": next_cursor, "total_estimate": None}


def _resolve_screening_questionnaire_slug(questionnaire_id: Optional[str]) -> Optional[str]:
    """Return the published slug of a linked questionnaire, or None.

    Best-effort: any error → None (never blocks the detail page).
    Reuses DynamoQuestionnaireRepository from app/services/questionnaires_repository.py.
    """
    if not questionnaire_id:
        return None
    try:
        from app.services.questionnaires_repository import DynamoQuestionnaireRepository
        repo = DynamoQuestionnaireRepository()
        draft = repo.get_questionnaire(questionnaire_id)
        if not draft or draft.get("status") != "published":
            return None
        published_version_id = draft.get("published_version_id")
        if not published_version_id:
            return None
        version = repo.get_version_by_id(questionnaire_id, published_version_id)
        if not version:
            return None
        return version.get("published_slug")
    except Exception:
        return None


def get_job_detail(slug: str) -> dict:
    """Resolve SLUG#{slug} → job_order_id → full job order.

    Returns a CareerJobDetailOut dict.
    Raises HTTPException(404) for unknown/non-public/closed slugs.
    Never returns internal fields (pay_rate, bill_rate, recruiter_notes, etc.).
    """
    _require_enabled()
    # 1. Resolve slug index row
    slug_row = T.career_portal.get_item(
        Key={"pk": f"SLUG#{slug}", "sk": "META"}
    ).get("Item")
    if not slug_row:
        raise HTTPException(status_code=404, detail="Job not found")
    job_order_id = slug_row.get("job_order_id")
    if not job_order_id:
        raise HTTPException(status_code=404, detail="Job not found")

    # 2. Load job order from JOB-* service
    jo = None
    try:
        from app.services.job_orders import get_job_order  # lazy import
        jo = get_job_order(job_order_id)
    except Exception:
        pass
    if not jo:
        raise HTTPException(status_code=404, detail="Job not found")

    # 3. Visibility gate: must be public + open
    if not jo.get("is_public"):
        raise HTTPException(status_code=404, detail="Job not found")
    if jo.get("status") not in _OPEN_STATUSES:
        raise HTTPException(status_code=404, detail="Job not found")

    # 4. Resolve optional screening questionnaire slug
    q_slug = _resolve_screening_questionnaire_slug(jo.get("screening_questionnaire_id"))

    return {
        **_to_job_summary(jo),
        "public_description": jo.get("public_description"),
        "screening_questionnaire_slug": q_slug,
        "apply_path": f"/public/careers/jobs/{slug}/apply",
    }


# ── PRT-003: RSS feed builder ────────────────────────────────────────────────


def _xml_escape(v: object) -> str:
    """Escape a value for safe interpolation into XML text content or attribute values.
    Uses stdlib html.escape (same pattern as app/services/seo_metadata.py:650-651).
    Covers &, <, >, " per XML 1.0 §2.4.
    """
    return _html.escape("" if v is None else str(v), quote=True)


def _rfc822_date(unix_ts: int) -> str:
    """Format a Unix timestamp as an RFC-822 date string for RSS <pubDate>/<lastBuildDate>."""
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _strip_html_excerpt(text: Optional[str], max_chars: int = 500) -> str:
    """Strip HTML tags and return a plain-text excerpt for RSS <description>.

    Reuses the _extract_excerpt regex approach from KB-011 §4.2.
    Inline here to avoid a cross-service import cycle.
    """
    if not text:
        return ""
    text = _re.sub(r"<[^>]+>", " ", text)
    text = _re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


def build_jobs_rss() -> str:
    """Build an RSS 2.0 XML document for public job listings.

    Returns a well-formed RSS 2.0 string. Calls _require_enabled() → 404 when
    career_portal_enabled is False. Calls list_public_jobs() (PRT-002) which
    already lazy-imports JOB-* and degrades gracefully to an empty list if absent.
    Channel metadata comes from get_portal_config() (PRT-001), which returns
    S-defaults if no admin config row exists.
    """
    _require_enabled()

    config = get_portal_config()          # never raises; returns S-defaults on no row
    portal_name = _xml_escape(config.get("portal_name") or "Careers")
    support_email = _xml_escape(config.get("support_email") or "")

    rss_max = getattr(S, "career_portal_rss_max_items", 50)
    listing = list_public_jobs(limit=rss_max, cursor=None)
    items: list = listing.get("items", []) or []

    portal_link = f"{S.public_base_url}/careers"
    now_str = _rfc822_date(now_ts())

    lines: list = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
        "  <channel>",
        f"    <title>{portal_name} — Open Positions</title>",
        f"    <link>{_xml_escape(portal_link)}</link>",
        f"    <description>Current job openings at {portal_name}</description>",
        "    <language>en-us</language>",
        f"    <lastBuildDate>{now_str}</lastBuildDate>",
        (
            f'    <atom:link href="{_xml_escape(S.public_base_url)}/public/careers/jobs.rss"'
            f' rel="self" type="application/rss+xml" />'
        ),
    ]
    if support_email:
        lines.append(f"    <managingEditor>{support_email}</managingEditor>")

    for item in items:
        slug = item.get("slug", "")
        item_link = f"{S.public_base_url}/public/careers/jobs/{_xml_escape(slug)}"
        posted_at = int(item.get("posted_at") or 0)
        pub_date = _rfc822_date(posted_at) if posted_at else now_str
        description_text = _strip_html_excerpt(item.get("public_description") or "", 500)

        lines += [
            "    <item>",
            f"      <title>{_xml_escape(item.get('title', ''))}</title>",
            f"      <link>{_xml_escape(item_link)}</link>",
            f"      <guid isPermaLink=\"true\">{_xml_escape(item_link)}</guid>",
            f"      <pubDate>{pub_date}</pubDate>",
            f"      <description>{_xml_escape(description_text)}</description>",
        ]
        if item.get("location"):
            lines.append(
                f"      <category>{_xml_escape(item['location'])}</category>"
            )
        if item.get("employment_type"):
            lines.append(
                f"      <category>{_xml_escape(item['employment_type'])}</category>"
            )
        lines.append("    </item>")

    lines += ["  </channel>", "</rss>"]
    return "\n".join(lines)


# ── PRT-004: Self-apply ───────────────────────────────────────────────────────


def create_application(
    *,
    slug: str,
    data: "CareerApplyIn",
    source_ip: str,
) -> "CareerApplyOut":
    """Process a public self-apply submission.

    Steps:
    1 - Flag guard
    2 - Honeypot check
    3 - Rate limit
    4 - Slug resolution
    5 - Job order validation (JOB-*, lazy)
    6 - Email normalization
    7 - Generate application_id
    8 - Create Candidate (CND-*, lazy)
    9 - Add to pipeline (PIP-*, lazy)
    9a - Finalize résumé upload (PRT-005, optional)
    9b - Attach résumé to Candidate (PRT-005, optional)
    9c - Read and store screening answers (PRT-005, optional)
    10 - Persist Application row
    11 - Best-effort emails
    12 - Audit event
    13 - Return
    """
    # Late import to avoid circular at module level; these are in models.py
    from app.models import CareerApplyOut

    # Step 1 — Flag guard
    _require_enabled()

    # Step 2 — Honeypot check
    if data.honeypot:
        return CareerApplyOut(application_id="bot", status="received")

    # Step 3 — Rate limit
    # Default anonymized IP (fallback in case rate_limit module is unavailable)
    anon_ip = (source_ip or "unknown").rsplit(".", 1)[0] if "." in (source_ip or "") else (source_ip or "unknown")
    try:
        from app.services.rate_limit import _bucket_limit, _ip_prefix
        anon_ip = _ip_prefix(source_ip or "unknown")
        if not _bucket_limit(
            f"ip#{anon_ip}",
            "rl#career_apply",
            S.career_portal_apply_rate_limit_per_ip_per_hour,
            3600,
        ):
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "Too many applications; try again later"},
            )
    except HTTPException:
        raise
    except Exception:
        pass  # anon_ip fallback already set above

    # Step 4 — Slug resolution
    slug_row = T.career_portal.get_item(
        Key={"pk": f"SLUG#{slug}", "sk": "META"}
    ).get("Item")
    if not slug_row:
        raise HTTPException(status_code=404, detail="Job posting not found")
    job_order_id = slug_row.get("job_order_id")
    if not job_order_id:
        raise HTTPException(status_code=404, detail="Job posting not found")

    # Step 5 — Job order validation
    try:
        from app.services import job_orders as _job_svc
        job = _job_svc.get_job_order_for_apply(job_order_id)
    except Exception:
        job = None
    if not job:
        raise HTTPException(status_code=404, detail="Job posting not available")

    # Step 6 — Email normalization
    try:
        from app.core.normalize import normalize_email
        email = normalize_email(data.email)
    except Exception:
        email = (data.email or "").strip()
    email_raw = data.email

    # Step 7 — Generate application ID
    application_id = "app_" + uuid4().hex[:20]

    # Step 8 — Create Candidate (best-effort)
    candidate_id: Optional[str] = None
    try:
        from app.services import candidates as _cnd_svc
        cnd_kwargs: dict = {
            "first_name": data.first_name,
            "last_name": data.last_name,
            "email": email,
            "source": "career_portal",
        }
        if data.phone:
            cnd_kwargs["phone"] = data.phone
        # Build CandidateCreateIn — use Pydantic model if available; fallback to SimpleNamespace.
        try:
            from app.models import CandidateCreateIn as _CndIn
            try:
                cnd_data = _CndIn(origin_job_order_id=job_order_id, **cnd_kwargs)
            except Exception:
                cnd_data = _CndIn(**cnd_kwargs)
        except ImportError:
            from types import SimpleNamespace as _SN
            cnd_data = _SN(**cnd_kwargs, origin_job_order_id=job_order_id)
        cnd_item = _cnd_svc.create_candidate(
            creator_sub="system_career_portal",
            data=cnd_data,
        )
        candidate_id = cnd_item.get("candidate_id") if isinstance(cnd_item, dict) else getattr(cnd_item, "candidate_id", None)
    except Exception:
        pass

    # Step 9 — Add to pipeline (best-effort, only if candidate_id set)
    pipeline_entry_id: Optional[str] = None
    if candidate_id:
        try:
            from app.services import pipeline as _pip_svc
            # Build PipelineEntryCreateIn — use Pydantic model if available; fallback to SimpleNamespace.
            try:
                from app.models import PipelineEntryCreateIn as _PipIn
                pip_data = _PipIn(
                    job_order_id=job_order_id,
                    candidate_id=candidate_id,
                    status="100_no_contact",
                )
            except ImportError:
                from types import SimpleNamespace as _SN2
                pip_data = _SN2(
                    job_order_id=job_order_id,
                    candidate_id=candidate_id,
                    status="100_no_contact",
                )
            pip_item = _pip_svc.add_to_pipeline(
                owner_sub="system_career_portal",
                data=pip_data,
            )
            pipeline_entry_id = getattr(pip_item, "pipeline_id", None) or (
                pip_item.get("pipeline_id") if isinstance(pip_item, dict) else None
            )
        except Exception:
            pass

    # Step 9a — Finalize résumé upload (PRT-005, best-effort)
    resume_ticket_id = getattr(data, "resume_ticket_id", None)
    resume_file_path: Optional[str] = None
    resume_linked: bool = False
    if resume_ticket_id:
        try:
            from app.services.filemanager import register_presigned_upload, _table as _fm_table_fn, pk_user, _upload_ticket_sk  # type: ignore[attr-defined]
            ticket_row = _fm_table_fn().get_item(
                Key={
                    "PK": pk_user("system_career_portal"),
                    "SK": _upload_ticket_sk(resume_ticket_id),
                },
                ConsistentRead=True,
            ).get("Item")
            if ticket_row:
                node = register_presigned_upload(
                    "system_career_portal",
                    ticket_row["path"],
                    s3_key=ticket_row["s3_key"],
                    ticket_id=resume_ticket_id,
                    content_type=ticket_row.get("content_type"),
                )
                resume_file_path = node.get("path")
        except Exception:
            pass

    # Step 9b — Attach résumé to Candidate (PRT-005, best-effort)
    if candidate_id and resume_file_path:
        try:
            from app.services import candidates as _cnd_svc2
            _cnd_svc2.attach_resume_to_candidate(
                candidate_id=candidate_id,
                file_path=resume_file_path,
                node_id=None,
            )
            resume_linked = True
        except Exception:
            pass

    # Step 9c — Read and store screening answers (PRT-005, best-effort)
    screening_response_session_id = getattr(data, "screening_response_session_id", None)
    screening_answers: Optional[dict] = None
    screening_questionnaire_id_stored: Optional[str] = None
    if screening_response_session_id:
        try:
            from app.services import job_orders as _job_svc2
            q_id = _job_svc2.get_screening_questionnaire_id(job_order_id)
            if q_id:
                from app.services.questionnaires_repository import DynamoQuestionnaireRepository
                repo = DynamoQuestionnaireRepository()
                answers = repo.list_session_answers(
                    questionnaire_id=q_id,
                    response_session_id=screening_response_session_id,
                )
                screening_answers = answers
                screening_questionnaire_id_stored = q_id
        except Exception:
            pass

    # Step 10 — Persist Application row
    now = now_ts()
    item: dict = {
        "pk": f"APPLICATION#{application_id}",
        "sk": "META",
        "application_id": application_id,
        "job_order_id": job_order_id,
        "slug": slug,
        "email": email,
        "email_raw": email_raw,
        "first_name": data.first_name,
        "last_name": data.last_name,
        "source_ip": anon_ip,
        "status": "received",
        "created_at": now,
        "GSI1PK": f"JOB#{job_order_id}",
        "GSI1SK": now,
    }
    if candidate_id:
        item["candidate_id"] = candidate_id
    if pipeline_entry_id:
        item["pipeline_entry_id"] = pipeline_entry_id
    if data.phone:
        item["phone"] = data.phone
    if data.cover_note:
        item["cover_note"] = (data.cover_note or "")[:4000]
    # PRT-005 résumé fields
    if resume_ticket_id:
        item["resume_ticket_id"] = resume_ticket_id
    if resume_file_path:
        item["resume_file_path"] = resume_file_path
    if resume_ticket_id:
        item["resume_linked"] = resume_linked
    # PRT-005 screening answers
    if screening_response_session_id:
        item["screening_response_session_id"] = screening_response_session_id
    if screening_questionnaire_id_stored:
        item["screening_questionnaire_id"] = screening_questionnaire_id_stored
    if screening_answers is not None:
        item["screening_answers"] = screening_answers
        item["screening_answers_stored_at"] = now_ts()

    T.career_portal.put_item(Item=item)

    # Step 11 — Best-effort emails
    try:
        from app.services.alerts import send_alert_email
        if getattr(S, "career_portal_apply_autoresponder_enabled", False):
            subject = getattr(S, "career_portal_apply_autoresponder_subject", "We received your application")
            job_title = job.get("title", "") if isinstance(job, dict) else ""
            body = (
                f"Dear {data.first_name},\n\n"
                f"Thank you for applying to {job_title}. We will be in touch.\n"
            )
            try:
                send_alert_email([email], subject, body)
            except Exception:
                pass
        notify_email = getattr(S, "career_portal_apply_notify_email", "")
        if notify_email:
            subj = f"New application: {job.get('title', 'Unknown')} from {data.first_name} {data.last_name}"
            body2 = f"Applicant: {data.first_name} {data.last_name} <{email}>\nJob: {job_order_id}\nApplication: {application_id}\n"
            try:
                send_alert_email([notify_email], subj, body2)
            except Exception:
                pass
    except Exception:
        pass

    # Step 12 — Audit event
    try:
        from app.services.alerts import audit_event
        audit_event(
            "career_portal.applied",
            "anonymous",
            application_id=application_id,
            job_order_id=job_order_id,
            candidate_id=candidate_id,
            source_ip=anon_ip,
        )
    except Exception:
        pass

    # Step 13 — Return
    return CareerApplyOut(
        application_id=application_id,
        candidate_id=candidate_id,
        status="received",
    )


# ── PRT-005: Résumé presign ────────────────────────────────────────────────


def presign_resume_upload(
    *,
    slug: str,
    data: "CareerResumePresignIn",
    source_ip: str,
) -> "CareerResumePresignOut":
    """Mint a presigned S3 PUT URL for résumé upload.

    Steps:
    1 - Flag guard
    2 - Honeypot
    3 - Rate limit
    4 - Slug resolution
    5 - Content-type validation
    6 - Size validation
    7 - Build file-manager path
    8 - Presign
    9 - Return
    """
    from app.models import CareerResumePresignOut

    # Step 1 — Flag guard
    _require_enabled()

    # Step 2 — Honeypot
    if data.honeypot:
        return CareerResumePresignOut(
            upload_url="",
            ticket_id="bot",
            key="",
            path="",
            content_type=data.content_type,
        )

    # Step 3 — Rate limit (shared bucket with apply)
    _presign_anon_ip = (source_ip or "unknown").rsplit(".", 1)[0] if "." in (source_ip or "") else (source_ip or "unknown")
    try:
        from app.services.rate_limit import _bucket_limit, _ip_prefix
        _presign_anon_ip = _ip_prefix(source_ip or "unknown")
        if not _bucket_limit(
            f"ip#{_presign_anon_ip}",
            "rl#career_apply",
            S.career_portal_apply_rate_limit_per_ip_per_hour,
            3600,
        ):
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "Too many requests; try again later"},
            )
    except HTTPException:
        raise
    except Exception:
        pass

    # Step 4 — Slug resolution
    slug_row = T.career_portal.get_item(
        Key={"pk": f"SLUG#{slug}", "sk": "META"}
    ).get("Item")
    if not slug_row:
        raise HTTPException(status_code=404, detail="Job posting not found")
    job_order_id = slug_row.get("job_order_id")
    if not job_order_id:
        raise HTTPException(status_code=404, detail="Job posting not found")

    # Step 5 — Content-type validation
    if data.content_type not in _CAREER_RESUME_ALLOWED_TYPES:
        raise HTTPException(
            status_code=415,
            detail={"code": "unsupported_content_type", "message": "Résumé must be PDF, DOC, or DOCX"},
        )

    # Step 6 — Size validation
    resume_max = getattr(S, "career_portal_resume_max_bytes", 10 * 1024 * 1024)
    if data.size_bytes > resume_max:
        raise HTTPException(
            status_code=413,
            detail={"code": "file_too_large", "max_bytes": resume_max},
        )

    # Step 7 — Build file-manager path
    ext_map = {
        "application/pdf": "pdf",
        "application/msword": "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    }
    ext = ext_map[data.content_type]
    obj_id = uuid4().hex
    path = f"/career-portal/resumes/{job_order_id}/{obj_id}.{ext}"

    # Step 8 — Presign (auto-create parent folders first)
    try:
        from app.services.filemanager import presign_upload, _auto_create_parents  # type: ignore[attr-defined]
        _auto_create_parents("system_career_portal", f"/career-portal/resumes/{job_order_id}/")
        result = presign_upload(
            "system_career_portal",
            path,
            content_type=data.content_type,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Presign failed: {exc}") from exc

    # Step 9 — Return
    return CareerResumePresignOut(
        upload_url=result["upload_url"],
        ticket_id=result["ticket_id"],
        key=result["key"],
        path=result["path"],
        content_type=result["content_type"],
    )
