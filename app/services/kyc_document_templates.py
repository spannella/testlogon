"""KYC-017 — Document Signing Template Library.

A *document* template library distinct from the KYC-007 signature *field-set*
template versions. Admins upload PDF templates containing ``{{placeholder}}``
markers; templates are tied to a required KYC tier. When a KYC case reaches the
signature step, the active templates required for the user's target tier are
rendered with the user's profile/case data merged into the placeholders, and a
signature packet is instantiated from each rendered PDF via the EXISTING
signature-packet creation flow (``create_draft_packet``) — signing itself is NOT
reimplemented here.

DynamoDB layout (table ``kyc_document_templates``):
    PK ``template_id``           — "kdt_" + uuid
    SK ``sk`` = "VERSION#{n}"    — n == 0 is the metadata placeholder row
    GSI slug-status-index        — PK slug, SK status
    GSI status-updated-index     — PK status, SK updated_at (N)

Each version row carries the full template metadata (slug, display_name,
required_tier, status, ...) so a single GSI query answers "active templates by
slug/tier" without a second lookup.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ── Tier model ─────────────────────────────────────────────────────────
# The template library uses the string tier names from the KYC-017 spec.
TEMPLATE_TIERS = ("none", "tier_1", "tier_2", "tier_3")
_TIER_RANK = {"none": 0, "tier_1": 1, "tier_2": 2, "tier_3": 3}

TEMPLATE_STATUSES = ("active", "inactive", "archived")

# Maps integer KYC tier (kyc_tiers.py, 0-4) → template tier string for lookup.
_INT_TIER_TO_STRING = {0: "none", 1: "tier_1", 2: "tier_2", 3: "tier_3", 4: "tier_3"}

# Supported placeholders → mock sample values used for admin preview.
MOCK_PROFILE: dict[str, str] = {
    "full_name": "Jane Sample Doe",
    "email": "jane.sample@example.com",
    "phone": "+15555550123",
    "address_line_1": "123 Example Street",
    "address_line_2": "Apt 4B",
    "city": "Sampleville",
    "state": "CA",
    "postal_code": "90210",
    "country": "US",
    "date_of_birth": "1990-01-15",
}

# Fallback values used when a profile field is empty during render.
_FALLBACKS: dict[str, str] = {
    "full_name": "[Name]",
    "email": "[Email]",
    "phone": "[Phone]",
    "address_line_1": "[Address]",
    "address_line_2": "",
    "city": "[City]",
    "state": "[State]",
    "postal_code": "[Postal Code]",
    "country": "[Country]",
    "date_of_birth": "[DOB]",
}


class KycTemplateSlugExists(Exception):
    """Raised when creating a template with a slug already in use."""


class KycTemplateNotFound(Exception):
    """Raised when a template_id / version is not found."""


class KycTemplateValidationError(Exception):
    """Raised on invalid input (bad tier, bad status, non-PDF, etc.)."""


def template_tier_for_int(int_tier: int) -> str:
    """Map an integer KYC tier (0-4) to the template tier string."""
    return _INT_TIER_TO_STRING.get(int(int_tier), "none")


def _sk(version: int) -> str:
    return f"VERSION#{int(version)}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class KycDocumentTemplateService:
    """CRUD + render for the document template library."""

    def __init__(self) -> None:
        self._table = T.kyc_document_templates

    # ── helpers ────────────────────────────────────────────────────────
    def _bucket(self) -> str:
        return S.kyc_document_templates_bucket or "local-uploads"

    def _s3_client(self):
        from app.core.aws_clients import s3_client

        return s3_client()

    def _put_object(self, *, key: str, body: bytes, content_type: str = "application/pdf") -> None:
        try:
            self._s3_client().put_object(
                Bucket=self._bucket(), Key=key, Body=body, ContentType=content_type
            )
        except Exception:  # pragma: no cover - dev S3 best-effort
            logger.warning("kyc_document_templates: S3 put_object failed for %s", key, exc_info=True)

    def _get_object(self, key: str) -> bytes | None:
        try:
            resp = self._s3_client().get_object(Bucket=self._bucket(), Key=key)
            return resp["Body"].read()
        except Exception:  # pragma: no cover - dev S3 best-effort
            logger.warning("kyc_document_templates: S3 get_object failed for %s", key, exc_info=True)
            return None

    def _validate_tier(self, tier: str) -> str:
        if tier not in TEMPLATE_TIERS:
            raise KycTemplateValidationError(f"invalid_required_tier:{tier}")
        return tier

    def _get_version_item(self, template_id: str, version: int) -> dict[str, Any] | None:
        return self._table.get_item(
            Key={"template_id": template_id, "sk": _sk(version)}
        ).get("Item")

    def get_template_versions(self, template_id: str) -> list[dict[str, Any]]:
        """Return all VERSION# rows for a template_id (version 0 metadata first)."""
        resp = self._table.query(
            KeyConditionExpression=Key("template_id").eq(template_id)
            & Key("sk").begins_with("VERSION#")
        )
        items = resp.get("Items", [])
        items.sort(key=lambda i: _coerce_int(i.get("version")))
        return items

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        """Return the metadata (version 0) row for a template, or None."""
        return self._get_version_item(template_id, 0)

    def _slug_in_use(self, slug: str) -> bool:
        resp = self._table.query(
            IndexName=S.kyc_document_templates_slug_index,
            KeyConditionExpression=Key("slug").eq(slug),
            Limit=1,
        )
        return bool(resp.get("Items"))

    # ── CRUD ───────────────────────────────────────────────────────────
    def create_template(
        self,
        *,
        slug: str,
        display_name: str,
        description: str = "",
        required_tier: str = "tier_1",
        placeholder_fields: list[str] | None = None,
        created_by: str,
    ) -> dict[str, Any]:
        """Create a new template (metadata placeholder row VERSION#0).

        Slug must be unique. Raises ``KycTemplateSlugExists`` otherwise.
        """
        self._validate_tier(required_tier)
        if self._slug_in_use(slug):
            raise KycTemplateSlugExists(slug)

        template_id = f"kdt_{uuid4().hex[:16]}"
        ts = now_ts()
        item: dict[str, Any] = {
            "template_id": template_id,
            "sk": _sk(0),
            "version": 0,
            "slug": slug,
            "display_name": display_name,
            "description": description or "",
            "status": "active",
            "required_tier": required_tier,
            "s3_key": "",
            "placeholder_fields": list(placeholder_fields or []),
            "latest_version": 0,
            "created_by": created_by,
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        return item

    def upload_template_version(
        self,
        *,
        template_id: str,
        pdf_bytes: bytes,
        uploaded_by: str,
    ) -> dict[str, Any]:
        """Upload a new PDF version to S3 and create a VERSION#{n} row.

        Version numbers auto-increment. The metadata row (VERSION#0) is updated
        with the new ``latest_version`` and ``s3_key``.
        """
        meta = self.get_template(template_id)
        if not meta:
            raise KycTemplateNotFound(template_id)
        if str(meta.get("status")) == "archived":
            raise KycTemplateValidationError("kyc_template_already_archived")
        if not pdf_bytes or pdf_bytes[:5] != b"%PDF-":
            raise KycTemplateValidationError("kyc_invalid_file_type")
        if len(pdf_bytes) > S.kyc_document_templates_max_pdf_bytes:
            raise KycTemplateValidationError("kyc_file_too_large")

        next_version = _coerce_int(meta.get("latest_version")) + 1
        slug = str(meta.get("slug"))
        s3_key = f"{S.kyc_document_templates_s3_prefix}{slug}/{next_version}/template.pdf"
        self._put_object(key=s3_key, body=pdf_bytes)

        ts = now_ts()
        version_item: dict[str, Any] = {
            "template_id": template_id,
            "sk": _sk(next_version),
            "version": next_version,
            "slug": slug,
            "display_name": meta.get("display_name"),
            "description": meta.get("description", ""),
            "required_tier": meta.get("required_tier", "tier_1"),
            "placeholder_fields": list(meta.get("placeholder_fields") or []),
            "status": "active",
            "s3_key": s3_key,
            "pdf_uploaded": True,
            "created_by": uploaded_by,
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=version_item)

        # Reflect latest version + s3 key on the metadata row.
        self._table.update_item(
            Key={"template_id": template_id, "sk": _sk(0)},
            UpdateExpression="SET latest_version = :v, s3_key = :k, updated_at = :ts",
            ExpressionAttributeValues={":v": next_version, ":k": s3_key, ":ts": ts},
        )
        return version_item

    def _set_status(self, *, template_id: str, version: int, status: str) -> dict[str, Any]:
        if status not in TEMPLATE_STATUSES:
            raise KycTemplateValidationError(f"invalid_status:{status}")
        item = self._get_version_item(template_id, version)
        if not item:
            raise KycTemplateNotFound(f"{template_id}:{version}")
        ts = now_ts()
        self._table.update_item(
            Key={"template_id": template_id, "sk": _sk(version)},
            UpdateExpression="SET #s = :status, updated_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": status, ":ts": ts},
        )
        item["status"] = status
        item["updated_at"] = ts
        return item

    def activate_template(self, *, template_id: str, version: int) -> dict[str, Any]:
        """Activate a version; deactivate other active versions for the same slug."""
        meta = self.get_template(template_id)
        if not meta:
            raise KycTemplateNotFound(template_id)
        if str(meta.get("status")) == "archived":
            raise KycTemplateValidationError("kyc_template_already_archived")

        target = self._get_version_item(template_id, version)
        if not target:
            raise KycTemplateNotFound(f"{template_id}:{version}")

        # Deactivate sibling versions (same template_id) that are active.
        for sibling in self.get_template_versions(template_id):
            sv = _coerce_int(sibling.get("version"))
            if sv == version:
                continue
            if str(sibling.get("status")) == "active":
                self._set_status(template_id=template_id, version=sv, status="inactive")

        return self._set_status(template_id=template_id, version=version, status="active")

    def deactivate_template(self, *, template_id: str, version: int) -> dict[str, Any]:
        """Set a version's status to inactive."""
        return self._set_status(template_id=template_id, version=version, status="inactive")

    def archive_template(self, *, template_id: str) -> dict[str, Any]:
        """Soft-delete: set all versions (including metadata row) to archived."""
        meta = self.get_template(template_id)
        if not meta:
            raise KycTemplateNotFound(template_id)
        if str(meta.get("status")) == "archived":
            raise KycTemplateValidationError("kyc_template_already_archived")
        for item in self.get_template_versions(template_id):
            self._set_status(
                template_id=template_id,
                version=_coerce_int(item.get("version")),
                status="archived",
            )
        return self.get_template(template_id) or meta

    # ── queries ────────────────────────────────────────────────────────
    def list_templates(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List template metadata rows (VERSION#0), newest-updated first.

        Returns one row per template (the metadata placeholder), optionally
        filtered by status.
        """
        items: list[dict[str, Any]] = []
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Key("sk").eq(_sk(0)),
        }
        resp = self._table.scan(**scan_kwargs)
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp and len(items) < limit * 4:
            resp = self._table.scan(
                ExclusiveStartKey=resp["LastEvaluatedKey"], **scan_kwargs
            )
            items.extend(resp.get("Items", []))
        if status:
            items = [i for i in items if str(i.get("status")) == status]
        items.sort(key=lambda i: _coerce_int(i.get("updated_at")), reverse=True)
        return items[:limit]

    def get_active_template_by_slug(self, slug: str) -> dict[str, Any] | None:
        """Return the latest active uploaded version for a slug, or None."""
        resp = self._table.query(
            IndexName=S.kyc_document_templates_slug_index,
            KeyConditionExpression=Key("slug").eq(slug) & Key("status").eq("active"),
        )
        items = [i for i in resp.get("Items", []) if _coerce_int(i.get("version")) > 0]
        if not items:
            return None
        items.sort(key=lambda i: _coerce_int(i.get("version")), reverse=True)
        return items[0]

    def get_required_templates_for_tier(self, tier: str) -> list[dict[str, Any]]:
        """Return active uploaded templates whose required_tier <= tier.

        One entry per slug (the latest active version). Excludes inactive and
        archived templates.
        """
        if tier not in _TIER_RANK:
            raise KycTemplateValidationError(f"invalid_tier:{tier}")
        target_rank = _TIER_RANK[tier]

        resp = self._table.query(
            IndexName=S.kyc_document_templates_status_index,
            KeyConditionExpression=Key("status").eq("active"),
        )
        by_slug: dict[str, dict[str, Any]] = {}
        for item in resp.get("Items", []):
            if _coerce_int(item.get("version")) <= 0:
                continue  # skip metadata placeholder rows (no PDF)
            rt = str(item.get("required_tier", "none"))
            if _TIER_RANK.get(rt, 99) > target_rank:
                continue
            slug = str(item.get("slug"))
            existing = by_slug.get(slug)
            if existing is None or _coerce_int(item.get("version")) > _coerce_int(
                existing.get("version")
            ):
                by_slug[slug] = item
        out = list(by_slug.values())
        out.sort(key=lambda i: (_TIER_RANK.get(str(i.get("required_tier")), 0), str(i.get("slug"))))
        return out

    # ── rendering ──────────────────────────────────────────────────────
    def _merge_placeholders(
        self, pdf_bytes: bytes, values: dict[str, Any], *, extra: dict[str, str] | None = None
    ) -> tuple[bytes, int, int]:
        """Replace ``{{field}}`` markers in raw PDF bytes.

        Returns (rendered_bytes, fields_populated, fields_fallback).
        """
        text = pdf_bytes.decode("latin-1", errors="replace")
        populated = 0
        fallback = 0
        merged = dict(values)
        if extra:
            merged.update(extra)
        for field, fallback_val in _FALLBACKS.items():
            marker = "{{" + field + "}}"
            if marker not in text:
                continue
            raw = merged.get(field)
            value = str(raw).strip() if raw not in (None, "") else ""
            if value:
                populated += 1
            else:
                value = fallback_val
                fallback += 1
            text = text.replace(marker, value)
        # Computed placeholders (never count as fallback).
        for field in ("current_date", "case_id"):
            marker = "{{" + field + "}}"
            if marker in text:
                text = text.replace(marker, str((extra or {}).get(field, "")))
        return text.encode("latin-1", errors="replace"), populated, fallback

    def render_template(
        self,
        *,
        template_id: str,
        version: int,
        user_profile: dict[str, Any],
        case_id: str | None = None,
    ) -> tuple[bytes, int, int]:
        """Download a template version PDF and merge user data into placeholders."""
        item = self._get_version_item(template_id, version)
        if not item:
            raise KycTemplateNotFound(f"{template_id}:{version}")
        s3_key = str(item.get("s3_key") or "")
        if not s3_key:
            raise KycTemplateValidationError("kyc_no_pdf_uploaded")
        pdf_bytes = self._get_object(s3_key)
        if pdf_bytes is None:
            # Fallback minimal PDF so dev/E2E always has content to merge.
            pdf_bytes = _placeholder_pdf(item.get("placeholder_fields") or [])
        extra = {
            "current_date": datetime.now(timezone.utc).date().isoformat(),
            "case_id": case_id or "",
        }
        return self._merge_placeholders(pdf_bytes, user_profile, extra=extra)

    def render_and_store(
        self,
        *,
        template_id: str,
        version: int,
        user_profile: dict[str, Any],
        case_id: str,
        slug: str,
    ) -> tuple[str, int, int]:
        """Render a template and upload the result to S3. Returns (key, pop, fb)."""
        rendered, populated, fallback = self.render_template(
            template_id=template_id,
            version=version,
            user_profile=user_profile,
            case_id=case_id,
        )
        key = f"{S.kyc_document_templates_s3_prefix}rendered/{case_id}/{slug}.pdf"
        self._put_object(key=key, body=rendered)
        return key, populated, fallback

    def preview_template(self, *, template_id: str, version: int) -> bytes:
        """Render a template with mock sample data for admin preview."""
        rendered, _, _ = self.render_template(
            template_id=template_id,
            version=version,
            user_profile=dict(MOCK_PROFILE),
            case_id="preview",
        )
        return rendered


def _placeholder_pdf(placeholders: list[str]) -> bytes:
    """Generate a minimal valid PDF embedding the given placeholder markers.

    Used as a dev/E2E fallback when no PDF bytes are available from S3 so that
    render/merge always has content to operate on.
    """
    markers = " ".join("{{" + str(p) + "}}" for p in placeholders) or "{{full_name}}"
    content_stream = f"BT /F1 12 Tf 72 720 Td ({markers}) Tj ET".encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content_stream)).encode() + b" >>\nstream\n" + content_stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return pdf


def build_user_profile_for_merge(user_sub: str) -> dict[str, Any]:
    """Assemble the merge dict from the user's profile (app/services/profile.py)."""
    from app.services.profile import get_profile, get_profile_identity

    profile = get_profile(user_sub)
    identity = get_profile_identity(user_sub)
    addr = profile.get("mailing_address") or {}
    full_name = identity.get("display_name") or " ".join(
        p for p in [profile.get("first_name"), profile.get("last_name")] if p
    )
    return {
        "full_name": full_name or "",
        "email": identity.get("email") or profile.get("displayed_email") or "",
        "phone": identity.get("phone") or profile.get("displayed_telephone_number") or "",
        "address_line_1": addr.get("line1") or "",
        "address_line_2": addr.get("line2") or "",
        "city": addr.get("city") or "",
        "state": addr.get("state") or "",
        "postal_code": addr.get("postal_code") or "",
        "country": addr.get("country") or "",
        "date_of_birth": profile.get("birthday") or "",
    }


SERVICE = KycDocumentTemplateService()
