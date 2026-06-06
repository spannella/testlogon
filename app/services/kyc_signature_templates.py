"""KYC signature template library (GAP-0261 / KYC-007).

Provides five hard-coded KYC consent/declaration templates
(terms_of_service, aml_declaration, pep_declaration, tax_compliance,
data_consent), each with auto-populated fields and version tracking, plus
witness co-signing support for high-risk cases.

This module is intentionally *service-only*. It wraps the existing signature
packet-store primitives (``create_draft_packet`` / ``upsert_packet_field`` /
``add_packet_signer`` in ``app/services/signature_packet_store.py``) into a
KYC-specific template workflow. No new DynamoDB table is introduced: template
packets reuse the existing ``signature_packets`` / ``signature_packet_fields``
/ ``signature_packet_signers`` tables.

Dev/prod parity (SECOPS-007): every storage call goes through the packet-store
primitives, which are already moto-backed in dev and gated by the
``signature_pdf_enabled`` flag via ``require_signature_pdf_enabled``. No
AWS-specific path diverges.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.services.profile import get_profile
from app.services.signature_packet_domain import SignatureFieldType
from app.services.signature_packet_store import (
    add_packet_signer,
    create_draft_packet,
    upsert_packet_field,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Template library
# ---------------------------------------------------------------------------

KYC_TEMPLATE_TYPES: Dict[str, Dict[str, Any]] = {
    "terms_of_service": {
        "display_name": "Terms of Service Agreement",
        "description": "Platform terms and conditions acceptance",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "date_of_birth", "type": "text", "label": "Date of Birth", "auto_populate": "date_of_birth"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "aml_declaration": {
        "display_name": "Anti-Money Laundering Declaration",
        "description": "Declaration that funds are not derived from illegal activity",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "address", "type": "text", "label": "Residential Address", "auto_populate": "mailing_address"},
            {"id": "declaration_checkbox", "type": "checkbox",
             "label": "I declare that my funds are from legitimate sources"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "pep_declaration": {
        "display_name": "Politically Exposed Person Declaration",
        "description": "Declaration of PEP status or non-PEP status",
        "version": "2026-05-v1",
        "required_for": ["enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "is_pep", "type": "checkbox", "label": "I am or have been a Politically Exposed Person"},
            {"id": "pep_details", "type": "text", "label": "If PEP, describe position held",
             "conditional_on": "is_pep"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "tax_compliance": {
        "display_name": "Tax Compliance Declaration",
        "description": "Acknowledgment of tax reporting obligations",
        "version": "2026-05-v1",
        "required_for": ["enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "tax_id", "type": "text", "label": "Tax Identification Number"},
            {"id": "tax_country", "type": "text", "label": "Tax Residence Country", "auto_populate": "country"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
    "data_consent": {
        "display_name": "Data Processing Consent",
        "description": "Consent for KYC data processing and storage",
        "version": "2026-05-v1",
        "required_for": ["standard", "enhanced", "high_risk"],
        "fields": [
            {"id": "full_name", "type": "text", "label": "Full Legal Name", "auto_populate": "display_name"},
            {"id": "email", "type": "text", "label": "Email Address", "auto_populate": "email"},
            {"id": "consent_checkbox", "type": "checkbox", "label": "I consent to KYC data processing"},
            {"id": "signature", "type": "signature", "label": "Signature"},
            {"id": "date_signed", "type": "date", "label": "Date"},
        ],
    },
}


# Witness fields appended to packets that require a witness co-signer
# (high-risk intake profiles). Each is assigned to the witness signer.
WITNESS_FIELDS: List[Dict[str, Any]] = [
    {"id": "witness_name", "type": "text", "label": "Witness Name", "signer": "witness"},
    {"id": "witness_role", "type": "text", "label": "Witness Role", "signer": "witness",
     "default": "KYC Reviewer"},
    {"id": "witness_signature", "type": "signature", "label": "Witness Signature", "signer": "witness"},
    {"id": "witness_date", "type": "date", "label": "Date", "signer": "witness"},
]


def _coerce_field_type(raw_type: str) -> SignatureFieldType:
    """Map a template field ``type`` string to a valid ``SignatureFieldType``.

    The template spec uses ``checkbox`` (and may use other presentation-only
    types) that the underlying packet field enum does not model. Those degrade
    gracefully to ``TEXT`` so packet creation never fails on an unknown type.
    """
    try:
        return SignatureFieldType(raw_type)
    except ValueError:
        return SignatureFieldType.TEXT


class KycSignatureTemplateService:
    """KYC-specific template workflow over the signature packet store."""

    # -- template discovery -------------------------------------------------

    def get_required_templates(self, *, intake_profile: str) -> List[Dict[str, Any]]:
        """Return template configs required for the given intake profile.

        Each entry is the template dict with an added ``template_type`` key.
        """
        profile = (intake_profile or "").strip().lower()
        return [
            {"template_type": template_type, **config}
            for template_type, config in KYC_TEMPLATE_TYPES.items()
            if profile in config["required_for"]
        ]

    def get_template_version(self, template_type: str) -> str:
        """Return the current version string for a template type."""
        return KYC_TEMPLATE_TYPES[template_type]["version"]

    # -- profile auto-population --------------------------------------------

    def auto_populate_fields(
        self,
        *,
        template: Dict[str, Any],
        profile: Optional[Dict[str, Any]] = None,
        user_sub: Optional[str] = None,
    ) -> Dict[str, str]:
        """Map ``auto_populate`` field hints to actual profile values.

        Pass either a pre-loaded ``profile`` dict or a ``user_sub`` to load it
        from the profile service. Returns ``{field_id: value}`` only for fields
        that have an ``auto_populate`` hint resolvable from the profile.
        """
        if profile is None:
            profile = self._load_profile(user_sub or "")
        out: Dict[str, str] = {}
        for fdef in template.get("fields", []):
            hint = fdef.get("auto_populate")
            if hint and profile.get(hint) is not None:
                out[fdef["id"]] = str(profile[hint])
        return out

    # -- packet creation ----------------------------------------------------

    def create_packets_for_case(
        self,
        *,
        case_id: str,
        user_sub: str,
        intake_profile: str,
        source_pdf_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Create one signature packet per required template for the case.

        Auto-populates each template's fields from the user's profile and
        returns a list of ``{template_type, packet_id, version}`` summaries
        suitable for storing under ``case["signature"]["template_packets"]``.
        """
        templates = self.get_required_templates(intake_profile=intake_profile)
        profile = self._load_profile(user_sub)
        results: List[Dict[str, Any]] = []
        for tmpl in templates:
            packet = create_draft_packet(
                owner_user_id=user_sub,
                source_path=source_pdf_path,
                source_content_type="application/pdf",
                source_name=tmpl["display_name"],
                origin_channel="kyc_template",
                origin_ref=f"{case_id}:{tmpl['template_type']}",
            )
            packet_id = packet["packet_id"]
            populated = self.auto_populate_fields(template=tmpl, profile=profile)
            for fdef in tmpl.get("fields", []):
                upsert_packet_field(
                    packet_id=packet_id,
                    field_id=fdef["id"],
                    page=1,
                    x=0.0,
                    y=0.0,
                    width=200.0,
                    height=30.0,
                    field_type=_coerce_field_type(fdef["type"]),
                    assigned_signer_id=user_sub,
                    required=True,
                )
            results.append(
                {
                    "template_type": tmpl["template_type"],
                    "packet_id": packet_id,
                    "version": tmpl["version"],
                    "auto_populated": populated,
                }
            )
        logger.info(
            "kyc.signature_template.packets_created case_id=%s intake_profile=%s count=%d",
            case_id,
            intake_profile,
            len(results),
        )
        return results

    # -- version migration --------------------------------------------------

    def check_version_migration(self, *, case: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect template packets that are stale vs. the current template.

        Reads ``case["signature"]["template_packets"]`` and returns a list of
        ``{template_type, signed_version, current_version}`` for each packet
        whose recorded version no longer matches the current template version.
        """
        stale: List[Dict[str, Any]] = []
        signature = case.get("signature") or {}
        for tp in list(signature.get("template_packets", [])):
            template_type = tp.get("template_type")
            if template_type not in KYC_TEMPLATE_TYPES:
                continue
            current = self.get_template_version(template_type)
            if tp.get("version") != current:
                stale.append(
                    {
                        "template_type": template_type,
                        "signed_version": tp.get("version"),
                        "current_version": current,
                    }
                )
        return stale

    # -- witness co-signing -------------------------------------------------

    def add_witness_signer(self, *, packet_id: str, witness_sub: str) -> Dict[str, Any]:
        """Add an admin as a witness co-signer on a KYC signature packet.

        Appends the witness-specific fields and registers the witness as a
        second signer on the (DRAFT) packet.
        """
        for fdef in WITNESS_FIELDS:
            upsert_packet_field(
                packet_id=packet_id,
                field_id=fdef["id"],
                page=1,
                x=0.0,
                y=0.0,
                width=200.0,
                height=30.0,
                field_type=_coerce_field_type(fdef["type"]),
                assigned_signer_id=witness_sub,
                required=True,
            )
        return add_packet_signer(packet_id=packet_id, signer_id=witness_sub, required=True)

    # -- internals ----------------------------------------------------------

    def _load_profile(self, user_sub: str) -> Dict[str, Any]:
        """Load the user's profile via the profile service (T.profile-backed)."""
        if not user_sub:
            return {}
        try:
            return get_profile(user_sub) or {}
        except Exception:  # pragma: no cover - defensive; profile is best-effort
            logger.warning("kyc.signature_template.profile_load_failed user_sub=%s", user_sub)
            return {}


# Module-level singleton for convenient import-and-call usage.
kyc_signature_template_service = KycSignatureTemplateService()
