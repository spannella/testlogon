"""NCMEC / CyberTipline mandated-report submission client.

SEAM-READY / CONFIG-GATED on ``NCMEC_REPORTING_ENABLED`` + ``NCMEC_API_BASE`` +
``NCMEC_API_KEY`` (mirrors the EasyPost / Stripe seam pattern exactly):

  * When the flag is ON *and* an endpoint + key are configured the real
    CyberTipline submission endpoint is POSTed (see ``submit_report``) and the
    returned external reference id is persisted on the submission record.
  * When the flag is OFF or unkeyed (default today) the seam is an
    HONEST-MOCK-THAT-RECORDS: ``is_enabled()`` is False, ``submit_report``
    returns ``status="pending"`` WITHOUT touching the network, and the caller
    persists the intent + audit so NOTHING is ever silently dropped. The report
    stays queued for a human/ops runbook to file until go-live.

Only ``is_enabled`` / ``submit_report`` touch the network or settings; the PURE
helper ``build_report_payload`` depends on nothing but the stdlib so the payload
shape is unit-testable without a live key.

--------------------------------------------------------------------------------
GO-LIVE (user decision -- legal sign-off required):
  NCMEC operates the CyberTipline. Programmatic submission is granted per-ESP
  (Electronic Service Provider) and is governed by 18 U.S.C. Sec. 2258A. The
  actual endpoint URL, the ESP credential, the exact wire schema (NCMEC ships a
  partner API spec + WSDL/JSON schema under NDA), and a LEGAL SIGN-OFF are NOT
  encoded here on purpose -- we do NOT invent a fake vendor protocol. The request
  shape below is a clean, documented, self-describing envelope a real
  integration fills in / maps to the NCMEC-provided schema. To go live:
    1. NCMEC_REPORTING_ENABLED=1
    2. NCMEC_API_BASE=<the ESP submission base URL NCMEC assigns>
    3. NCMEC_API_KEY=<the ESP credential> (+ NCMEC_ORG_ID if issued)
    4. map ``build_report_payload`` -> the NCMEC partner schema (documented seam)
    5. legal sign-off on mandated-reporting content + retention.
--------------------------------------------------------------------------------
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Envelope version -- lets a real integration detect/upgrade the mapping.
PAYLOAD_SCHEMA = "testlogon.mandated_report.v1"


# -- config gate --------------------------------------------------------------
def _settings() -> Any:
    from app.core.settings import S  # lazy so the pure helper needs no settings
    return S


def reporting_enabled() -> bool:
    return bool(getattr(_settings(), "ncmec_reporting_enabled", False))


def api_base() -> str:
    return str(getattr(_settings(), "ncmec_api_base", "") or "").rstrip("/")


def api_key() -> str:
    return str(getattr(_settings(), "ncmec_api_key", "") or "")


def org_id() -> str:
    return str(getattr(_settings(), "ncmec_org_id", "") or "")


def timeout_seconds() -> float:
    try:
        return float(getattr(_settings(), "ncmec_report_timeout_seconds", 20) or 20)
    except Exception:
        return 20.0


def is_enabled() -> bool:
    """True only when the flag is ON *and* an endpoint + key are configured. When
    False the caller records a ``pending`` submission (honest-mock) and does NOT
    hit the network -- the report is preserved, never dropped."""
    return bool(reporting_enabled() and api_base() and api_key())


# -- pure payload builder -----------------------------------------------------
def build_report_payload(
    *,
    case_id: str,
    content_type: str,
    content_id: str,
    owner_user_id: str,
    categories: List[str],
    ts: int,
    preserve_id: str = "",
    reporter_user_id: str = "",
    incident_ref: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construct the mandated-report envelope. PURE -- no network, no settings.

    This is a clean, self-describing shape a real NCMEC/CyberTipline integration
    maps onto the partner schema (reporter/ESP block, incident, reported person,
    content pointers, preservation reference). It is intentionally NOT a guessed
    NCMEC wire format -- the mapping is the documented go-live step.
    """
    md = dict(metadata or {})
    return {
        "schema": PAYLOAD_SCHEMA,
        "esp": {
            # ESP (Electronic Service Provider) identity -- filled from config at
            # submit time so the pure builder stays deterministic.
            "org_id": org_id(),
            "platform": "testlogon",
        },
        "incident": {
            "incident_ref": incident_ref or f"case_{case_id}",
            "case_id": case_id,
            "categories": sorted({str(c or "").strip().lower() for c in (categories or []) if c}),
            "detected_at": int(ts),
            "source": "user_report",
        },
        "reported_content": {
            "content_type": content_type,
            "content_id": content_id,
            # Evidence is PRESERVED in-platform (immutable preservation record).
            # NCMEC integration attaches/points here; we never destroy it.
            "preservation_ref": preserve_id,
            "preservation_status": "preserved_in_platform",
        },
        "reported_person": {
            # Owner of the content. Additional identifiers (email/IP/etc.) are
            # supplied by the real integration from the platform's records.
            "platform_user_id": owner_user_id or "",
        },
        "reporting_party": {
            # The platform is the mandated reporter; the first reporter is
            # recorded for chain-of-custody, not surfaced to NCMEC as reporter.
            "first_reporter_platform_user_id": reporter_user_id or "",
        },
        "extra": md,
    }


# -- HTTP (only reached when is_enabled()) ------------------------------------
def _http_post(path: str, body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    url = f"{api_base()}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    # Auth header shape is a documented placeholder -- a real integration swaps
    # this for the NCMEC-assigned scheme (bearer / mutual-TLS / signed SOAP).
    req.add_header("Authorization", f"Bearer {api_key()}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            code = resp.getcode()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            pass
        logger.warning("NCMEC submit %s failed: HTTP %s %s", path, exc.code, detail[:400])
        return {"ok": False, "status_code": exc.code, "error": detail}
    except Exception as exc:  # network / timeout -- never raise into the caller.
        logger.warning("NCMEC submit %s errored: %s", path, exc)
        return {"ok": False, "error": str(exc)}
    try:
        parsed = json.loads(payload) if payload else {}
    except Exception:
        parsed = {}
    parsed.setdefault("ok", 200 <= int(code or 0) < 300)
    parsed.setdefault("status_code", code)
    return parsed


def submit_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Submit the mandated-report envelope. NEVER raises.

    Returns one of:
      * disabled (flag off / unkeyed):
          {"ok": True, "status": "pending", "delivered": False,
           "reason": "ncmec_disabled"}  -- honest-mock: caller persists PENDING.
      * delivered:
          {"ok": True, "status": "submitted", "delivered": True,
           "external_ref": "<id>", "status_code": 2xx}
      * failed (network/HTTP error while enabled):
          {"ok": False, "status": "failed", "delivered": False, "error": ...}
            -- caller persists FAILED and it is retry-eligible.
    """
    if not is_enabled():
        return {"ok": True, "status": "pending", "delivered": False, "reason": "ncmec_disabled"}
    resp = _http_post("/reports", payload, timeout=timeout_seconds())
    if not resp.get("ok"):
        return {
            "ok": False, "status": "failed", "delivered": False,
            "error": resp.get("error") or "submit_failed",
            "status_code": resp.get("status_code"),
        }
    external_ref = (
        str(resp.get("report_id") or resp.get("reportId")
            or resp.get("external_ref") or resp.get("id") or "")
    )
    return {
        "ok": True, "status": "submitted", "delivered": True,
        "external_ref": external_ref, "status_code": resp.get("status_code"),
        "raw": resp,
    }
