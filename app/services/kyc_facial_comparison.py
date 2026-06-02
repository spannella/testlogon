"""KYC-014: Facial Comparison service -- compares the uploaded selfie against
the ID-document photo and produces a confidence score (0-100).

NET-NEW feature. It reads the selfie + id_front file references already attached
to a KYC case (via ``POST /v1/kyc/cases/{case_id}/files`` -- see
``app/routers/kyc_cases.py``) and stores each comparison attempt back on the
*same* ``kyc_cases`` single-table item collection under a distinct sort key
``FACE_MATCH#{ts}`` (mirroring the KYC-010 scan-result style, which itself lives
in a separate ``kyc_id_scans`` table -- here we keep results co-located with the
case so the admin case view can surface them without a second table).

Determinism: in dev / E2E mode the comparison score is derived deterministically
from the selfie file metadata (filename keywords, else a stable hash of the file
references). We use ``zlib.crc32`` -- NOT the builtin ``hash()`` which is salted
per-process -- so the same inputs always yield the same score across runs.
"""

from __future__ import annotations

import logging
import uuid
import zlib
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# --- thresholds / limits ---------------------------------------------------

THRESHOLD_AUTO_PASS = 70  # score >= 70 -> auto-pass
THRESHOLD_AUTO_FAIL = 50  # score 50-69 -> manual review; < 50 -> auto-fail
MAX_SELFIE_ATTEMPTS = 3

# anti-spoof heuristics (dev mode)
_MIN_FILE_SIZE_BYTES = 50_000
_ALLOWED_IMAGE_FORMATS = {"image/jpeg", "image/png", "image/webp"}
_SCREENSHOT_EXTENSIONS = {".bmp", ".tiff", ".gif"}


# --- errors ----------------------------------------------------------------


class KycFacialComparisonError(ValueError):
    """Base error for facial-comparison operations (string code = message)."""


# --- helpers ---------------------------------------------------------------


def _case_pk(case_id: str) -> str:
    return f"KYC#{case_id}"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _find_file_ref(case: dict[str, Any], file_type: str) -> dict[str, Any] | None:
    """Find the most recent attached file of a given type on a KYC case.

    KYC-case file entries store ``{"type": ..., "path": ..., "size": ...}``
    (see ``attach_kyc_file`` in ``app/routers/kyc_cases.py``). We also tolerate
    the ``{"file_type": ..., "file_node_id": ...}`` shape from the spec examples.
    """
    files = case.get("files") or []
    matches = [
        f
        for f in files
        if isinstance(f, dict)
        and str(f.get("type") or f.get("file_type") or "") == file_type
    ]
    if not matches:
        return None
    # Last attached wins (attach_kyc_file appends; latest selfie is used).
    return matches[-1]


def _file_ref_path(ref: dict[str, Any]) -> str:
    return str(ref.get("path") or ref.get("file_node_id") or "")


def _node_metadata(user_sub: str, ref: dict[str, Any]) -> dict[str, Any]:
    """Resolve file metadata for a case file reference.

    Tries the file manager first (the real source of truth). When the node
    cannot be resolved (e.g. E2E seeds the case files array directly via DDB
    without a backing file-manager node) we fall back to metadata carried on
    the case file reference itself plus the path basename as a filename. This
    keeps the deterministic mock driveable from filename keywords in tests.
    """
    path = _file_ref_path(ref)
    file_name = path.rsplit("/", 1)[-1] if path else ""
    meta: dict[str, Any] = {
        "node_id": path,
        "file_name": file_name,
        "file_size": _coerce_int(ref.get("size") or ref.get("file_size"), 0),
        "mime_type": str(ref.get("mime_type") or ""),
    }
    try:
        from app.services.filemanager import get_node  # local import keeps module import-safe

        node = get_node(user_sub, path)
        if isinstance(node, dict):
            meta["node_id"] = str(node.get("path") or node.get("node_id") or path)
            meta["file_name"] = str(node.get("name") or node.get("file_name") or file_name)
            meta["file_size"] = _coerce_int(
                node.get("size") if node.get("size") is not None else meta["file_size"],
                meta["file_size"],
            )
            meta["mime_type"] = str(
                node.get("mime_type") or node.get("content_type") or meta["mime_type"]
            )
    except Exception:  # pragma: no cover - filemanager miss is expected in E2E seeds
        pass
    # Infer a sensible mime type from the extension when not supplied.
    if not meta["mime_type"]:
        meta["mime_type"] = _infer_mime_from_name(meta["file_name"])
    return meta


def _infer_mime_from_name(file_name: str) -> str:
    lower = str(file_name).lower()
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".webp"):
        return "image/webp"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".bmp"):
        return "image/bmp"
    if lower.endswith(".tiff") or lower.endswith(".tif"):
        return "image/tiff"
    if lower.endswith(".gif"):
        return "image/gif"
    return ""


# --- anti-spoof ------------------------------------------------------------


def _anti_spoof_check(selfie_meta: dict[str, Any]) -> dict[str, Any]:
    """Heuristic anti-spoof checks on the selfie metadata (dev mode)."""
    checks: list[dict[str, Any]] = []
    passed = True

    file_name = str(selfie_meta.get("file_name", ""))
    file_size = _coerce_int(selfie_meta.get("file_size"), 0)
    mime_type = str(selfie_meta.get("mime_type", ""))

    # Check 1: reasonable file size (real photos are larger than a tiny upload).
    size_ok = file_size > _MIN_FILE_SIZE_BYTES
    checks.append(
        {
            "check": "file_size",
            "passed": size_ok,
            "detail": f"File size: {file_size} bytes"
            + ("" if size_ok else " (too small for a real photo)"),
        }
    )
    passed = passed and size_ok

    # Check 2: acceptable image format.
    format_ok = mime_type in _ALLOWED_IMAGE_FORMATS
    checks.append(
        {
            "check": "image_format",
            "passed": format_ok,
            "detail": f"Format: {mime_type or 'unknown'}",
        }
    )
    passed = passed and format_ok

    # Check 3: not a known screenshot/raster format.
    ext = "." + file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    screenshot_ok = ext not in _SCREENSHOT_EXTENSIONS
    checks.append(
        {
            "check": "not_screenshot",
            "passed": screenshot_ok,
            "detail": f"Extension: {ext or 'none'}"
            + ("" if screenshot_ok else " (screenshot format detected)"),
        }
    )
    passed = passed and screenshot_ok

    return {
        "passed": passed,
        "checks": checks,
        "total_checks": len(checks),
        "passed_checks": sum(1 for c in checks if c["passed"]),
    }


# --- comparison engine -----------------------------------------------------


def _mock_compare(selfie_meta: dict[str, Any], id_meta: dict[str, Any]) -> int:
    """Deterministic mock facial comparison for dev / E2E mode.

    Filename keywords drive predictable buckets:
      * "match" (not "mismatch")  -> 85 (pass)
      * "partial"                 -> 60 (review)
      * "mismatch"                -> 30 (fail)
    Otherwise a stable crc32 of both file references yields a 55-95 score.
    """
    selfie_name = str(selfie_meta.get("file_name", "")).lower()

    if "mismatch" in selfie_name:
        return 30
    if "partial" in selfie_name:
        return 60
    if "match" in selfie_name:
        return 85

    combined = f"{selfie_meta.get('node_id', '')}|{id_meta.get('node_id', '')}".encode("utf-8")
    # crc32 is process-stable (unlike builtin hash()), so scores are reproducible.
    digest = zlib.crc32(combined)
    return 55 + (digest % 41)  # 55-95 inclusive


def _production_compare(selfie_meta: dict[str, Any], id_meta: dict[str, Any]) -> int:
    """Production comparison placeholder (would call AWS Rekognition CompareFaces)."""
    raise KycFacialComparisonError("comparison_service_error")


def _decide(score: int, anti_spoof_passed: bool) -> tuple[str, int]:
    """Map a score + anti-spoof outcome to (result, effective_score)."""
    if not anti_spoof_passed:
        return "fail", 0
    if score >= THRESHOLD_AUTO_PASS:
        return "pass", score
    if score >= THRESHOLD_AUTO_FAIL:
        return "review", score
    return "fail", score


# --- storage / queries -----------------------------------------------------


def _get_comparisons(case_id: str) -> list[dict[str, Any]]:
    """All face-comparison attempts for a case, newest first."""
    resp = T.kyc_cases.query(
        KeyConditionExpression=(
            Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("FACE_MATCH#")
        ),
        ScanIndexForward=False,
    )
    items = list(resp.get("Items", []))
    items.sort(key=lambda c: _coerce_int(c.get("created_at")), reverse=True)
    return items


def list_attempts(case_id: str) -> list[dict[str, Any]]:
    return _get_comparisons(case_id)


def get_comparison_detail(case_id: str, comparison_id: str) -> dict[str, Any] | None:
    return next(
        (c for c in _get_comparisons(case_id) if c.get("comparison_id") == comparison_id),
        None,
    )


def get_best_comparison(case_id: str) -> dict[str, Any] | None:
    """The highest-scoring comparison for a case (admin/decisioning uses this)."""
    comparisons = _get_comparisons(case_id)
    if not comparisons:
        return None
    return max(comparisons, key=lambda c: _coerce_int(c.get("confidence_score")))


def _public_view(item: dict[str, Any]) -> dict[str, Any]:
    """Shape a stored comparison item into the API response fields."""
    return {
        "comparison_id": item.get("comparison_id"),
        "confidence_score": _coerce_int(item.get("confidence_score")),
        "result": item.get("result"),
        "anti_spoof": item.get("anti_spoof"),
        "attempt_number": _coerce_int(item.get("attempt_number"), 1),
        "max_attempts": _coerce_int(item.get("max_attempts"), MAX_SELFIE_ATTEMPTS),
        "remaining_attempts": max(
            0, MAX_SELFIE_ATTEMPTS - _coerce_int(item.get("attempt_number"), 1)
        ),
        "created_at": _coerce_int(item.get("created_at")),
        "admin_override": item.get("admin_override"),
    }


# --- public API ------------------------------------------------------------


def compare_faces(
    *,
    case_id: str,
    user_sub: str,
    request: Any = None,
) -> dict[str, Any]:
    """Run a facial comparison between the case selfie and id_front photo.

    Raises ``KycFacialComparisonError`` with a string code on failure:
      case_not_found / access_forbidden / selfie_not_uploaded /
      id_front_not_uploaded / max_attempts_exceeded / comparison_service_error
    """
    case = T.kyc_cases.get_item(
        Key={"pk": _case_pk(case_id), "sk": "META"}
    ).get("Item")
    if not case:
        raise KycFacialComparisonError("case_not_found")
    if str(case.get("user_sub") or "") != str(user_sub):
        raise KycFacialComparisonError("access_forbidden")

    selfie_ref = _find_file_ref(case, "selfie")
    id_front_ref = _find_file_ref(case, "id_front")
    if not selfie_ref:
        raise KycFacialComparisonError("selfie_not_uploaded")
    if not id_front_ref:
        raise KycFacialComparisonError("id_front_not_uploaded")

    existing = _get_comparisons(case_id)
    attempt_number = len(existing) + 1
    if attempt_number > MAX_SELFIE_ATTEMPTS:
        raise KycFacialComparisonError("max_attempts_exceeded")

    selfie_meta = _node_metadata(user_sub, selfie_ref)
    id_meta = _node_metadata(user_sub, id_front_ref)

    anti_spoof = _anti_spoof_check(selfie_meta)

    if S.dev_mode:
        raw_score = _mock_compare(selfie_meta, id_meta)
    else:
        raw_score = _production_compare(selfie_meta, id_meta)

    result, score = _decide(raw_score, bool(anti_spoof["passed"]))

    comparison_id = f"fc_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    record = {
        "pk": _case_pk(case_id),
        "sk": f"FACE_MATCH#{ts:013d}#{comparison_id}",
        "entity_type": "kyc_face_comparison",
        "comparison_id": comparison_id,
        "case_id": case_id,
        "user_sub": user_sub,
        "confidence_score": score,
        "result": result,
        "anti_spoof": anti_spoof,
        "attempt_number": attempt_number,
        "max_attempts": MAX_SELFIE_ATTEMPTS,
        "selfie_node_id": _file_ref_path(selfie_ref),
        "id_front_node_id": _file_ref_path(id_front_ref),
        "created_at": ts,
        "admin_override": None,
    }
    T.kyc_cases.put_item(Item=record)

    logger.info(
        "kyc.face.comparison.run case_id=%s comparison_id=%s score=%s result=%s attempt=%s",
        case_id,
        comparison_id,
        score,
        result,
        attempt_number,
    )
    if not anti_spoof["passed"]:
        failed = [c["check"] for c in anti_spoof["checks"] if not c["passed"]]
        logger.warning(
            "kyc.face.anti_spoof.failed case_id=%s failed_checks=%s", case_id, failed
        )

    audit_event(
        "kyc_face_comparison",
        user_sub,
        request,
        outcome=result,
        kyc_case_id=case_id,
        comparison_id=comparison_id,
        confidence_score=score,
        attempt=attempt_number,
        anti_spoof_passed=bool(anti_spoof["passed"]),
    )

    return _public_view(record)


def admin_override_comparison(
    *,
    case_id: str,
    comparison_id: str,
    decision: str,
    reason: str,
    admin_sub: str,
    request: Any = None,
) -> dict[str, Any]:
    """Admin overrides a stored comparison result (approve/reject the match)."""
    comparison = get_comparison_detail(case_id, comparison_id)
    if not comparison:
        raise KycFacialComparisonError("comparison_not_found")

    ts = now_ts()
    override = {
        "decision": decision,
        "reason": reason,
        "admin_sub": admin_sub,
        "overridden_at": ts,
    }
    T.kyc_cases.update_item(
        Key={"pk": _case_pk(case_id), "sk": comparison["sk"]},
        UpdateExpression="SET admin_override = :o",
        ExpressionAttributeValues={":o": override},
    )

    logger.warning(
        "kyc.face.admin_override case_id=%s comparison_id=%s admin_sub=%s "
        "original_result=%s override_decision=%s",
        case_id,
        comparison_id,
        admin_sub,
        comparison.get("result"),
        decision,
    )
    audit_event(
        "kyc_face_comparison_admin_override",
        admin_sub,
        request,
        outcome="success",
        kyc_case_id=case_id,
        comparison_id=comparison_id,
        original_result=comparison.get("result"),
        override_decision=decision,
    )

    return {
        "comparison_id": comparison_id,
        "original_result": comparison.get("result"),
        "original_score": _coerce_int(comparison.get("confidence_score")),
        "admin_override": override,
    }


def build_admin_view(case_id: str) -> dict[str, Any] | None:
    """Assemble the admin side-by-side comparison payload for a case.

    Returns ``None`` when the case does not exist.
    """
    case = T.kyc_cases.get_item(
        Key={"pk": _case_pk(case_id), "sk": "META"}
    ).get("Item")
    if not case:
        return None

    selfie_ref = _find_file_ref(case, "selfie")
    id_front_ref = _find_file_ref(case, "id_front")
    comparisons = _get_comparisons(case_id)
    best = get_best_comparison(case_id)

    return {
        "case_id": case_id,
        "user_sub": case.get("user_sub"),
        "selfie_file": _admin_file_ref(selfie_ref),
        "id_front_file": _admin_file_ref(id_front_ref),
        "selfie_url": _dev_image_url(selfie_ref),
        "id_front_url": _dev_image_url(id_front_ref),
        "comparisons": [_public_view(c) for c in comparisons],
        "best_comparison": _best_view(best),
        "total_attempts": len(comparisons),
        "max_attempts": MAX_SELFIE_ATTEMPTS,
    }


def _admin_file_ref(ref: dict[str, Any] | None) -> dict[str, Any] | None:
    if not ref:
        return None
    path = _file_ref_path(ref)
    return {
        "file_type": str(ref.get("type") or ref.get("file_type") or ""),
        "file_node_id": path,
        "attached_at": _coerce_int(ref.get("uploaded_at") or ref.get("attached_at"), 0),
    }


def _best_view(best: dict[str, Any] | None) -> dict[str, Any] | None:
    if not best:
        return None
    return {
        "comparison_id": best.get("comparison_id"),
        "confidence_score": _coerce_int(best.get("confidence_score")),
        "result": best.get("result"),
    }


def _dev_image_url(ref: dict[str, Any] | None) -> str | None:
    """Build a /mock/s3/... dev URL for a case file reference (admin preview)."""
    if not ref or not S.dev_mode:
        return None
    path = _file_ref_path(ref)
    if not path:
        return None
    if path.startswith("/mock/s3/"):
        return path
    bucket = S.kyc_documents_bucket or "local-uploads"
    return f"/mock/s3/{bucket}/{path.lstrip('/')}"
