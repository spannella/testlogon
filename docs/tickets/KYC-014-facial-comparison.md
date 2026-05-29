# KYC-014: Facial Comparison (Selfie vs ID Photo)

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 7-9 days  
**Dependencies**: KYC-010 (Passport & National ID Scanner), KYC-013 (User Self-Service Portal)

---

## 1. Overview & Motivation

### 1.1 The Gap

The current KYC system requires users to upload a selfie and an identity document (id_front, id_back) via `POST /v1/kyc/cases/{case_id}/files` (see `app/routers/kyc_cases.py:734`). However, once uploaded, these files are treated as opaque attachments. There is no automated comparison between the selfie and the photo on the identity document. An admin reviewing the case must manually compare the selfie against the ID photo -- a time-consuming, subjective, and error-prone process.

### 1.2 What This Ticket Adds

1. **Facial comparison service** -- Compares the uploaded selfie against the ID document photo and produces a confidence score (0-100).
2. **Mock comparison service** for dev mode -- Deterministic results based on test file metadata, enabling predictable E2E testing.
3. **Confidence thresholds**:
   - Score >= 70: auto-pass (no manual review needed for face matching)
   - Score 50-69: manual review required (admin reviews side-by-side)
   - Score < 50: auto-fail (flag as likely mismatch)
4. **Anti-spoofing checks** -- Mock implementation that checks image metadata for camera vs screenshot indicators.
5. **Multiple selfie attempts** -- Users can upload up to 3 selfie attempts; the highest-scoring comparison is used.
6. **Admin side-by-side comparison view** -- Overlay displaying both images with confidence score and decision buttons.

### 1.3 Architecture

```
Facial Comparison Flow:

  POST /v1/kyc/cases/{case_id}/compare-face
       |
       v
  kyc_facial_comparison.compare_faces()
       |
       +-- 1. Retrieve selfie from case files
       +-- 2. Retrieve id_front from case files
       +-- 3. anti_spoof_check(selfie_metadata)
       |       +-- Check image source (camera vs screenshot)
       |       +-- Check resolution (minimum 640x480)
       |       +-- Check EXIF for camera model (presence = real photo)
       +-- 4. compare(selfie_image, id_photo)
       |       +-- Dev mode: _mock_compare() -> deterministic score
       |       +-- Prod mode: external API call (AWS Rekognition / etc.)
       +-- 5. Store result (kyc_cases table, SK=FACE_MATCH#{ts})
       |
       v
  Response:
  {
    "comparison_id": "fc_abc123",
    "confidence_score": 82,
    "result": "pass",     // pass | review | fail
    "anti_spoof": { "passed": true, "checks": [...] },
    "attempt_number": 1,
    "max_attempts": 3
  }

Admin View:
  GET /v1/kyc/cases/admin/cases/{case_id}/face-comparison
       |
       v
  Returns side-by-side image URLs + comparison results
  Admin can override result (approve/reject with reason)
```

---

## 2. Current State Analysis

### 2.1 File Attachments on KYC Cases

The `attach_kyc_file()` endpoint (see `app/routers/kyc_cases.py:734`) stores file references as dicts in the case's `files` array:

```python
{
    "file_type": "selfie",       # or "id_front", "id_back", "proof_of_address"
    "file_node_id": "node_abc",
    "attached_at": 1717000000,
    "attached_by": "user_sub",
}
```

The `file_node_id` references a node in the file manager (see `app/services/filemanager.py:450`). The file manager stores the S3 key for the actual file data. To retrieve the image, the comparison service calls `get_node(owner, path)` and then downloads from S3.
<!-- NOTE: get_node(owner, path) takes an owner string and a path string, NOT (user_sub, node_id). The file_node_id stored on the KYC case would need to be mapped to the correct path format used by get_node. -->

### 2.2 KYC Cases Table -- Existing Item Schema

The `kyc_cases` table uses single-table design:
- `pk=KYC#{case_id}`, `sk=META` -- main case record (see `app/services/kyc_cases.py:36` for `_case_pk`)
- `pk=KYC#{case_id}`, `sk=SCAN#{scan_id}` -- document scan results (KYC-010)
<!-- NOTE: KYC-010 (Passport & National ID Scanner) is a dependency — verify SCAN# SK pattern exists when that ticket is implemented -->

Face comparison results will use `sk=FACE_MATCH#{timestamp}` to store each comparison attempt.

### 2.3 S3 Access in Dev Mode

The moto S3 mock is started in-process by `app/core/dev_s3.py` (see CLAUDE.md "S3 mock" section). File data uploaded through the file manager is stored in the mock S3 bucket and can be retrieved via `boto3.client("s3").get_object()`.

### 2.4 Admin Case Detail (see `app/routers/kyc_cases.py:997`)

The `get_admin_kyc_case_detail()` endpoint builds a detailed case view via `_build_admin_case_detail()` (see `app/routers/kyc_cases.py:345`). The face comparison results need to be included in this admin view, along with signed URLs for the selfie and ID images.

### 2.5 Mock Dev Image URLs

The `_message_out_from_item` function in messaging generates `/mock/s3/...` URLs for images in dev mode. The same pattern should be used for KYC file URLs in the admin comparison view.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_facial_comparison.py`
<!-- NOTE: app/services/kyc_facial_comparison.py does not exist yet — new implementation required -->

```python
"""Facial comparison service -- compares selfie against ID document photo."""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.filemanager import get_node  # see app/services/filemanager.py:450 — NOTE: signature is get_node(owner, path), not (user_sub, node_id)
from app.services.alerts import audit_event  # see app/services/alerts.py:695

# Confidence thresholds
THRESHOLD_AUTO_PASS = 70
THRESHOLD_AUTO_FAIL = 50
MAX_SELFIE_ATTEMPTS = 3

# Minimum image requirements
MIN_WIDTH = 640
MIN_HEIGHT = 480


def compare_faces(
    *,
    case_id: str,
    user_sub: str,
    request=None,
) -> dict[str, Any]:
    """Run facial comparison between selfie and ID front photo.

    Returns comparison result with confidence score.
    """
    # Get case files
    case = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"}).get("Item")
    if not case:
        raise ValueError("case_not_found")
    if str(case.get("user_sub", "")) != user_sub:
        raise ValueError("access_forbidden")

    files = case.get("files", [])
    selfie_ref = next((f for f in files if f.get("file_type") == "selfie"), None)
    id_front_ref = next((f for f in files if f.get("file_type") == "id_front"), None)

    if not selfie_ref:
        raise ValueError("selfie_not_uploaded")
    if not id_front_ref:
        raise ValueError("id_front_not_uploaded")

    # Check attempt count
    existing_comparisons = _get_comparisons(case_id)
    attempt_number = len(existing_comparisons) + 1
    if attempt_number > MAX_SELFIE_ATTEMPTS:
        raise ValueError("max_attempts_exceeded")

    # Retrieve file metadata
    # NOTE: get_node takes (owner, path) — file_node_id must be translated to path format
    selfie_node = get_node(user_sub, selfie_ref["file_node_id"])
    id_front_node = get_node(user_sub, id_front_ref["file_node_id"])

    # Anti-spoof check on selfie
    anti_spoof = _anti_spoof_check(selfie_node)

    # Run comparison
    if S.dev_mode:
        score = _mock_compare(selfie_node, id_front_node)
    else:
        score = _production_compare(selfie_node, id_front_node)

    # Determine result
    if not anti_spoof["passed"]:
        result = "fail"
        score = 0
    elif score >= THRESHOLD_AUTO_PASS:
        result = "pass"
    elif score >= THRESHOLD_AUTO_FAIL:
        result = "review"
    else:
        result = "fail"

    # Store comparison result
    comparison_id = f"fc_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    comparison_record = {
        "pk": f"KYC#{case_id}",
        "sk": f"FACE_MATCH#{ts}",
        "comparison_id": comparison_id,
        "case_id": case_id,
        "user_sub": user_sub,
        "confidence_score": score,
        "result": result,
        "anti_spoof": anti_spoof,
        "attempt_number": attempt_number,
        "max_attempts": MAX_SELFIE_ATTEMPTS,
        "selfie_node_id": selfie_ref["file_node_id"],
        "id_front_node_id": id_front_ref["file_node_id"],
        "created_at": ts,
    }
    T.kyc_cases.put_item(Item=comparison_record)

    # Audit
    audit_event(
        "kyc.face_comparison",
        user_sub,
        request,
        outcome=result,
        case_id=case_id,
        comparison_id=comparison_id,
        confidence_score=score,
        attempt=attempt_number,
    )

    return {
        "comparison_id": comparison_id,
        "confidence_score": score,
        "result": result,
        "anti_spoof": anti_spoof,
        "attempt_number": attempt_number,
        "max_attempts": MAX_SELFIE_ATTEMPTS,
        "remaining_attempts": MAX_SELFIE_ATTEMPTS - attempt_number,
        "created_at": ts,
    }


def _anti_spoof_check(selfie_node: dict) -> dict[str, Any]:
    """Check selfie image for spoofing indicators.

    In dev mode, uses file metadata heuristics:
    - Check if image was captured by a camera (EXIF data presence)
    - Check minimum resolution
    - Check file extension (screenshot formats like .bmp flagged)
    """
    checks = []
    passed = True

    file_name = selfie_node.get("file_name", "")
    file_size = selfie_node.get("file_size", 0)
    mime_type = selfie_node.get("mime_type", "")

    # Check 1: Reasonable file size (real photos > 50KB)
    size_ok = int(file_size or 0) > 50_000
    checks.append({
        "check": "file_size",
        "passed": size_ok,
        "detail": f"File size: {file_size} bytes" + (" (too small for a real photo)" if not size_ok else ""),
    })
    if not size_ok:
        passed = False

    # Check 2: Acceptable image format
    allowed_formats = {"image/jpeg", "image/png", "image/webp"}
    format_ok = mime_type in allowed_formats
    checks.append({
        "check": "image_format",
        "passed": format_ok,
        "detail": f"Format: {mime_type}",
    })
    if not format_ok:
        passed = False

    # Check 3: Not a known screenshot format
    screenshot_indicators = {".bmp", ".tiff", ".gif"}
    ext = "." + file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    screenshot_ok = ext not in screenshot_indicators
    checks.append({
        "check": "not_screenshot",
        "passed": screenshot_ok,
        "detail": f"Extension: {ext}" + (" (screenshot format detected)" if not screenshot_ok else ""),
    })
    if not screenshot_ok:
        passed = False

    return {
        "passed": passed,
        "checks": checks,
        "total_checks": len(checks),
        "passed_checks": sum(1 for c in checks if c["passed"]),
    }


def _mock_compare(selfie_node: dict, id_front_node: dict) -> int:
    """Mock facial comparison for dev mode.

    Produces deterministic confidence scores based on file metadata:
    - If selfie file_name contains "match": score 85
    - If selfie file_name contains "partial": score 60
    - If selfie file_name contains "mismatch": score 30
    - Default: score based on hash of both node IDs (deterministic but varied)
    """
    selfie_name = str(selfie_node.get("file_name", "")).lower()

    if "match" in selfie_name and "mis" not in selfie_name:
        return 85
    elif "partial" in selfie_name:
        return 60
    elif "mismatch" in selfie_name:
        return 30
    else:
        # Deterministic score from 55-95 based on node IDs
        combined = f"{selfie_node.get('node_id', '')}{id_front_node.get('node_id', '')}"
        hash_val = int(hashlib.md5(combined.encode()).hexdigest()[:8], 16)
        return 55 + (hash_val % 41)  # 55-95 range


def _production_compare(selfie_node: dict, id_front_node: dict) -> int:
    """Production facial comparison -- calls external service.

    In production, this would call AWS Rekognition CompareFaces or
    a similar service. Returns confidence score 0-100.
    """
    # Placeholder for production implementation
    raise NotImplementedError("Production facial comparison not configured")


def _get_comparisons(case_id: str) -> list[dict[str, Any]]:
    """Retrieve all face comparison attempts for a case."""
    from boto3.dynamodb.conditions import Key
    resp = T.kyc_cases.query(
        KeyConditionExpression=(
            Key("pk").eq(f"KYC#{case_id}")
            & Key("sk").begins_with("FACE_MATCH#")
        ),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def get_comparison_detail(case_id: str, comparison_id: str) -> dict[str, Any] | None:
    """Get a specific comparison by ID."""
    comparisons = _get_comparisons(case_id)
    return next((c for c in comparisons if c.get("comparison_id") == comparison_id), None)


def get_best_comparison(case_id: str) -> dict[str, Any] | None:
    """Get the comparison with the highest confidence score."""
    comparisons = _get_comparisons(case_id)
    if not comparisons:
        return None
    return max(comparisons, key=lambda c: int(c.get("confidence_score", 0)))


def admin_override_comparison(
    *,
    case_id: str,
    comparison_id: str,
    decision: str,
    reason: str,
    admin_sub: str,
    request=None,
) -> dict[str, Any]:
    """Admin overrides comparison result."""
    comparison = get_comparison_detail(case_id, comparison_id)
    if not comparison:
        raise ValueError("comparison_not_found")

    ts = now_ts()
    T.kyc_cases.update_item(
        Key={"pk": f"KYC#{case_id}", "sk": comparison["sk"]},
        UpdateExpression="SET admin_override = :override",
        ExpressionAttributeValues={
            ":override": {
                "decision": decision,
                "reason": reason,
                "admin_sub": admin_sub,
                "overridden_at": ts,
            },
        },
    )

    audit_event(
        "kyc.face_comparison.admin_override",
        admin_sub,
        request,
        outcome="success",
        case_id=case_id,
        comparison_id=comparison_id,
        original_result=comparison.get("result"),
        override_decision=decision,
    )

    return {
        "comparison_id": comparison_id,
        "original_result": comparison.get("result"),
        "original_score": comparison.get("confidence_score"),
        "admin_override": {
            "decision": decision,
            "reason": reason,
            "admin_sub": admin_sub,
            "overridden_at": ts,
        },
    }
```

### 3.2 API Endpoints

Add to `app/routers/kyc_cases.py`:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/{case_id}/compare-face` | `require_ui_session` | Run facial comparison |
| `GET` | `/{case_id}/face-comparisons` | `require_ui_session` | List comparison attempts |
| `GET` | `/admin/cases/{case_id}/face-comparison` | `require_ui_session` + admin role check | Admin view with side-by-side |
| `POST` | `/admin/cases/{case_id}/face-comparison/{comparison_id}/override` | `require_ui_session` + admin role check | Admin override |
<!-- NOTE: Existing admin KYC endpoints use require_ui_session + manual role check (Role.ADMIN or Role.ROOT), NOT require_root_session. The new admin endpoints should follow the same pattern (see app/routers/kyc_cases.py:1000-1003). -->

```python
@router.post("/{case_id}/compare-face")
def run_face_comparison(case_id: str, request: Request, ctx=Depends(require_ui_session)):
    from app.services.kyc_facial_comparison import compare_faces
    try:
        return compare_faces(
            case_id=case_id,
            user_sub=ctx["user_sub"],
            request=request,
        )
    except ValueError as exc:
        error_map = {
            "case_not_found": 404,
            "access_forbidden": 403,
            "selfie_not_uploaded": 400,
            "id_front_not_uploaded": 400,
            "max_attempts_exceeded": 409,
        }
        raise HTTPException(
            status_code=error_map.get(str(exc), 400),
            detail=str(exc),
        )


@router.get("/{case_id}/face-comparisons")
def list_face_comparisons(case_id: str, ctx=Depends(require_ui_session)):
    from app.services.kyc_facial_comparison import _get_comparisons
    # Verify ownership
    case = STORE.get_case(case_id)
    if not case or str(case.get("user_sub", "")) != ctx["user_sub"]:
        raise HTTPException(404, "case_not_found")
    comparisons = _get_comparisons(case_id)
    return {"comparisons": comparisons}


@router.get("/admin/cases/{case_id}/face-comparison")
def admin_face_comparison(case_id: str, _ctx=Depends(require_ui_session), user=Depends(get_authenticated_user)):
    # NOTE: follow existing pattern — check Role.ADMIN or Role.ROOT manually (see kyc_cases.py:1003)
    from app.services.kyc_facial_comparison import _get_comparisons, get_best_comparison
    case = STORE.get_case(case_id)
    if not case:
        raise HTTPException(404, "case_not_found")

    comparisons = _get_comparisons(case_id)
    best = get_best_comparison(case_id)

    # Build image URLs for side-by-side view
    files = case.get("files", [])
    selfie_ref = next((f for f in files if f.get("file_type") == "selfie"), None)
    id_front_ref = next((f for f in files if f.get("file_type") == "id_front"), None)

    return {
        "case_id": case_id,
        "user_sub": case.get("user_sub"),
        "selfie_file": selfie_ref,
        "id_front_file": id_front_ref,
        "comparisons": comparisons,
        "best_comparison": best,
        "total_attempts": len(comparisons),
        "max_attempts": 3,
    }


@router.post("/admin/cases/{case_id}/face-comparison/{comparison_id}/override")
def admin_override_face(
    case_id: str,
    comparison_id: str,
    body: FaceComparisonOverrideRequest,
    request: Request,
    _ctx=Depends(require_ui_session),
    user=Depends(get_authenticated_user),
):
    # NOTE: follow existing pattern — check Role.ADMIN or Role.ROOT manually (see kyc_cases.py:1003)
    from app.services.kyc_facial_comparison import admin_override_comparison
    try:
        return admin_override_comparison(
            case_id=case_id,
            comparison_id=comparison_id,
            decision=body.decision,
            reason=body.reason,
            admin_sub=user.sub,
            request=request,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc))
```

### 3.3 Frontend Components

**File**: `frontend/src/pages/kyc/FaceComparisonResult.tsx`
<!-- NOTE: frontend/src/pages/kyc/ directory does not exist yet — new implementation required -->

Displayed after selfie upload in the KYC wizard (Step 3):
- Shows confidence score as a circular progress gauge
- Color-coded result badge: green (pass), yellow (review), red (fail)
- If failed: "Upload a new selfie" button (if attempts remaining)
- Attempt counter: "Attempt 1 of 3"
- Anti-spoof check results as expandable detail panel

**File**: `frontend/src/pages/admin/KycFaceComparison.tsx`

Admin-facing component shown in the admin case detail view:
- Side-by-side image display (selfie on left, ID photo on right)
- Confidence score overlay
- All comparison attempts listed with scores
- Override buttons: "Approve Match" / "Reject Match" with reason input dialog

**File**: `frontend/src/api/endpoints/kyc-face.ts`
<!-- NOTE: frontend/src/api/endpoints/kyc-face.ts does not exist yet — new implementation required -->

```typescript
export const compareFace = (caseId: string) =>
  client.post(`/v1/kyc/cases/${caseId}/compare-face`);
export const getFaceComparisons = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}/face-comparisons`);
export const adminGetFaceComparison = (caseId: string) =>
  client.get(`/v1/kyc/cases/admin/cases/${caseId}/face-comparison`);
export const adminOverrideFace = (
  caseId: string,
  comparisonId: string,
  data: { decision: "pass" | "fail"; reason: string },
) => client.post(
  `/v1/kyc/cases/admin/cases/${caseId}/face-comparison/${comparisonId}/override`,
  data,
);
```

---

## 4. Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           User Browser                                     │
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  KycWizard.tsx  → Step 3: SelfieStep                               │    │
│  │  ┌──────────────────┐                                              │    │
│  │  │ CameraCapture    │  getUserMedia → canvas → File                │    │
│  │  │ (or file upload) │                                              │    │
│  │  └────────┬─────────┘                                              │    │
│  │           │ File                                                    │    │
│  │           ▼                                                         │    │
│  │  POST /files (file manager) → node_id                              │    │
│  │           │                                                         │    │
│  │           ▼                                                         │    │
│  │  POST /{case_id}/files (attach selfie)                             │    │
│  │           │                                                         │    │
│  │           ▼                                                         │    │
│  │  POST /{case_id}/compare-face                                      │    │
│  │           │                                                         │    │
│  │           ▼                                                         │    │
│  │  ┌──────────────────────────────────────────────────┐              │    │
│  │  │ FaceComparisonResult.tsx                          │              │    │
│  │  │ ┌────────────┐  ┌────────────┐  ┌─────────────┐ │              │    │
│  │  │ │ Score Gauge │  │Result Badge│  │ Anti-Spoof  │ │              │    │
│  │  │ │   82/100    │  │   PASS     │  │ 3/3 checks  │ │              │    │
│  │  │ └────────────┘  └────────────┘  └─────────────┘ │              │    │
│  │  │ "Attempt 1 of 3"  [Upload New Selfie] (if fail) │              │    │
│  │  └──────────────────────────────────────────────────┘              │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Admin: KycFaceComparison.tsx  (root session)                      │    │
│  │  ┌────────────────────────────────────────────────────────────┐    │    │
│  │  │  Side-by-Side View                                          │    │    │
│  │  │  ┌──────────┐        ┌──────────┐                          │    │    │
│  │  │  │  Selfie   │   VS   │ ID Photo │                          │    │    │
│  │  │  │  (image)  │        │ (image)  │                          │    │    │
│  │  │  └──────────┘        └──────────┘                          │    │    │
│  │  │  Score: 60  |  Result: REVIEW  |  Attempt: 2/3             │    │    │
│  │  │  [Approve Match]  [Reject Match]                            │    │    │
│  │  └────────────────────────────────────────────────────────────┘    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │  HTTPS + cookies + CSRF
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     FastAPI Backend  (port 8000)                          │
│                                                                          │
│  app/routers/kyc_cases.py                                                │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  POST /{case_id}/compare-face       → compare_faces()             │  │
│  │  GET  /{case_id}/face-comparisons   → _get_comparisons()          │  │
│  │  GET  /admin/.../face-comparison    → admin_face_comparison()      │  │
│  │  POST /admin/.../override           → admin_override_comparison()  │  │
│  └───────────────────────────┬────────────────────────────────────────┘  │
│                              │                                            │
│  app/services/kyc_facial_comparison.py                                    │
│  ┌───────────────────────────┼────────────────────────────────────────┐  │
│  │  compare_faces()          │                                        │  │
│  │    │                      │                                        │  │
│  │    ├── get case files (T.kyc_cases.get_item)                       │  │
│  │    ├── _get_comparisons() → count existing attempts                │  │
│  │    ├── get_node() → selfie metadata (filemanager)                  │  │
│  │    ├── get_node() → id_front metadata (filemanager)                │  │
│  │    ├── _anti_spoof_check()                                         │  │
│  │    │     ├── file_size check (>50KB)                               │  │
│  │    │     ├── image_format check (jpeg/png/webp)                    │  │
│  │    │     └── not_screenshot check (no .bmp/.tiff/.gif)             │  │
│  │    ├── _mock_compare() (dev) / _production_compare() (prod)        │  │
│  │    │     ├── "match" in filename → 85                              │  │
│  │    │     ├── "partial" in filename → 60                            │  │
│  │    │     ├── "mismatch" in filename → 30                           │  │
│  │    │     └── default: hash(node_ids) → 55-95                       │  │
│  │    ├── Threshold logic:                                            │  │
│  │    │     ├── anti_spoof failed → result=fail, score=0              │  │
│  │    │     ├── score >= 70 → result=pass                             │  │
│  │    │     ├── score 50-69 → result=review                           │  │
│  │    │     └── score < 50 → result=fail                              │  │
│  │    ├── T.kyc_cases.put_item(pk=KYC#{id}, sk=FACE_MATCH#{ts})      │  │
│  │    └── audit_event("kyc.face_comparison")                          │  │
│  │                                                                    │  │
│  │  admin_override_comparison()                                       │  │
│  │    ├── get_comparison_detail()                                     │  │
│  │    ├── T.kyc_cases.update_item (SET admin_override)                │  │
│  │    └── audit_event("kyc.face_comparison.admin_override")           │  │
│  │                                                                    │  │
│  │  get_best_comparison() → max(comparisons, key=confidence_score)    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  app/services/filemanager.py                                       │  │
│  │  get_node(user_sub, node_id) → { file_name, file_size, mime_type,  │  │
│  │                                   s3_key, node_id }                │  │
│  └──────────────────────────────┬─────────────────────────────────────┘  │
│                                 │                                         │
│                                 ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  moto S3 (in-process)                                              │  │
│  │  Bucket: uploads  /  Key: users/{sub}/kyc/selfie_001.jpg           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     DynamoDB Local  (port 8001)                           │
│                                                                          │
│  kyc_cases table                                                         │
│  ┌──────────────────────┬────────────────────────────────────────────┐  │
│  │ pk = KYC#{case_id}   │ sk = META                                  │  │
│  │                      │ status, user_sub, files[], ...              │  │
│  ├──────────────────────┼────────────────────────────────────────────┤  │
│  │ pk = KYC#{case_id}   │ sk = FACE_MATCH#{ts}                       │  │
│  │                      │ comparison_id, confidence_score, result,    │  │
│  │                      │ anti_spoof{}, attempt_number, admin_override│  │
│  ├──────────────────────┼────────────────────────────────────────────┤  │
│  │ pk = KYC#{case_id}   │ sk = SCAN#{scan_id}  (from KYC-010)        │  │
│  │                      │ mrz_data, extraction_fields, ...           │  │
│  └──────────────────────┴────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 5. DynamoDB Access Patterns

### 5.1 Access Patterns Table

| Operation | Table | PK | SK / KeyCondition | GSI | Filter | Notes |
|-----------|-------|----|--------------------|-----|--------|-------|
| Get case for comparison | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | GetItem; checks user_sub ownership |
| Store comparison result | `kyc_cases` | `KYC#{case_id}` | `FACE_MATCH#{ts}` | -- | -- | PutItem |
| List all comparisons | `kyc_cases` | `KYC#{case_id}` | `begins_with("FACE_MATCH#")` | -- | -- | Query; ScanIndexForward=False (newest first) |
| Get specific comparison | `kyc_cases` | `KYC#{case_id}` | `begins_with("FACE_MATCH#")` | -- | `comparison_id = :id` | Query + client filter |
| Admin override | `kyc_cases` | `KYC#{case_id}` | `FACE_MATCH#{ts}` (from comparison) | -- | -- | UpdateItem: SET admin_override |
| Count attempts | `kyc_cases` | `KYC#{case_id}` | `begins_with("FACE_MATCH#")` | -- | -- | Query (count returned items) |

### 5.2 Example Items

**Face comparison result (pass)**:

```json
{
  "pk": "KYC#kyc_a1b2c3d4",
  "sk": "FACE_MATCH#1717050000",
  "comparison_id": "fc_7a8b9c0d1e2f",
  "case_id": "kyc_a1b2c3d4",
  "user_sub": "e2e_alice@test.local",
  "confidence_score": 85,
  "result": "pass",
  "anti_spoof": {
    "passed": true,
    "checks": [
      { "check": "file_size", "passed": true, "detail": "File size: 157320 bytes" },
      { "check": "image_format", "passed": true, "detail": "Format: image/jpeg" },
      { "check": "not_screenshot", "passed": true, "detail": "Extension: .jpg" }
    ],
    "total_checks": 3,
    "passed_checks": 3
  },
  "attempt_number": 1,
  "max_attempts": 3,
  "selfie_node_id": "node_selfie_001",
  "id_front_node_id": "node_id_front_001",
  "created_at": 1717050000
}
```

**Face comparison result (review, with admin override)**:

```json
{
  "pk": "KYC#kyc_e5f6g7h8",
  "sk": "FACE_MATCH#1717060000",
  "comparison_id": "fc_aabbccdd1122",
  "case_id": "kyc_e5f6g7h8",
  "user_sub": "e2e_bob@test.local",
  "confidence_score": 60,
  "result": "review",
  "anti_spoof": {
    "passed": true,
    "checks": [
      { "check": "file_size", "passed": true, "detail": "File size: 98000 bytes" },
      { "check": "image_format", "passed": true, "detail": "Format: image/jpeg" },
      { "check": "not_screenshot", "passed": true, "detail": "Extension: .jpg" }
    ],
    "total_checks": 3,
    "passed_checks": 3
  },
  "attempt_number": 2,
  "max_attempts": 3,
  "selfie_node_id": "node_selfie_002",
  "id_front_node_id": "node_id_front_002",
  "created_at": 1717060000,
  "admin_override": {
    "decision": "pass",
    "reason": "Manual visual comparison confirms identity. Partial score due to lighting conditions.",
    "admin_sub": "root.admin@testdev.local",
    "overridden_at": 1717070000
  }
}
```

**Face comparison result (fail, anti-spoof failed)**:

```json
{
  "pk": "KYC#kyc_x1y2z3w4",
  "sk": "FACE_MATCH#1717080000",
  "comparison_id": "fc_deadbeef0000",
  "case_id": "kyc_x1y2z3w4",
  "user_sub": "e2e_alice@test.local",
  "confidence_score": 0,
  "result": "fail",
  "anti_spoof": {
    "passed": false,
    "checks": [
      { "check": "file_size", "passed": false, "detail": "File size: 512 bytes (too small for a real photo)" },
      { "check": "image_format", "passed": true, "detail": "Format: image/jpeg" },
      { "check": "not_screenshot", "passed": true, "detail": "Extension: .jpg" }
    ],
    "total_checks": 3,
    "passed_checks": 2
  },
  "attempt_number": 1,
  "max_attempts": 3,
  "selfie_node_id": "node_tiny_selfie",
  "id_front_node_id": "node_id_front_003",
  "created_at": 1717080000
}
```

---

## 6. API Request/Response Examples

### 6.1 Run Face Comparison (Pass)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/compare-face"
```

Response (200):
```json
{
  "comparison_id": "fc_7a8b9c0d1e2f",
  "confidence_score": 85,
  "result": "pass",
  "anti_spoof": {
    "passed": true,
    "checks": [
      { "check": "file_size", "passed": true, "detail": "File size: 157320 bytes" },
      { "check": "image_format", "passed": true, "detail": "Format: image/jpeg" },
      { "check": "not_screenshot", "passed": true, "detail": "Extension: .jpg" }
    ],
    "total_checks": 3,
    "passed_checks": 3
  },
  "attempt_number": 1,
  "max_attempts": 3,
  "remaining_attempts": 2,
  "created_at": 1717050000
}
```

### 6.2 Run Face Comparison (Mismatch/Fail)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_mismatch01/compare-face"
```

Response (200):
```json
{
  "comparison_id": "fc_fail11223344",
  "confidence_score": 30,
  "result": "fail",
  "anti_spoof": { "passed": true, "checks": [...], "total_checks": 3, "passed_checks": 3 },
  "attempt_number": 1,
  "max_attempts": 3,
  "remaining_attempts": 2,
  "created_at": 1717055000
}
```

### 6.3 Compare Without Selfie (400)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_noselfie/compare-face"
```

Response (400):
```json
{
  "detail": "selfie_not_uploaded"
}
```

### 6.4 Max Attempts Exceeded (409)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_maxed/compare-face"
```

Response (409):
```json
{
  "detail": "max_attempts_exceeded"
}
```

### 6.5 List Face Comparisons

```bash
curl -s -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_a1b2c3d4/face-comparisons"
```

Response (200):
```json
{
  "comparisons": [
    {
      "comparison_id": "fc_7a8b9c0d1e2f",
      "confidence_score": 85,
      "result": "pass",
      "attempt_number": 1,
      "created_at": 1717050000
    }
  ]
}
```

### 6.6 Admin Face Comparison (Side-by-Side)

```bash
curl -s -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_a1b2c3d4/face-comparison"
```

Response (200):
```json
{
  "case_id": "kyc_a1b2c3d4",
  "user_sub": "e2e_alice@test.local",
  "selfie_file": {
    "file_type": "selfie",
    "file_node_id": "node_selfie_001",
    "attached_at": 1717049500
  },
  "id_front_file": {
    "file_type": "id_front",
    "file_node_id": "node_id_front_001",
    "attached_at": 1717049000
  },
  "comparisons": [
    {
      "comparison_id": "fc_7a8b9c0d1e2f",
      "confidence_score": 85,
      "result": "pass",
      "attempt_number": 1,
      "created_at": 1717050000
    }
  ],
  "best_comparison": {
    "comparison_id": "fc_7a8b9c0d1e2f",
    "confidence_score": 85,
    "result": "pass"
  },
  "total_attempts": 1,
  "max_attempts": 3
}
```

### 6.7 Admin Override

```bash
curl -s -X POST -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "pass",
    "reason": "Manual visual comparison confirms identity despite low score."
  }' \
  "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_e5f6g7h8/face-comparison/fc_aabbccdd1122/override"
```

Response (200):
```json
{
  "comparison_id": "fc_aabbccdd1122",
  "original_result": "review",
  "original_score": 60,
  "admin_override": {
    "decision": "pass",
    "reason": "Manual visual comparison confirms identity despite low score.",
    "admin_sub": "root.admin@testdev.local",
    "overridden_at": 1717070000
  }
}
```

### 6.8 Admin Override Short Reason (422)

```bash
curl -s -X POST -b "ui_session=sess_root123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_root123" \
  -H "Content-Type: application/json" \
  -d '{ "decision": "pass", "reason": "ok" }' \
  "http://localhost:8000/v1/kyc/cases/admin/cases/kyc_e5f6g7h8/face-comparison/fc_abc/override"
```

Response (422):
```json
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "reason"],
      "msg": "String should have at least 5 characters",
      "ctx": { "min_length": 5 }
    }
  ]
}
```

---

## 7. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code / Detail | User-Facing Message | Recovery Action |
|----------------|-------------|---------------------|---------------------|-----------------|
| Case not found | 404 | `case_not_found` | "Verification case not found." | Verify case ID |
| Case belongs to another user | 403 | `access_forbidden` | "You do not have access to this case." | -- |
| Selfie not uploaded | 400 | `selfie_not_uploaded` | "Please upload a selfie before running comparison." | Upload selfie first |
| ID front not uploaded | 400 | `id_front_not_uploaded` | "Please upload the front of your ID before running comparison." | Upload ID front first |
| Max attempts exceeded (>3) | 409 | `max_attempts_exceeded` | "Maximum comparison attempts reached. Contact support." | Admin review only |
| Anti-spoof failed (tiny file) | 200 | `result: "fail"`, score=0 | "Your selfie did not pass verification. Please take a clearer photo." | Upload new selfie |
| Anti-spoof failed (screenshot format) | 200 | `result: "fail"`, score=0 | "Screenshots are not accepted. Please take a live photo." | Use camera |
| Comparison not found (override) | 404 | `comparison_not_found` | "Comparison result not found." | Check comparison ID |
| Non-root user accesses admin endpoint | 403 | `root_session_required` | "You do not have permission." | Log in as root |
| Override reason too short (<5 chars) | 422 | Pydantic validation | "Reason must be at least 5 characters." | Provide longer reason |
| Override invalid decision value | 422 | Pydantic validation | "Decision must be 'pass' or 'fail'." | Use valid decision |
| File manager node not found | 404 | `file_not_found` | "Uploaded file could not be located." | Re-upload the file |
| S3 download failure (prod) | 500 | `comparison_service_error` | "An error occurred. Please try again." | Retry |
| Production comparison API timeout | 504 | `comparison_timeout` | "Comparison timed out. Please try again." | Retry |
| No session cookie | 401 | `session_expired` | "Please log in." | Re-authenticate |
| CSRF token missing/mismatch | 403 | `csrf_token_mismatch` | "Security validation failed." | Refresh page |

---

## 8. Pydantic Models

### 8.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class FaceComparisonOverrideRequest(BaseModel):
    """Request for admin to override a face comparison result."""
    decision: Literal["pass", "fail"] = Field(
        description="Override decision. Must be 'pass' or 'fail'.",
    )
    reason: str = Field(
        min_length=5,
        max_length=500,
        description="Reason for the override decision.",
        examples=["Manual visual comparison confirms identity despite low automated score."],
    )
```

### 8.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any, Literal


class AntiSpoofCheckOut(BaseModel):
    """Result of a single anti-spoof check."""
    check: str = Field(description="Check name (file_size, image_format, not_screenshot)")
    passed: bool
    detail: str


class AntiSpoofResultOut(BaseModel):
    """Overall anti-spoof result."""
    passed: bool
    checks: list[AntiSpoofCheckOut]
    total_checks: int = Field(ge=0)
    passed_checks: int = Field(ge=0)


class FaceComparisonResultOut(BaseModel):
    """Result of a face comparison attempt."""
    comparison_id: str = Field(pattern=r"^fc_[a-f0-9]{12}$")
    confidence_score: int = Field(ge=0, le=100)
    result: Literal["pass", "review", "fail"]
    anti_spoof: AntiSpoofResultOut
    attempt_number: int = Field(ge=1, le=3)
    max_attempts: int = Field(default=3)
    remaining_attempts: int = Field(ge=0, le=3)
    created_at: int


class FaceComparisonListOut(BaseModel):
    """List of face comparison attempts for a case."""
    comparisons: list[FaceComparisonResultOut]


class AdminOverrideOut(BaseModel):
    """Admin override details."""
    decision: Literal["pass", "fail"]
    reason: str
    admin_sub: str
    overridden_at: int


class FaceComparisonOverrideResultOut(BaseModel):
    """Response after admin overrides a comparison."""
    comparison_id: str
    original_result: Literal["pass", "review", "fail"]
    original_score: int
    admin_override: AdminOverrideOut


class KycFileRefOut(BaseModel):
    """File reference for admin comparison view."""
    file_type: str
    file_node_id: str
    attached_at: int


class BestComparisonOut(BaseModel):
    """Summary of the best comparison for admin view."""
    comparison_id: str
    confidence_score: int
    result: Literal["pass", "review", "fail"]


class AdminFaceComparisonOut(BaseModel):
    """Admin view of face comparison data with side-by-side image refs."""
    case_id: str
    user_sub: str
    selfie_file: KycFileRefOut | None
    id_front_file: KycFileRefOut | None
    comparisons: list[FaceComparisonResultOut]
    best_comparison: BestComparisonOut | None
    total_attempts: int = Field(ge=0)
    max_attempts: int = Field(default=3)
```

---

## 9. Frontend Component Tree

```
FaceComparisonResult.tsx  (embedded in KycWizard Step 3)
├── Props: { caseId: string, comparisonResult: FaceComparisonResultOut | null }
├── State:
│   ├── showAntiSpoofDetail: boolean (useState, default false)
│   └── retrying: boolean (from useMutation)
├── Queries:
│   └── useQuery(["kyc","face-comparisons", caseId]) → FaceComparisonListOut
├── Mutations:
│   └── useMutation(compareFace(caseId))
│       → onSuccess: invalidate ["kyc","face-comparisons", caseId]
│
├── {!comparisonResult && <Button onClick={runComparison}>"Run Face Comparison"</Button>}
│
├── {comparisonResult &&
│   <Card>
│     ├── <div className="flex items-center gap-6">
│     │   ├── <CircularProgress value={confidence_score} max={100}>
│     │   │   └── Center text: "{score}/100"
│     │   │   └── Color: score>=70 ? "green" : score>=50 ? "yellow" : "red"
│     │   │
│     │   ├── <Badge variant={resultVariant}>
│     │   │   └── result === "pass" ? "Match Confirmed"
│     │   │       : result === "review" ? "Manual Review Required"
│     │   │       : "Match Failed"
│     │   │
│     │   └── <span className="text-sm text-muted-foreground">
│     │       "Attempt {attempt_number} of {max_attempts}"
│     │
│     ├── {result === "fail" && remaining_attempts > 0 &&
│     │   <div>
│     │     <p>"Your selfie did not match. You have {remaining} attempts left."</p>
│     │     <Button onClick={uploadNewSelfie}>"Upload New Selfie"</Button>
│     │   </div>}
│     │
│     ├── {result === "fail" && remaining_attempts === 0 &&
│     │   <Alert variant="destructive">
│     │     "All comparison attempts used. An admin will review manually."
│     │   </Alert>}
│     │
│     ├── <Collapsible open={showAntiSpoofDetail}>
│     │   ├── <CollapsibleTrigger>"Anti-Spoof Details"</CollapsibleTrigger>
│     │   └── <CollapsibleContent>
│     │       └── anti_spoof.checks.map(check =>
│     │           <div>
│     │             {check.passed ? <CheckCircle2 green/> : <XCircle red/>}
│     │             <span>{check.check}</span>
│     │             <span className="text-muted-foreground">{check.detail}</span>
│     │           </div>)
│     └── </Collapsible>
│   </Card>}

KycFaceComparison.tsx  (admin panel in case detail)
├── Props: { caseId: string }
├── State:
│   ├── overrideDialogOpen: boolean
│   ├── selectedComparisonId: string | null
│   └── overrideForm: useForm({ decision, reason })
├── Queries:
│   └── useQuery(["kyc","admin-face-comparison", caseId]) → AdminFaceComparisonOut
├── Mutations:
│   └── useMutation(adminOverrideFace)
│       → onSuccess: invalidate ["kyc","admin-face-comparison", caseId]
│
├── <Card>
│   ├── <CardHeader>
│   │   └── <CardTitle>"Face Comparison"</CardTitle>
│   │
│   ├── <CardContent>
│   │   ├── <div className="grid grid-cols-2 gap-4">
│   │   │   ├── <div>
│   │   │   │   ├── <h4>"Selfie"</h4>
│   │   │   │   └── <img src={selfieUrl} className="rounded-lg" />
│   │   │   └── <div>
│   │   │       ├── <h4>"ID Photo"</h4>
│   │   │       └── <img src={idFrontUrl} className="rounded-lg" />
│   │   │
│   │   ├── <div className="text-center py-4">
│   │   │   ├── <span className="text-3xl font-bold">{best.confidence_score}</span>
│   │   │   ├── <Badge>{best.result}</Badge>
│   │   │   └── <p>"Best of {total_attempts} attempts"</p>
│   │   │
│   │   ├── <h4>"All Attempts"</h4>
│   │   ├── <DataTable>
│   │   │   └── Columns: [Attempt, Score, Result, Date, Override]
│   │   │       └── Each row: comparison data + "Override" button if result !== "pass"
│   │   │
│   │   └── <div className="flex gap-2 justify-end">
│   │       ├── <Button variant="default" onClick={() => openOverride("pass")}>
│   │       │   "Approve Match"
│   │       └── <Button variant="destructive" onClick={() => openOverride("fail")}>
│   │           "Reject Match"
│   │
│   └── <Dialog open={overrideDialogOpen}>
│       └── <DialogContent>
│           ├── <DialogTitle>"Override Comparison Result"</DialogTitle>
│           ├── <Form>
│           │   ├── <Select label="Decision" options={["pass","fail"]} />
│           │   ├── <Textarea label="Reason" minLength={5} />
│           │   └── <Button type="submit">"Confirm Override"</Button>
│           └── </Form>
│
└── </Card>
```

### React Query Keys

| Key | Endpoint | Stale Time | Invalidation |
|-----|----------|------------|--------------|
| `["kyc","face-comparisons", caseId]` | `GET /{caseId}/face-comparisons` | 10s | After `compare-face` mutation |
| `["kyc","admin-face-comparison", caseId]` | `GET /admin/cases/{caseId}/face-comparison` | 5s | After override mutation |

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_face_comparison_total` | Counter | `result` (pass/review/fail) | Total comparisons by result |
| `kyc_face_comparison_score` | Histogram | -- | Distribution of confidence scores |
| `kyc_face_comparison_duration_ms` | Histogram | `mode` (mock/production) | Comparison latency |
| `kyc_anti_spoof_total` | Counter | `passed` (true/false) | Anti-spoof check outcomes |
| `kyc_anti_spoof_check_failed` | Counter | `check` (file_size/image_format/not_screenshot) | Individual check failures |
| `kyc_face_comparison_attempts` | Histogram | -- | Number of attempts per case |
| `kyc_face_comparison_admin_override_total` | Counter | `original_result`, `override_decision` | Admin overrides |
| `kyc_face_comparison_max_attempts_reached` | Counter | -- | Cases hitting 3-attempt limit |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.face.comparison.run` | INFO | `case_id`, `comparison_id`, `score`, `result`, `attempt`, `duration_ms` | Comparison completed |
| `kyc.face.comparison.pass` | INFO | `case_id`, `score` | Auto-pass (score >= 70) |
| `kyc.face.comparison.review` | INFO | `case_id`, `score` | Manual review required (50-69) |
| `kyc.face.comparison.fail` | WARN | `case_id`, `score`, `anti_spoof_passed` | Auto-fail (score < 50 or anti-spoof failed) |
| `kyc.face.anti_spoof.failed` | WARN | `case_id`, `failed_checks` | Anti-spoof check failed |
| `kyc.face.max_attempts` | WARN | `case_id`, `user_sub`, `best_score` | User exhausted all 3 attempts |
| `kyc.face.admin_override` | WARN | `case_id`, `comparison_id`, `admin_sub`, `original_result`, `override_decision` | Admin overrode result |
| `kyc.face.comparison.error` | ERROR | `case_id`, `error_type`, `error_msg` | Comparison service error |

### 10.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Anti-spoof failure rate > 20% | `anti_spoof_failed / total > 0.2` | P3 | Review anti-spoof thresholds |
| Auto-fail rate > 30% | `fail_total / total > 0.3` | P3 | Check image quality guidance |
| Max attempts rate > 10% | `max_attempts_reached / unique_cases > 0.1` | P2 | Improve comparison accuracy or increase limit |
| Admin override rate > 50% of "review" results | `overrides / review_total > 0.5` | P3 | Adjust THRESHOLD_AUTO_PASS downward |
| Comparison latency p95 > 5s | `face_comparison_duration_ms_p95 > 5000` | P2 | Check external API performance |
| Comparison errors > 5/hour | `rate(comparison_error_total[1h]) > 5` | P2 | Check S3 access, API connectivity |

### 10.4 Dashboard Queries

**Comparison result distribution (last 7 days)**:
```sql
SELECT result, COUNT(*) AS count,
       AVG(confidence_score) AS avg_score,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY confidence_score) AS median_score
FROM kyc_face_comparison_events
WHERE event = 'kyc.face.comparison.run'
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY result;
```

**Admin override history**:
```sql
SELECT comparison_id, case_id, admin_sub,
       original_result, override_decision, reason, overridden_at
FROM kyc_face_comparison_events
WHERE event = 'kyc.face.admin_override'
ORDER BY overridden_at DESC
LIMIT 50;
```

---

## 11. Rollout Plan

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_FACE_COMPARISON_ENABLED` | `false` | Enable face comparison endpoint |
| `KYC_FACE_AUTO_COMPARE` | `false` | Auto-run comparison after selfie upload |
| `KYC_FACE_ADMIN_OVERRIDE_ENABLED` | `true` | Allow admin overrides |

### 11.2 Rollout Phases

**Phase 1: Shadow mode (Week 1)**
1. Enable comparison endpoint but results are informational only.
2. Do not block case progression based on comparison result.
3. Log all comparison results for calibration.

**Phase 2: Advisory mode (Week 2)**
1. Show comparison result to admin in case detail view.
2. Admin can use the result to inform their decision but it is not binding.
3. Collect admin feedback on threshold accuracy.

**Phase 3: Auto-gating (Week 3)**
1. Cases with score >= 70 skip manual face verification step.
2. Cases with score < 50 are automatically flagged for review.
3. Cases with score 50-69 require admin confirmation.

**Phase 4: User-facing (Week 4)**
1. Show comparison result to users after selfie upload.
2. Enable retry flow (upload new selfie if failed).
3. Auto-trigger comparison after selfie upload (`KYC_FACE_AUTO_COMPARE=true`).

### 11.3 Rollback Procedure

1. Set `KYC_FACE_COMPARISON_ENABLED=false` -- comparison endpoint returns 503.
2. Remove face comparison from admin case detail view.
3. `FACE_MATCH#*` records in DynamoDB are independent of case META and can be ignored.
4. Delete `app/services/kyc_facial_comparison.py` if permanent rollback.

---

## 12. Performance Considerations

### 12.1 Query Costs

| Operation | DDB Read/Write | Latency (mock) | Latency (production) |
|-----------|----------------|-----------------|----------------------|
| Compare faces | 1 RCU (get case) + 1 WCU (store result) | 20ms | 2-5s (Rekognition API) |
| List comparisons | 1 RCU (query, <3 items) | 5ms | 5ms |
| Admin view | 1 RCU (get case) + 1 RCU (query comparisons) | 10ms | 10ms |
| Admin override | 1 RCU (get comparison) + 1 WCU (update) | 10ms | 10ms |

### 12.2 Mock vs Production Performance

In dev mode, the mock comparison is pure computation (hash-based) with no I/O except DynamoDB reads/writes. Total latency is ~20ms.

In production, the comparison would call AWS Rekognition `CompareFaces` API which has:
- Average latency: 2-3 seconds
- Max latency: 5 seconds (timeout)
- Cost: $0.001 per comparison

### 12.3 Image Size Optimization

To keep comparison latency low in production:
- Compress selfie to max 1280x720 JPEG at quality 85 before S3 upload.
- ID front images are typically already compressed from the scan pipeline (KYC-010).
- Max file size for comparison: 5MB per image (Rekognition limit).

### 12.4 Caching

Comparison results are stored in DynamoDB and never re-computed for the same selfie+id_front pair. The `attempt_number` increments even if the same files are used. This is intentional -- the user must take a new selfie for each retry.

### 12.5 Rate Limiting

| Endpoint | Rate Limit | Window | Notes |
|----------|------------|--------|-------|
| `POST /{case_id}/compare-face` | 3 | per case per day | Enforced by MAX_SELFIE_ATTEMPTS |
| `GET /{case_id}/face-comparisons` | 30 | per minute | Normal polling |
| `POST /admin/.../override` | 10 | per minute per admin | Admin actions |

---

## 13. Implementation Plan

### Phase 1: Comparison Service (3 days)

| File | Change |
|------|--------|
| `app/services/kyc_facial_comparison.py` | New: comparison engine, anti-spoof, mock, storage (~350 lines) |

### Phase 2: API Endpoints (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_cases.py` | Add: 4 endpoints for face comparison (~100 lines) |
| `app/contracts/kyc_cases_contract.py` | Add: `FaceComparisonOverrideRequest` model (see existing file `app/contracts/kyc_cases_contract.py`) |

### Phase 3: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/FaceComparisonResult.tsx` | New: user-facing comparison result (~120 lines) |
| `frontend/src/pages/admin/KycFaceComparison.tsx` | New: admin side-by-side view (~200 lines) |
| `frontend/src/api/endpoints/kyc-face.ts` | New: API endpoint wrappers |

### Phase 4: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-face-comparison.spec.ts` | New: ~15 tests, sections 203-205 |

---

## 14. E2E Test Plan (`frontend/e2e/kyc-face-comparison.spec.ts`)

**Test file**: `frontend/e2e/kyc-face-comparison.spec.ts`  
**Total tests**: ~15  
**Sections**: 203-205

### Section 203: Face Comparison API (6 tests)

1. `POST /{case_id}/compare-face returns confidence score and result` -- Upload selfie (file named `match_selfie.jpg`) and id_front; run comparison; verify `confidence_score: 85`, `result: "pass"`.
2. `Selfie named "mismatch" returns low score` -- Upload selfie named `mismatch_selfie.jpg`; verify `confidence_score: 30`, `result: "fail"`.
3. `Selfie named "partial" returns review result` -- Upload `partial_selfie.jpg`; verify `confidence_score: 60`, `result: "review"`.
4. `Compare without selfie returns 400` -- Case has id_front but no selfie; verify 400 `selfie_not_uploaded`.
5. `Compare without id_front returns 400` -- Case has selfie but no id_front; verify 400 `id_front_not_uploaded`.
6. `Fourth attempt returns 409 max_attempts_exceeded` -- Run comparison 3 times (re-upload selfie between each); fourth call returns 409.

### Section 204: Anti-Spoof & Multiple Attempts (5 tests)

1. `Anti-spoof passes for JPEG selfie with reasonable size` -- Upload 100KB JPEG; verify `anti_spoof.passed: true`.
2. `Anti-spoof fails for tiny file` -- Upload 1KB selfie; verify `anti_spoof.passed: false`, `anti_spoof.checks` contains failed `file_size` check.
3. `Anti-spoof fails for BMP format` -- Upload .bmp file; verify `anti_spoof.passed: false`, `not_screenshot` check failed.
4. `GET /{case_id}/face-comparisons lists all attempts` -- After 2 comparisons; verify array length is 2.
5. `Attempts are numbered sequentially` -- First comparison has `attempt_number: 1`, second has `attempt_number: 2`.

### Section 205: Admin Face Comparison (4 tests)

1. `Admin GET /admin/cases/{case_id}/face-comparison returns side-by-side data` -- Root queries; verify response has `selfie_file`, `id_front_file`, `comparisons` array, `best_comparison`.
2. `Admin override changes result to pass` -- Override a "fail" comparison to "pass"; verify `admin_override.decision: "pass"`.
3. `Admin override with short reason returns 422` -- Reason "ok" fails validation.
4. `Non-root user cannot access admin face comparison` -- Alice queries admin endpoint; returns 403.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;
let caseId: string;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Create KYC case
  const caseResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {});
  caseId = caseResp.case.kyc_case_id;

  // Upload test files to file manager (create file nodes)
  // ... upload selfie and id_front via file manager API
  // Attach to case via POST /{caseId}/files
});
```

### Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Selfie replaced between attempts | New comparison uses the latest selfie attached to the case |
| Anti-spoof fails | Score set to 0, result is "fail" regardless of face match |
| Both selfie and id_front are same image | Mock returns high score (hash-based); production would also match |
| Case already approved | Comparison still allowed (user might re-verify); stored for audit |
| Admin override on already-overridden comparison | New override replaces previous; audit trail captures both |

---

## 15. Expanded E2E Test Details

### Section 203a: Face Comparison Edge Cases (4 tests)

1. `Default selfie name produces deterministic score between 55-95` -- Upload a selfie with a generic name (no "match"/"partial"/"mismatch"); verify score is in 55-95 range; run again with same files; verify same score (deterministic).
2. `Comparison on case belonging to another user returns 403` -- Bob tries to run comparison on Alice's case; verify 403 `access_forbidden`.
3. `Comparison on non-existent case returns 404` -- POST to `/v1/kyc/cases/kyc_nonexistent/compare-face`; verify 404.
4. `Comparison result includes remaining_attempts` -- First attempt: `remaining_attempts: 2`; second: `remaining_attempts: 1`; third: `remaining_attempts: 0`.

### Section 204a: Anti-Spoof Detail Cases (4 tests)

1. `Anti-spoof check detail includes all 3 checks` -- Verify `anti_spoof.total_checks: 3` and all check names present (file_size, image_format, not_screenshot).
2. `PNG selfie passes format check` -- Upload .png selfie; verify `image_format` check passed.
3. `WebP selfie passes format check` -- Upload .webp selfie; verify `image_format` check passed.
4. `GIF selfie fails screenshot check` -- Upload .gif selfie; verify `not_screenshot` check failed and overall `anti_spoof.passed: false`.

### Section 205a: Admin Override Edge Cases (4 tests)

1. `Admin override on pass result to fail` -- Override a passing comparison to "fail"; verify `original_result: "pass"`, `admin_override.decision: "fail"`.
2. `Admin override reason at boundary (5 chars) accepted` -- Reason "Valid" (5 chars); verify override succeeds.
3. `Admin override reason at boundary (501 chars) rejected (422)` -- 501-character reason; verify 422.
4. `Best comparison reflects highest score across attempts` -- 3 attempts with scores 30, 85, 60; verify `best_comparison.confidence_score: 85`.

### Section 205b: Concurrent and Authorization Edge Cases (3 tests)

1. `Alice cannot access admin face comparison endpoint` -- Alice (USER) queries admin endpoint; verify 403.
2. `Alice cannot override comparison` -- Alice POSTs to admin override; verify 403.
3. `Admin can view face comparison for any user's case` -- Root queries Alice's case; verify 200 with valid data.

---

## 16. Security Considerations

- Facial comparison results are stored in the `kyc_cases` table alongside the case, subject to the same retention policies.
- Image data is not stored in the comparison record -- only `file_node_id` references. The images themselves are in S3 under the user's namespace.
- Anti-spoof checks in dev mode are heuristic (file size, format). Production would use ML-based liveness detection.
- Admin override requires `require_root_session` and creates an audit trail entry.
- The mock comparison service produces deterministic results from file metadata -- no actual facial recognition is performed in dev mode.
- Comparison scores are not exposed in any public endpoint; only the case owner and root admins can see them.
- The `_mock_compare` function uses MD5 for hash-based scoring -- this is not a security-sensitive use (deterministic test scoring only).

---

## 17. Rollback Plan

- Set `KYC_FACE_COMPARISON_ENABLED=false` to disable comparison endpoints.
- Remove face comparison endpoints from `app/routers/kyc_cases.py`.
- Delete `app/services/kyc_facial_comparison.py`.
- `FACE_MATCH#*` records in the `kyc_cases` table are independent of the case META record and can be ignored.
- Frontend components (`FaceComparisonResult.tsx`, `KycFaceComparison.tsx`) can be deleted without affecting the wizard flow (Step 3 falls back to simple file upload).

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC router (prefix `/v1/kyc/cases`) | `app/routers/kyc_cases.py` | 48 | Exists |
| KYC router registration | `app/main.py` | 88, 406 | Exists |
| `attach_kyc_file()` endpoint | `app/routers/kyc_cases.py` | 734 | Exists |
| `_build_admin_case_detail()` | `app/routers/kyc_cases.py` | 345 | Exists |
| `get_admin_kyc_case_detail()` | `app/routers/kyc_cases.py` | 997 | Exists |
| Admin auth pattern (role check) | `app/routers/kyc_cases.py` | 1000-1003 | Exists — uses `require_ui_session` + manual role check, NOT `require_root_session` |
| `STORE` (KycCaseStore) | `app/services/kyc_cases.py` | 94 | Exists |
| `KycCaseStore.get_case()` | `app/services/kyc_cases.py` | 138 | Exists |
| `_case_pk()` helper | `app/services/kyc_cases.py` | 36 | Exists |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | Exists (with owner + status GSIs) |
| KYC settings | `app/core/settings.py` | 1065-1072 | Exists |
| `get_node(owner, path)` | `app/services/filemanager.py` | 450 | Exists — signature is `(owner, path)` not `(user_sub, node_id)` |
| `audit_event()` | `app/services/alerts.py` | 695 | Exists |
| S3 mock (moto in-process) | `app/core/dev_s3.py` | -- | Exists |
| KYC contracts file | `app/contracts/kyc_cases_contract.py` | -- | Exists (no `FaceComparisonOverrideRequest` yet) |
| `app/services/kyc_facial_comparison.py` | -- | -- | Does NOT exist — new implementation required |
| `frontend/src/pages/kyc/` | -- | -- | Does NOT exist — new directory/files required |
| `frontend/src/api/endpoints/kyc-face.ts` | -- | -- | Does NOT exist — new file required |
| `frontend/e2e/kyc-face-comparison.spec.ts` | -- | -- | Does NOT exist — new test file required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_facial.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_capture_selfie`
  - `test_extract_face_from_selfie`
  - `test_compare_faces_match`
  - `test_compare_faces_no_match`
  - `test_comparison_confidence_score`
  - `test_liveness_detection_on_selfie`
  - `test_store_comparison_result`

### Integration Tests

  - Selfie capture triggers facial comparison against stored ID photo
  - Comparison result stored with confidence score in kyc_documents
  - Admin reviews comparison result with side-by-side images

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-facial.spec.ts`
**Test count**: 10

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `kyc_documents (facial comparison results)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_FACIAL_COMPARISON_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-010 | Passport & National ID Scanner | Extracted ID photo used as reference |
| KYC-013 | User Self-Service Portal | Selfie capture in self-service flow |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after KYC-010, KYC-013. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 10 E2E tests pass with `npx playwright test kyc-facial.spec.ts`
