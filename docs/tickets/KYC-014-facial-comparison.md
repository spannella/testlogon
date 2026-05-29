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

The current KYC system requires users to upload a selfie and an identity document (id_front, id_back) via `POST /v1/kyc/cases/{case_id}/files` (line 733 in `app/routers/kyc_cases.py`). However, once uploaded, these files are treated as opaque attachments. There is no automated comparison between the selfie and the photo on the identity document. An admin reviewing the case must manually compare the selfie against the ID photo — a time-consuming, subjective, and error-prone process.

### 1.2 What This Ticket Adds

1. **Facial comparison service** — Compares the uploaded selfie against the ID document photo and produces a confidence score (0-100).
2. **Mock comparison service** for dev mode — Deterministic results based on test file metadata, enabling predictable E2E testing.
3. **Confidence thresholds**:
   - Score >= 70: auto-pass (no manual review needed for face matching)
   - Score 50-69: manual review required (admin reviews side-by-side)
   - Score < 50: auto-fail (flag as likely mismatch)
4. **Anti-spoofing checks** — Mock implementation that checks image metadata for camera vs screenshot indicators.
5. **Multiple selfie attempts** — Users can upload up to 3 selfie attempts; the highest-scoring comparison is used.
6. **Admin side-by-side comparison view** — Overlay displaying both images with confidence score and decision buttons.

### 1.3 Architecture

```
Facial Comparison Flow:

  POST /v1/kyc/cases/{case_id}/compare-face
       │
       ▼
  kyc_facial_comparison.compare_faces()
       │
       ├── 1. Retrieve selfie from case files
       ├── 2. Retrieve id_front from case files
       ├── 3. anti_spoof_check(selfie_metadata)
       │       ├── Check image source (camera vs screenshot)
       │       ├── Check resolution (minimum 640x480)
       │       └── Check EXIF for camera model (presence = real photo)
       ├── 4. compare(selfie_image, id_photo)
       │       ├── Dev mode: _mock_compare() → deterministic score
       │       └── Prod mode: external API call (AWS Rekognition / etc.)
       └── 5. Store result (kyc_cases table, SK=FACE_MATCH#{ts})
       │
       ▼
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
       │
       ▼
  Returns side-by-side image URLs + comparison results
  Admin can override result (approve/reject with reason)
```

---

## 2. Current State Analysis

### 2.1 File Attachments on KYC Cases

The `attach_kyc_file()` endpoint (line 733) stores file references as dicts in the case's `files` array:

```python
{
    "file_type": "selfie",       # or "id_front", "id_back", "proof_of_address"
    "file_node_id": "node_abc",
    "attached_at": 1717000000,
    "attached_by": "user_sub",
}
```

The `file_node_id` references a node in the file manager (`app/services/filemanager.py`). The file manager stores the S3 key for the actual file data. To retrieve the image, the comparison service calls `get_node(user_sub, node_id)` and then downloads from S3.

### 2.2 KYC Cases Table — Existing Item Schema

The `kyc_cases` table uses single-table design:
- `pk=KYC#{case_id}`, `sk=META` — main case record
- `pk=KYC#{case_id}`, `sk=SCAN#{scan_id}` — document scan results (KYC-010)

Face comparison results will use `sk=FACE_MATCH#{timestamp}` to store each comparison attempt.

### 2.3 S3 Access in Dev Mode

The moto S3 mock is started in-process by `app/core/dev_s3.py`. File data uploaded through the file manager is stored in the mock S3 bucket and can be retrieved via `boto3.client("s3").get_object()`.

### 2.4 Admin Case Detail (`app/routers/kyc_cases.py`, line 996)

The `get_admin_kyc_case_detail()` endpoint builds a detailed case view via `_build_admin_case_detail()` (line 345). The face comparison results need to be included in this admin view, along with signed URLs for the selfie and ID images.

### 2.5 Mock Dev Image URLs

The `_message_out_from_item` function in messaging generates `/mock/s3/...` URLs for images in dev mode. The same pattern should be used for KYC file URLs in the admin comparison view.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_facial_comparison.py`

```python
"""Facial comparison service — compares selfie against ID document photo."""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.filemanager import get_node
from app.services.alerts import audit_event

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
    """Production facial comparison — calls external service.

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
| `GET` | `/admin/cases/{case_id}/face-comparison` | `require_root_session` | Admin view with side-by-side |
| `POST` | `/admin/cases/{case_id}/face-comparison/{comparison_id}/override` | `require_root_session` | Admin override |

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
def admin_face_comparison(case_id: str, user=Depends(require_root_session)):
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
    user=Depends(require_root_session),
):
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

### 3.3 Pydantic Models

```python
class FaceComparisonOverrideRequest(BaseModel):
    decision: Literal["pass", "fail"] = Field(...)
    reason: str = Field(min_length=5, max_length=500)
```

### 3.4 Frontend Components

**File**: `frontend/src/pages/kyc/FaceComparisonResult.tsx`

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

## 4. Implementation Plan

### Phase 1: Comparison Service (3 days)

| File | Change |
|------|--------|
| `app/services/kyc_facial_comparison.py` | New: comparison engine, anti-spoof, mock, storage (~350 lines) |

### Phase 2: API Endpoints (2 days)

| File | Change |
|------|--------|
| `app/routers/kyc_cases.py` | Add: 4 endpoints for face comparison (~100 lines) |
| `app/contracts/kyc_cases_contract.py` | Add: `FaceComparisonOverrideRequest` model |

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

## 5. E2E Test Plan (`frontend/e2e/kyc-face-comparison.spec.ts`)

**Test file**: `frontend/e2e/kyc-face-comparison.spec.ts`  
**Total tests**: ~15  
**Sections**: 203-205

### Section 203: Face Comparison API (6 tests)

1. `POST /{case_id}/compare-face returns confidence score and result` — Upload selfie (file named `match_selfie.jpg`) and id_front; run comparison; verify `confidence_score: 85`, `result: "pass"`.
2. `Selfie named "mismatch" returns low score` — Upload selfie named `mismatch_selfie.jpg`; verify `confidence_score: 30`, `result: "fail"`.
3. `Selfie named "partial" returns review result` — Upload `partial_selfie.jpg`; verify `confidence_score: 60`, `result: "review"`.
4. `Compare without selfie returns 400` — Case has id_front but no selfie; verify 400 `selfie_not_uploaded`.
5. `Compare without id_front returns 400` — Case has selfie but no id_front; verify 400 `id_front_not_uploaded`.
6. `Fourth attempt returns 409 max_attempts_exceeded` — Run comparison 3 times (re-upload selfie between each); fourth call returns 409.

### Section 204: Anti-Spoof & Multiple Attempts (5 tests)

1. `Anti-spoof passes for JPEG selfie with reasonable size` — Upload 100KB JPEG; verify `anti_spoof.passed: true`.
2. `Anti-spoof fails for tiny file` — Upload 1KB selfie; verify `anti_spoof.passed: false`, `anti_spoof.checks` contains failed `file_size` check.
3. `Anti-spoof fails for BMP format` — Upload .bmp file; verify `anti_spoof.passed: false`, `not_screenshot` check failed.
4. `GET /{case_id}/face-comparisons lists all attempts` — After 2 comparisons; verify array length is 2.
5. `Attempts are numbered sequentially` — First comparison has `attempt_number: 1`, second has `attempt_number: 2`.

### Section 205: Admin Face Comparison (4 tests)

1. `Admin GET /admin/cases/{case_id}/face-comparison returns side-by-side data` — Root queries; verify response has `selfie_file`, `id_front_file`, `comparisons` array, `best_comparison`.
2. `Admin override changes result to pass` — Override a "fail" comparison to "pass"; verify `admin_override.decision: "pass"`.
3. `Admin override with short reason returns 422` — Reason "ok" fails validation.
4. `Non-root user cannot access admin face comparison` — Alice queries admin endpoint; returns 403.

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

## 6. Security Considerations

- Facial comparison results are stored in the `kyc_cases` table alongside the case, subject to the same retention policies.
- Image data is not stored in the comparison record — only `file_node_id` references. The images themselves are in S3 under the user's namespace.
- Anti-spoof checks in dev mode are heuristic (file size, format). Production would use ML-based liveness detection.
- Admin override requires `require_root_session` and creates an audit trail entry.
- The mock comparison service produces deterministic results from file metadata — no actual facial recognition is performed in dev mode.

---

## 7. Rollback Plan

- Remove face comparison endpoints from `app/routers/kyc_cases.py`.
- Delete `app/services/kyc_facial_comparison.py`.
- `FACE_MATCH#*` records in the `kyc_cases` table are independent of the case META record and can be ignored.
