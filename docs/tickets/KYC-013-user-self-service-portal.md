# KYC-013: KYC User Self-Service Portal

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Critical  
**Estimated effort**: 10-14 days  
**Dependencies**: KYC-009 (Tiered Verification Levels), KYC-010 (Passport & National ID Scanner)

---

## 1. Overview & Motivation

### 1.1 The Gap

The existing KYC system has a comprehensive backend (`app/routers/kyc_cases.py`, 1295 lines; `app/services/kyc_cases.py`, 829 lines) with a full case lifecycle, document uploads, questionnaire integration, and signature packet linking. However, there is **no dedicated user-facing frontend page** for the KYC process. Users must interact with the KYC system entirely through raw API calls or through indirect integrations (the file manager for uploads, the questionnaires page for intake forms).

This means:
1. Users have no clear path to start verification — there is no "Verify Your Identity" page.
2. There is no step-by-step wizard guiding users through the required documents and checks.
3. Users cannot track their case status in a visual timeline.
4. When an admin requests additional information, users have no obvious place to respond.
5. Historical cases (previous rejected/expired applications) are not surfaced.

### 1.2 What This Ticket Adds

1. **KYC Wizard** — A multi-step form at `/kyc` that walks users through the verification process:
   - Step 1: Personal Information (name, DOB, nationality, address)
   - Step 2: Identity Document Upload (id_front, id_back with document type selection)
   - Step 3: Selfie Capture (camera interface or file upload)
   - Step 4: Proof of Address (utility bill, bank statement upload)
   - Step 5: Questionnaire (embedded questionnaire from the existing questionnaires system)
   - Step 6: Consent & Signature (link to document signing)
   - Step 7: Review & Submit
2. **KYC Status Page** at `/kyc/status` — Case status tracking with visual timeline, estimated wait time, and document re-upload capability.
3. **Historical Cases View** — List of previous KYC applications with outcomes.
4. **Mobile-Optimized Camera Capture** — For selfie and ID document photography.
5. **Estimated Wait Time** — Based on admin queue metrics (from existing `GET /v1/kyc/cases/admin/metrics`).

### 1.3 User Journey

```
User clicks "Verify Account" (sidebar / tier progress page)
       │
       ▼
  /kyc → KycWizard.tsx
       │
       ├── Step 1: Personal Info form → PATCH /{case_id} (intake_profile)
       ├── Step 2: ID Upload → POST /{case_id}/files (id_front, id_back)
       │                     → POST /{case_id}/scan-document (KYC-010)
       ├── Step 3: Selfie → POST /{case_id}/files (selfie)
       ├── Step 4: PoA → POST /{case_id}/files (proof_of_address)
       ├── Step 5: Questionnaire → POST /{case_id}/start-questionnaire
       │                         → (embedded questionnaire session)
       ├── Step 6: Consent → POST /{case_id}/signature-packet
       │                   → (redirect to signing page)
       └── Step 7: Review & Submit → POST /{case_id}/submit
       │
       ▼
  Redirect to /kyc/status
       │
       ├── Timeline: submitted → under_review → decision
       ├── Estimated wait time display
       ├── Document re-upload (if needs_more_info)
       └── Link to previous cases
```

---

## 2. Current State Analysis

### 2.1 Existing Backend Endpoints

All necessary backend endpoints already exist in `app/routers/kyc_cases.py`:

| Endpoint | Purpose | Used in Step |
|----------|---------|-------------|
| `POST /v1/kyc/cases` | Create new case | Wizard init |
| `PATCH /v1/kyc/cases/{id}` | Update draft (intake_profile) | Step 1 |
| `POST /v1/kyc/cases/{id}/files` | Attach file | Steps 2, 3, 4 |
| `GET /v1/kyc/cases/{id}/files/validation` | Check required files | Step 7 |
| `POST /v1/kyc/cases/{id}/start-questionnaire` | Start questionnaire session | Step 5 |
| `GET /v1/kyc/cases/{id}/questionnaire-status` | Check questionnaire completion | Step 5 |
| `POST /v1/kyc/cases/{id}/signature-packet` | Create/link signature packet | Step 6 |
| `GET /v1/kyc/cases/{id}/signature-status` | Check signature completion | Step 6 |
| `GET /v1/kyc/cases/{id}/readiness` | Check all submit prerequisites | Step 7 |
| `POST /v1/kyc/cases/{id}/submit` | Submit case for review | Step 7 |
| `GET /v1/kyc/cases` | List user's cases | Status page |
| `GET /v1/kyc/cases/{id}` | Get case details | Status page |

### 2.2 Readiness Check (`app/routers/kyc_cases.py`, line 809)

The `kyc_readiness()` endpoint returns a comprehensive readiness status:

```json
{
  "readiness": {
    "ready": false,
    "checks": {
      "intake_profile": { "ok": true },
      "files": { "ok": false, "missing": ["id_back"] },
      "questionnaire": { "ok": false, "reason": "not_started" },
      "signature": { "ok": true }
    }
  }
}
```

This is the data source for the wizard's step completion indicators.

### 2.3 File Manager (`app/services/filemanager.py`)

Files uploaded through the file manager get a `node_id` which is passed to `POST /{case_id}/files` via `file_node_id`. The wizard needs to handle file upload first (creating a file node) and then attach it to the case.

### 2.4 Admin Metrics (`app/routers/kyc_cases.py`, line 946)

`GET /v1/kyc/cases/admin/metrics` returns queue metrics including `processing_time_p50` and `processing_time_p95`. The status page can use a public/user-facing variant of this data to display estimated wait times.

### 2.5 Existing Frontend Pages

No KYC-specific frontend pages exist. Related pages:
- `frontend/src/pages/files/FilesPage.tsx` — File manager (for document uploads)
- `frontend/src/pages/questionnaires/` — Questionnaire forms
- `frontend/src/pages/signing/SigningPage.tsx` — Document signing

### 2.6 Frontend Routing (`frontend/src/App.tsx`)

No `/kyc` routes exist. The routing needs two new entries: `/kyc` (wizard) and `/kyc/status` (status tracker).

---

## 3. Technical Design

### 3.1 New API Endpoint: Estimated Wait Time

The existing admin metrics endpoint requires root access. Add a user-facing endpoint:

```python
# app/routers/kyc_cases.py — new endpoint

@router.get("/estimated-wait")
def get_estimated_wait_time(ctx=Depends(require_ui_session)):
    """Return estimated wait time for KYC review (user-facing, no queue details)."""
    metrics = STORE.get_metrics_snapshot(stale_after_seconds=48 * 3600)
    submitted_count = metrics.get("total_cases", {}).get("submitted", 0)
    under_review_count = metrics.get("total_cases", {}).get("under_review", 0)
    queue_size = submitted_count + under_review_count

    p50 = metrics.get("processing_time_p50")

    if queue_size == 0:
        est_hours = 1
    elif p50:
        est_hours = max(1, int(p50 / 3600))
    else:
        est_hours = 24  # default

    return {
        "estimated_hours": est_hours,
        "queue_position": None,  # Not exposed to user
        "message": _wait_message(est_hours),
    }


def _wait_message(hours: int) -> str:
    if hours <= 2:
        return "Your application is being processed. Expected review within a few hours."
    elif hours <= 24:
        return f"Estimated review time: {hours} hours. We'll notify you when there's an update."
    elif hours <= 72:
        return f"Estimated review time: {hours // 24} days. We'll notify you when there's an update."
    else:
        return "Review times are currently extended. We'll notify you as soon as possible."
```

### 3.2 Frontend: KYC Wizard

**File**: `frontend/src/pages/kyc/KycWizard.tsx` (~400 lines)

```tsx
import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, Circle, Loader2 } from "lucide-react";

const STEPS = [
  { id: "personal", label: "Personal Information", icon: "User" },
  { id: "id_upload", label: "Identity Document", icon: "CreditCard" },
  { id: "selfie", label: "Selfie Verification", icon: "Camera" },
  { id: "address", label: "Proof of Address", icon: "Home" },
  { id: "questionnaire", label: "Questionnaire", icon: "ClipboardList" },
  { id: "consent", label: "Consent & Signature", icon: "FileSignature" },
  { id: "review", label: "Review & Submit", icon: "CheckSquare" },
];

export default function KycWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [caseId, setCaseId] = useState<string | null>(null);

  // Create or resume KYC case
  const { data: cases } = useQuery({
    queryKey: ["kyc", "cases"],
    queryFn: () => client.get("/v1/kyc/cases").then(r => r.data),
  });

  useEffect(() => {
    const draftCase = cases?.items?.find(c => c.status === "draft");
    if (draftCase) {
      setCaseId(draftCase.kyc_case_id);
    }
  }, [cases]);

  const readiness = useQuery({
    queryKey: ["kyc", "readiness", caseId],
    queryFn: () => client.get(`/v1/kyc/cases/${caseId}/readiness`).then(r => r.data),
    enabled: !!caseId,
  });

  // Step completion derived from readiness check
  const stepComplete = {
    personal: readiness.data?.readiness?.checks?.intake_profile?.ok ?? false,
    id_upload: /* check for id_front + id_back in files */ false,
    selfie: /* check for selfie in files */ false,
    address: /* check for proof_of_address in files */ false,
    questionnaire: readiness.data?.readiness?.checks?.questionnaire?.ok ?? false,
    consent: readiness.data?.readiness?.checks?.signature?.ok ?? false,
    review: false,
  };

  return (
    <div className="max-w-3xl mx-auto py-8 px-4">
      <h1 className="text-2xl font-bold mb-6">Identity Verification</h1>

      {/* Progress bar */}
      <Progress value={(currentStep / STEPS.length) * 100} className="mb-8" />

      {/* Step indicators */}
      <div className="flex justify-between mb-8">
        {STEPS.map((step, i) => (
          <button
            key={step.id}
            onClick={() => setCurrentStep(i)}
            className={`flex flex-col items-center gap-1 text-xs
              ${i === currentStep ? "text-blue-600 font-bold" : "text-gray-500"}`}
          >
            {stepComplete[step.id] ? (
              <CheckCircle2 className="w-6 h-6 text-green-500" />
            ) : (
              <Circle className="w-6 h-6" />
            )}
            {step.label}
          </button>
        ))}
      </div>

      {/* Step content */}
      <Card>
        <CardContent className="p-6">
          {currentStep === 0 && <PersonalInfoStep caseId={caseId} />}
          {currentStep === 1 && <IdUploadStep caseId={caseId} />}
          {currentStep === 2 && <SelfieStep caseId={caseId} />}
          {currentStep === 3 && <AddressProofStep caseId={caseId} />}
          {currentStep === 4 && <QuestionnaireStep caseId={caseId} />}
          {currentStep === 5 && <ConsentStep caseId={caseId} />}
          {currentStep === 6 && <ReviewSubmitStep caseId={caseId} readiness={readiness.data} />}
        </CardContent>
      </Card>

      {/* Navigation */}
      <div className="flex justify-between mt-6">
        <Button
          variant="outline"
          onClick={() => setCurrentStep(s => Math.max(0, s - 1))}
          disabled={currentStep === 0}
        >
          Back
        </Button>
        <Button
          onClick={() => setCurrentStep(s => Math.min(STEPS.length - 1, s + 1))}
          disabled={currentStep === STEPS.length - 1}
        >
          Continue
        </Button>
      </div>
    </div>
  );
}
```

### 3.3 Step Components

**PersonalInfoStep** — Form fields: first name, last name, date of birth, nationality, address. Submits to `PATCH /v1/kyc/cases/{id}` with `intake_profile` (JSON string).

**IdUploadStep** — Document type selector (passport, national ID, driving license, residence permit). Shows which sides are needed based on type. File upload triggers: (1) upload to file manager, (2) attach to case via `POST /{id}/files`, (3) trigger scan via `POST /{id}/scan-document` (KYC-010). Displays extraction results after scan.

**SelfieStep** — Camera interface using `getUserMedia()` API for mobile/desktop webcam capture. Fallback to file upload for browsers without camera access. Captures a single selfie image, uploads to file manager, attaches to case.

**AddressProofStep** — File upload for proof of address. Accepts utility bill, bank statement, government letter. Preview of uploaded document.

**QuestionnaireStep** — Embeds the questionnaire session started by `POST /{id}/start-questionnaire`. Monitors completion via `GET /{id}/questionnaire-status`.

**ConsentStep** — Creates/links a signature packet via `POST /{id}/signature-packet`. Shows signing status via `GET /{id}/signature-status`. Links to the signing page for actual signature.

**ReviewSubmitStep** — Shows readiness checklist from `GET /{id}/readiness`. Lists all attached documents, questionnaire status, signature status. Submit button calls `POST /{id}/submit`. Disabled until all checks pass.

### 3.4 Frontend: KYC Status Page

**File**: `frontend/src/pages/kyc/KycStatusPage.tsx` (~250 lines)

```tsx
export default function KycStatusPage() {
  const { data: cases } = useQuery({
    queryKey: ["kyc", "cases"],
    queryFn: () => client.get("/v1/kyc/cases").then(r => r.data),
  });

  const activeCases = cases?.items?.filter(c =>
    ["submitted", "under_review", "needs_more_info"].includes(c.status)
  ) ?? [];
  const historicalCases = cases?.items?.filter(c =>
    ["approved", "rejected", "expired"].includes(c.status)
  ) ?? [];

  return (
    <div className="max-w-3xl mx-auto py-8 px-4">
      <h1 className="text-2xl font-bold mb-6">Verification Status</h1>

      {activeCases.map(kycCase => (
        <ActiveCaseCard key={kycCase.kyc_case_id} kycCase={kycCase} />
      ))}

      {activeCases.length === 0 && (
        <Card className="mb-6">
          <CardContent className="p-6 text-center text-gray-500">
            No active verification. <Link to="/kyc">Start verification</Link>
          </CardContent>
        </Card>
      )}

      <h2 className="text-xl font-semibold mt-8 mb-4">Previous Applications</h2>
      {historicalCases.map(kycCase => (
        <HistoricalCaseCard key={kycCase.kyc_case_id} kycCase={kycCase} />
      ))}
    </div>
  );
}
```

**ActiveCaseCard** — Shows:
- Status badge (submitted / under review / needs more info)
- Visual timeline with dots for each status transition
- Estimated wait time (from `GET /v1/kyc/cases/estimated-wait`)
- If `needs_more_info`: shows requested items and "Update Documents" button linking back to wizard
- Submission details (submitted_at, evidence snapshot)

**HistoricalCaseCard** — Shows:
- Status badge (approved / rejected / expired)
- Decision date, reason codes (for rejected)
- Link to "Start New Application" (for rejected/expired)

### 3.5 Frontend: Camera Capture Component

**File**: `frontend/src/components/shared/CameraCapture.tsx`

```tsx
interface CameraCaptureProps {
  onCapture: (file: File) => void;
  facing?: "user" | "environment";  // user = selfie, environment = document
  label?: string;
}

export function CameraCapture({ onCapture, facing = "user", label }: CameraCaptureProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [captured, setCaptured] = useState<string | null>(null);

  const startCamera = async () => {
    try {
      const mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      setStream(mediaStream);
      if (videoRef.current) videoRef.current.srcObject = mediaStream;
    } catch {
      // Camera not available — show file upload fallback
    }
  };

  const capture = () => {
    if (!videoRef.current) return;
    const canvas = document.createElement("canvas");
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    canvas.getContext("2d")?.drawImage(videoRef.current, 0, 0);
    canvas.toBlob(blob => {
      if (blob) {
        const file = new File([blob], "capture.jpg", { type: "image/jpeg" });
        onCapture(file);
        setCaptured(canvas.toDataURL());
      }
    }, "image/jpeg", 0.9);
  };

  // ... render video preview, capture button, retake button, file upload fallback
}
```

### 3.6 Frontend API Endpoints

**File**: `frontend/src/api/endpoints/kyc.ts`

```typescript
export const createKycCase = () =>
  client.post("/v1/kyc/cases", {});
export const getKycCases = () =>
  client.get("/v1/kyc/cases");
export const getKycCase = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}`);
export const patchKycCase = (caseId: string, data: { expected_version: number; intake_profile: string }) =>
  client.patch(`/v1/kyc/cases/${caseId}`, data);
export const attachKycFile = (caseId: string, data: { file_type: string; file_node_id: string }) =>
  client.post(`/v1/kyc/cases/${caseId}/files`, data);
export const getKycReadiness = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}/readiness`);
export const submitKycCase = (caseId: string, data: { expected_version: number }) =>
  client.post(`/v1/kyc/cases/${caseId}/submit`, data);
export const getEstimatedWait = () =>
  client.get("/v1/kyc/cases/estimated-wait");
export const startKycQuestionnaire = (caseId: string, data: { published_slug: string }) =>
  client.post(`/v1/kyc/cases/${caseId}/start-questionnaire`, data);
export const getQuestionnaireStatus = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}/questionnaire-status`);
export const getSignatureStatus = (caseId: string) =>
  client.get(`/v1/kyc/cases/${caseId}/signature-status`);
```

### 3.7 Frontend Routes

**File**: `frontend/src/App.tsx`

```tsx
const KycWizard = lazy(() => import("./pages/kyc/KycWizard"));
const KycStatusPage = lazy(() => import("./pages/kyc/KycStatusPage"));

// Routes:
<Route path="/kyc" element={<KycWizard />} />
<Route path="/kyc/status" element={<KycStatusPage />} />
```

### 3.8 Sidebar Integration

**File**: `frontend/src/components/layout/Sidebar.tsx`

Add "Verification" link under Security/Account group with `ShieldCheck` icon:

```tsx
{ to: "/kyc", label: "Verification", icon: ShieldCheck },
{ to: "/kyc/status", label: "KYC Status", icon: FileCheck },
```

### 3.9 Help/FAQ Section

**File**: `frontend/src/pages/kyc/KycHelp.tsx`

Static FAQ component embedded at the bottom of the wizard:
- "What documents are accepted?"
- "How long does verification take?"
- "Why was my application rejected?"
- "Can I reapply after rejection?"
- "How is my data protected?"

---

## 4. Implementation Plan

### Phase 1: Backend — Estimated Wait Endpoint (1 day)

| File | Change |
|------|--------|
| `app/routers/kyc_cases.py` | Add `GET /estimated-wait` endpoint (~30 lines) |

### Phase 2: Frontend — KYC Wizard (4 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KycWizard.tsx` | New: multi-step wizard (~400 lines) |
| `frontend/src/pages/kyc/steps/PersonalInfoStep.tsx` | New: personal info form (~120 lines) |
| `frontend/src/pages/kyc/steps/IdUploadStep.tsx` | New: ID document upload with type selection (~150 lines) |
| `frontend/src/pages/kyc/steps/SelfieStep.tsx` | New: selfie capture/upload (~100 lines) |
| `frontend/src/pages/kyc/steps/AddressProofStep.tsx` | New: PoA upload (~80 lines) |
| `frontend/src/pages/kyc/steps/QuestionnaireStep.tsx` | New: embedded questionnaire (~80 lines) |
| `frontend/src/pages/kyc/steps/ConsentStep.tsx` | New: signature linking (~80 lines) |
| `frontend/src/pages/kyc/steps/ReviewSubmitStep.tsx` | New: readiness display + submit (~120 lines) |

### Phase 3: Frontend — Status Page (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KycStatusPage.tsx` | New: status tracking page (~250 lines) |
| `frontend/src/pages/kyc/KycHelp.tsx` | New: FAQ section (~100 lines) |

### Phase 4: Frontend — Camera & Integration (2 days)

| File | Change |
|------|--------|
| `frontend/src/components/shared/CameraCapture.tsx` | New: webcam capture component (~150 lines) |
| `frontend/src/api/endpoints/kyc.ts` | New: KYC API endpoint wrappers |
| `frontend/src/api/types.ts` | Add KYC types |
| `frontend/src/App.tsx` | Add `/kyc` and `/kyc/status` routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add Verification links |
| `frontend/src/components/layout/AppShell.tsx` | Add to MobileSidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add to MORE_LINKS |

### Phase 5: E2E Tests (3 days)

| File | Change |
|------|--------|
| `frontend/e2e/kyc-wizard.spec.ts` | New: ~25 tests, sections 197-202 |

---

## 5. E2E Test Plan (`frontend/e2e/kyc-wizard.spec.ts`)

**Test file**: `frontend/e2e/kyc-wizard.spec.ts`  
**Total tests**: ~25  
**Sections**: 197-202

### Section 197: KYC Case Creation API (3 tests)

1. `POST /v1/kyc/cases creates a draft case` — Verify response has `status: "draft"`, `kyc_case_id` starts with `kyc_`.
2. `GET /v1/kyc/cases lists user's cases` — After creation, list returns at least 1 case.
3. `GET /v1/kyc/cases/estimated-wait returns estimated hours` — Verify response has `estimated_hours` (number) and `message` (string).

### Section 198: Wizard Personal Info Step API (3 tests)

1. `PATCH /{case_id} updates intake_profile` — Send personal info JSON; verify case now has `intake_profile` populated.
2. `Readiness check shows intake_profile as ok after update` — GET readiness; verify `checks.intake_profile.ok: true`.
3. `Invalid expected_version returns 409` — PATCH with wrong version; verify 409 conflict error.

### Section 199: Wizard File Attachment API (5 tests)

1. `POST /{case_id}/files attaches id_front` — Upload a file, get node_id, attach with `file_type: "id_front"`; verify case files array has entry.
2. `POST /{case_id}/files attaches id_back` — Same for `id_back`.
3. `POST /{case_id}/files attaches selfie` — Same for `selfie`.
4. `POST /{case_id}/files attaches proof_of_address` — Same for `proof_of_address`.
5. `GET /{case_id}/files/validation shows missing files` — After attaching only selfie; verify `missing: ["id_front", "id_back"]`.

### Section 200: Wizard Submit Flow API (4 tests)

1. `GET /{case_id}/readiness with all prerequisites met returns ready=true` — After attaching all files + questionnaire + signature; verify `ready: true`.
2. `POST /{case_id}/submit transitions to submitted` — Verify case status becomes `"submitted"`.
3. `POST /{case_id}/submit without prerequisites returns 400` — Create new case without files; submit returns 400 with `kyc_submit_prereq_failed`.
4. `Submitted case cannot be re-submitted` — POST submit on already-submitted case returns error.

### Section 201: KYC Status Page UI (5 tests)

1. `Status page shows active case with submitted badge` — Navigate to `/kyc/status`; verify submitted case appears with status badge.
2. `Status page shows estimated wait time` — Verify "Estimated review time" text is displayed.
3. `Historical cases section shows previous rejected case` — Create and reject a case; navigate to status page; verify rejected case appears under "Previous Applications".
4. `Needs-more-info case shows update documents button` — Set case to needs_more_info; navigate; verify "Update Documents" button is visible.
5. `Start New Application link navigates to wizard` — Click link; verify navigation to `/kyc`.

### Section 202: KYC Wizard UI (5 tests)

1. `Wizard page loads with step indicators` — Navigate to `/kyc`; verify 7 step labels are visible.
2. `Step completion checkmarks appear after completing steps` — Complete step 1; verify green checkmark appears on step 1 indicator.
3. `Continue button advances to next step` — Click Continue; verify step 2 content is displayed.
4. `Back button returns to previous step` — Click Back; verify step 1 content is displayed.
5. `Submit button is disabled until all checks pass` — Navigate to step 7 without completing all steps; verify Submit button is disabled.

### Test Setup

```typescript
const TS = Date.now();
let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});
```

### Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Camera API not available in headless Chromium | SelfieStep falls back to file upload; E2E tests use file upload path only |
| File upload timing | Use `waitForResponse` after file upload to confirm server acknowledged before proceeding |
| Questionnaire session state | Use a pre-published questionnaire slug seeded in beforeAll |
| Multiple draft cases from prior runs | Wizard resumes existing draft (uses first `status=draft` case); no duplicate creation |
| Readiness cache | Query readiness after each step to confirm server-side state before proceeding |

---

## 6. Security Considerations

- All wizard steps use `require_ui_session` — unauthenticated users are redirected to login.
- File uploads go through the existing file manager with the user's own S3 namespace.
- The `intake_profile` field is stored as a JSON string; the backend does not interpret the contents beyond length validation.
- Camera capture happens entirely client-side; the captured image is uploaded as a standard file.
- The estimated wait time endpoint does not expose admin queue details (case count, admin assignments) — only a derived hour estimate.

---

## 7. Rollback Plan

- Remove `/kyc` and `/kyc/status` routes from `App.tsx`.
- Remove sidebar links.
- Delete `frontend/src/pages/kyc/` directory.
- The `GET /estimated-wait` backend endpoint can remain (it is a read-only endpoint with no side effects).
