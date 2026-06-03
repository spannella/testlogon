# KYC-013: KYC User Self-Service Portal

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Critical  
**Estimated effort**: 10-14 days  
**Dependencies**: KYC-009 (Tiered Verification Levels), KYC-010 (Passport & National ID Scanner)

---

## 1. Overview & Motivation

### 1.1 The Gap

The existing KYC system has a comprehensive backend (`app/routers/kyc_cases.py`, 1294 lines; `app/services/kyc_cases.py`, 828 lines) with a full case lifecycle, document uploads, questionnaire integration, and signature packet linking.
<!-- NOTE: ticket originally cited 1295 and 829 lines -- actual counts are 1294 and 828 --> However, there is **no dedicated user-facing frontend page** for the KYC process. Users must interact with the KYC system entirely through raw API calls or through indirect integrations (the file manager for uploads, the questionnaires page for intake forms).

This means:
1. Users have no clear path to start verification -- there is no "Verify Your Identity" page.
2. There is no step-by-step wizard guiding users through the required documents and checks.
3. Users cannot track their case status in a visual timeline.
4. When an admin requests additional information, users have no obvious place to respond.
5. Historical cases (previous rejected/expired applications) are not surfaced.

### 1.2 What This Ticket Adds

1. **KYC Wizard** -- A multi-step form at `/kyc` that walks users through the verification process:
   - Step 1: Personal Information (name, DOB, nationality, address)
   - Step 2: Identity Document Upload (id_front, id_back with document type selection)
   - Step 3: Selfie Capture (camera interface or file upload)
   - Step 4: Proof of Address (utility bill, bank statement upload)
   - Step 5: Questionnaire (embedded questionnaire from the existing questionnaires system)
   - Step 6: Consent & Signature (link to document signing)
   - Step 7: Review & Submit
2. **KYC Status Page** at `/kyc/status` -- Case status tracking with visual timeline, estimated wait time, and document re-upload capability.
3. **Historical Cases View** -- List of previous KYC applications with outcomes.
4. **Mobile-Optimized Camera Capture** -- For selfie and ID document photography.
5. **Estimated Wait Time** -- Based on admin queue metrics (from existing `GET /v1/kyc/cases/admin/metrics`).

### 1.3 User Journey

```
User clicks "Verify Account" (sidebar / tier progress page)
       |
       v
  /kyc -> KycWizard.tsx
       |
       +-- Step 1: Personal Info form -> PATCH /{case_id} (intake_profile)
       +-- Step 2: ID Upload -> POST /{case_id}/files (id_front, id_back)
       |                     -> POST /{case_id}/scan-document (KYC-010)
       +-- Step 3: Selfie -> POST /{case_id}/files (selfie)
       +-- Step 4: PoA -> POST /{case_id}/files (proof_of_address)
       +-- Step 5: Questionnaire -> POST /{case_id}/start-questionnaire
       |                         -> (embedded questionnaire session)
       +-- Step 6: Consent -> POST /{case_id}/signature-packet
       |                   -> (redirect to signing page)
       +-- Step 7: Review & Submit -> POST /{case_id}/submit
       |
       v
  Redirect to /kyc/status
       |
       +-- Timeline: submitted -> under_review -> decision
       +-- Estimated wait time display
       +-- Document re-upload (if needs_more_info)
       +-- Link to previous cases
```

---

## 2. Current State Analysis

### 2.1 Existing Backend Endpoints

All necessary backend endpoints already exist in `app/routers/kyc_cases.py` (see `app/routers/kyc_cases.py`):

| Endpoint | Purpose | Used in Step | Line |
|----------|---------|-------------|------|
| `POST /v1/kyc/cases` | Create new case | Wizard init | see `:519` |
| `PATCH /v1/kyc/cases/{id}` | Update draft (intake_profile) | Step 1 | |
| `POST /v1/kyc/cases/{id}/files` | Attach file | Steps 2, 3, 4 | see `:734` |
| `GET /v1/kyc/cases/{id}/files/validation` | Check required files | Step 7 | see `:791` |
| `POST /v1/kyc/cases/{id}/start-questionnaire` | Start questionnaire session | Step 5 | see `:625` |
| `GET /v1/kyc/cases/{id}/questionnaire-status` | Check questionnaire completion | Step 5 | |
| `POST /v1/kyc/cases/{id}/signature-packet` | Create/link signature packet | Step 6 | see `:1206` |
| `GET /v1/kyc/cases/{id}/signature-status` | Check signature completion | Step 6 | see `:184` |
| `GET /v1/kyc/cases/{id}/readiness` | Check all submit prerequisites | Step 7 | see `:223` |
| `POST /v1/kyc/cases/{id}/submit` | Submit case for review | Step 7 | see `:830` |
| `GET /v1/kyc/cases` | List user's cases | Status page | |
| `GET /v1/kyc/cases/{id}` | Get case details | Status page | |

### 2.2 Readiness Check (see `app/routers/kyc_cases.py:809`)

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

### 2.4 Admin Metrics (see `app/routers/kyc_cases.py:947` for `get_admin_kyc_metrics`)

`GET /v1/kyc/cases/admin/metrics` returns queue metrics including `processing_time_p50` and `processing_time_p95`. The status page can use a public/user-facing variant of this data to display estimated wait times.

### 2.5 Existing Frontend Pages

No KYC-specific frontend pages exist. Related pages:
- `frontend/src/pages/files/FilesPage.tsx` -- File manager (for document uploads)
- `frontend/src/pages/questionnaires/` -- Questionnaire forms
- `frontend/src/pages/signing/SigningPage.tsx` -- Document signing

### 2.6 Frontend Routing (`frontend/src/App.tsx`)

No `/kyc` routes exist. The routing needs two new entries: `/kyc` (wizard) and `/kyc/status` (status tracker).

---

## 3. Technical Design

### 3.1 New API Endpoint: Estimated Wait Time

The existing admin metrics endpoint requires root access. Add a user-facing endpoint:

```python
# app/routers/kyc_cases.py -- new endpoint

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

**PersonalInfoStep** -- Form fields: first name, last name, date of birth, nationality, address. Submits to `PATCH /v1/kyc/cases/{id}` with `intake_profile` (JSON string).

**IdUploadStep** -- Document type selector (passport, national ID, driving license, residence permit). Shows which sides are needed based on type. File upload triggers: (1) upload to file manager, (2) attach to case via `POST /{id}/files`, (3) trigger scan via `POST /{id}/scan-document` (KYC-010). Displays extraction results after scan.

**SelfieStep** -- Camera interface using `getUserMedia()` API for mobile/desktop webcam capture. Fallback to file upload for browsers without camera access. Captures a single selfie image, uploads to file manager, attaches to case.

**AddressProofStep** -- File upload for proof of address. Accepts utility bill, bank statement, government letter. Preview of uploaded document.

**QuestionnaireStep** -- Embeds the questionnaire session started by `POST /{id}/start-questionnaire`. Monitors completion via `GET /{id}/questionnaire-status`.

**ConsentStep** -- Creates/links a signature packet via `POST /{id}/signature-packet`. Shows signing status via `GET /{id}/signature-status`. Links to the signing page for actual signature.

**ReviewSubmitStep** -- Shows readiness checklist from `GET /{id}/readiness`. Lists all attached documents, questionnaire status, signature status. Submit button calls `POST /{id}/submit`. Disabled until all checks pass.

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

**ActiveCaseCard** -- Shows:
- Status badge (submitted / under review / needs more info)
- Visual timeline with dots for each status transition
- Estimated wait time (from `GET /v1/kyc/cases/estimated-wait`)
- If `needs_more_info`: shows requested items and "Update Documents" button linking back to wizard
- Submission details (submitted_at, evidence snapshot)

**HistoricalCaseCard** -- Shows:
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
      // Camera not available -- show file upload fallback
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

## 4. Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           User Browser                                     │
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  KycWizard.tsx  (/kyc)                                             │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │    │
│  │  │ Personal │ │ ID Upload│ │  Selfie  │ │  PoA     │ │Consent │  │    │
│  │  │  Info    │ │          │ │          │ │  Upload  │ │        │  │    │
│  │  │ Step 1   │ │ Step 2   │ │ Step 3   │ │ Step 4   │ │Step 5-7│  │    │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘  │    │
│  │       │             │            │            │           │        │    │
│  │       │ PATCH       │ POST       │ POST       │ POST      │ POST   │    │
│  │       │ /cases/{id} │ /files     │ /files     │ /files    │/submit │    │
│  │       ▼             ▼            ▼            ▼           ▼        │    │
│  │  ┌──────────────────────────────────────────────────────────────┐  │    │
│  │  │  React Query Cache                                           │  │    │
│  │  │  ["kyc","cases"]           → list of user's cases            │  │    │
│  │  │  ["kyc","readiness",id]    → readiness check result          │  │    │
│  │  │  ["kyc","estimated-wait"]  → wait time estimate              │  │    │
│  │  │  ["kyc","case",id]         → single case detail              │  │    │
│  │  └──────────────────────────────┬───────────────────────────────┘  │    │
│  └─────────────────────────────────┼──────────────────────────────────┘    │
│                                    │                                       │
│  ┌─────────────────────────────────┼──────────────────────────────────┐    │
│  │  KycStatusPage.tsx  (/kyc/status)                                  │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │    │
│  │  │ ActiveCaseCard   │  │HistoricalCaseCard│  │  WaitTimeCard   │  │    │
│  │  │ (status timeline)│  │ (decision badge) │  │ (estimated hrs) │  │    │
│  │  └──────────────────┘  └──────────────────┘  └─────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  CameraCapture.tsx  (shared component)                             │    │
│  │  getUserMedia() → <video> preview → canvas.toBlob() → File        │    │
│  │  Fallback: <input type="file" accept="image/*" capture="user">    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │  HTTPS + ui_session cookie + CSRF
                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     FastAPI Backend  (port 8000)                          │
│                                                                          │
│  app/routers/kyc_cases.py (existing endpoints + new estimated-wait)      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  POST   /v1/kyc/cases                   → create_case()           │  │
│  │  PATCH  /v1/kyc/cases/{id}              → update_draft()          │  │
│  │  POST   /v1/kyc/cases/{id}/files        → attach_file()          │  │
│  │  GET    /v1/kyc/cases/{id}/files/validation → validate_files()    │  │
│  │  POST   /v1/kyc/cases/{id}/start-questionnaire → start_qn()      │  │
│  │  GET    /v1/kyc/cases/{id}/questionnaire-status → check_qn()     │  │
│  │  POST   /v1/kyc/cases/{id}/signature-packet → link_sig()         │  │
│  │  GET    /v1/kyc/cases/{id}/signature-status → check_sig()        │  │
│  │  GET    /v1/kyc/cases/{id}/readiness    → check_all_prereqs()    │  │
│  │  POST   /v1/kyc/cases/{id}/submit       → submit_case()          │  │
│  │  GET    /v1/kyc/cases                   → list_user_cases()       │  │
│  │  GET    /v1/kyc/cases/{id}              → get_case_detail()       │  │
│  │  GET    /v1/kyc/cases/estimated-wait    → get_wait_time() [NEW]   │  │
│  └───────────────────────────┬────────────────────────────────────────┘  │
│                              │                                            │
│  ┌───────────────────────────┼────────────────────────────────────────┐  │
│  │  app/services/kyc_cases.py │                                       │  │
│  │  STORE.create_case()       │  STORE.update_draft()                 │  │
│  │  STORE.attach_file()       │  STORE.check_readiness()              │  │
│  │  STORE.submit_case()       │  STORE.get_metrics_snapshot()         │  │
│  │  STORE.list_cases_by_owner()                                       │  │
│  └───────────────────────────┼────────────────────────────────────────┘  │
│                              │                                            │
│  ┌───────────────────────────┼────────────────────────────────────────┐  │
│  │  app/services/filemanager.py                                       │  │
│  │  upload_file() → S3 put_object → node_id                          │  │
│  │  get_node() → file metadata + S3 URL                               │  │
│  └───────────────────────────┼────────────────────────────────────────┘  │
│                              │                                            │
│  ┌───────────────────────────┼────────────────────────────────────────┐  │
│  │  app/services/questionnaires.py + app/services/signature_*.py      │  │
│  │  create_session() / get_session_status()                           │  │
│  │  create_packet() / get_packet_status()                             │  │
│  └───────────────────────────┼────────────────────────────────────────┘  │
└──────────────────────────────┼────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     DynamoDB Local  (port 8001)                           │
│                                                                          │
│  kyc_cases table                                                         │
│  pk = KYC#{case_id}  |  sk = META                                        │
│    status, user_sub, created_at, files[], intake_profile,                │
│    submission{}, review{}, version                                       │
│                                                                          │
│  GSI: owner-updated-index                                                │
│    gsi_owner_pk = OWNER#{user_sub}                                       │
│    gsi_owner_sk = UPDATED#{ts}#KYC#{case_id}                             │
│                                                                          │
│  GSI: status-updated-index                                               │
│    gsi_status_pk = STATUS#{status}                                       │
│    gsi_status_sk = UPDATED#{ts}#KYC#{case_id}                            │
│                                                                          │
│  S3 Mock (moto, in-process)                                              │
│  Bucket: uploads / Prefix: users/{user_sub}/kyc/                         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 5. DynamoDB Access Patterns

### 5.1 Access Patterns Table

| Operation | Table | PK | SK / KeyCondition | GSI | Filter | Notes |
|-----------|-------|----|--------------------|-----|--------|-------|
| Create case | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | PutItem with condition `attribute_not_exists(pk)` |
| Get case | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | GetItem |
| Update draft (intake_profile) | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | UpdateItem with OCC (`version = :expected`) |
| Attach file | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | UpdateItem: `SET files = list_append(files, :new_file)` |
| Check readiness | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | GetItem then in-memory checks |
| Submit case | `kyc_cases` | `KYC#{case_id}` | `META` | -- | -- | UpdateItem with condition `status = :draft` |
| List user cases | `kyc_cases` | -- | -- | `owner-updated-index` | -- | Query `gsi_owner_pk = OWNER#{user_sub}` |
| Estimated wait | `kyc_cases` | -- | -- | `status-updated-index` | -- | Counts by status (existing metrics) |

### 5.2 Example Items

**Draft case (after Step 1)**:

```json
{
  "pk": "KYC#kyc_9f1a2b3c4d",
  "sk": "META",
  "kyc_case_id": "kyc_9f1a2b3c4d",
  "user_sub": "e2e_alice@test.local",
  "status": "draft",
  "version": 2,
  "created_at": 1717000000,
  "updated_at": 1717000100,
  "intake_profile": "{\"first_name\":\"Alice\",\"last_name\":\"Test\",\"dob\":\"1990-01-15\",\"nationality\":\"US\",\"address\":\"123 Main St, Anytown, US 12345\"}",
  "files": [],
  "gsi_owner_pk": "OWNER#e2e_alice@test.local",
  "gsi_owner_sk": "UPDATED#0001717000100#KYC#kyc_9f1a2b3c4d",
  "gsi_status_pk": "STATUS#draft",
  "gsi_status_sk": "UPDATED#0001717000100#KYC#kyc_9f1a2b3c4d"
}
```

**Case with files attached (after Steps 2-4)**:

```json
{
  "pk": "KYC#kyc_9f1a2b3c4d",
  "sk": "META",
  "status": "draft",
  "version": 6,
  "files": [
    {
      "file_type": "id_front",
      "file_node_id": "node_id_front_001",
      "attached_at": 1717000200,
      "attached_by": "e2e_alice@test.local"
    },
    {
      "file_type": "id_back",
      "file_node_id": "node_id_back_002",
      "attached_at": 1717000210,
      "attached_by": "e2e_alice@test.local"
    },
    {
      "file_type": "selfie",
      "file_node_id": "node_selfie_003",
      "attached_at": 1717000300,
      "attached_by": "e2e_alice@test.local"
    },
    {
      "file_type": "proof_of_address",
      "file_node_id": "node_poa_004",
      "attached_at": 1717000400,
      "attached_by": "e2e_alice@test.local"
    }
  ]
}
```

**Submitted case**:

```json
{
  "pk": "KYC#kyc_9f1a2b3c4d",
  "sk": "META",
  "status": "submitted",
  "version": 8,
  "submission": {
    "submitted_at": 1717001000,
    "evidence_snapshot": {
      "files_attached": 4,
      "questionnaire_completed": true,
      "signature_completed": true
    }
  },
  "gsi_status_pk": "STATUS#submitted",
  "gsi_status_sk": "UPDATED#0001717001000#KYC#kyc_9f1a2b3c4d"
}
```

---

## 6. API Request/Response Examples

### 6.1 Create KYC Case

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "http://localhost:8000/v1/kyc/cases"
```

Response (201):
```json
{
  "case": {
    "kyc_case_id": "kyc_9f1a2b3c4d",
    "status": "draft",
    "version": 1,
    "created_at": 1717000000,
    "updated_at": 1717000000,
    "files": [],
    "intake_profile": null
  }
}
```

### 6.2 Update Personal Info (Step 1)

```bash
curl -s -X PATCH -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_version": 1,
    "intake_profile": "{\"first_name\":\"Alice\",\"last_name\":\"Test\",\"dob\":\"1990-01-15\",\"nationality\":\"US\"}"
  }' \
  "http://localhost:8000/v1/kyc/cases/kyc_9f1a2b3c4d"
```

Response (200):
```json
{
  "case": {
    "kyc_case_id": "kyc_9f1a2b3c4d",
    "status": "draft",
    "version": 2,
    "intake_profile": "{\"first_name\":\"Alice\",\"last_name\":\"Test\",\"dob\":\"1990-01-15\",\"nationality\":\"US\"}"
  }
}
```

### 6.3 Attach ID Document (Step 2)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{
    "file_type": "id_front",
    "file_node_id": "node_id_front_001"
  }' \
  "http://localhost:8000/v1/kyc/cases/kyc_9f1a2b3c4d/files"
```

Response (200):
```json
{
  "ok": true,
  "file_type": "id_front",
  "file_node_id": "node_id_front_001",
  "attached_at": 1717000200
}
```

### 6.4 Check Readiness (Step 7)

```bash
curl -s -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/kyc_9f1a2b3c4d/readiness"
```

Response (200):
```json
{
  "readiness": {
    "ready": true,
    "checks": {
      "intake_profile": { "ok": true },
      "files": { "ok": true, "missing": [] },
      "questionnaire": { "ok": true },
      "signature": { "ok": true }
    }
  }
}
```

### 6.5 Submit Case (Step 7)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{ "expected_version": 7 }' \
  "http://localhost:8000/v1/kyc/cases/kyc_9f1a2b3c4d/submit"
```

Response (200):
```json
{
  "case": {
    "kyc_case_id": "kyc_9f1a2b3c4d",
    "status": "submitted",
    "version": 8,
    "submission": {
      "submitted_at": 1717001000,
      "evidence_snapshot": { "files_attached": 4, "questionnaire_completed": true, "signature_completed": true }
    }
  }
}
```

### 6.6 Estimated Wait Time

```bash
curl -s -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  "http://localhost:8000/v1/kyc/cases/estimated-wait"
```

Response (200):
```json
{
  "estimated_hours": 24,
  "queue_position": null,
  "message": "Estimated review time: 24 hours. We'll notify you when there's an update."
}
```

### 6.7 Submit Without Prerequisites (400)

```bash
curl -s -X POST -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{ "expected_version": 1 }' \
  "http://localhost:8000/v1/kyc/cases/kyc_newdraft/submit"
```

Response (400):
```json
{
  "detail": "kyc_submit_prereq_failed",
  "missing_checks": ["files", "questionnaire", "signature"]
}
```

### 6.8 OCC Version Conflict (409)

```bash
curl -s -X PATCH -b "ui_session=sess_alice123; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_alice123" \
  -H "Content-Type: application/json" \
  -d '{ "expected_version": 999, "intake_profile": "{}" }' \
  "http://localhost:8000/v1/kyc/cases/kyc_9f1a2b3c4d"
```

Response (409):
```json
{
  "detail": "version_conflict"
}
```

---

## 7. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code / Detail | User-Facing Message | Recovery Action |
|----------------|-------------|---------------------|---------------------|-----------------|
| No session cookie | 401 | `session_expired` | "Please log in to continue." | Redirect to /login |
| Case not found | 404 | `case_not_found` | "Verification case not found." | Create a new case |
| Case belongs to another user | 403 | `access_forbidden` | "You do not have access to this case." | -- |
| OCC version conflict | 409 | `version_conflict` | "Another update was made. Please refresh." | Refetch case, retry |
| Submit without prerequisites | 400 | `kyc_submit_prereq_failed` | "Please complete all steps before submitting." | Complete missing steps |
| Invalid file_type | 422 | `value_error` | "Invalid document type." | Use accepted file_type |
| File node_id not found | 404 | `file_not_found` | "Uploaded file not found." | Re-upload the file |
| Duplicate file_type attach | 200 | -- (replaces previous) | N/A (silent replace) | Expected behavior |
| Case already submitted | 400 | `invalid_status_transition` | "This case has already been submitted." | View status page |
| Questionnaire not started | 200 | `questionnaire.ok: false` | "Please complete the questionnaire." | Navigate to step 5 |
| Signature not completed | 200 | `signature.ok: false` | "Please sign the consent form." | Navigate to step 6 |
| Camera permission denied | N/A (client) | -- | "Camera access was denied. Please upload a file instead." | Use file upload fallback |
| File too large (>10MB) | 413 | `file_too_large` | "File exceeds the 10MB size limit." | Compress or resize |
| Unsupported image format | 422 | `unsupported_format` | "Please upload a JPEG or PNG image." | Convert file format |
| CSRF token missing | 403 | `csrf_token_mismatch` | "Security validation failed." | Refresh page |
| Expired case (re-submit) | 400 | `case_expired` | "This application has expired. Please start a new one." | Create new case |

---

## 8. Pydantic Models

### 8.1 Request Models

```python
from pydantic import BaseModel, Field
from typing import Literal


class CreateKycCaseRequest(BaseModel):
    """Request to create a new KYC case. Body is empty -- case is initialized with defaults."""
    pass


class UpdateKycDraftRequest(BaseModel):
    """Request to update a draft KYC case (Step 1: personal info)."""
    expected_version: int = Field(
        ge=1,
        description="Optimistic concurrency control version. Must match the current case version.",
        examples=[1],
    )
    intake_profile: str | None = Field(
        default=None,
        max_length=10000,
        description="JSON string containing personal information fields.",
        examples=['{"first_name":"Alice","last_name":"Test","dob":"1990-01-15","nationality":"US"}'],
    )
    document_type: str | None = Field(
        default=None,
        max_length=50,
        description="Primary identity document type (passport, national_id, driving_license, residence_permit).",
        examples=["passport"],
    )


class AttachKycFileRequest(BaseModel):
    """Request to attach a file to a KYC case."""
    file_type: Literal["id_front", "id_back", "selfie", "proof_of_address"] = Field(
        description="The type of document being attached.",
    )
    file_node_id: str = Field(
        min_length=1,
        max_length=256,
        description="The file manager node ID for the uploaded file.",
        examples=["node_id_front_001"],
    )


class SubmitKycCaseRequest(BaseModel):
    """Request to submit a KYC case for review."""
    expected_version: int = Field(
        ge=1,
        description="Optimistic concurrency control version.",
        examples=[7],
    )


class StartQuestionnaireRequest(BaseModel):
    """Request to start a questionnaire session for a KYC case."""
    published_slug: str = Field(
        min_length=1,
        max_length=200,
        description="The slug of the published questionnaire template.",
        examples=["kyc-intake-v2"],
    )
```

### 8.2 Response Models

```python
from pydantic import BaseModel, Field
from typing import Any


class KycFileRefOut(BaseModel):
    """A file reference attached to a KYC case."""
    file_type: str
    file_node_id: str
    attached_at: int
    attached_by: str


class KycSubmissionOut(BaseModel):
    """Submission metadata for a submitted KYC case."""
    submitted_at: int
    evidence_snapshot: dict[str, Any] = Field(default_factory=dict)


class KycReviewOut(BaseModel):
    """Review metadata for a decided KYC case."""
    decided_at: int | None = None
    decision: str | None = None
    decided_by: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    assigned_admin_sub: str | None = None


class KycCaseOut(BaseModel):
    """A KYC case record."""
    kyc_case_id: str
    status: str
    version: int
    created_at: int
    updated_at: int
    intake_profile: str | None = None
    document_type: str | None = None
    files: list[KycFileRefOut] = Field(default_factory=list)
    submission: KycSubmissionOut | None = None
    review: KycReviewOut | None = None


class KycCaseResponse(BaseModel):
    """Wrapper for a single KYC case response."""
    case: KycCaseOut


class KycCaseListResponse(BaseModel):
    """Response for listing a user's KYC cases."""
    items: list[KycCaseOut]
    total: int


class ReadinessCheckOut(BaseModel):
    """A single readiness check result."""
    ok: bool
    missing: list[str] | None = None
    reason: str | None = None


class ReadinessOut(BaseModel):
    """Overall readiness status for a KYC case."""
    ready: bool
    checks: dict[str, ReadinessCheckOut]


class ReadinessResponse(BaseModel):
    """Response for the readiness endpoint."""
    readiness: ReadinessOut


class AttachFileResponse(BaseModel):
    """Response after attaching a file to a KYC case."""
    ok: bool = True
    file_type: str
    file_node_id: str
    attached_at: int


class EstimatedWaitResponse(BaseModel):
    """Response for the estimated wait time endpoint."""
    estimated_hours: int = Field(ge=1, description="Estimated hours until review")
    queue_position: int | None = Field(
        default=None,
        description="Queue position (not exposed to users)",
    )
    message: str = Field(description="Human-readable wait time message")


class QuestionnaireStatusOut(BaseModel):
    """Status of a questionnaire session linked to a KYC case."""
    started: bool
    completed: bool
    session_id: str | None = None
    completed_at: int | None = None


class SignatureStatusOut(BaseModel):
    """Status of a signature packet linked to a KYC case."""
    linked: bool
    signed: bool
    packet_id: str | None = None
    signed_at: int | None = None
```

---

## 9. Frontend Component Tree

```
/kyc -> KycWizard.tsx
├── Props: none (route-level page component)
├── State:
│   ├── currentStep: number (useState, default 0)
│   ├── caseId: string | null (useState)
│   └── createCasePending: boolean (from useMutation)
├── Queries:
│   ├── useQuery(["kyc","cases"]) → KycCaseListResponse
│   ├── useQuery(["kyc","readiness", caseId], { enabled: !!caseId })
│   └── useQuery(["kyc","case", caseId], { enabled: !!caseId })
├── Mutations:
│   └── useMutation(createKycCase) → on success: setCaseId(data.case.kyc_case_id)
│
├── <div className="max-w-3xl mx-auto py-8 px-4">
│   ├── <h1>"Identity Verification"</h1>
│   ├── <Progress value={(currentStep / 7) * 100} />
│   │
│   ├── <StepIndicatorBar>
│   │   ├── Props: { steps: STEPS[], currentStep: number, stepComplete: Record<string,boolean> }
│   │   └── For each step:
│   │       ├── <button onClick={() => setCurrentStep(i)}>
│   │       │   ├── stepComplete[id] ? <CheckCircle2 green/> : <Circle gray/>
│   │       │   └── <span>{step.label}</span>
│   │       └── Active step: "text-blue-600 font-bold"
│   │
│   ├── <Card>
│   │   └── <CardContent className="p-6">
│   │       ├── currentStep === 0: <PersonalInfoStep>
│   │       │   ├── Props: { caseId: string, onComplete: () => void }
│   │       │   ├── State: form (useForm with Zod schema)
│   │       │   ├── Mutation: useMutation(patchKycCase)
│   │       │   ├── Fields:
│   │       │   │   ├── <Input label="First Name" {...register("first_name")} />
│   │       │   │   ├── <Input label="Last Name" {...register("last_name")} />
│   │       │   │   ├── <Input type="date" label="Date of Birth" />
│   │       │   │   ├── <Select label="Nationality" options={COUNTRIES} />
│   │       │   │   └── <Textarea label="Address" />
│   │       │   └── <Button type="submit">"Save & Continue"</Button>
│   │       │
│   │       ├── currentStep === 1: <IdUploadStep>
│   │       │   ├── Props: { caseId: string }
│   │       │   ├── State: docType (useState), uploadedFront/Back (useState)
│   │       │   ├── Mutations: useMutation(attachKycFile), useMutation(uploadFile)
│   │       │   ├── <Select label="Document Type" options={DOC_TYPES} />
│   │       │   ├── <FileUploadZone label="Front of Document" accept="image/*" />
│   │       │   │   └── onDrop → uploadFile → attachKycFile(caseId, {file_type:"id_front"})
│   │       │   ├── <FileUploadZone label="Back of Document" accept="image/*" />
│   │       │   │   └── (conditionally shown based on docType)
│   │       │   └── <ScanResultsPreview> (shown after scan-document)
│   │       │
│   │       ├── currentStep === 2: <SelfieStep>
│   │       │   ├── Props: { caseId: string }
│   │       │   ├── <CameraCapture facing="user" onCapture={handleCapture} />
│   │       │   │   ├── <video ref={videoRef} autoPlay />
│   │       │   │   ├── <Button onClick={capture}>"Take Photo"</Button>
│   │       │   │   ├── <Button onClick={retake}>"Retake"</Button> (if captured)
│   │       │   │   └── Fallback: <input type="file" accept="image/*" capture="user" />
│   │       │   └── <img src={capturedPreview} /> (after capture)
│   │       │
│   │       ├── currentStep === 3: <AddressProofStep>
│   │       │   ├── Props: { caseId: string }
│   │       │   ├── <p>"Upload a utility bill, bank statement, or government letter"</p>
│   │       │   ├── <FileUploadZone accept="image/*,.pdf" />
│   │       │   └── <DocumentPreview file={uploadedFile} />
│   │       │
│   │       ├── currentStep === 4: <QuestionnaireStep>
│   │       │   ├── Props: { caseId: string }
│   │       │   ├── Query: useQuery(["kyc","questionnaire-status", caseId])
│   │       │   ├── Mutation: useMutation(startKycQuestionnaire)
│   │       │   ├── Not started: <Button>"Start Questionnaire"</Button>
│   │       │   ├── In progress: <p>"Questionnaire in progress..."</p>
│   │       │   └── Completed: <CheckCircle2 /> "Questionnaire completed"
│   │       │
│   │       ├── currentStep === 5: <ConsentStep>
│   │       │   ├── Props: { caseId: string }
│   │       │   ├── Query: useQuery(["kyc","signature-status", caseId])
│   │       │   ├── Not linked: <Button>"Create Consent Form"</Button>
│   │       │   ├── Linked but unsigned: <Link to="/signing">"Go to Signing"</Link>
│   │       │   └── Signed: <CheckCircle2 /> "Consent form signed"
│   │       │
│   │       └── currentStep === 6: <ReviewSubmitStep>
│   │           ├── Props: { caseId: string, readiness: ReadinessResponse }
│   │           ├── Mutation: useMutation(submitKycCase)
│   │           ├── <h3>"Review Your Application"</h3>
│   │           ├── For each check in readiness.checks:
│   │           │   ├── check.ok ? <CheckCircle2 green/> : <XCircle red/>
│   │           │   └── <span>{checkLabel}</span>
│   │           ├── <FilesList> (attached files preview)
│   │           └── <Button disabled={!readiness.ready} onClick={submit}>"Submit"</Button>
│   │
│   └── <div className="flex justify-between mt-6">  {/* Navigation */}
│       ├── <Button variant="outline" onClick={back} disabled={step===0}>"Back"</Button>
│       └── <Button onClick={next} disabled={step===6}>"Continue"</Button>
│
└── <KycHelp />  {/* FAQ accordion at bottom */}
    ├── <Accordion>
    │   ├── <AccordionItem>"What documents are accepted?"</AccordionItem>
    │   ├── <AccordionItem>"How long does verification take?"</AccordionItem>
    │   ├── <AccordionItem>"Why was my application rejected?"</AccordionItem>
    │   ├── <AccordionItem>"Can I reapply after rejection?"</AccordionItem>
    │   └── <AccordionItem>"How is my data protected?"</AccordionItem>
    └── </Accordion>

/kyc/status -> KycStatusPage.tsx
├── Props: none
├── Query: useQuery(["kyc","cases"]) → KycCaseListResponse
├── Derived:
│   ├── activeCases = items.filter(status in [submitted, under_review, needs_more_info])
│   └── historicalCases = items.filter(status in [approved, rejected, expired])
│
├── <h1>"Verification Status"</h1>
│
├── activeCases.map(case =>
│   <ActiveCaseCard>
│   ├── Props: { kycCase: KycCaseOut }
│   ├── Query: useQuery(["kyc","estimated-wait"]) → EstimatedWaitResponse
│   ├── <Badge variant={statusVariant}>{case.status}</Badge>
│   ├── <StatusTimeline>
│   │   ├── Props: { currentStatus: string }
│   │   └── Dots: submitted (green) → under_review (yellow/green) → decision (gray/green)
│   ├── <p>"Submitted on {formatDate(submission.submitted_at)}"</p>
│   ├── <p>{estimatedWait.message}</p>
│   └── {case.status === "needs_more_info" &&
│       <Button asChild><Link to="/kyc">"Update Documents"</Link></Button>}
│   )
│
├── {activeCases.length === 0 &&
│   <Card><CardContent>"No active verification."
│     <Link to="/kyc">"Start verification"</Link>
│   </CardContent></Card>}
│
├── <h2>"Previous Applications"</h2>
│
└── historicalCases.map(case =>
    <HistoricalCaseCard>
    ├── Props: { kycCase: KycCaseOut }
    ├── <Badge>{case.status}</Badge>
    ├── <p>"Decision: {review.decision} on {formatDate(review.decided_at)}"</p>
    ├── {review.reason_codes.length > 0 &&
    │   <ul>{reason_codes.map(rc => <li>{rc}</li>)}</ul>}
    └── <Button asChild><Link to="/kyc">"Start New Application"</Link></Button>
    )
```

### React Query Keys

| Key | Endpoint | Stale Time | Notes |
|-----|----------|------------|-------|
| `["kyc","cases"]` | `GET /v1/kyc/cases` | 30s | Invalidated after submit |
| `["kyc","case", caseId]` | `GET /v1/kyc/cases/{id}` | 10s | Invalidated after file attach |
| `["kyc","readiness", caseId]` | `GET /v1/kyc/cases/{id}/readiness` | 5s | Refetched after each step |
| `["kyc","estimated-wait"]` | `GET /v1/kyc/cases/estimated-wait` | 120s | Low frequency |
| `["kyc","questionnaire-status", caseId]` | `GET /v1/kyc/cases/{id}/questionnaire-status` | 10s | Polled during step 5 |
| `["kyc","signature-status", caseId]` | `GET /v1/kyc/cases/{id}/signature-status` | 10s | Polled during step 6 |

---

## 10. Observability & Monitoring

### 10.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `kyc_wizard_step_completed_total` | Counter | `step` | Wizard step completions |
| `kyc_wizard_started_total` | Counter | -- | Wizard page loads (case created) |
| `kyc_wizard_submitted_total` | Counter | -- | Cases submitted through wizard |
| `kyc_wizard_abandoned_total` | Counter | `last_step` | Wizard exits without submission |
| `kyc_file_upload_total` | Counter | `file_type` | File uploads by type |
| `kyc_file_upload_duration_ms` | Histogram | `file_type` | Upload latency |
| `kyc_estimated_wait_hours` | Gauge | -- | Current estimated wait time |
| `kyc_camera_capture_total` | Counter | `outcome` (success/fallback/error) | Camera capture attempts |
| `kyc_status_page_views_total` | Counter | -- | Status page views |

### 10.2 Structured Log Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `kyc.wizard.started` | INFO | `user_sub`, `case_id`, `resumed` (bool) | Wizard page loaded; case created or resumed |
| `kyc.wizard.step_completed` | INFO | `user_sub`, `case_id`, `step`, `duration_ms` | Step successfully completed |
| `kyc.wizard.file_attached` | INFO | `user_sub`, `case_id`, `file_type`, `file_size` | File uploaded and attached |
| `kyc.wizard.submitted` | INFO | `user_sub`, `case_id`, `total_files`, `duration_since_start_ms` | Case submitted |
| `kyc.wizard.submit_failed` | WARN | `user_sub`, `case_id`, `error`, `missing_checks` | Submit attempted without prerequisites |
| `kyc.wizard.abandoned` | INFO | `user_sub`, `case_id`, `last_step`, `time_on_page_ms` | User left wizard without submitting |
| `kyc.camera.permission_denied` | WARN | `user_sub`, `browser` | Camera access denied |
| `kyc.camera.capture_success` | INFO | `user_sub`, `file_size` | Photo captured |
| `kyc.status.viewed` | INFO | `user_sub`, `active_cases`, `historical_cases` | Status page loaded |

### 10.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Wizard abandonment rate > 50% | `abandoned / started > 0.5` (rolling 24h) | P3 | Review UX friction; check error logs |
| File upload error rate > 10% | `upload_errors / upload_total > 0.1` | P2 | Check S3 connectivity, file size limits |
| Estimated wait > 72 hours | `kyc_estimated_wait_hours > 72` | P2 | Increase admin review capacity |
| Submit failure rate > 20% | `submit_failed / submit_attempted > 0.2` | P3 | Check readiness endpoint accuracy |
| Camera fallback rate > 80% | `camera_fallback / camera_total > 0.8` | P4 | Expected in headless/desktop; review mobile |

### 10.4 Dashboard Queries

**Wizard funnel conversion**:
```sql
SELECT step, COUNT(*) AS completions,
       COUNT(*) * 100.0 / MAX(total_starts) AS conversion_pct
FROM kyc_wizard_events
WHERE event IN ('kyc.wizard.step_completed', 'kyc.wizard.started')
  AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY step
ORDER BY step;
```

---

## 11. Rollout Plan

### 11.1 Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `KYC_SELF_SERVICE_PORTAL_ENABLED` | `false` | Master switch for /kyc routes |
| `KYC_CAMERA_CAPTURE_ENABLED` | `true` | Camera capture in selfie step |
| `KYC_ESTIMATED_WAIT_ENABLED` | `true` | Show estimated wait time |

### 11.2 Rollout Phases

**Phase 1: Internal testing (Week 1)**
1. Enable portal for internal users only (whitelist by user_sub).
2. Test all 7 wizard steps end-to-end.
3. Verify camera capture on mobile Safari, Chrome, Firefox.
4. Verify fallback to file upload when camera is denied.

**Phase 2: Beta rollout (Week 2)**
1. Enable for 10% of new users.
2. Monitor wizard abandonment rate and funnel conversion.
3. Monitor file upload success rates.
4. Collect user feedback on UX.

**Phase 3: General availability (Week 3)**
1. Enable for all users.
2. Add sidebar link to "Verify Account".
3. Show verification prompt on restricted pages.

**Phase 4: Optimization (Week 4)**
1. A/B test step ordering (selfie before ID vs. after).
2. Add document quality feedback (blur detection, lighting hints).
3. Add progress save/resume across browser sessions.

### 11.3 Rollback Procedure

1. Set `KYC_SELF_SERVICE_PORTAL_ENABLED=false`.
2. Remove `/kyc` and `/kyc/status` routes from `App.tsx`.
3. Remove sidebar links.
4. The `GET /estimated-wait` endpoint can remain (read-only, no side effects).
5. Draft cases created during the rollout remain in DynamoDB and can be completed via API.

---

## 12. Performance Considerations

### 12.1 Query Costs

| Operation | DDB Read/Write | Latency | Frequency |
|-----------|----------------|---------|-----------|
| Create case | 1 WCU | 10ms | Once per user per verification |
| Update draft (PATCH) | 1 WCU | 10ms | 1-3 times per wizard session |
| Attach file | 1 WCU | 10ms | 4 times per wizard (4 file types) |
| Check readiness | 1 RCU | 10ms | After each step (7 times) |
| Submit case | 1 WCU | 10ms | Once per case |
| List user cases | ~1-5 RCU | 20ms | Each page load |
| Estimated wait | ~10 RCU | 50ms | Each status page load |

### 12.2 File Upload Performance

File uploads go through the file manager which uploads to S3. In dev mode, S3 is moto (in-process). Expected upload latencies:

| File Size | Dev Mode (moto) | Production (S3) |
|-----------|-----------------|-----------------|
| 100KB (selfie) | <50ms | 200-500ms |
| 500KB (ID scan) | <100ms | 500ms-1s |
| 2MB (proof of address PDF) | <200ms | 1-2s |

### 12.3 Camera Capture Optimization

- Compress captured images to JPEG quality 0.9 before upload (reduces 3MB raw canvas to ~200KB JPEG).
- Set ideal resolution to 1280x720 to balance quality vs. upload size.
- Show progress indicator during upload.

### 12.4 Caching Strategy

| Data | Cache | Stale Time | Invalidation |
|------|-------|------------|--------------|
| Case list | React Query | 30s | After submit mutation |
| Readiness | React Query | 5s | After file attach / step complete |
| Estimated wait | React Query | 120s | None (low frequency) |
| Case detail | React Query | 10s | After any mutation on that case |

### 12.5 Rate Limiting

| Endpoint | Rate Limit | Window | Notes |
|----------|------------|--------|-------|
| `POST /v1/kyc/cases` | 3 | per hour per user | Prevent case spam |
| `POST /v1/kyc/cases/{id}/files` | 20 | per hour per user | Allow re-uploads |
| `POST /v1/kyc/cases/{id}/submit` | 5 | per hour per user | Prevent submit spam |
| `GET /v1/kyc/cases/estimated-wait` | 30 | per minute per user | Polling-safe |

---

## 13. Implementation Plan

### Phase 1: Backend -- Estimated Wait Endpoint (1 day)

| File | Change |
|------|--------|
| `app/routers/kyc_cases.py` | Add `GET /estimated-wait` endpoint (~30 lines) |

### Phase 2: Frontend -- KYC Wizard (4 days)

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

### Phase 3: Frontend -- Status Page (2 days)

| File | Change |
|------|--------|
| `frontend/src/pages/kyc/KycStatusPage.tsx` | New: status tracking page (~250 lines) |
| `frontend/src/pages/kyc/KycHelp.tsx` | New: FAQ section (~100 lines) |

### Phase 4: Frontend -- Camera & Integration (2 days)

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

## 14. E2E Test Plan (`frontend/e2e/kyc-wizard.spec.ts`)

**Test file**: `frontend/e2e/kyc-wizard.spec.ts`  
**Total tests**: ~25  
**Sections**: 197-202

### Section 197: KYC Case Creation API (3 tests)

1. `POST /v1/kyc/cases creates a draft case` -- Verify response has `status: "draft"`, `kyc_case_id` starts with `kyc_`.
2. `GET /v1/kyc/cases lists user's cases` -- After creation, list returns at least 1 case.
3. `GET /v1/kyc/cases/estimated-wait returns estimated hours` -- Verify response has `estimated_hours` (number) and `message` (string).

### Section 198: Wizard Personal Info Step API (3 tests)

1. `PATCH /{case_id} updates intake_profile` -- Send personal info JSON; verify case now has `intake_profile` populated.
2. `Readiness check shows intake_profile as ok after update` -- GET readiness; verify `checks.intake_profile.ok: true`.
3. `Invalid expected_version returns 409` -- PATCH with wrong version; verify 409 conflict error.

### Section 199: Wizard File Attachment API (5 tests)

1. `POST /{case_id}/files attaches id_front` -- Upload a file, get node_id, attach with `file_type: "id_front"`; verify case files array has entry.
2. `POST /{case_id}/files attaches id_back` -- Same for `id_back`.
3. `POST /{case_id}/files attaches selfie` -- Same for `selfie`.
4. `POST /{case_id}/files attaches proof_of_address` -- Same for `proof_of_address`.
5. `GET /{case_id}/files/validation shows missing files` -- After attaching only selfie; verify `missing: ["id_front", "id_back"]`.

### Section 200: Wizard Submit Flow API (4 tests)

1. `GET /{case_id}/readiness with all prerequisites met returns ready=true` -- After attaching all files + questionnaire + signature; verify `ready: true`.
2. `POST /{case_id}/submit transitions to submitted` -- Verify case status becomes `"submitted"`.
3. `POST /{case_id}/submit without prerequisites returns 400` -- Create new case without files; submit returns 400 with `kyc_submit_prereq_failed`.
4. `Submitted case cannot be re-submitted` -- POST submit on already-submitted case returns error.

### Section 201: KYC Status Page UI (5 tests)

1. `Status page shows active case with submitted badge` -- Navigate to `/kyc/status`; verify submitted case appears with status badge.
2. `Status page shows estimated wait time` -- Verify "Estimated review time" text is displayed.
3. `Historical cases section shows previous rejected case` -- Create and reject a case; navigate to status page; verify rejected case appears under "Previous Applications".
4. `Needs-more-info case shows update documents button` -- Set case to needs_more_info; navigate; verify "Update Documents" button is visible.
5. `Start New Application link navigates to wizard` -- Click link; verify navigation to `/kyc`.

### Section 202: KYC Wizard UI (5 tests)

1. `Wizard page loads with step indicators` -- Navigate to `/kyc`; verify 7 step labels are visible.
2. `Step completion checkmarks appear after completing steps` -- Complete step 1; verify green checkmark appears on step 1 indicator.
3. `Continue button advances to next step` -- Click Continue; verify step 2 content is displayed.
4. `Back button returns to previous step` -- Click Back; verify step 1 content is displayed.
5. `Submit button is disabled until all checks pass` -- Navigate to step 7 without completing all steps; verify Submit button is disabled.

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

## 15. Expanded E2E Test Details

### Section 197a: Case Creation Edge Cases (4 tests)

1. `Creating a case while another draft exists resumes the existing draft` -- Create case A (draft); create case B; wizard should use case A (first draft found).
2. `Unauthenticated user cannot create a case (401)` -- No cookies; POST returns 401.
3. `GET /v1/kyc/cases with no cases returns empty list` -- New user with no history; verify `items: []`, `total: 0`.
4. `Estimated wait with empty queue returns 1 hour` -- When no cases are submitted; verify `estimated_hours: 1`.

### Section 199a: File Attachment Edge Cases (4 tests)

1. `Attaching same file_type twice replaces previous` -- Attach id_front with node A; attach id_front with node B; verify only node B remains.
2. `Attaching file to non-existent case returns 404` -- POST to `/v1/kyc/cases/kyc_nonexistent/files`; verify 404.
3. `Attaching file to submitted case returns 400` -- Submit a case; try to attach file; verify 400 `invalid_status`.
4. `File validation after all files attached shows no missing` -- Attach all 4 file types; GET validation; verify `missing: []`.

### Section 200a: Submit Edge Cases (4 tests)

1. `Submit with wrong version returns 409` -- Submit with `expected_version: 999`; verify 409.
2. `Submit with only partial files returns 400` -- Case has id_front but missing id_back; submit fails.
3. `Case status changes from draft to submitted` -- Verify GET case after submit shows `status: "submitted"`.
4. `Submit creates submission.evidence_snapshot` -- Verify `submission.evidence_snapshot.files_attached` equals the number of attached files.

### Section 201a: Status Page Edge Cases (3 tests)

1. `Status page with no active cases shows "Start verification" link` -- User with only historical cases; verify link visible.
2. `Multiple active cases all displayed` -- Create 2 submitted cases; verify both ActiveCaseCards rendered.
3. `Historical case shows reason codes for rejected` -- Root rejects a case with reason codes; verify reason codes displayed on status page.

### Section 202a: Wizard Navigation Edge Cases (3 tests)

1. `Wizard back button disabled on first step` -- Verify Back button has `disabled` attribute on step 0.
2. `Wizard continue button disabled on last step` -- Navigate to step 7; verify Continue button has `disabled` attribute.
3. `Clicking step indicator jumps to that step` -- Click on step 4 indicator; verify step 4 content is displayed.

---

## 16. Security Considerations

- All wizard steps use `require_ui_session` -- unauthenticated users are redirected to login.
- File uploads go through the existing file manager with the user's own S3 namespace.
- The `intake_profile` field is stored as a JSON string; the backend does not interpret the contents beyond length validation.
- Camera capture happens entirely client-side; the captured image is uploaded as a standard file.
- The estimated wait time endpoint does not expose admin queue details (case count, admin assignments) -- only a derived hour estimate.
- OCC (Optimistic Concurrency Control) via `expected_version` prevents race conditions when multiple browser tabs edit the same case.

---

## 17. Rollback Plan

- Remove `/kyc` and `/kyc/status` routes from `App.tsx`.
- Remove sidebar links.
- Delete `frontend/src/pages/kyc/` directory.
- The `GET /estimated-wait` backend endpoint can remain (it is a read-only endpoint with no side effects).
- Draft cases in DynamoDB are unaffected and can be completed via API if the portal is re-enabled.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| KYC cases router | `app/routers/kyc_cases.py` | all | VERIFIED (1294 lines, not 1295 as ticket states) |
| KYC cases service | `app/services/kyc_cases.py` | all | VERIFIED (828 lines, not 829 as ticket states) |
| `create_kyc_case()` | `app/routers/kyc_cases.py` | 519 | VERIFIED |
| `submit_kyc_case()` | `app/routers/kyc_cases.py` | 830 | VERIFIED |
| `attach_kyc_file()` | `app/routers/kyc_cases.py` | 734 | VERIFIED |
| `validate_kyc_file_requirements()` | `app/routers/kyc_cases.py` | 791 | VERIFIED |
| `start_kyc_questionnaire()` | `app/routers/kyc_cases.py` | 625 | VERIFIED |
| `_readiness_for_case()` | `app/routers/kyc_cases.py` | 223 | VERIFIED |
| `_signature_status_for_case()` | `app/routers/kyc_cases.py` | 184 | VERIFIED |
| `create_or_link_signature_packet()` | `app/routers/kyc_cases.py` | 1206 | VERIFIED |
| `get_admin_kyc_metrics()` | `app/routers/kyc_cases.py` | 947 | VERIFIED (ticket cites line 946 -- off by 1) |
| `list_cases_by_owner()` | `app/services/kyc_cases.py` | 607 | VERIFIED |
| `kyc_cases` DDB table | `scripts/local-ddb-init.py` | 91-96 | VERIFIED (2 GSIs) |
| KYC settings | `app/core/settings.py` | 1065-1072 | VERIFIED |
| KYC cases router registration | `app/main.py` | 406 | VERIFIED |
| `require_ui_session` | `app/auth/deps.py` | exists | VERIFIED |
| File manager service | `app/services/filemanager.py` | exists | VERIFIED |
| Questionnaire repository | `app/services/questionnaires_repository.py` | 38 | VERIFIED |
| Signature packet store | `app/services/signature_packet_store.py` | exists | VERIFIED |
| Signing page | `frontend/src/pages/signing/SigningPage.tsx` | exists | VERIFIED |
| Files page | `frontend/src/pages/files/FilesPage.tsx` | exists | VERIFIED |
| Questionnaires pages | `frontend/src/pages/questionnaires/` | exists | VERIFIED |

### Corrections

<!-- NOTE: The ticket states `app/routers/kyc_cases.py` has 1295 lines -- actual count is 1294. -->
<!-- NOTE: The ticket states `app/services/kyc_cases.py` has 829 lines -- actual count is 828. -->
<!-- NOTE: The ticket cites `get_admin_kyc_metrics()` at "line 946" -- actual line is 947. -->
<!-- NOTE: The "readiness" endpoint is cited at "line 809" -- actual `_readiness_for_case()` is at line 223 and the `kyc_readiness()` route handler needs separate verification. -->

### Not Yet Implemented (requires new code)

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `GET /v1/kyc/cases/estimated-wait` endpoint | `app/routers/kyc_cases.py` | NOT FOUND -- new endpoint required |
| `frontend/src/pages/kyc/KycWizard.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new page required |
| `frontend/src/pages/kyc/KycStatusPage.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new page required |
| `frontend/src/pages/kyc/KycHelp.tsx` | `frontend/src/pages/kyc/` | NOT FOUND -- new component required |
| `frontend/src/pages/kyc/steps/*.tsx` (7 step components) | `frontend/src/pages/kyc/steps/` | NOT FOUND -- new directory + components required |
| `frontend/src/components/shared/CameraCapture.tsx` | `frontend/src/components/shared/` | NOT FOUND -- new component required |
| `frontend/src/api/endpoints/kyc.ts` | `frontend/src/api/endpoints/` | NOT FOUND -- new endpoint file required |
| `/kyc` and `/kyc/status` routes | `frontend/src/App.tsx` | NOT FOUND -- new routes required |
| Verification sidebar links | `frontend/src/components/layout/Sidebar.tsx` | NOT FOUND -- needs modification |
| `KYC_SELF_SERVICE_PORTAL_ENABLED` feature flag | `app/core/settings.py` | NOT FOUND -- new setting required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_kyc_self_service.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_get_verification_status`
  - `test_get_next_tier_requirements`
  - `test_submit_document_for_review`
  - `test_view_submission_history`
  - `test_resubmit_rejected_document`
  - `test_upload_progress_tracking`
  - `test_user_cannot_access_other_user_status`

### Integration Tests

  - Self-service submission creates kyc_submissions record for admin review
  - User sees real-time status updates as admin reviews submissions
  - Document resubmission creates new version linked to previous rejection

### E2E Tests (Playwright)

**File**: `frontend/e2e/kyc-self-service.spec.ts`
**Test count**: 12

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

- **DDB seeds**: Seed `kyc_submissions (user-facing views)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `KYC_SELF_SERVICE_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| KYC-009 | Tiered Verification Levels | Users see current tier and next-tier requirements |
| KYC-010 | Passport & National ID Scanner | Scanner integrated into upload flow |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| KYC-014 | Facial Comparison | Selfie capture integrated into self-service flow |

### Merge Strategy

**Sequential**

Merge after KYC-009, KYC-010. This ticket depends on tables/services introduced by those tickets.

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
- [ ] All 12 E2E tests pass with `npx playwright test kyc-self-service.spec.ts`
