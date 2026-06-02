import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  ShieldCheck,
} from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CameraCapture } from "@/components/shared/CameraCapture";
import { FaceComparisonResult } from "@/pages/kyc/FaceComparisonResult";
import { EidVerificationPanel } from "@/components/shared/EidVerificationPanel";
import { ApiError } from "@/api/client";
import {
  createKycCase,
  listKycCases,
  getKycCase,
  getKycReadiness,
  patchKycDraft,
  submitKycCase,
  startKycQuestionnaire,
  getKycQuestionnaireStatus,
  getKycSignatureStatus,
  uploadAndAttachKycFile,
} from "@/api/endpoints/kyc";
import type {
  KycSelfServiceCase,
  KycSelfServiceFileType,
} from "@/api/types";

const STEPS = [
  { id: "personal", label: "Personal Information" },
  { id: "id_upload", label: "Identity Document" },
  { id: "selfie", label: "Selfie" },
  { id: "address", label: "Proof of Address" },
  { id: "questionnaire", label: "Questionnaire" },
  { id: "consent", label: "Consent & Signature" },
  { id: "review", label: "Review & Submit" },
] as const;

const DOC_TYPES = [
  { value: "passport", label: "Passport" },
  { value: "national_id", label: "National ID Card" },
  { value: "driving_license", label: "Driving License" },
  { value: "residence_permit", label: "Residence Permit" },
];

function hasFileType(kycCase: KycSelfServiceCase | undefined, t: KycSelfServiceFileType): boolean {
  return !!kycCase?.files?.some((f) => f.type === t);
}

export default function KycWizardPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [currentStep, setCurrentStep] = useState(0);
  const [caseId, setCaseId] = useState<string | null>(null);

  const casesQuery = useQuery({
    queryKey: ["kyc", "cases"],
    queryFn: listKycCases,
  });

  // Resume an existing draft, otherwise we lazily create one on first action.
  useEffect(() => {
    if (caseId) return;
    const draft = casesQuery.data?.items?.find((c) => c.status === "draft");
    if (draft) setCaseId(draft.kyc_case_id);
  }, [casesQuery.data, caseId]);

  const caseQuery = useQuery({
    queryKey: ["kyc", "case", caseId],
    queryFn: () => getKycCase(caseId as string),
    enabled: !!caseId,
  });
  const kycCase = caseQuery.data?.case;

  const readinessQuery = useQuery({
    queryKey: ["kyc", "readiness", caseId],
    queryFn: () => getKycReadiness(caseId as string),
    enabled: !!caseId,
  });
  const readiness = readinessQuery.data?.readiness;

  const ensureCase = async (): Promise<KycSelfServiceCase> => {
    if (kycCase) return kycCase;
    if (caseId) {
      const refreshed = await getKycCase(caseId);
      return refreshed.case;
    }
    const created = await createKycCase();
    setCaseId(created.case.kyc_case_id);
    qc.invalidateQueries({ queryKey: ["kyc", "cases"] });
    return created.case;
  };

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["kyc", "case", caseId] });
    qc.invalidateQueries({ queryKey: ["kyc", "readiness", caseId] });
    qc.invalidateQueries({ queryKey: ["kyc", "cases"] });
  };

  const stepComplete: Record<string, boolean> = useMemo(
    () => ({
      personal: !!(kycCase?.intake_profile && kycCase.intake_profile.length > 0),
      id_upload: hasFileType(kycCase, "id_front"),
      selfie: hasFileType(kycCase, "selfie"),
      address: hasFileType(kycCase, "proof_of_address"),
      questionnaire: readiness?.checks?.questionnaire ?? false,
      consent: readiness?.checks?.signature ?? false,
      review: !!readiness?.ready_to_submit,
    }),
    [kycCase, readiness],
  );

  const stepProps = { ensureCase, refresh, kycCase };

  return (
    <div className="mx-auto max-w-3xl px-4 py-8" data-testid="kyc-wizard">
      <div className="mb-6 flex items-center gap-2">
        <ShieldCheck className="h-6 w-6 text-blue-600" />
        <h1 className="text-2xl font-bold">Identity Verification</h1>
      </div>

      <Progress value={((currentStep + 1) / STEPS.length) * 100} className="mb-6" />

      <div className="mb-8 grid grid-cols-7 gap-1">
        {STEPS.map((step, i) => (
          <button
            key={step.id}
            type="button"
            onClick={() => setCurrentStep(i)}
            data-testid={`kyc-step-tab-${step.id}`}
            className={`flex flex-col items-center gap-1 text-[10px] ${
              i === currentStep ? "font-bold text-blue-600" : "text-gray-500"
            }`}
          >
            {stepComplete[step.id] ? (
              <CheckCircle2 className="h-5 w-5 text-green-500" />
            ) : (
              <Circle className="h-5 w-5" />
            )}
            <span className="text-center leading-tight">{step.label}</span>
          </button>
        ))}
      </div>

      <Card>
        <CardContent className="p-6">
          {currentStep === 0 && <PersonalInfoStep {...stepProps} />}
          {currentStep === 1 && (
            <>
              <IdUploadStep {...stepProps} />
              {caseId && (
                <div className="mt-6 border-t pt-6">
                  <p className="mb-3 text-sm font-medium text-gray-700">
                    Or skip the upload and verify with your electronic ID:
                  </p>
                  <EidVerificationPanel caseId={caseId} onVerified={refresh} />
                </div>
              )}
            </>
          )}
          {currentStep === 2 && (
            <>
              <SelfieStep {...stepProps} />
              {caseId && hasFileType(kycCase, "selfie") && hasFileType(kycCase, "id_front") && (
                <div className="mt-6">
                  <FaceComparisonResult caseId={caseId} />
                </div>
              )}
            </>
          )}
          {currentStep === 3 && <AddressProofStep {...stepProps} />}
          {currentStep === 4 && <QuestionnaireStep caseId={caseId} ensureCase={ensureCase} refresh={refresh} />}
          {currentStep === 5 && <ConsentStep caseId={caseId} ensureCase={ensureCase} refresh={refresh} kycCase={kycCase} />}
          {currentStep === 6 && (
            <ReviewSubmitStep
              caseId={caseId}
              kycCase={kycCase}
              readyToSubmit={!!readiness?.ready_to_submit}
              checks={readiness?.checks ?? {}}
              missing={readiness?.missing_requirements ?? []}
              onSubmitted={() => navigate("/kyc/status")}
              refresh={refresh}
            />
          )}
        </CardContent>
      </Card>

      <div className="mt-6 flex justify-between">
        <Button
          variant="outline"
          onClick={() => setCurrentStep((s) => Math.max(0, s - 1))}
          disabled={currentStep === 0}
          data-testid="kyc-back"
        >
          Back
        </Button>
        <Button
          onClick={() => setCurrentStep((s) => Math.min(STEPS.length - 1, s + 1))}
          disabled={currentStep === STEPS.length - 1}
          data-testid="kyc-continue"
        >
          Continue
        </Button>
      </div>

      <KycHelp />
    </div>
  );
}

// ─── Step props ──────────────────────────────────────────────────────────────

interface StepProps {
  ensureCase: () => Promise<KycSelfServiceCase>;
  refresh: () => void;
  kycCase?: KycSelfServiceCase;
}

// ─── Step 1: Personal Info ───────────────────────────────────────────────────

function PersonalInfoStep({ ensureCase, refresh, kycCase }: StepProps) {
  const initial = useMemo(() => {
    try {
      return kycCase?.intake_profile ? JSON.parse(kycCase.intake_profile) : {};
    } catch {
      return {};
    }
  }, [kycCase?.intake_profile]);

  const [firstName, setFirstName] = useState(initial.first_name ?? "");
  const [lastName, setLastName] = useState(initial.last_name ?? "");
  const [dob, setDob] = useState(initial.dob ?? "");
  const [nationality, setNationality] = useState(initial.nationality ?? "");

  const mutation = useMutation({
    mutationFn: async () => {
      const c = await ensureCase();
      // intake_profile is capped at 80 chars by the backend contract — keep it terse.
      const profile = JSON.stringify({
        first_name: firstName,
        last_name: lastName,
        dob,
        nationality,
      });
      return patchKycDraft(c.kyc_case_id, {
        expected_version: c.version,
        intake_profile: profile,
      });
    },
    onSuccess: () => {
      toast.success("Personal information saved");
      refresh();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to save"),
  });

  const profileLen = JSON.stringify({ first_name: firstName, last_name: lastName, dob, nationality }).length;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Personal Information</h2>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="kyc-fn">First Name</Label>
          <Input id="kyc-fn" value={firstName} onChange={(e) => setFirstName(e.target.value)} data-testid="kyc-first-name" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kyc-ln">Last Name</Label>
          <Input id="kyc-ln" value={lastName} onChange={(e) => setLastName(e.target.value)} data-testid="kyc-last-name" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kyc-dob">Date of Birth</Label>
          <Input id="kyc-dob" type="date" value={dob} onChange={(e) => setDob(e.target.value)} data-testid="kyc-dob" />
        </div>
        <div className="space-y-1">
          <Label htmlFor="kyc-nat">Nationality</Label>
          <Input
            id="kyc-nat"
            value={nationality}
            onChange={(e) => setNationality(e.target.value)}
            placeholder="e.g. US"
            maxLength={3}
            data-testid="kyc-nationality"
          />
        </div>
      </div>
      {profileLen > 80 ? (
        <p className="text-xs text-amber-600">
          Entry too long for storage ({profileLen}/80). Please shorten your details.
        </p>
      ) : null}
      <Button
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending || !firstName || !lastName || profileLen > 80}
        data-testid="kyc-save-personal"
      >
        {mutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
        Save &amp; Continue
      </Button>
    </div>
  );
}

// ─── Shared upload helper UI ─────────────────────────────────────────────────

function FileAttachControl({
  ensureCase,
  refresh,
  fileType,
  label,
  facing,
  accept = "image/*",
  attached,
  useCamera = false,
}: StepProps & {
  fileType: KycSelfServiceFileType;
  label: string;
  facing?: "user" | "environment";
  accept?: string;
  attached: boolean;
  useCamera?: boolean;
}) {
  const [busy, setBusy] = useState(false);

  const handleFile = async (file: File) => {
    setBusy(true);
    try {
      const c = await ensureCase();
      await uploadAndAttachKycFile({
        caseId: c.kyc_case_id,
        expectedVersion: c.version,
        fileType,
        file,
      });
      toast.success(`${label} uploaded`);
      refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.detail : `Failed to upload ${label}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2 rounded border p-4" data-testid={`kyc-upload-${fileType}`}>
      <div className="flex items-center gap-2">
        {attached ? (
          <CheckCircle2 className="h-4 w-4 text-green-500" />
        ) : (
          <Circle className="h-4 w-4 text-gray-400" />
        )}
        <p className="text-sm font-medium">{label}</p>
      </div>
      {useCamera ? (
        <CameraCapture onCapture={handleFile} facing={facing} accept={accept} disabled={busy} />
      ) : (
        <input
          type="file"
          accept={accept}
          data-testid={`kyc-file-input-${fileType}`}
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void handleFile(f);
          }}
          className="block text-xs"
        />
      )}
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
    </div>
  );
}

// ─── Step 2: ID Upload ───────────────────────────────────────────────────────

function IdUploadStep({ ensureCase, refresh, kycCase }: StepProps) {
  const [docType, setDocType] = useState("passport");
  const showBack = docType !== "passport";

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Identity Document</h2>
      <div className="space-y-1">
        <Label htmlFor="kyc-doctype">Document Type</Label>
        <select
          id="kyc-doctype"
          value={docType}
          onChange={(e) => setDocType(e.target.value)}
          data-testid="kyc-doc-type"
          className="block w-full rounded border bg-background p-2 text-sm"
        >
          {DOC_TYPES.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
      </div>
      <FileAttachControl
        ensureCase={ensureCase}
        refresh={refresh}
        fileType="id_front"
        label="Front of Document"
        facing="environment"
        attached={hasFileType(kycCase, "id_front")}
      />
      {showBack ? (
        <FileAttachControl
          ensureCase={ensureCase}
          refresh={refresh}
          fileType="id_back"
          label="Back of Document"
          facing="environment"
          attached={hasFileType(kycCase, "id_back")}
        />
      ) : null}
    </div>
  );
}

// ─── Step 3: Selfie ──────────────────────────────────────────────────────────

function SelfieStep({ ensureCase, refresh, kycCase }: StepProps) {
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Selfie Verification</h2>
      <p className="text-sm text-muted-foreground">
        Take a selfie or upload a clear photo of your face.
      </p>
      <FileAttachControl
        ensureCase={ensureCase}
        refresh={refresh}
        fileType="selfie"
        label="Selfie"
        facing="user"
        attached={hasFileType(kycCase, "selfie")}
        useCamera
      />
    </div>
  );
}

// ─── Step 4: Proof of Address ────────────────────────────────────────────────

function AddressProofStep({ ensureCase, refresh, kycCase }: StepProps) {
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Proof of Address</h2>
      <p className="text-sm text-muted-foreground">
        Upload a utility bill, bank statement, or government letter (PDF or image).
      </p>
      <FileAttachControl
        ensureCase={ensureCase}
        refresh={refresh}
        fileType="proof_of_address"
        label="Proof of Address Document"
        accept="image/*,.pdf"
        attached={hasFileType(kycCase, "proof_of_address")}
      />
    </div>
  );
}

// ─── Step 5: Questionnaire ───────────────────────────────────────────────────

function QuestionnaireStep({
  caseId,
  ensureCase,
  refresh,
}: {
  caseId: string | null;
  ensureCase: () => Promise<KycSelfServiceCase>;
  refresh: () => void;
}) {
  const [slug, setSlug] = useState("kyc-intake");
  const statusQuery = useQuery({
    queryKey: ["kyc", "questionnaire-status", caseId],
    queryFn: () => getKycQuestionnaireStatus(caseId as string),
    enabled: !!caseId,
  });
  const status = statusQuery.data?.questionnaire;

  const startMutation = useMutation({
    mutationFn: async () => {
      const c = await ensureCase();
      return startKycQuestionnaire(c.kyc_case_id, { published_slug: slug });
    },
    onSuccess: () => {
      toast.success("Questionnaire started");
      statusQuery.refetch();
      refresh();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to start questionnaire"),
  });

  return (
    <div className="space-y-4" data-testid="kyc-questionnaire-step">
      <h2 className="text-lg font-semibold">Questionnaire</h2>
      {status?.submitted ? (
        <p className="flex items-center gap-2 text-sm text-green-600">
          <CheckCircle2 className="h-4 w-4" /> Questionnaire completed.
        </p>
      ) : status?.questionnaire_bound ? (
        <p className="text-sm text-muted-foreground">
          Questionnaire in progress. Complete it in the Questionnaires section, then return here.
        </p>
      ) : (
        <div className="space-y-2">
          <Label htmlFor="kyc-qn-slug">Questionnaire</Label>
          <Input
            id="kyc-qn-slug"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            data-testid="kyc-qn-slug"
          />
          <Button
            onClick={() => startMutation.mutate()}
            disabled={startMutation.isPending || !slug}
            data-testid="kyc-start-questionnaire"
          >
            {startMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Start Questionnaire
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Step 6: Consent & Signature ─────────────────────────────────────────────

function ConsentStep({
  caseId,
  refresh,
}: {
  caseId: string | null;
  ensureCase: () => Promise<KycSelfServiceCase>;
  refresh: () => void;
  kycCase?: KycSelfServiceCase;
}) {
  const statusQuery = useQuery({
    queryKey: ["kyc", "signature-status", caseId],
    queryFn: () => getKycSignatureStatus(caseId as string),
    enabled: !!caseId,
  });
  const status = statusQuery.data?.signature;

  return (
    <div className="space-y-4" data-testid="kyc-consent-step">
      <h2 className="text-lg font-semibold">Consent &amp; Signature</h2>
      {status?.completed ? (
        <p className="flex items-center gap-2 text-sm text-green-600">
          <CheckCircle2 className="h-4 w-4" /> Consent form signed.
        </p>
      ) : status?.packet_id ? (
        <div className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            A consent document has been prepared. Sign it to continue.
          </p>
          <Button asChild variant="outline">
            <a href="/signing" data-testid="kyc-goto-signing">Go to Document Signing</a>
          </Button>
        </div>
      ) : (
        <div className="space-y-2 text-sm">
          <p className="text-muted-foreground">
            Prepare and sign the consent form on the Document Signing page, then link the signed
            packet to your case.
          </p>
          <Button asChild variant="outline">
            <a href="/signing" data-testid="kyc-goto-signing">Go to Document Signing</a>
          </Button>
        </div>
      )}
      <Button variant="ghost" size="sm" onClick={() => { statusQuery.refetch(); refresh(); }}>
        Refresh status
      </Button>
    </div>
  );
}

// ─── Step 7: Review & Submit ─────────────────────────────────────────────────

function ReviewSubmitStep({
  caseId,
  kycCase,
  readyToSubmit,
  checks,
  missing,
  onSubmitted,
  refresh,
}: {
  caseId: string | null;
  kycCase?: KycSelfServiceCase;
  readyToSubmit: boolean;
  checks: Record<string, boolean>;
  missing: string[];
  onSubmitted: () => void;
  refresh: () => void;
}) {
  const submitMutation = useMutation({
    mutationFn: async () => {
      if (!caseId || !kycCase) throw new ApiError(400, "No case to submit");
      return submitKycCase(caseId, { expected_version: kycCase.version });
    },
    onSuccess: () => {
      toast.success("Application submitted for review");
      refresh();
      onSubmitted();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Submit failed"),
  });

  const checkEntries = Object.entries(checks);

  return (
    <div className="space-y-4" data-testid="kyc-review-step">
      <h2 className="text-lg font-semibold">Review &amp; Submit</h2>
      <ul className="space-y-2">
        {checkEntries.length === 0 ? (
          <li className="text-sm text-muted-foreground">Complete the earlier steps to see your checklist.</li>
        ) : (
          checkEntries.map(([key, ok]) => (
            <li key={key} className="flex items-center gap-2 text-sm" data-testid={`kyc-check-${key}`}>
              {ok ? (
                <CheckCircle2 className="h-4 w-4 text-green-500" />
              ) : (
                <XCircle className="h-4 w-4 text-red-500" />
              )}
              <span className="capitalize">{key.replace(/_/g, " ")}</span>
            </li>
          ))
        )}
      </ul>

      <div className="rounded border p-3 text-sm">
        <p className="font-medium">Attached documents</p>
        <ul className="mt-1 list-inside list-disc text-muted-foreground">
          {(kycCase?.files ?? []).length === 0 ? (
            <li>None yet</li>
          ) : (
            kycCase?.files.map((f) => <li key={f.type}>{f.type.replace(/_/g, " ")}</li>)
          )}
        </ul>
      </div>

      {!readyToSubmit && missing.length > 0 ? (
        <p className="text-xs text-amber-600" data-testid="kyc-missing">
          Missing: {missing.join(", ")}
        </p>
      ) : null}

      <Button
        onClick={() => submitMutation.mutate()}
        disabled={!readyToSubmit || submitMutation.isPending}
        data-testid="kyc-submit"
      >
        {submitMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
        Submit Application
      </Button>
    </div>
  );
}

// ─── Help / FAQ ──────────────────────────────────────────────────────────────

const FAQ = [
  {
    q: "What documents are accepted?",
    a: "A government-issued ID (passport, national ID, driving license, or residence permit), a selfie, and a recent proof of address such as a utility bill or bank statement.",
  },
  {
    q: "How long does verification take?",
    a: "Most applications are reviewed within 24 hours. The status page shows a live estimate.",
  },
  {
    q: "Why was my application rejected?",
    a: "Common reasons include blurry documents, mismatched details, or expired IDs. You can start a new application after a rejection.",
  },
  {
    q: "Can I reapply after rejection?",
    a: "Yes. Start a new application from this page and resubmit corrected documents.",
  },
  {
    q: "How is my data protected?",
    a: "Documents are stored encrypted and are only accessible to authorized reviewers.",
  },
];

function KycHelp() {
  return (
    <div className="mt-10" data-testid="kyc-help">
      <h2 className="mb-3 text-lg font-semibold">Frequently Asked Questions</h2>
      <div className="space-y-2">
        {FAQ.map((item) => (
          <details key={item.q} className="rounded border p-3">
            <summary className="cursor-pointer text-sm font-medium">{item.q}</summary>
            <p className="mt-2 text-sm text-muted-foreground">{item.a}</p>
          </details>
        ))}
      </div>
    </div>
  );
}
