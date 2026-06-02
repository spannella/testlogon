import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Clock, ShieldCheck, Upload, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/api/client";
import {
  listKycCases,
  getKycEstimatedWait,
  uploadAndAttachKycFile,
} from "@/api/endpoints/kyc";
import type { KycSelfServiceCase, KycCaseStatus } from "@/api/types";

const ACTIVE_STATUSES: KycCaseStatus[] = ["submitted", "under_review", "needs_more_info"];
const HISTORICAL_STATUSES: KycCaseStatus[] = ["approved", "rejected", "expired"];

const TIMELINE: KycCaseStatus[] = ["submitted", "under_review", "approved"];

function statusBadgeClass(status: string): string {
  switch (status) {
    case "approved":
      return "bg-green-100 text-green-800";
    case "rejected":
      return "bg-red-100 text-red-800";
    case "needs_more_info":
      return "bg-yellow-100 text-yellow-800";
    case "expired":
      return "bg-gray-200 text-gray-700";
    case "under_review":
      return "bg-blue-100 text-blue-800";
    default:
      return "bg-slate-100 text-slate-800";
  }
}

function StatusTimeline({ status }: { status: KycCaseStatus }) {
  const currentIdx =
    status === "rejected"
      ? TIMELINE.indexOf("under_review")
      : Math.max(0, TIMELINE.indexOf(status === "needs_more_info" ? "under_review" : status));
  return (
    <div className="flex items-center gap-2" data-testid="kyc-timeline">
      {TIMELINE.map((stage, i) => {
        const reached = i <= currentIdx;
        return (
          <div key={stage} className="flex items-center gap-2">
            <div className="flex flex-col items-center">
              <div
                className={`h-3 w-3 rounded-full ${reached ? "bg-blue-600" : "bg-gray-300"}`}
                data-testid={`kyc-timeline-dot-${stage}`}
              />
              <span className="mt-1 text-[10px] capitalize text-muted-foreground">
                {stage.replace(/_/g, " ")}
              </span>
            </div>
            {i < TIMELINE.length - 1 ? (
              <div className={`h-0.5 w-8 ${i < currentIdx ? "bg-blue-600" : "bg-gray-300"}`} />
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function EstimatedWaitCard() {
  const waitQuery = useQuery({
    queryKey: ["kyc", "estimated-wait"],
    queryFn: getKycEstimatedWait,
  });
  const wait = waitQuery.data?.estimated_wait;
  return (
    <div className="flex items-start gap-2 rounded border bg-muted/40 p-3 text-sm" data-testid="kyc-estimated-wait">
      <Clock className="mt-0.5 h-4 w-4 text-blue-600" />
      <div>
        <p className="font-medium">Estimated review time</p>
        {waitQuery.isLoading ? (
          <p className="text-muted-foreground">Calculating…</p>
        ) : wait ? (
          <p className="text-muted-foreground">
            ~{wait.estimated_hours} hour{wait.estimated_hours === 1 ? "" : "s"} — {wait.message}
          </p>
        ) : (
          <p className="text-muted-foreground">Unavailable right now.</p>
        )}
      </div>
    </div>
  );
}

function ReuploadControl({ kycCase }: { kycCase: KycSelfServiceCase }) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const mutation = useMutation({
    mutationFn: async (file: File) =>
      uploadAndAttachKycFile({
        caseId: kycCase.kyc_case_id,
        expectedVersion: kycCase.version,
        fileType: "proof_of_address",
        file,
      }),
    onSuccess: () => {
      toast.success("Document re-uploaded");
      qc.invalidateQueries({ queryKey: ["kyc", "cases"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Re-upload failed"),
    onSettled: () => setBusy(false),
  });
  return (
    <div className="space-y-1" data-testid="kyc-reupload">
      <p className="flex items-center gap-1 text-sm font-medium">
        <Upload className="h-4 w-4" /> Update your documents
      </p>
      <input
        type="file"
        accept="image/*,.pdf"
        data-testid="kyc-reupload-input"
        disabled={busy}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) {
            setBusy(true);
            mutation.mutate(f);
          }
        }}
        className="block text-xs"
      />
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
    </div>
  );
}

function ActiveCaseCard({ kycCase }: { kycCase: KycSelfServiceCase }) {
  return (
    <Card className="mb-4" data-testid="kyc-active-case">
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-base">
          <span>Verification #{kycCase.kyc_case_id.slice(0, 12)}</span>
          <Badge className={statusBadgeClass(kycCase.status)}>{kycCase.status.replace(/_/g, " ")}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <StatusTimeline status={kycCase.status} />
        <EstimatedWaitCard />
        {kycCase.status === "needs_more_info" ? (
          <div className="space-y-3 rounded border border-yellow-300 bg-yellow-50 p-3">
            <p className="text-sm font-medium text-yellow-900">
              Additional information requested. Please update your documents.
            </p>
            {kycCase.review?.reason_codes && kycCase.review.reason_codes.length > 0 ? (
              <p className="text-xs text-yellow-800">Requested: {kycCase.review.reason_codes.join(", ")}</p>
            ) : null}
            <ReuploadControl kycCase={kycCase} />
            <Button asChild size="sm" variant="outline">
              <Link to="/kyc">Open Wizard</Link>
            </Button>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function HistoricalCaseCard({ kycCase }: { kycCase: KycSelfServiceCase }) {
  return (
    <Card className="mb-3" data-testid="kyc-historical-case">
      <CardContent className="flex items-center justify-between p-4">
        <div>
          <p className="text-sm font-medium">#{kycCase.kyc_case_id.slice(0, 12)}</p>
          {kycCase.review?.decided_at ? (
            <p className="text-xs text-muted-foreground">
              Decided {new Date(kycCase.review.decided_at * 1000).toLocaleDateString()}
            </p>
          ) : null}
          {kycCase.status === "rejected" && kycCase.review?.reason_codes?.length ? (
            <p className="text-xs text-red-700">Reasons: {kycCase.review.reason_codes.join(", ")}</p>
          ) : null}
        </div>
        <div className="flex items-center gap-3">
          <Badge className={statusBadgeClass(kycCase.status)}>{kycCase.status}</Badge>
          {kycCase.status !== "approved" ? (
            <Button asChild size="sm" variant="ghost">
              <Link to="/kyc">Start New</Link>
            </Button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

export default function KycStatusPage() {
  const casesQuery = useQuery({
    queryKey: ["kyc", "cases"],
    queryFn: listKycCases,
  });

  const items = casesQuery.data?.items ?? [];
  const activeCases = items.filter((c) => ACTIVE_STATUSES.includes(c.status));
  const historicalCases = items.filter((c) => HISTORICAL_STATUSES.includes(c.status));
  const draftCases = items.filter((c) => c.status === "draft");

  return (
    <div className="mx-auto max-w-3xl px-4 py-8" data-testid="kyc-status-page">
      <div className="mb-6 flex items-center gap-2">
        <ShieldCheck className="h-6 w-6 text-blue-600" />
        <h1 className="text-2xl font-bold">Verification Status</h1>
      </div>

      {casesQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          {activeCases.length > 0 ? (
            activeCases.map((c) => <ActiveCaseCard key={c.kyc_case_id} kycCase={c} />)
          ) : (
            <Card className="mb-6" data-testid="kyc-no-active">
              <CardContent className="p-6 text-center text-sm text-muted-foreground">
                {draftCases.length > 0
                  ? "You have a verification in progress."
                  : "No active verification."}{" "}
                <Link to="/kyc" className="text-blue-600 underline">
                  {draftCases.length > 0 ? "Continue" : "Start verification"}
                </Link>
              </CardContent>
            </Card>
          )}

          <h2 className="mb-3 mt-8 text-xl font-semibold">Previous Applications</h2>
          {historicalCases.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="kyc-no-history">
              No previous applications.
            </p>
          ) : (
            historicalCases.map((c) => <HistoricalCaseCard key={c.kyc_case_id} kycCase={c} />)
          )}
        </>
      )}
    </div>
  );
}
