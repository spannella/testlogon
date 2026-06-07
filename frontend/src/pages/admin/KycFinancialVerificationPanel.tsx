import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  kycProofOfFundsApi,
  type ProofOfFundsSubmission,
} from "@/api/endpoints/kycProofOfFunds";
import { VerificationStateBadge } from "@/components/shared/VerificationStateBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(ts: number | null | undefined): string {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function formatAmount(
  cents: number | null | undefined,
  currency: string | null | undefined,
): string {
  if (cents == null) return "--";
  const amount = (cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  return `${(currency ?? "USD").toUpperCase()} ${amount}`;
}

/** Risk contribution is positive = increases risk (red), negative = lowers risk (green). */
function RiskContributionBadge({ value }: { value: number }) {
  if (value > 0) {
    return (
      <Badge variant="destructive" data-testid="risk-contribution">
        +{value}
      </Badge>
    );
  }
  if (value < 0) {
    return (
      <Badge
        variant="default"
        className="bg-green-600 hover:bg-green-600"
        data-testid="risk-contribution"
      >
        {value}
      </Badge>
    );
  }
  return (
    <Badge variant="outline" data-testid="risk-contribution">
      0
    </Badge>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const variant =
    score >= 70 ? "default" : score >= 40 ? "secondary" : "destructive";
  return (
    <Badge variant={variant} data-testid="pof-score">
      {score}
    </Badge>
  );
}

// ─── Adjudication actions ──────────────────────────────────────────────────────

type Decision = "verified" | "rejected" | "needs_more_info";

const DECISION_LABELS: Record<Decision, string> = {
  verified: "Verify",
  rejected: "Reject",
  needs_more_info: "Request Info",
};

const ADJUDICABLE_STATUSES = ["submitted", "under_review", "needs_more_info"];

function SubmissionRow({
  submission,
  userSub,
}: {
  submission: ProofOfFundsSubmission;
  userSub: string;
}) {
  const queryClient = useQueryClient();
  const [dialogDecision, setDialogDecision] = useState<Decision | null>(null);
  const [reviewerNote, setReviewerNote] = useState("");

  const adjudicateMut = useMutation({
    mutationFn: (decision: Decision) =>
      kycProofOfFundsApi.adjudicate(submission.submission_id, {
        decision,
        reviewer_note: reviewerNote.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Submission adjudicated.");
      queryClient.invalidateQueries({
        queryKey: ["kyc-proof-of-funds-admin", userSub],
      });
      setDialogDecision(null);
      setReviewerNote("");
    },
    onError: () => {
      toast.error("Failed to adjudicate submission.");
    },
  });

  const canAdjudicate = ADJUDICABLE_STATUSES.includes(submission.status);

  return (
    <>
      <tr className="border-b last:border-0" data-testid="pof-submission-row">
        <td className="py-2 pr-4 text-muted-foreground">
          {formatDate(submission.created_at)}
        </td>
        <td className="py-2 pr-4 capitalize" data-testid="pof-source-category">
          {submission.source_category?.replace(/_/g, " ") ?? "--"}
        </td>
        <td className="py-2 pr-4" data-testid="pof-declared-amount">
          {formatAmount(submission.declared_amount_cents, submission.currency)}
        </td>
        <td className="py-2 pr-4">
          <ScoreBadge score={submission.score} />
        </td>
        <td className="py-2 pr-4">
          <VerificationStateBadge state={submission.status} />
        </td>
        <td className="py-2 pr-4">
          <RiskContributionBadge value={submission.risk_contribution} />
        </td>
        <td className="py-2">
          {canAdjudicate ? (
            <div className="flex flex-wrap gap-1">
              {(Object.keys(DECISION_LABELS) as Decision[]).map((d) => (
                <Button
                  key={d}
                  size="sm"
                  variant={d === "rejected" ? "destructive" : "outline"}
                  onClick={() => {
                    setReviewerNote(submission.reviewer_note ?? "");
                    setDialogDecision(d);
                  }}
                  data-testid={`pof-adjudicate-${d}`}
                >
                  {DECISION_LABELS[d]}
                </Button>
              ))}
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">
              Adjudicated
              {submission.reviewer_sub ? ` by ${submission.reviewer_sub}` : ""}
            </span>
          )}
        </td>
      </tr>

      <Dialog
        open={dialogDecision !== null}
        onOpenChange={(open) => {
          if (!open) setDialogDecision(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {dialogDecision ? DECISION_LABELS[dialogDecision] : ""} proof of funds
            </DialogTitle>
            <DialogDescription>
              Record an adjudication decision for this proof-of-funds submission.
              This updates the applicant&apos;s financial verification status and
              risk contribution.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="pof-reviewer-note">Reviewer note</Label>
            <Textarea
              id="pof-reviewer-note"
              placeholder="Add an optional note..."
              value={reviewerNote}
              onChange={(e) => setReviewerNote(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogDecision(null)}>
              Cancel
            </Button>
            <Button
              variant={dialogDecision === "rejected" ? "destructive" : "default"}
              disabled={adjudicateMut.isPending || dialogDecision === null}
              onClick={() => dialogDecision && adjudicateMut.mutate(dialogDecision)}
            >
              {adjudicateMut.isPending
                ? "Saving..."
                : dialogDecision
                  ? `Confirm ${DECISION_LABELS[dialogDecision]}`
                  : "Confirm"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// ─── Panel ─────────────────────────────────────────────────────────────────────

interface KycFinancialVerificationPanelProps {
  userSub: string;
}

export function KycFinancialVerificationPanel({
  userSub,
}: KycFinancialVerificationPanelProps) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["kyc-proof-of-funds-admin", userSub],
    queryFn: () => kycProofOfFundsApi.getAdminSubmissionsForUser(userSub),
    enabled: !!userSub,
  });

  if (isLoading) {
    return (
      <p className="py-4 text-sm text-muted-foreground">
        Loading financial verification...
      </p>
    );
  }

  if (isError) {
    return (
      <p className="py-4 text-sm text-destructive">
        Failed to load proof-of-funds submissions.
      </p>
    );
  }

  const submissions: ProofOfFundsSubmission[] = data?.submissions ?? [];

  // Aggregate: latest status + total active risk contribution.
  const activeRisk = submissions.reduce(
    (sum, s) => sum + (s.risk_contribution ?? 0),
    0,
  );
  const latest = submissions[0];

  if (submissions.length === 0) {
    return (
      <Card data-testid="financial-verification-panel">
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          No proof-of-funds submissions for this user.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-testid="financial-verification-panel">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Financial Verification</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary row */}
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Submissions</span>
            <Badge variant="secondary" data-testid="pof-total-count">
              {submissions.length}
            </Badge>
          </div>
          {latest && (
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Latest</span>
              <VerificationStateBadge state={latest.status} />
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Active risk contribution</span>
            <RiskContributionBadge value={activeRisk} />
          </div>
        </div>

        {/* Submissions table */}
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b">
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Date
                </th>
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Source
                </th>
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Declared amount
                </th>
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Score
                </th>
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Status
                </th>
                <th className="py-1 pr-4 text-left font-medium text-muted-foreground">
                  Risk
                </th>
                <th className="py-1 text-left font-medium text-muted-foreground">
                  Adjudicate
                </th>
              </tr>
            </thead>
            <tbody>
              {submissions.map((s) => (
                <SubmissionRow
                  key={s.submission_id}
                  submission={s}
                  userSub={userSub}
                />
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

export default KycFinancialVerificationPanel;
