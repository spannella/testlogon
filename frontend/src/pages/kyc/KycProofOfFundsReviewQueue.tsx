import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  kycProofOfFundsApi,
  ProofOfFundsSubmission,
} from "@/api/endpoints/kycProofOfFunds";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const STATUS_TABS = [
  "pending",
  "needs_more_info",
  "verified",
  "rejected",
  "expired",
] as const;

type PofStatus = (typeof STATUS_TABS)[number];

const STATUS_LABELS: Record<PofStatus, string> = {
  pending: "Pending",
  needs_more_info: "Needs more info",
  verified: "Verified",
  rejected: "Rejected",
  expired: "Expired",
};

const STATUS_VARIANTS: Record<
  string,
  "default" | "secondary" | "destructive" | "outline"
> = {
  pending: "secondary",
  needs_more_info: "secondary",
  verified: "default",
  rejected: "destructive",
  expired: "outline",
};

type Decision = "verified" | "rejected" | "needs_more_info";

const DECISIONS: Decision[] = ["verified", "needs_more_info", "rejected"];

function formatAmount(cents?: number | null, currency?: string | null): string {
  if (cents === null || cents === undefined) return "—";
  return `${(cents / 100).toFixed(2)} ${currency || "USD"}`;
}

function formatDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function riskVariant(
  risk: number,
): "default" | "secondary" | "destructive" | "outline" {
  if (risk > 0) return "destructive";
  if (risk < 0) return "default";
  return "secondary";
}

function SubmissionRow({
  row,
  onAdjudicate,
}: {
  row: ProofOfFundsSubmission;
  onAdjudicate: (row: ProofOfFundsSubmission) => void;
}) {
  return (
    <div
      className="rounded-md border p-3"
      data-testid="proof-of-funds-row"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="space-y-1">
          <div className="font-medium">{row.source_category ?? "—"}</div>
          <div className="text-xs text-muted-foreground">
            {row.user_sub} · {row.submission_id.slice(0, 12)}…
          </div>
          <div className="text-sm">
            {formatAmount(row.declared_amount_cents, row.currency)}
          </div>
          <div className="text-xs text-muted-foreground">
            Submitted {formatDate(row.created_at)}
          </div>
          {row.note && (
            <div className="text-xs text-muted-foreground">Note: {row.note}</div>
          )}
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Badge variant={STATUS_VARIANTS[row.status] ?? "outline"}>
              {STATUS_LABELS[row.status as PofStatus] ?? row.status}
            </Badge>
            <Badge variant="outline" data-testid="proof-of-funds-score">
              score {row.score}
            </Badge>
            <Badge variant={riskVariant(row.risk_contribution)}>
              risk {row.risk_contribution > 0 ? "+" : ""}
              {row.risk_contribution}
            </Badge>
          </div>
          <Button
            size="sm"
            onClick={() => onAdjudicate(row)}
            data-testid="proof-of-funds-adjudicate"
          >
            Adjudicate
          </Button>
        </div>
      </div>
      {row.reviewer_sub && (
        <div className="mt-2 text-xs text-muted-foreground">
          Reviewed by {row.reviewer_sub} · {formatDate(row.reviewed_at)}
          {row.reviewer_note ? ` · ${row.reviewer_note}` : ""}
        </div>
      )}
    </div>
  );
}

function AdjudicateDialog({
  row,
  onClose,
  onAdjudicated,
}: {
  row: ProofOfFundsSubmission | null;
  onClose: () => void;
  onAdjudicated: () => void;
}) {
  const [decision, setDecision] = useState<Decision>("verified");
  const [note, setNote] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      kycProofOfFundsApi.adjudicate(row!.submission_id, {
        decision,
        reviewer_note: note || undefined,
      }),
    onSuccess: () => {
      onAdjudicated();
      onClose();
    },
  });

  return (
    <Dialog open={!!row} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Adjudicate Proof of Funds</DialogTitle>
          <DialogDescription>
            {row
              ? `${row.source_category ?? "—"} · ${formatAmount(
                  row.declared_amount_cents,
                  row.currency,
                )} · score ${row.score}`
              : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {DECISIONS.map((d) => (
              <Button
                key={d}
                size="sm"
                variant={decision === d ? "default" : "outline"}
                onClick={() => setDecision(d)}
                data-testid={`decision-${d}`}
              >
                {STATUS_LABELS[d]}
              </Button>
            ))}
          </div>
          <Textarea
            placeholder="Reviewer note (optional)…"
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
            data-testid="reviewer-note"
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={mutation.isPending}
            onClick={() => mutation.mutate()}
            data-testid="submit-adjudication"
          >
            Submit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function KycProofOfFundsReviewQueue() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<PofStatus>("pending");
  const [adjudicating, setAdjudicating] =
    useState<ProofOfFundsSubmission | null>(null);

  const queueQuery = useQuery({
    queryKey: ["kyc", "proof-of-funds", "by-status", status],
    queryFn: () => kycProofOfFundsApi.listByStatus(status),
  });

  const submissions = queueQuery.data?.submissions ?? [];

  const onAdjudicated = () => {
    queryClient.invalidateQueries({
      queryKey: ["kyc", "proof-of-funds", "by-status"],
    });
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Proof of Funds Review Queue</h1>
        <p className="text-sm text-muted-foreground">
          Review source-of-funds submissions, inspect declared amounts and risk
          contribution, and adjudicate each submission.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        {STATUS_TABS.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={s === status ? "default" : "outline"}
            onClick={() => setStatus(s)}
            data-testid={`status-${s}`}
          >
            {STATUS_LABELS[s]}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{STATUS_LABELS[status]} submissions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {queueQuery.isLoading && <p className="text-sm">Loading…</p>}
          {queueQuery.isError && (
            <p className="text-sm text-destructive">
              Failed to load submissions.
            </p>
          )}
          {!queueQuery.isLoading && submissions.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No submissions in this queue.
            </p>
          )}
          {submissions.map((row) => (
            <SubmissionRow
              key={row.submission_id}
              row={row}
              onAdjudicate={setAdjudicating}
            />
          ))}
        </CardContent>
      </Card>

      <AdjudicateDialog
        row={adjudicating}
        onClose={() => setAdjudicating(null)}
        onAdjudicated={onAdjudicated}
      />
    </div>
  );
}

export default KycProofOfFundsReviewQueue;
