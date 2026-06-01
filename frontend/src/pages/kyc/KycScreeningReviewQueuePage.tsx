import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  adminGetKycCaseScreening,
  listKycScreeningPending,
  rescreenKycCase,
  reviewKycScreeningMatch,
  runKycScreening,
} from "@/api/endpoints/kycScreening";
import type {
  KycScreeningDecision,
  KycScreeningResultOut,
  KycScreeningResultStatus,
  KycScreenType,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const SCREEN_TYPE_LABELS: Record<KycScreenType, string> = {
  sanctions_ofac: "OFAC SDN",
  sanctions_eu: "EU Sanctions",
  sanctions_un: "UN Sanctions",
  pep_check: "PEP Check",
  adverse_media: "Adverse Media",
};

const RESULT_VARIANTS: Record<
  KycScreeningResultStatus,
  "default" | "secondary" | "destructive" | "outline"
> = {
  clear: "default",
  potential_match: "secondary",
  confirmed_match: "destructive",
};

const RESULT_LABELS: Record<KycScreeningResultStatus, string> = {
  clear: "Clear",
  potential_match: "Potential Match",
  confirmed_match: "Confirmed Match",
};

function ResultRow({
  row,
  onReview,
}: {
  row: KycScreeningResultOut;
  onReview: (row: KycScreeningResultOut) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const match = row.match_details[0];
  const isMatch = row.result !== "clear";
  return (
    <div className="rounded-md border p-3" data-testid="screening-row">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="font-medium">{SCREEN_TYPE_LABELS[row.screen_type]}</div>
        <div className="flex items-center gap-2">
          <Badge variant={RESULT_VARIANTS[row.result]} data-testid="screening-result-badge">
            {RESULT_LABELS[row.result]}
            {isMatch && match ? ` (${Number(match.match_score).toFixed(2)})` : ""}
          </Badge>
          {row.review_decision && (
            <Badge variant="outline" data-testid="screening-review-badge">
              Reviewed - {row.review_decision}
            </Badge>
          )}
          {isMatch && (
            <Button size="sm" variant="ghost" onClick={() => setExpanded((v) => !v)}>
              {expanded ? "Hide" : "Details"}
            </Button>
          )}
          {isMatch && !row.review_decision && row.screen_key && (
            <Button size="sm" onClick={() => onReview(row)}>
              Review
            </Button>
          )}
        </div>
      </div>
      {expanded && match && (
        <div className="mt-2 space-y-1 rounded-md bg-muted/40 p-2 text-sm">
          <div>List: {match.list_name}</div>
          <div>Matched: {match.matched_name}</div>
          {match.matched_dob && <div>DOB: {match.matched_dob}</div>}
          <div>Score: {Number(match.match_score).toFixed(2)}</div>
          <div>
            Entity: {match.entity_id} ({match.entity_type})
          </div>
          {match.listed_since && <div>Listed since: {match.listed_since}</div>}
          {match.source_url && (
            <a
              className="text-primary underline"
              href={match.source_url}
              target="_blank"
              rel="noreferrer"
            >
              View Source
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function ReviewDialog({
  row,
  onClose,
  onReviewed,
}: {
  row: KycScreeningResultOut | null;
  onClose: () => void;
  onReviewed: () => void;
}) {
  const [decision, setDecision] = useState<KycScreeningDecision>("clear");
  const [note, setNote] = useState("");
  const mutation = useMutation({
    mutationFn: () =>
      reviewKycScreeningMatch(row!.case_id ?? "", row!.screen_key ?? "", {
        decision,
        note,
      }),
    onSuccess: () => {
      onReviewed();
      onClose();
    },
  });
  return (
    <Dialog open={!!row} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Review Screening Match</DialogTitle>
          <DialogDescription>
            {row ? `${SCREEN_TYPE_LABELS[row.screen_type]} · ${row.match_details[0]?.matched_name ?? ""}` : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {(["clear", "confirm", "escalate"] as KycScreeningDecision[]).map((d) => (
              <Button
                key={d}
                size="sm"
                variant={decision === d ? "default" : "outline"}
                onClick={() => setDecision(d)}
                data-testid={`decision-${d}`}
              >
                {d}
              </Button>
            ))}
          </div>
          <Textarea
            placeholder="Provide justification..."
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
            data-testid="review-note"
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={mutation.isPending || note.trim().length === 0}
            onClick={() => mutation.mutate()}
            data-testid="submit-review"
          >
            Submit Review
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function KycScreeningReviewQueuePage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<KycScreeningResultStatus>("potential_match");
  const [typeFilter, setTypeFilter] = useState<"all" | KycScreenType>("all");
  const [reviewing, setReviewing] = useState<KycScreeningResultOut | null>(null);

  // case lookup / run controls
  const [caseId, setCaseId] = useState("");
  const [runUserSub, setRunUserSub] = useState("");
  const [activeCaseId, setActiveCaseId] = useState("");

  const pendingQuery = useQuery({
    queryKey: ["kyc", "screening", "pending", statusFilter],
    queryFn: () => listKycScreeningPending(statusFilter),
  });

  const caseQuery = useQuery({
    queryKey: ["kyc", "screening", "case", activeCaseId],
    queryFn: () => adminGetKycCaseScreening(activeCaseId),
    enabled: !!activeCaseId,
  });

  const runMutation = useMutation({
    mutationFn: () => runKycScreening({ user_sub: runUserSub, case_id: caseId || undefined }),
    onSuccess: (resp) => {
      setActiveCaseId(resp.case_id);
      queryClient.invalidateQueries({ queryKey: ["kyc", "screening", "pending"] });
    },
  });

  const rescreenMutation = useMutation({
    mutationFn: () => rescreenKycCase(activeCaseId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["kyc", "screening", "case", activeCaseId] });
      queryClient.invalidateQueries({ queryKey: ["kyc", "screening", "pending"] });
    },
  });

  const pendingItems = useMemo(() => {
    const items = pendingQuery.data?.items ?? [];
    return typeFilter === "all" ? items : items.filter((i) => i.screen_type === typeFilter);
  }, [pendingQuery.data, typeFilter]);

  const onReviewed = () => {
    queryClient.invalidateQueries({ queryKey: ["kyc", "screening", "pending"] });
    if (activeCaseId) {
      queryClient.invalidateQueries({ queryKey: ["kyc", "screening", "case", activeCaseId] });
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Sanctions / PEP Screening</h1>
        <p className="text-sm text-muted-foreground">
          Run sanctions and politically-exposed-persons screening, review potential matches, and
          adjudicate each result.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Run / Inspect a Case</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 sm:grid-cols-2">
            <Input
              placeholder="User sub (to run screening)"
              value={runUserSub}
              onChange={(e) => setRunUserSub(e.target.value)}
              data-testid="run-user-sub"
            />
            <Input
              placeholder="Case ID (optional)"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              data-testid="run-case-id"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={!runUserSub || runMutation.isPending}
              onClick={() => runMutation.mutate()}
              data-testid="run-screening"
            >
              Run Screening
            </Button>
            <Button
              variant="outline"
              disabled={!caseId}
              onClick={() => setActiveCaseId(caseId)}
              data-testid="load-case"
            >
              Load Case Results
            </Button>
            {activeCaseId && (
              <Button
                variant="secondary"
                disabled={rescreenMutation.isPending}
                onClick={() => rescreenMutation.mutate()}
                data-testid="rescreen"
              >
                Re-screen
              </Button>
            )}
          </div>

          {activeCaseId && (
            <div className="space-y-2">
              <div className="text-sm font-medium">Results for {activeCaseId}</div>
              {caseQuery.isLoading && <p className="text-sm">Loading…</p>}
              {(caseQuery.data?.results ?? []).map((row) => (
                <ResultRow key={row.screen_key} row={row} onReview={setReviewing} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Review Queue</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {(["potential_match", "confirmed_match"] as KycScreeningResultStatus[]).map((s) => (
              <Button
                key={s}
                size="sm"
                variant={s === statusFilter ? "default" : "outline"}
                onClick={() => setStatusFilter(s)}
                data-testid={`status-${s}`}
              >
                {RESULT_LABELS[s]}
              </Button>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant={typeFilter === "all" ? "secondary" : "outline"}
              onClick={() => setTypeFilter("all")}
              data-testid="type-all"
            >
              All Types
            </Button>
            {(Object.keys(SCREEN_TYPE_LABELS) as KycScreenType[]).map((t) => (
              <Button
                key={t}
                size="sm"
                variant={typeFilter === t ? "secondary" : "outline"}
                onClick={() => setTypeFilter(t)}
                data-testid={`type-${t}`}
              >
                {SCREEN_TYPE_LABELS[t]}
              </Button>
            ))}
          </div>

          {pendingQuery.isLoading && <p className="text-sm">Loading…</p>}
          {!pendingQuery.isLoading && pendingItems.length === 0 && (
            <p className="text-sm text-muted-foreground">No pending reviews.</p>
          )}
          {pendingItems.map((row) => (
            <div key={`${row.case_id}-${row.screen_key}`} className="space-y-1">
              <div className="text-xs text-muted-foreground">
                Case {row.case_id} · {row.user_sub}
              </div>
              <ResultRow row={row} onReview={setReviewing} />
            </div>
          ))}
        </CardContent>
      </Card>

      <ReviewDialog row={reviewing} onClose={() => setReviewing(null)} onReviewed={onReviewed} />
    </div>
  );
}

export default KycScreeningReviewQueuePage;
