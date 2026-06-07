import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Gavel, Scale, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  claimAppeal,
  decideAppeal,
  getAppealDetail,
  getAppealQueueStats,
  listAppealQueue,
  type Appeal,
  type AppealDecision,
} from "@/api/endpoints/appeals";

const STATUS_TABS = ["submitted", "under_review", "upheld", "modified", "reversed", "withdrawn"];

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function statusVariant(status: string) {
  switch (status) {
    case "submitted":
      return "warning" as const;
    case "under_review":
      return "info" as const;
    case "reversed":
      return "success" as const;
    case "modified":
      return "warning" as const;
    case "upheld":
      return "danger" as const;
    default:
      return "neutral" as const;
  }
}

export default function AppealReviewQueuePage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("submitted");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [decideTarget, setDecideTarget] = useState<Appeal | null>(null);
  const [decision, setDecision] = useState<AppealDecision>("upheld");
  const [decisionNote, setDecisionNote] = useState("");
  const [modifiedType, setModifiedType] = useState("");
  const [modifiedDuration, setModifiedDuration] = useState("");

  const statsQuery = useQuery({
    queryKey: ["appeal-queue-stats"],
    queryFn: () => getAppealQueueStats(),
    staleTime: 30_000,
  });

  const listQuery = useQuery({
    queryKey: ["appeal-queue", { status: statusFilter }],
    queryFn: () => listAppealQueue({ status: statusFilter, limit: 100 }),
    staleTime: 15_000,
  });

  const detailQuery = useQuery({
    queryKey: ["appeal-detail", selectedId],
    queryFn: () => getAppealDetail(selectedId!),
    enabled: !!selectedId,
  });

  const claimMut = useMutation({
    mutationFn: (appealId: string) => claimAppeal(appealId),
    onSuccess: () => {
      toast.success("Appeal claimed for review");
      void queryClient.invalidateQueries({ queryKey: ["appeal-queue"] });
      void queryClient.invalidateQueries({ queryKey: ["appeal-queue-stats"] });
      if (selectedId) void detailQuery.refetch();
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 409) {
        toast.error("Appeal is not in submitted status or was already claimed.");
        return;
      }
      toast.error(err instanceof ApiError ? err.detail : "Unable to claim appeal");
    },
  });

  const decideMut = useMutation({
    mutationFn: (appealId: string) =>
      decideAppeal(appealId, {
        decision,
        decision_note: decisionNote.trim() || undefined,
        modified_enforcement_type:
          decision === "modified" && modifiedType.trim() ? modifiedType.trim() : undefined,
        modified_duration_days:
          decision === "modified" && modifiedDuration.trim()
            ? Number(modifiedDuration.trim())
            : undefined,
      }),
    onSuccess: () => {
      toast.success("Decision recorded");
      setDecideTarget(null);
      setDecisionNote("");
      setModifiedType("");
      setModifiedDuration("");
      void queryClient.invalidateQueries({ queryKey: ["appeal-queue"] });
      void queryClient.invalidateQueries({ queryKey: ["appeal-queue-stats"] });
      if (selectedId) void detailQuery.refetch();
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 409) {
        toast.error("Appeal is not under review.");
        return;
      }
      toast.error(err instanceof ApiError ? err.detail : "Unable to record decision");
    },
  });

  const stats = statsQuery.data;
  const items = listQuery.data?.items ?? [];
  const detail = detailQuery.data;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader title="Appeal Queue" description="Review, claim, and decide user appeals." />

      <div className="grid gap-3 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Submitted</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">{stats?.total_submitted ?? 0}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Under review</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {stats?.total_under_review ?? 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Oldest submitted (min)</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {stats?.oldest_submitted_age_minutes ?? 0}
          </CardContent>
        </Card>
      </div>

      <div className="flex flex-wrap gap-2">
        {STATUS_TABS.map((s) => (
          <Button
            key={s}
            variant={statusFilter === s ? "default" : "outline"}
            size="sm"
            className="capitalize"
            onClick={() => {
              setStatusFilter(s);
              setSelectedId(null);
            }}
          >
            {s.replace(/_/g, " ")}
          </Button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Queue</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {listQuery.isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-20 w-full rounded-lg" />
                ))}
              </div>
            )}

            {!listQuery.isLoading && items.length === 0 && (
              <EmptyState
                icon={<ShieldAlert className="h-6 w-6" />}
                title={`No ${statusFilter.replace(/_/g, " ")} appeals`}
                description="Nothing to review here."
              />
            )}

            <div className="space-y-2 max-h-[480px] overflow-auto">
              {items.map((appeal) => (
                <button
                  key={appeal.appeal_id}
                  type="button"
                  onClick={() => setSelectedId(appeal.appeal_id)}
                  className={`w-full rounded-md border p-2 text-left text-sm ${
                    selectedId === appeal.appeal_id
                      ? "border-primary bg-primary/5"
                      : "hover:bg-muted/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <StatusBadge variant={statusVariant(appeal.status)} className="capitalize">
                      {appeal.status.replace(/_/g, " ")}
                    </StatusBadge>
                    <span className="text-xs text-muted-foreground">{fmt(appeal.created_at)}</span>
                  </div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">
                    {appeal.appeal_id} • user {appeal.user_id}
                  </div>
                </button>
              ))}
            </div>

            <Button
              variant="outline"
              onClick={() => void listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              Refresh
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Appeal detail</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {!selectedId && (
              <p className="text-sm text-muted-foreground">Select an appeal from the queue.</p>
            )}

            {selectedId && detailQuery.isLoading && (
              <Skeleton className="h-40 w-full rounded-lg" />
            )}

            {detail && (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <StatusBadge
                    variant={statusVariant(detail.appeal.status)}
                    className="capitalize"
                  >
                    {detail.appeal.status.replace(/_/g, " ")}
                  </StatusBadge>
                  <span>user {detail.appeal.user_id}</span>
                  <span>enforcement {detail.appeal.enforcement_id}</span>
                </div>

                <div className="rounded-md border p-3">
                  <p className="text-xs font-medium text-muted-foreground">Appeal text</p>
                  <p className="mt-1 whitespace-pre-wrap text-sm">{detail.appeal.appeal_text}</p>
                </div>

                {detail.appeal.decision_note && (
                  <div className="rounded-md bg-muted p-2 text-xs">
                    <span className="font-medium">Decision:</span> {detail.appeal.decision_note}
                  </div>
                )}

                <div className="grid gap-2 text-xs">
                  <div className="rounded-md border p-2">
                    <p className="font-medium text-muted-foreground">Enforcement record</p>
                    <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words">
                      {JSON.stringify(detail.enforcement_record ?? {}, null, 2)}
                    </pre>
                  </div>
                  <div className="rounded-md border p-2">
                    <p className="font-medium text-muted-foreground">
                      Moderation ticket
                    </p>
                    <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words">
                      {JSON.stringify(detail.moderation_ticket ?? {}, null, 2)}
                    </pre>
                  </div>
                  <div className="rounded-md border p-2">
                    <p className="font-medium text-muted-foreground">
                      User enforcement history ({detail.user_enforcement_history.length})
                    </p>
                    <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words">
                      {JSON.stringify(detail.user_enforcement_history ?? [], null, 2)}
                    </pre>
                  </div>
                  <div className="rounded-md border p-2">
                    <p className="font-medium text-muted-foreground">
                      User appeal history ({detail.user_appeal_history.length})
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => claimMut.mutate(detail.appeal.appeal_id)}
                    disabled={detail.appeal.status !== "submitted" || claimMut.isPending}
                  >
                    <Scale className="mr-1 h-3.5 w-3.5" /> Claim
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => {
                      setDecideTarget(detail.appeal);
                      setDecision("upheld");
                      setDecisionNote("");
                      setModifiedType("");
                      setModifiedDuration("");
                    }}
                    disabled={detail.appeal.status !== "under_review"}
                  >
                    <Gavel className="mr-1 h-3.5 w-3.5" /> Decide
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={!!decideTarget} onOpenChange={(o) => { if (!o) setDecideTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Decide appeal</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1">
              <Label>Decision</Label>
              <Select value={decision} onValueChange={(v) => setDecision(v as AppealDecision)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="upheld">Upheld (deny appeal)</SelectItem>
                  <SelectItem value="modified">Modified</SelectItem>
                  <SelectItem value="reversed">Reversed (grant appeal)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {decision === "modified" && (
              <>
                <div className="space-y-1">
                  <Label htmlFor="modified-type">Modified enforcement type</Label>
                  <Input
                    id="modified-type"
                    value={modifiedType}
                    onChange={(e) => setModifiedType(e.target.value)}
                    placeholder="e.g. warning"
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="modified-duration">Modified duration (days)</Label>
                  <Input
                    id="modified-duration"
                    type="number"
                    min={1}
                    max={3650}
                    value={modifiedDuration}
                    onChange={(e) => setModifiedDuration(e.target.value)}
                    placeholder="e.g. 7"
                  />
                </div>
              </>
            )}

            <div className="space-y-1">
              <Label htmlFor="decision-note">Decision note</Label>
              <Textarea
                id="decision-note"
                rows={4}
                value={decisionNote}
                onChange={(e) => setDecisionNote(e.target.value)}
                placeholder="Explain the decision (optional, max 2000 chars)..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDecideTarget(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (decideTarget) decideMut.mutate(decideTarget.appeal_id);
              }}
              disabled={decideMut.isPending}
            >
              Record decision
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
