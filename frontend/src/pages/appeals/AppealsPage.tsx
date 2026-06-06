import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Scale } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  listMyAppeals,
  submitAppeal,
  withdrawAppeal,
  type Appeal,
} from "@/api/endpoints/appeals";

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
    case "withdrawn":
      return "neutral" as const;
    default:
      return "neutral" as const;
  }
}

const WITHDRAWABLE = new Set(["submitted", "under_review"]);

export default function AppealsPage() {
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();

  const [enforcementId, setEnforcementId] = useState("");
  const [appealText, setAppealText] = useState("");
  const [withdrawTarget, setWithdrawTarget] = useState<Appeal | null>(null);

  // Deep-link support: /appeals?enforcement_id=enf_xxx pre-fills the form.
  useEffect(() => {
    const fromQuery = searchParams.get("enforcement_id");
    if (fromQuery) setEnforcementId(fromQuery);
  }, [searchParams]);

  const listQuery = useQuery({
    queryKey: ["my-appeals"],
    queryFn: () => listMyAppeals({ limit: 50 }),
    staleTime: 30_000,
  });

  const submitMut = useMutation({
    mutationFn: () =>
      submitAppeal({ enforcement_id: enforcementId.trim(), appeal_text: appealText.trim() }),
    onSuccess: (res) => {
      toast.success(`Appeal submitted (${res.appeal_id})`);
      setAppealText("");
      setEnforcementId("");
      void queryClient.invalidateQueries({ queryKey: ["my-appeals"] });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          toast.error("An appeal already exists for this enforcement action.");
          return;
        }
        if (err.status === 429) {
          toast.error("You already have a pending appeal. Wait for it to be resolved.");
          return;
        }
        if (err.status === 404) {
          toast.error("Enforcement record not found.");
          return;
        }
        toast.error(err.detail || "Unable to submit appeal");
        return;
      }
      toast.error(err instanceof Error ? err.message : "Unable to submit appeal");
    },
  });

  const withdrawMut = useMutation({
    mutationFn: (appealId: string) => withdrawAppeal(appealId),
    onSuccess: () => {
      toast.success("Appeal withdrawn");
      setWithdrawTarget(null);
      void queryClient.invalidateQueries({ queryKey: ["my-appeals"] });
    },
    onError: (err: unknown) => {
      setWithdrawTarget(null);
      toast.error(err instanceof ApiError ? err.detail : "Unable to withdraw appeal");
    },
  });

  const items = listQuery.data?.items ?? [];
  const canSubmit =
    enforcementId.trim().startsWith("enf_") &&
    appealText.trim().length >= 5 &&
    appealText.trim().length <= 5000 &&
    !submitMut.isPending;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="My Appeals"
        description="File an appeal against an enforcement action and track its status."
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Appeal Enforcement Action</CardTitle>
            <CardDescription>
              Reference the enforcement ID (starts with <code>enf_</code>) and explain why the
              action should be reconsidered.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="appeal-enforcement-id">Enforcement ID</Label>
              <Input
                id="appeal-enforcement-id"
                value={enforcementId}
                onChange={(e) => setEnforcementId(e.target.value)}
                placeholder="enf_..."
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="appeal-text">Why are you appealing?</Label>
              <Textarea
                id="appeal-text"
                rows={6}
                value={appealText}
                onChange={(e) => setAppealText(e.target.value)}
                placeholder="Describe why this enforcement action should be reconsidered (5–5000 characters)..."
              />
              <p className="text-xs text-muted-foreground">{appealText.trim().length} / 5000</p>
            </div>
            <Button onClick={() => submitMut.mutate()} disabled={!canSubmit}>
              Submit appeal
            </Button>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Your appeals</CardTitle>
            <CardDescription>Appeals you have filed and their current status.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {listQuery.isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-24 w-full rounded-lg" />
                ))}
              </div>
            )}

            {!listQuery.isLoading && items.length === 0 && (
              <EmptyState
                icon={<Scale className="h-6 w-6" />}
                title="No appeals yet"
                description="When you appeal an enforcement action, it will appear here."
              />
            )}

            <div className="space-y-3">
              {items.map((appeal) => (
                <div key={appeal.appeal_id} className="rounded-lg border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <StatusBadge variant={statusVariant(appeal.status)} className="capitalize">
                        {appeal.status.replace(/_/g, " ")}
                      </StatusBadge>
                      {appeal.enforcement_type && (
                        <span className="text-xs text-muted-foreground capitalize">
                          {appeal.enforcement_type.replace(/_/g, " ")}
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground">{fmt(appeal.created_at)}</span>
                  </div>

                  <p className="mt-2 text-xs text-muted-foreground">
                    {appeal.appeal_id} • enforcement {appeal.enforcement_id}
                  </p>

                  <p className="mt-2 whitespace-pre-wrap text-sm">{appeal.appeal_text}</p>

                  {appeal.decision_note && (
                    <div className="mt-2 rounded-md bg-muted p-2 text-xs">
                      <span className="font-medium">Decision:</span> {appeal.decision_note}
                    </div>
                  )}

                  {WITHDRAWABLE.has(appeal.status) && (
                    <div className="mt-3">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setWithdrawTarget(appeal)}
                        disabled={withdrawMut.isPending}
                      >
                        Withdraw
                      </Button>
                    </div>
                  )}
                </div>
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
      </div>

      <Dialog open={!!withdrawTarget} onOpenChange={(o) => { if (!o) setWithdrawTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Withdraw appeal?</DialogTitle>
          </DialogHeader>
          <p className="py-2 text-sm text-muted-foreground">
            This cannot be undone. The appeal {withdrawTarget?.appeal_id} will be marked as
            withdrawn and removed from the review queue.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setWithdrawTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (withdrawTarget) withdrawMut.mutate(withdrawTarget.appeal_id);
              }}
              disabled={withdrawMut.isPending}
            >
              Withdraw
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
