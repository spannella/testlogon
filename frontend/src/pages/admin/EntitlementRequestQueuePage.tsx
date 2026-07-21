import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Check, X, Hand } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import {
  listEntitlementRequestQueue,
  claimEntitlementRequest,
  approveEntitlementRequest,
  rejectEntitlementRequest,
  type EntitlementRequest,
} from "@/api/endpoints/entitlementRequests";

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function statusVariant(s: string) {
  switch (s) {
    case "pending": return "warning" as const;
    case "claimed": return "neutral" as const;
    case "approved": return "success" as const;
    case "rejected": return "danger" as const;
    default: return "neutral" as const;
  }
}

const STATUSES = ["pending", "claimed", "approved", "rejected"];

export default function EntitlementRequestQueuePage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("pending");
  const [decideDialog, setDecideDialog] = useState<{ req: EntitlementRequest; action: "approve" | "reject" } | null>(null);
  const [reason, setReason] = useState("");

  const query = useQuery({
    queryKey: ["entitlement-requests", "queue", { statusFilter }],
    queryFn: () => listEntitlementRequestQueue(statusFilter, 100),
    staleTime: 15_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["entitlement-requests", "queue"] });

  const claimMut = useMutation({
    mutationFn: (id: string) => claimEntitlementRequest(id),
    onSuccess: () => { toast.success("Request claimed"); invalidate(); },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Claim failed"),
  });

  const decideMut = useMutation({
    mutationFn: ({ id, action, reason }: { id: string; action: "approve" | "reject"; reason: string }) =>
      action === "approve" ? approveEntitlementRequest(id, reason) : rejectEntitlementRequest(id, reason),
    onSuccess: (_d, vars) => {
      toast.success(vars.action === "approve" ? "Request approved" : "Request rejected");
      setDecideDialog(null);
      setReason("");
      invalidate();
    },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Decision failed"),
  });

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="The entitlement-request review queue is available only to operators."
      />
    );
  }

  const items = query.data?.requests ?? [];

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Entitlement Requests"
        description="Review, claim, and decide access / entitlement grant requests"
      />

      <div className="flex flex-wrap gap-2">
        {STATUSES.map((s) => (
          <Button
            key={s}
            variant={statusFilter === s ? "default" : "outline"}
            size="sm"
            onClick={() => setStatusFilter(s)}
            className="capitalize"
          >
            {s}
          </Button>
        ))}
      </div>

      {query.isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28 w-full rounded-lg" />)}
        </div>
      )}

      {!query.isLoading && items.length === 0 && (
        <EmptyState icon={<KeyRound className="h-6 w-6" />} title={`No ${statusFilter} requests`} description="All clear." />
      )}

      <div className="space-y-3">
        {items.map((r: EntitlementRequest) => (
          <Card key={r.request_id}>
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusBadge variant={statusVariant(r.status)} className="capitalize">{r.status}</StatusBadge>
                  <span className="text-sm font-medium capitalize">{r.entitlement_kind?.replace(/_/g, " ")}</span>
                  <span className="font-mono text-xs text-muted-foreground">{r.target_ref}</span>
                </div>
                <span className="text-xs text-muted-foreground">{fmtDate(r.created_at)}</span>
              </div>

              <p className="text-xs text-muted-foreground">
                Requester: {r.requester_sub} · ID: {r.request_id}
                {r.claimed_by_sub ? ` · claimed by ${r.claimed_by_sub}` : ""}
              </p>

              {r.justification && <p className="text-sm">{r.justification}</p>}

              {r.decision_reason && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium">Decision:</span> {r.decision_reason}
                </div>
              )}

              {(r.status === "pending" || r.status === "claimed") && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {r.status === "pending" && (
                    <Button size="sm" variant="outline" disabled={claimMut.isPending}
                      onClick={() => claimMut.mutate(r.request_id)}>
                      <Hand className="mr-1 h-3.5 w-3.5" /> Claim
                    </Button>
                  )}
                  <Button size="sm" onClick={() => { setDecideDialog({ req: r, action: "approve" }); setReason(""); }}>
                    <Check className="mr-1 h-3.5 w-3.5" /> Approve
                  </Button>
                  <Button size="sm" variant="destructive"
                    onClick={() => { setDecideDialog({ req: r, action: "reject" }); setReason(""); }}>
                    <X className="mr-1 h-3.5 w-3.5" /> Reject
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Dialog open={!!decideDialog} onOpenChange={(open) => { if (!open) setDecideDialog(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {decideDialog?.action === "approve" ? "Approve" : "Reject"} Entitlement Request
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-xs text-muted-foreground">
              Approving grants access; rejecting closes the request. Approval requires root privileges.
            </p>
            <Label htmlFor="reason">Reason (required)</Label>
            <Textarea id="reason" rows={4} value={reason}
              placeholder="Explain the decision..."
              onChange={(e) => setReason(e.target.value)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDecideDialog(null)}>Cancel</Button>
            <Button
              variant={decideDialog?.action === "reject" ? "destructive" : "default"}
              disabled={!reason.trim() || decideMut.isPending}
              onClick={() => {
                if (decideDialog) {
                  decideMut.mutate({ id: decideDialog.req.request_id, action: decideDialog.action, reason });
                }
              }}
            >
              {decideDialog?.action === "approve" ? "Approve" : "Reject"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
