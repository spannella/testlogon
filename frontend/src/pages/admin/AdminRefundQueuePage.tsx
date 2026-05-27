import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, Check, X } from "lucide-react";
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
import { toast } from "sonner";
import {
  adminListRefundRequests,
  adminApproveRefund,
  adminRejectRefund,
} from "@/api/endpoints/refundRequests";
import type { RefundRequestOut } from "@/api/types";

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function statusVariant(status: string) {
  switch (status) {
    case "pending": return "warning" as const;
    case "approved":
    case "completed": return "success" as const;
    case "denied": return "danger" as const;
    default: return "neutral" as const;
  }
}

export default function AdminRefundQueuePage() {
  const [statusFilter, setStatusFilter] = useState("pending");
  const [denyDialog, setDenyDialog] = useState<RefundRequestOut | null>(null);
  const [denyNotes, setDenyNotes] = useState("");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["refunds", "admin-queue", { status: statusFilter }],
    queryFn: () => adminListRefundRequests(statusFilter, 100),
    staleTime: 30_000,
  });

  const approveMutation = useMutation({
    mutationFn: ({ id }: { id: string }) => adminApproveRefund(id, {}),
    onSuccess: () => {
      toast.success("Refund approved");
      queryClient.invalidateQueries({ queryKey: ["refunds", "admin-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(String(err?.response?.data?.detail || err.message));
    },
  });

  const denyMutation = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) => adminRejectRefund(id, { notes }),
    onSuccess: () => {
      toast.success("Refund denied");
      setDenyDialog(null);
      setDenyNotes("");
      queryClient.invalidateQueries({ queryKey: ["refunds", "admin-queue"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(String(err?.response?.data?.detail || err.message));
    },
  });

  const items = query.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Refund Queue" description="Review and process customer refund requests" />

      <div className="flex gap-2">
        {["pending", "approved", "denied"].map((s) => (
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
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full rounded-lg" />
          ))}
        </div>
      )}

      {!query.isLoading && items.length === 0 && (
        <EmptyState
          icon={<RotateCcw className="h-6 w-6" />}
          title={`No ${statusFilter} requests`}
          description="All clear."
        />
      )}

      <div className="space-y-3">
        {items.map((r) => (
          <Card key={r.refund_request_id}>
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusBadge variant={statusVariant(r.status)} className="capitalize">
                    {r.status}
                  </StatusBadge>
                  <span className="font-medium text-sm">{formatCents(r.amount_cents)}</span>
                  {r.transaction_type && (
                    <span className="text-xs text-muted-foreground capitalize">
                      ({r.transaction_type.replace(/_/g, " ")})
                    </span>
                  )}
                </div>
                <span className="text-xs text-muted-foreground">{formatDate(r.created_at)}</span>
              </div>

              <p className="text-xs text-muted-foreground">
                User: {r.requester_user_id} | ID: {r.refund_request_id}
              </p>

              <p className="text-sm">{r.reason}</p>

              {r.admin_notes && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium">Admin notes:</span> {r.admin_notes}
                </div>
              )}

              {r.status === "pending" && (
                <div className="flex gap-2 pt-1">
                  <Button
                    size="sm"
                    onClick={() => approveMutation.mutate({ id: r.refund_request_id })}
                    disabled={approveMutation.isPending}
                  >
                    <Check className="mr-1 h-3.5 w-3.5" /> Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => { setDenyDialog(r); setDenyNotes(""); }}
                  >
                    <X className="mr-1 h-3.5 w-3.5" /> Deny
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Deny dialog */}
      <Dialog open={!!denyDialog} onOpenChange={(open) => { if (!open) setDenyDialog(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deny Refund Request</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Label htmlFor="deny-notes">Reason for denial (required)</Label>
            <Textarea
              id="deny-notes"
              placeholder="Explain why this refund is being denied..."
              value={denyNotes}
              onChange={(e) => setDenyNotes(e.target.value)}
              rows={4}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDenyDialog(null)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (denyDialog) {
                  denyMutation.mutate({ id: denyDialog.refund_request_id, notes: denyNotes });
                }
              }}
              disabled={!denyNotes.trim() || denyMutation.isPending}
            >
              Deny Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
