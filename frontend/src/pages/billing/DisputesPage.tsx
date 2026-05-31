import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ShieldAlert, Plus } from "lucide-react";
import { Link } from "react-router-dom";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { toast } from "sonner";
import { listMyDisputes, fileDispute } from "@/api/endpoints/billingDisputes";
import type { DisputeOut } from "@/api/types";

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function statusVariant(status: string) {
  switch (status) {
    case "open":
      return "warning" as const;
    case "under_review":
      return "neutral" as const;
    case "resolved":
      return "success" as const;
    default:
      return "neutral" as const;
  }
}

export default function DisputesPage() {
  const [open, setOpen] = useState(false);
  const [amount, setAmount] = useState("");
  const [reason, setReason] = useState("");
  const [entryId, setEntryId] = useState("");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["disputes", "my-disputes"],
    queryFn: () => listMyDisputes(100),
    staleTime: 60_000,
  });

  const fileMutation = useMutation({
    mutationFn: () =>
      fileDispute({
        amount_cents: Math.round(parseFloat(amount || "0") * 100),
        reason,
        transaction_entry_id: entryId || null,
      }),
    onSuccess: () => {
      toast.success("Dispute filed");
      setOpen(false);
      setAmount("");
      setReason("");
      setEntryId("");
      queryClient.invalidateQueries({ queryKey: ["disputes", "my-disputes"] });
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error(String(err?.response?.data?.detail || err.message));
    },
  });

  const disputes = query.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center gap-2">
        <Link to="/billing?tab=ledger">
          <Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button>
        </Link>
        <PageHeader title="Disputes" description="File and track payment disputes" />
        <Button size="sm" className="ml-auto" onClick={() => setOpen(true)}>
          <Plus className="mr-1 h-4 w-4" /> File Dispute
        </Button>
      </div>

      {query.isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
      )}

      {!query.isLoading && disputes.length === 0 && (
        <EmptyState
          icon={<ShieldAlert className="h-6 w-6" />}
          title="No disputes"
          description="You have not filed any disputes yet."
        />
      )}

      <div className="space-y-3">
        {disputes.map((d: DisputeOut) => (
          <Card key={d.dispute_id}>
            <CardContent className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusBadge variant={statusVariant(d.status)} className="capitalize">
                    {d.status.replace(/_/g, " ")}
                  </StatusBadge>
                  <span className="text-sm font-medium">{formatCents(d.amount_cents)}</span>
                </div>
                <span className="text-xs text-muted-foreground">{formatDate(d.created_at)}</span>
              </div>
              <p className="text-sm">{d.reason}</p>
              {d.resolution && (
                <div className="rounded-md bg-muted p-2 text-xs">
                  <span className="font-medium">Resolution:</span> {d.resolution}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>File a Dispute</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1">
              <Label htmlFor="dispute-amount">Amount (USD)</Label>
              <Input
                id="dispute-amount"
                type="number"
                min="0.01"
                step="0.01"
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="dispute-entry">Transaction ID (optional)</Label>
              <Input
                id="dispute-entry"
                placeholder="le_..."
                value={entryId}
                onChange={(e) => setEntryId(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="dispute-reason">Reason (min 10 characters)</Label>
              <Textarea
                id="dispute-reason"
                placeholder="Describe why you are disputing this charge..."
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              onClick={() => fileMutation.mutate()}
              disabled={
                fileMutation.isPending ||
                reason.trim().length < 10 ||
                !(parseFloat(amount || "0") > 0)
              }
            >
              File Dispute
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
