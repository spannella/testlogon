import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  FileText,
  CheckCircle2,
  RotateCcw,
  XCircle,
  ChevronDown,
  ChevronUp,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { ShippingTimeline } from "./ShippingTimeline";
import { CancelRequestDialog, CancelRespondDialog } from "./CancelDialog";
import {
  getTransaction,
  listEvents,
  getReceipt,
  markComplete,
  markReverted,
  requestCancel,
  respondCancel,
} from "@/api/endpoints/purchases";
import type { TransactionEvent } from "@/api/endpoints/purchases";

// ─── Helpers ──────────────────────────────────────────────────

function statusVariant(status: string) {
  switch (status) {
    case "COMPLETED":
    case "CANCEL_DENIED":
      return "success" as const;
    case "PENDING":
      return "warning" as const;
    case "CANCELLED":
      return "neutral" as const;
    case "REVERTED":
      return "danger" as const;
    case "CANCEL_REQUESTED":
      return "warning" as const;
    default:
      return "info" as const;
  }
}

function formatCurrency(amount: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(amount);
}

function formatDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatEventName(name: string | undefined): string {
  if (!name) return "Unknown Event";
  return name
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Events Timeline Sub-component ───────────────────────────

function EventsTimeline({ txnId }: { txnId: string }) {
  const [expanded, setExpanded] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["purchases", txnId, "events"],
    queryFn: () => listEvents(txnId, 100),
  });

  const events: TransactionEvent[] = data?.events ?? [];
  const visibleEvents = expanded ? events : events.slice(0, 5);
  const hasMore = events.length > 5;

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground">No events recorded.</p>;
  }

  return (
    <div className="space-y-1">
      <div className="relative pl-6">
        {/* Vertical line */}
        <div className="absolute left-[9px] top-2 bottom-2 w-px bg-border" />

        {visibleEvents.map((event, i) => (
          <div key={i} className="relative flex gap-3 pb-4 last:pb-0">
            {/* Dot */}
            <div className="absolute left-[-15px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-primary bg-background" />

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">
                  {formatEventName(event.event_type)}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                {formatDate(event.ts)}
              </p>
              {event.detail && (
                <p className="mt-0.5 text-xs text-muted-foreground">{event.detail}</p>
              )}
            </div>
          </div>
        ))}
      </div>

      {hasMore && (
        <Button
          variant="ghost"
          size="sm"
          className="w-full"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? (
            <>
              <ChevronUp className="mr-1 h-4 w-4" /> Show less
            </>
          ) : (
            <>
              <ChevronDown className="mr-1 h-4 w-4" /> Show all {events.length} events
            </>
          )}
        </Button>
      )}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────

export function TransactionDetail() {
  const { txnId } = useParams<{ txnId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Dialogs
  const [cancelRequestOpen, setCancelRequestOpen] = useState(false);
  const [cancelRespondOpen, setCancelRespondOpen] = useState(false);
  const [completeConfirmOpen, setCompleteConfirmOpen] = useState(false);
  const [revertConfirmOpen, setRevertConfirmOpen] = useState(false);

  // ─── Queries ──────────────────────────────────────────────

  const { data: txn, isLoading } = useQuery({
    queryKey: ["purchases", txnId],
    queryFn: () => getTransaction(txnId!),
    enabled: !!txnId,
  });

  // ─── Mutations ────────────────────────────────────────────

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["purchases"] });
  };

  const completeMutation = useMutation({
    mutationFn: () => markComplete(txnId!),
    onSuccess: () => {
      toast.success("Order marked as complete");
      invalidate();
      setCompleteConfirmOpen(false);
    },
    onError: () => toast.error("Failed to complete order"),
  });

  const revertMutation = useMutation({
    mutationFn: () => markReverted(txnId!),
    onSuccess: () => {
      toast.success("Order reverted");
      invalidate();
      setRevertConfirmOpen(false);
    },
    onError: () => toast.error("Failed to revert order"),
  });

  const cancelRequestMutation = useMutation({
    mutationFn: (reason: string) => requestCancel(txnId!, reason),
    onSuccess: () => {
      toast.success("Cancellation requested");
      invalidate();
      setCancelRequestOpen(false);
    },
    onError: () => toast.error("Failed to request cancellation"),
  });

  const cancelRespondMutation = useMutation({
    mutationFn: ({ decision, note }: { decision: "APPROVE" | "DENY"; note: string }) =>
      respondCancel(txnId!, decision, note),
    onSuccess: (_data, vars) => {
      toast.success(
        vars.decision === "APPROVE" ? "Cancellation approved" : "Cancellation denied",
      );
      invalidate();
      setCancelRespondOpen(false);
    },
    onError: () => toast.error("Failed to respond to cancellation"),
  });

  const receiptMutation = useMutation({
    mutationFn: () => getReceipt(txnId!),
    onSuccess: (data) => {
      if (data.receipt_url) {
        window.open(data.receipt_url, "_blank", "noopener");
      } else {
        toast.info("Receipt is being generated. Try again shortly.");
      }
    },
    onError: () => toast.error("Failed to get receipt"),
  });

  // ─── Loading state ────────────────────────────────────────

  if (isLoading || !txn) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full rounded-xl" />
        <Skeleton className="h-24 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    );
  }

  // ─── Determine available actions based on status ──────────
  const status = txn.status;
  const canComplete = status === "PENDING" || status === "CANCEL_DENIED";
  const canRevert = status === "COMPLETED" || status === "PENDING";
  const canRequestCancel = status === "PENDING" || status === "COMPLETED";
  const canRespondCancel = status === "CANCEL_REQUESTED";

  return (
    <div className="space-y-6">
      {/* Back button + header */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate("/purchases")}
          aria-label="Back to orders"
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-lg font-semibold">
              {txn.description ?? `Order ${txn.txn_id.slice(0, 8)}...`}
            </h2>
            <StatusBadge variant={statusVariant(status)} className="shrink-0 uppercase">
              {status.replace(/_/g, " ")}
            </StatusBadge>
          </div>
          <p className="text-xs text-muted-foreground">
            ID: {txn.txn_id}
          </p>
        </div>
      </div>

      {/* Shipping Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Order Progress</CardTitle>
        </CardHeader>
        <CardContent>
          <ShippingTimeline
            txnStatus={status}
            createdAt={txn.created_at}
            shippedAt={txn.shipping?.shipped_at}
            deliveredAt={txn.shipping?.delivered_at}
            completedAt={txn.completed_at}
            revertedAt={txn.reverted_at}
          />
        </CardContent>
      </Card>

      {/* Summary Card */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Order Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">Amount</dt>
              <dd className="font-semibold">{formatCurrency(txn.amount, txn.currency)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Status</dt>
              <dd className="capitalize">{status.replace(/_/g, " ").toLowerCase()}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{formatDate(txn.created_at)}</dd>
            </div>
            {txn.merchant_id && (
              <div>
                <dt className="text-muted-foreground">Merchant</dt>
                <dd>{txn.merchant_id}</dd>
              </div>
            )}
            {txn.external_ref && (
              <div>
                <dt className="text-muted-foreground">Reference</dt>
                <dd className="truncate">{txn.external_ref}</dd>
              </div>
            )}
            {txn.completed_at && (
              <div>
                <dt className="text-muted-foreground">Completed</dt>
                <dd>{formatDate(txn.completed_at)}</dd>
              </div>
            )}
            {txn.reverted_at && (
              <div>
                <dt className="text-muted-foreground">Reverted</dt>
                <dd>{formatDate(txn.reverted_at)}</dd>
              </div>
            )}
          </dl>

          {/* Shipping details */}
          {txn.shipping && (
            <div className="mt-4 border-t pt-4">
              <h4 className="mb-2 text-sm font-medium">Shipping</h4>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                {txn.shipping.carrier && (
                  <div>
                    <dt className="text-muted-foreground">Carrier</dt>
                    <dd>{txn.shipping.carrier}</dd>
                  </div>
                )}
                {txn.shipping.tracking_number && (
                  <div>
                    <dt className="text-muted-foreground">Tracking</dt>
                    <dd className="font-mono text-xs">{txn.shipping.tracking_number}</dd>
                  </div>
                )}
                {txn.shipping.shipped_at && (
                  <div>
                    <dt className="text-muted-foreground">Shipped</dt>
                    <dd>{formatDate(txn.shipping.shipped_at)}</dd>
                  </div>
                )}
                {txn.shipping.delivered_at && (
                  <div>
                    <dt className="text-muted-foreground">Delivered</dt>
                    <dd>{formatDate(txn.shipping.delivered_at)}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* Cancel details */}
          {txn.cancel && Object.keys(txn.cancel).length > 0 && (
            <div className="mt-4 border-t pt-4">
              <h4 className="mb-2 text-sm font-medium">Cancellation</h4>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                {!!(txn.cancel as Record<string, unknown>).reason && (
                  <div className="col-span-2">
                    <dt className="text-muted-foreground">Reason</dt>
                    <dd>{String((txn.cancel as Record<string, unknown>).reason)}</dd>
                  </div>
                )}
                {!!(txn.cancel as Record<string, unknown>).status && (
                  <div>
                    <dt className="text-muted-foreground">Decision</dt>
                    <dd className="capitalize">
                      {String((txn.cancel as Record<string, unknown>).status).toLowerCase()}
                    </dd>
                  </div>
                )}
                {!!(txn.cancel as Record<string, unknown>).note && (
                  <div className="col-span-2">
                    <dt className="text-muted-foreground">Note</dt>
                    <dd>{String((txn.cancel as Record<string, unknown>).note)}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Action buttons */}
      {(canComplete || canRevert || canRequestCancel || canRespondCancel) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {canComplete && (
                <Button
                  size="sm"
                  onClick={() => setCompleteConfirmOpen(true)}
                >
                  <CheckCircle2 className="mr-1.5 h-4 w-4" />
                  Mark Complete
                </Button>
              )}
              {canRevert && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setRevertConfirmOpen(true)}
                >
                  <RotateCcw className="mr-1.5 h-4 w-4" />
                  Revert
                </Button>
              )}
              {canRequestCancel && (
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => setCancelRequestOpen(true)}
                >
                  <XCircle className="mr-1.5 h-4 w-4" />
                  Request Cancellation
                </Button>
              )}
              {canRespondCancel && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setCancelRespondOpen(true)}
                >
                  Respond to Cancel Request
                </Button>
              )}

              {/* Receipt button — always available */}
              <Button
                size="sm"
                variant="outline"
                onClick={() => receiptMutation.mutate()}
                disabled={receiptMutation.isPending}
              >
                {receiptMutation.isPending ? (
                  <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                ) : (
                  <FileText className="mr-1.5 h-4 w-4" />
                )}
                Download Receipt
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Receipt button fallback when no other actions */}
      {!canComplete && !canRevert && !canRequestCancel && !canRespondCancel && (
        <div className="flex">
          <Button
            size="sm"
            variant="outline"
            onClick={() => receiptMutation.mutate()}
            disabled={receiptMutation.isPending}
          >
            {receiptMutation.isPending ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <FileText className="mr-1.5 h-4 w-4" />
            )}
            Download Receipt
          </Button>
        </div>
      )}

      {/* Events Audit Trail */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Activity</CardTitle>
        </CardHeader>
        <CardContent>
          <EventsTimeline txnId={txnId!} />
        </CardContent>
      </Card>

      {/* ─── Dialogs ─────────────────────────────────────────── */}

      <ConfirmDialog
        open={completeConfirmOpen}
        onOpenChange={setCompleteConfirmOpen}
        title="Mark as Complete"
        description="This will mark the order as completed. Continue?"
        confirmLabel="Complete"
        onConfirm={() => completeMutation.mutate()}
        loading={completeMutation.isPending}
      />

      <ConfirmDialog
        open={revertConfirmOpen}
        onOpenChange={setRevertConfirmOpen}
        title="Revert Order"
        description="This will revert the order. This action can be difficult to undo."
        confirmLabel="Revert"
        variant="danger"
        onConfirm={() => revertMutation.mutate()}
        loading={revertMutation.isPending}
      />

      <CancelRequestDialog
        open={cancelRequestOpen}
        onOpenChange={setCancelRequestOpen}
        onSubmit={(reason) => cancelRequestMutation.mutate(reason)}
        loading={cancelRequestMutation.isPending}
      />

      <CancelRespondDialog
        open={cancelRespondOpen}
        onOpenChange={setCancelRespondOpen}
        onRespond={(decision, note) => cancelRespondMutation.mutate({ decision, note })}
        loading={cancelRespondMutation.isPending}
      />
    </div>
  );
}
