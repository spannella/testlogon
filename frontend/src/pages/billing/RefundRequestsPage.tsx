import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, RotateCcw } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { listMyRefundRequests } from "@/api/endpoints/refundRequests";
import type { RefundRequestOut } from "@/api/types";

function statusVariant(status: string) {
  switch (status) {
    case "pending":
      return "warning" as const;
    case "approved":
    case "completed":
      return "success" as const;
    case "denied":
      return "danger" as const;
    default:
      return "neutral" as const;
  }
}

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

function RequestCard({ request }: { request: RefundRequestOut }) {
  return (
    <Card>
      <CardContent className="p-4 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <StatusBadge variant={statusVariant(request.status)} className="capitalize">
              {request.status}
            </StatusBadge>
            <span className="text-sm font-medium">{formatCents(request.amount_cents)}</span>
          </div>
          <span className="text-xs text-muted-foreground">{formatDate(request.created_at)}</span>
        </div>
        {request.transaction_type && (
          <p className="text-sm text-muted-foreground capitalize">
            {request.transaction_type.replace(/_/g, " ")}
          </p>
        )}
        <p className="text-sm">{request.reason}</p>
        {request.admin_notes && (
          <div className="rounded-md bg-muted p-2 text-xs">
            <span className="font-medium">Admin notes:</span> {request.admin_notes}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function RefundRequestsPage() {
  const query = useQuery({
    queryKey: ["refunds", "my-requests"],
    queryFn: () => listMyRefundRequests(100),
    staleTime: 60_000,
  });

  const requests = query.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center gap-2">
        <Link to="/billing?tab=ledger">
          <Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button>
        </Link>
        <PageHeader title="Refund Requests" description="Track the status of your refund requests" />
      </div>

      {query.isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full rounded-lg" />
          ))}
        </div>
      )}

      {!query.isLoading && requests.length === 0 && (
        <EmptyState
          icon={<RotateCcw className="h-6 w-6" />}
          title="No refund requests"
          description="You have not submitted any refund requests yet."
        />
      )}

      <div className="space-y-3">
        {requests.map((r) => (
          <RequestCard key={r.refund_request_id} request={r} />
        ))}
      </div>
    </div>
  );
}
