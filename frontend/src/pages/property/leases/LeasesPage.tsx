/**
 * LeasesPage — Lease Management (LSE-004)
 * Route: /property/leases
 *
 * Feature flag: LEASES_ENABLED (backend default false → 404)
 * When the flag is off the backend returns 404 "leases not enabled".
 * This page detects that case and shows a clean "feature not enabled" banner.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PlusCircle, FileText, AlertTriangle, ChevronRight } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { ApiError } from "@/api/client";
import {
  listLeases,
  type LeaseOut,
  type LeaseStatus,
} from "@/api/endpoints/leases";
import { LeaseCreateDialog } from "./LeaseCreateDialog";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isFeatureDisabled(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.status === 404 || error.status === 503) &&
    /not enabled/i.test(error.detail ?? "")
  );
}

function fmtDate(ts: number | null): string {
  if (!ts) return "Open-ended";
  return new Date(ts * 1000).toLocaleDateString();
}

function fmtCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

const STATUS_COLORS: Record<LeaseStatus, string> = {
  draft: "bg-gray-100 text-gray-700",
  upcoming: "bg-blue-100 text-blue-700",
  active: "bg-green-100 text-green-700",
  ended: "bg-red-100 text-red-700",
};

function StatusBadge({ status }: { status: string }) {
  const cls =
    STATUS_COLORS[status as LeaseStatus] ?? "bg-gray-100 text-gray-700";
  return (
    <Badge className={cls} variant="outline">
      {status}
    </Badge>
  );
}

function isExpiringSoon(lease: LeaseOut): boolean {
  if (!lease.end_date || lease.status !== "active") return false;
  const daysLeft = (lease.end_date - Date.now() / 1000) / 86400;
  return daysLeft >= 0 && daysLeft <= 60;
}

// ─── Status filter options ────────────────────────────────────────────────────

const STATUS_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "all", label: "All statuses" },
  { value: "draft", label: "Draft" },
  { value: "upcoming", label: "Upcoming" },
  { value: "active", label: "Active" },
  { value: "ended", label: "Ended" },
];

// ─── Main page ────────────────────────────────────────────────────────────────

export default function LeasesPage() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [createOpen, setCreateOpen] = useState(false);
  const [transitioning, setTransitioning] = useState<string | null>(null);

  const filterStatus =
    statusFilter === "all" ? undefined : (statusFilter as LeaseStatus);

  const query = useQuery({
    queryKey: ["leases", { status: filterStatus, cursor }],
    queryFn: () => listLeases({ status: filterStatus, limit: 50, cursor }),
    retry: (failCount, error) => {
      if (isFeatureDisabled(error)) return false;
      return failCount < 2;
    },
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["leases"] });

  const { mutate: transition } = useMutation({
    mutationFn: async ({
      leaseId,
      status,
    }: {
      leaseId: string;
      status: string;
    }) => {
      const { transitionLeaseStatus } = await import(
        "@/api/endpoints/leases"
      );
      setTransitioning(leaseId);
      return transitionLeaseStatus(leaseId, status);
    },
    onSuccess: () => {
      toast.success("Lease status updated");
      invalidate();
    },
    onError: (err) => {
      const msg =
        err instanceof ApiError
          ? err.detail
          : "Failed to update lease status";
      toast.error(msg);
    },
    onSettled: () => setTransitioning(null),
  });

  // ── Feature-disabled guard ─────────────────────────────────────────────────
  if (isFeatureDisabled(query.error)) {
    return (
      <div className="p-6 space-y-6">
        <PageHeader title="Leases" description="Manage property lease agreements" />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
              <AlertTriangle className="w-10 h-10" />
              <p className="font-medium">Lease management is not enabled</p>
              <p className="text-sm">
                Set <code>LEASES_ENABLED=1</code> in your environment to
                activate this feature.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const leases: LeaseOut[] = query.data?.leases ?? [];
  const nextCursor = query.data?.next_cursor ?? null;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Leases"
        description="Manage property lease agreements"
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <PlusCircle className="w-4 h-4 mr-2" />
            New Lease
          </Button>
        }
      />

      {/* Filter bar */}
      <div className="flex items-center gap-3">
        <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setCursor(undefined); }}>
          <SelectTrigger className="w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {query.isFetching && (
          <span className="text-sm text-muted-foreground">Loading…</span>
        )}
      </div>

      {/* Error state (non-feature-disabled) */}
      {query.isError && !isFeatureDisabled(query.error) && (
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">
              Failed to load leases. Please try again.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Loading skeleton */}
      {query.isLoading && (
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Empty state */}
      {!query.isLoading && !query.isError && leases.length === 0 && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
              <FileText className="w-10 h-10" />
              <p className="font-medium">No leases found</p>
              <p className="text-sm">
                {statusFilter !== "all"
                  ? `No ${statusFilter} leases.`
                  : "Create your first lease to get started."}
              </p>
              <Button variant="outline" onClick={() => setCreateOpen(true)}>
                <PlusCircle className="w-4 h-4 mr-2" />
                New Lease
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Leases table */}
      {leases.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>
              Leases{" "}
              <span className="text-muted-foreground font-normal text-sm">
                ({query.data?.count ?? 0})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Lease #</TableHead>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Unit</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>End</TableHead>
                  <TableHead>Monthly Rent</TableHead>
                  <TableHead>Actions</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {leases.map((lease) => (
                  <TableRow
                    key={lease.lease_id}
                    className={
                      isExpiringSoon(lease)
                        ? "bg-amber-50 dark:bg-amber-950/20"
                        : undefined
                    }
                  >
                    <TableCell className="font-mono text-sm">
                      {lease.lease_number}
                      {isExpiringSoon(lease) && (
                        <AlertTriangle className="inline ml-1 w-3 h-3 text-amber-500" />
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {lease.tenant_id}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {lease.unit_id}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={lease.status} />
                    </TableCell>
                    <TableCell className="text-sm">
                      {fmtDate(lease.start_date)}
                    </TableCell>
                    <TableCell className="text-sm">
                      {fmtDate(lease.end_date)}
                    </TableCell>
                    <TableCell className="text-sm font-medium">
                      {fmtCents(lease.monthly_rent_cents, lease.currency)}
                      <span className="text-xs text-muted-foreground ml-1">
                        /mo
                      </span>
                    </TableCell>
                    <TableCell>
                      <TransitionActions
                        lease={lease}
                        isLoading={transitioning === lease.lease_id}
                        onTransition={(status) =>
                          transition({ leaseId: lease.lease_id, status })
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Link to={`/property/leases/${lease.lease_id}`}>
                        <Button variant="ghost" size="sm">
                          <ChevronRight className="w-4 h-4" />
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {/* Pagination */}
            {nextCursor && (
              <div className="p-4 border-t">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCursor(nextCursor)}
                  disabled={query.isFetching}
                >
                  Load more
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Create dialog */}
      <LeaseCreateDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => {
          setCreateOpen(false);
          invalidate();
        }}
      />
    </div>
  );
}

// ─── Transition action buttons ────────────────────────────────────────────────

interface TransitionActionsProps {
  lease: LeaseOut;
  isLoading: boolean;
  onTransition: (status: string) => void;
}

function TransitionActions({ lease, isLoading, onTransition }: TransitionActionsProps) {
  const NEXT_STATUSES: Record<string, string[]> = {
    draft: ["upcoming", "active"],
    upcoming: ["active", "ended"],
    active: ["ended"],
    ended: [],
  };

  const next = NEXT_STATUSES[lease.status] ?? [];
  if (next.length === 0) return <span className="text-xs text-muted-foreground">—</span>;

  return (
    <div className="flex items-center gap-1">
      {next.map((s) => (
        <Button
          key={s}
          size="sm"
          variant="outline"
          disabled={isLoading}
          onClick={() => onTransition(s)}
          className="text-xs h-7 px-2"
        >
          → {s}
        </Button>
      ))}
    </div>
  );
}
