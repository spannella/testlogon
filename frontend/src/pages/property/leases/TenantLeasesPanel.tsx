/**
 * TenantLeasesPanel — Reusable lease history panel for a specific tenant (LSE-004 / LSE-003)
 * Consumed by the TEN tenant-profile page.
 *
 * Prop: tenantId — the tenant's opaque ID
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FileText, AlertTriangle, ChevronRight } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { ApiError } from "@/api/client";
import { listTenantLeases, type LeaseOut, type LeaseStatus } from "@/api/endpoints/leases";

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

// ─── Component ────────────────────────────────────────────────────────────────

interface TenantLeasesPanelProps {
  tenantId: string;
}

export function TenantLeasesPanel({ tenantId }: TenantLeasesPanelProps) {
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const query = useQuery({
    queryKey: ["tenant-leases", tenantId, cursor],
    queryFn: () => listTenantLeases(tenantId, { limit: 20, cursor }),
    enabled: Boolean(tenantId),
    retry: (failCount, error) => {
      if (isFeatureDisabled(error)) return false;
      return failCount < 2;
    },
  });

  const leases: LeaseOut[] = query.data?.leases ?? [];
  const nextCursor = query.data?.next_cursor ?? null;

  if (isFeatureDisabled(query.error)) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <FileText className="w-4 h-4" />
            Lease History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertTriangle className="w-4 h-4" />
            Lease management is not enabled.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <FileText className="w-4 h-4" />
          Lease History
          {query.data && (
            <span className="text-muted-foreground font-normal text-sm">
              ({query.data.count})
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {/* Loading */}
        {query.isLoading && (
          <div className="p-4 space-y-2">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        )}

        {/* Error */}
        {query.isError && !isFeatureDisabled(query.error) && (
          <div className="p-4 text-sm text-destructive">
            Failed to load lease history.
          </div>
        )}

        {/* Empty */}
        {!query.isLoading && !query.isError && leases.length === 0 && (
          <div className="p-6 text-center text-sm text-muted-foreground">
            No leases found for this tenant.
          </div>
        )}

        {/* Table */}
        {leases.length > 0 && (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Lease #</TableHead>
                  <TableHead>Unit</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Term</TableHead>
                  <TableHead>Monthly Rent</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {leases.map((lease) => (
                  <TableRow key={lease.lease_id}>
                    <TableCell className="font-mono text-sm">
                      {lease.lease_number}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {lease.unit_id}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={lease.status} />
                    </TableCell>
                    <TableCell className="text-sm">
                      {fmtDate(lease.start_date)} – {fmtDate(lease.end_date)}
                    </TableCell>
                    <TableCell className="text-sm font-medium">
                      {fmtCents(lease.monthly_rent_cents, lease.currency)}
                      <span className="text-xs text-muted-foreground ml-1">
                        /mo
                      </span>
                    </TableCell>
                    <TableCell>
                      <Link to={`/property/leases/${lease.lease_id}`}>
                        <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                          <ChevronRight className="w-3 h-3" />
                        </Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {nextCursor && (
              <div className="p-3 border-t">
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
          </>
        )}
      </CardContent>
    </Card>
  );
}
