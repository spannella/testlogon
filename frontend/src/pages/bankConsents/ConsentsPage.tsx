/**
 * ConsentsPage — CSN-001 / CSN-003 / CSN-005
 *
 * Lists all PSD2 consents granted by the current user to third parties.
 * Handles feature flag off (404/503) gracefully.
 *
 * Route: /bank/consents
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheck,
  Plus,
  AlertCircle,
  Loader2,
  RefreshCw,
  ChevronRight,
  InboxIcon,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  listOwnConsents,
  type ConsentOut,
  type ConsentStatus,
} from "@/api/endpoints/psd2Consents";
import { STATUS_BADGE, STATUS_LABEL, typeLabel, fmtDate } from "./consentUtils";

// ─── Status filter options ────────────────────────────────────────────────────

const STATUS_OPTIONS: { label: string; value: ConsentStatus | "" }[] = [
  { label: "All statuses", value: "" },
  { label: "Initiated", value: "INITIATED" },
  { label: "Accepted", value: "ACCEPTED" },
  { label: "Revoked", value: "REVOKED" },
  { label: "Expired", value: "EXPIRED" },
];

// ─── Feature-disabled state ───────────────────────────────────────────────────

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
      <AlertCircle className="h-12 w-12 text-muted-foreground" />
      <div>
        <p className="font-semibold text-lg">PSD2 Consents not enabled</p>
        <p className="text-sm text-muted-foreground mt-1">
          This feature requires OPEN_BANK_PROJECT_ENABLED and PSD2_CONSENTS_ENABLED to be active.
        </p>
      </div>
    </div>
  );
}

// ─── Consent row ─────────────────────────────────────────────────────────────

function ConsentRow({ consent }: { consent: ConsentOut }) {
  return (
    <Link
      to={`/bank/consents/${consent.consent_id}`}
      className="flex items-center justify-between rounded-md border p-3 hover:bg-muted/40 transition-colors group"
      data-testid={`consent-row-${consent.consent_id}`}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm truncate">{consent.consumer_ref}</span>
          <Badge
            variant="outline"
            className={`text-xs ${STATUS_BADGE[consent.status as ConsentStatus] ?? ""}`}
          >
            {STATUS_LABEL[consent.status as ConsentStatus] ?? consent.status}
          </Badge>
          <Badge variant="secondary" className="text-xs">
            {typeLabel(consent.consent_type)}
          </Badge>
        </div>
        <div className="mt-1 text-xs text-muted-foreground flex flex-wrap gap-3">
          <span>Accounts: {consent.account_refs.join(", ") || "—"}</span>
          <span>Valid until: {fmtDate(consent.valid_until)}</span>
          {consent.recurring && <span className="text-blue-600 dark:text-blue-400">Recurring</span>}
        </div>
      </div>
      <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors ml-2" />
    </Link>
  );
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────

function ConsentSkeleton() {
  return (
    <div className="space-y-2">
      {[1, 2, 3].map((i) => (
        <Skeleton key={i} className="h-16 w-full rounded-md" />
      ))}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ConsentsPage() {
  const [statusFilter, setStatusFilter] = useState<ConsentStatus | "">("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const query = useQuery({
    queryKey: ["psd2-consents", "list", statusFilter, cursor],
    queryFn: () =>
      listOwnConsents({
        status: statusFilter || undefined,
        limit: 20,
        cursor,
      }),
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        return false;
      }
      return failureCount < 2;
    },
  });

  const isDisabled =
    query.isError &&
    query.error instanceof ApiError &&
    (query.error.status === 404 || query.error.status === 503);

  const consents = query.data?.consents ?? [];
  const nextCursor = query.data?.cursor ?? null;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="PSD2 Consents"
        description="Manage third-party access consents granted to your accounts."
      />

      {isDisabled ? (
        <FeatureDisabled />
      ) : (
        <div className="space-y-4">
          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-3">
            <Select
              value={statusFilter}
              onValueChange={(v) => {
                setStatusFilter(v as ConsentStatus | "");
                setCursor(undefined);
              }}
            >
              <SelectTrigger className="w-44" data-testid="status-filter">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                {STATUS_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button
              variant="outline"
              size="sm"
              onClick={() => void query.refetch()}
              disabled={query.isFetching}
              data-testid="refresh-btn"
            >
              {query.isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              <span className="ml-1">Refresh</span>
            </Button>

            <Button asChild size="sm" data-testid="create-consent-btn">
              <Link to="/bank/consents/new">
                <Plus className="h-4 w-4 mr-1" />
                New consent
              </Link>
            </Button>
          </div>

          {/* Consent list */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldCheck className="h-5 w-5" />
                Granted consents
              </CardTitle>
              <CardDescription>
                Consents you have granted to third-party applications.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {query.isLoading && <ConsentSkeleton />}

              {!query.isLoading && !query.isError && consents.length === 0 && (
                <div className="flex flex-col items-center justify-center py-10 gap-3 text-center">
                  <InboxIcon className="h-8 w-8 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">No consents found.</p>
                  <Button asChild variant="outline" size="sm">
                    <Link to="/bank/consents/new">Grant your first consent</Link>
                  </Button>
                </div>
              )}

              {!query.isLoading &&
                query.isError &&
                !isDisabled && (
                  <div className="flex items-center gap-2 text-destructive text-sm py-4">
                    <AlertCircle className="h-4 w-4" />
                    {query.error instanceof ApiError
                      ? query.error.detail
                      : "Failed to load consents."}
                  </div>
                )}

              {consents.map((c) => (
                <ConsentRow key={c.consent_id} consent={c} />
              ))}
            </CardContent>
          </Card>

          {/* Pagination */}
          {(cursor || nextCursor) && (
            <div className="flex gap-2">
              {cursor && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCursor(undefined)}
                  data-testid="prev-page-btn"
                >
                  First page
                </Button>
              )}
              {nextCursor && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCursor(nextCursor)}
                  disabled={query.isFetching}
                  data-testid="next-page-btn"
                >
                  Next page
                </Button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
