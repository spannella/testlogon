/**
 * VEW-003 — Read resource data through a view (authenticated).
 *
 * Route: /bank/views/read/:resourceType/:resourceId/:viewId
 *
 * Displays the field-projected data for a financial resource
 * as permitted by the named view. Works for both resource owners
 * and active grantees.
 */

import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, AlertCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  readResourceThroughView,
  type ResourceType,
} from "@/api/endpoints/accountViews";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtCents(cents: unknown): string {
  if (cents == null || cents === "") return "—";
  const num = Number(cents);
  if (isNaN(num)) return String(cents);
  return (num / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });
}

function fmtTs(ts: unknown): string {
  if (!ts) return "—";
  const num = Number(ts);
  if (isNaN(num)) return String(ts);
  return new Date(num * 1000).toLocaleString();
}

function humanizeKey(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Data renderers ───────────────────────────────────────────────────────────

function WalletDataPanel({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
      {data["wallet_balance_cents"] != null && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Balance</p>
          <p className="text-2xl font-bold">{fmtCents(data["wallet_balance_cents"])}</p>
        </div>
      )}
      {data["available_balance_cents"] != null && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Available</p>
          <p className="text-xl font-semibold">{fmtCents(data["available_balance_cents"])}</p>
        </div>
      )}
      {data["currency"] != null && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Currency</p>
          <p className="text-sm font-medium uppercase">{String(data["currency"])}</p>
        </div>
      )}
      {data["label"] != null && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Label</p>
          <p className="text-sm">{String(data["label"])}</p>
        </div>
      )}
      {data["updated_at"] != null && (
        <div className="space-y-1 col-span-2">
          <p className="text-xs text-muted-foreground">Last updated</p>
          <p className="text-sm">{fmtTs(data["updated_at"])}</p>
        </div>
      )}
    </div>
  );
}

function LedgerDataPanel({ data }: { data: Record<string, unknown> }) {
  const summary = data["balance_summary"] as Record<string, unknown> | undefined;
  const txList = data["transaction_list"] as Record<string, unknown>[] | undefined;

  return (
    <div className="space-y-4">
      {summary && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Total settled balance</p>
          <p className="text-2xl font-bold">
            {fmtCents(summary["total_settled_cents"])}
          </p>
          <p className="text-xs text-muted-foreground uppercase">
            {String(summary["currency"] ?? "usd")}
          </p>
        </div>
      )}
      {txList && txList.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-semibold">Transactions ({txList.length})</p>
          <div className="rounded-md border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  {txList[0] && Object.keys(txList[0]).map((k) => (
                    <th key={k} className="px-3 py-2 text-left text-xs font-medium text-muted-foreground">
                      {humanizeKey(k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y">
                {txList.map((row, i) => (
                  <tr key={i} className="hover:bg-muted/30">
                    {Object.entries(row).map(([k, v]) => (
                      <td key={k} className="px-3 py-2 text-xs">
                        {k.includes("cents")
                          ? fmtCents(v)
                          : k === "ts" || k.endsWith("_at")
                          ? fmtTs(v)
                          : v == null
                          ? "—"
                          : String(v)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {txList && txList.length === 0 && (
        <p className="text-sm text-muted-foreground">No transactions visible through this view.</p>
      )}
    </div>
  );
}

function PayoutDataPanel({ data }: { data: Record<string, unknown> }) {
  const rows: { label: string; value: string }[] = [];

  const push = (label: string, key: string, fmt?: (v: unknown) => string) => {
    if (data[key] != null) {
      rows.push({ label, value: fmt ? fmt(data[key]) : String(data[key]) });
    }
  };

  push("Method", "method");
  push("Method ID", "method_id");
  push("Status", "status");
  push("Amount", "amount_cents", fmtCents);
  push("Notes", "notes");
  push("Reject reason", "reject_reason");
  push("Approved by", "approved_by");
  push("Created", "created_at", fmtTs);
  push("Updated", "updated_at", fmtTs);
  push("Completed", "completed_at", fmtTs);

  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
      {rows.map((r) => (
        <div key={r.label} className="space-y-0.5">
          <dt className="text-xs text-muted-foreground">{r.label}</dt>
          <dd className="text-sm font-medium">{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function GenericDataPanel({ data }: { data: Record<string, unknown> }) {
  const displayEntries = Object.entries(data).filter(
    ([k]) => !["resource_type", "resource_id", "payout_id", "user_id"].includes(k),
  );

  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
      {displayEntries.map(([k, v]) => (
        <div key={k} className="space-y-0.5">
          <dt className="text-xs text-muted-foreground">{humanizeKey(k)}</dt>
          <dd className="text-sm font-medium">
            {v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ViewResourcePage() {
  const { resourceType, resourceId, viewId } = useParams<{
    resourceType: string;
    resourceId: string;
    viewId: string;
  }>();

  const dataQ = useQuery({
    queryKey: ["account-views", "data", resourceType, resourceId, viewId],
    queryFn: () =>
      readResourceThroughView(
        resourceType as ResourceType,
        resourceId!,
        viewId!,
      ),
    enabled: !!resourceType && !!resourceId && !!viewId,
    retry: false,
  });

  const featureOff =
    dataQ.isError &&
    dataQ.error instanceof ApiError &&
    (dataQ.error.status === 404 || dataQ.error.status === 503);

  const noAccess =
    dataQ.isError &&
    dataQ.error instanceof ApiError &&
    dataQ.error.status === 403;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/bank/views">
            <ArrowLeft className="h-4 w-4 mr-1" /> Back to views
          </Link>
        </Button>
      </div>

      <PageHeader
        title="Resource Data"
        description={`Viewing ${resourceType ?? "resource"} through view ${viewId ?? ""}`}
      />

      {dataQ.isLoading && (
        <div className="space-y-4">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-32 w-full rounded-lg" />
        </div>
      )}

      {featureOff && (
        <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
          <AlertCircle className="h-12 w-12 text-muted-foreground" />
          <p className="text-lg font-semibold text-muted-foreground">Account Views not enabled</p>
        </div>
      )}

      {noAccess && (
        <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
          <AlertCircle className="h-12 w-12 text-muted-foreground" />
          <p className="text-lg font-semibold text-muted-foreground">No access</p>
          <p className="text-sm text-muted-foreground max-w-sm">
            You do not have an active grant for this view, or the grant has been revoked.
          </p>
        </div>
      )}

      {dataQ.isError && !featureOff && !noAccess && (
        <p className="text-sm text-destructive">
          {dataQ.error instanceof Error ? dataQ.error.message : "Failed to load resource data"}
        </p>
      )}

      {dataQ.data && (
        <div className="space-y-4">
          {/* Provenance banner */}
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="pt-4 pb-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-medium">{dataQ.data._view.view_name || viewId}</span>
                {dataQ.data._view.preset && (
                  <Badge variant="outline" className="text-xs capitalize">
                    {dataQ.data._view.preset}
                  </Badge>
                )}
                <span className="text-muted-foreground text-xs">
                  Visible fields:{" "}
                  {dataQ.data._view.granted_fields.length === 0
                    ? "none"
                    : dataQ.data._view.granted_fields.join(", ")}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Resource data */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base capitalize">
                {dataQ.data.resource_type.replace(/_/g, " ")}
              </CardTitle>
              <CardDescription className="font-mono text-xs">
                {dataQ.data.resource_id}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {dataQ.data.resource_type === "wallet" && (
                <WalletDataPanel data={dataQ.data.data} />
              )}
              {dataQ.data.resource_type === "ledger_account" && (
                <LedgerDataPanel data={dataQ.data.data} />
              )}
              {dataQ.data.resource_type === "payout_destination" && (
                <PayoutDataPanel data={dataQ.data.data} />
              )}
              {!["wallet", "ledger_account", "payout_destination"].includes(
                dataQ.data.resource_type,
              ) && <GenericDataPanel data={dataQ.data.data} />}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
