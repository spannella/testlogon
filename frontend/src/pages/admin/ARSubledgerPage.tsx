import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Receipt } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { ApiError } from "@/api/client";
import { getARAging, type ARAgingItem } from "@/api/endpoints/erpFinance";

function fmtCents(c: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(c / 100);
}

function bucketVariant(bucket: string) {
  switch (bucket) {
    case "current": return "success" as const;
    case "30": return "neutral" as const;
    case "60": return "warning" as const;
    default: return "danger" as const;
  }
}

export default function ARSubledgerPage() {
  const [userFilter, setUserFilter] = useState("");
  const [applied, setApplied] = useState("");

  const query = useQuery({
    queryKey: ["ar", "aging", { applied }],
    queryFn: () => getARAging({ targetUserSub: applied || undefined, limit: 200 }),
    staleTime: 30_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="The AR subledger is available only to finance operators."
      />
    );
  }

  const d = query.data;

  const buckets = d
    ? [
        { label: "Current", cents: d.current_cents, variant: "success" as const },
        { label: "1–30 days", cents: d.days_30_cents, variant: "neutral" as const },
        { label: "31–60 days", cents: d.days_60_cents, variant: "warning" as const },
        { label: "90+ days", cents: d.days_90_plus_cents, variant: "danger" as const },
      ]
    : [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="AR Subledger"
        description="Accounts-receivable open-item aging (read-only view over live invoices)"
      />

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="user">Filter by user sub (optional)</Label>
          <Input
            id="user"
            placeholder="all users"
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            className="w-64"
          />
        </div>
        <Button size="sm" onClick={() => setApplied(userFilter.trim())}>Apply</Button>
      </div>

      {query.isLoading && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}
        </div>
      )}

      {d && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {buckets.map((b) => (
              <Card key={b.label}>
                <CardContent className="p-4">
                  <p className="text-xs text-muted-foreground">{b.label}</p>
                  <p className="mt-1 text-lg font-semibold">{fmtCents(b.cents)}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardContent className="flex items-center justify-between p-4 text-sm">
              <span className="text-muted-foreground">
                {d.open_item_count} open item(s) · sourced from {d.source_invoice_count ?? "?"} invoice(s)
              </span>
              <span className="font-semibold">Total open: {fmtCents(d.total_open_cents)}</span>
            </CardContent>
          </Card>

          {d.items.length === 0 ? (
            <EmptyState icon={<Receipt className="h-6 w-6" />} title="No open receivables" description="Nothing outstanding for this filter." />
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Reference</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead className="text-right">Amount</TableHead>
                      <TableHead className="text-right">Age (days)</TableHead>
                      <TableHead>Bucket</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {d.items.map((it: ARAgingItem, i) => (
                      <TableRow key={`${it.ref_id}-${i}`}>
                        <TableCell className="font-mono text-xs">{it.ref_id || "—"}</TableCell>
                        <TableCell className="text-xs">{it.user_sub || "—"}</TableCell>
                        <TableCell className="text-right">{fmtCents(it.amount_cents)}</TableCell>
                        <TableCell className="text-right">{it.age_days}</TableCell>
                        <TableCell>
                          <StatusBadge variant={bucketVariant(it.bucket)}>
                            {it.bucket === "90_plus" ? "90+" : it.bucket}
                          </StatusBadge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
