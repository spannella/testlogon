import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { FileText, RefreshCw, Settings2, ArrowRightLeft } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  listCrmInvoices,
  formatCents,
  type CrmInvoice,
} from "@/api/endpoints/crmInvoices";
import { CrmFeatureDisabled } from "./CrmFeatureDisabled";

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "paid":
      return "default";
    case "void":
      return "destructive";
    case "sent":
    case "emailed":
      return "secondary";
    default:
      return "outline";
  }
}

export default function CrmInvoicesPage() {
  const [typeFilter, setTypeFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  const query = useQuery({
    queryKey: ["crm-invoices", { typeFilter, cursor }],
    queryFn: () =>
      listCrmInvoices({
        type: typeFilter.trim() || undefined,
        limit: 25,
        cursor,
      }),
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 404 || err.status === 503)) && count < 2,
  });

  if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 503)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="CRM Invoices"
          description="SuiteCRM AOS invoices — line items, currency, tax & totals."
        />
        <CrmFeatureDisabled
          title="Invoices not enabled"
          message="The SuiteCRM invoices feature is currently disabled. Ask an administrator to enable INVOICES_ENABLED."
        />
      </div>
    );
  }

  const invoices: CrmInvoice[] = query.data?.invoices ?? [];
  const nextCursor = query.data?.next_cursor ?? null;

  const goNext = () => {
    if (!nextCursor) return;
    setCursorStack((s) => [...s, cursor ?? ""]);
    setCursor(nextCursor);
  };
  const goPrev = () => {
    setCursorStack((s) => {
      const copy = [...s];
      const prev = copy.pop();
      setCursor(prev || undefined);
      return copy;
    });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="CRM Invoices"
        description="SuiteCRM AOS invoices — line items, currency, tax & totals."
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <Link to="/crm/invoices/convert">
                <ArrowRightLeft className="mr-1 h-4 w-4" />
                Convert from Quote
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to="/crm/billing-settings">
                <Settings2 className="mr-1 h-4 w-4" />
                Currency &amp; Tax
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => query.refetch()}>
              <RefreshCw className="mr-1 h-4 w-4" />
              Refresh
            </Button>
          </div>
        }
      />

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-end justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="h-4 w-4" />
            Invoices
          </CardTitle>
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="type-filter" className="text-xs">
                Type
              </Label>
              <Input
                id="type-filter"
                placeholder="shop, subscription…"
                className="h-8 w-44"
                value={typeFilter}
                onChange={(e) => {
                  setTypeFilter(e.target.value);
                  setCursor(undefined);
                  setCursorStack([]);
                }}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {query.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : invoices.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              No invoices found.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Invoice #</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Buyer</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Tax</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {invoices.map((inv) => (
                  <TableRow key={inv.invoice_id}>
                    <TableCell className="font-medium">
                      <Link
                        to={`/crm/invoices/${encodeURIComponent(inv.invoice_number)}`}
                        className="text-primary hover:underline"
                      >
                        {inv.invoice_number}
                      </Link>
                      {inv.aos_quote_id && (
                        <Badge variant="outline" className="ml-2 text-[10px]">
                          from quote
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="capitalize">{inv.invoice_type}</TableCell>
                    <TableCell>{inv.buyer_name || inv.buyer_email || "—"}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(inv.status)} className="capitalize">
                        {inv.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(inv.tax_cents, inv.currency)}
                    </TableCell>
                    <TableCell className="text-right font-medium tabular-nums">
                      {formatCents(inv.total_cents, inv.currency)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {fmtDate(inv.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="mt-4 flex items-center justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={cursorStack.length === 0}
              onClick={goPrev}
            >
              Previous
            </Button>
            <Button variant="outline" size="sm" disabled={!nextCursor} onClick={goNext}>
              Next
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
