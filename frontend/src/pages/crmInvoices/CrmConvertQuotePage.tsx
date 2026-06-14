import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft, ArrowRightLeft, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
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
import {
  listCrmQuotes,
  convertQuoteToInvoice,
  formatCents,
  type CrmQuote,
} from "@/api/endpoints/crmInvoices";
import { CrmFeatureDisabled } from "./CrmFeatureDisabled";

export default function CrmConvertQuotePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [converting, setConverting] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["crm-quotes-convertible"],
    queryFn: () => listCrmQuotes({ limit: 50 }),
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 404 || err.status === 503)) && count < 2,
  });

  const convertMut = useMutation({
    mutationFn: (quoteId: string) => convertQuoteToInvoice(quoteId),
    onMutate: (quoteId) => setConverting(quoteId),
    onSuccess: (inv) => {
      toast.success(`Created invoice ${inv.invoice_number}`);
      qc.invalidateQueries({ queryKey: ["crm-invoices"] });
      qc.invalidateQueries({ queryKey: ["crm-quotes-convertible"] });
      navigate(`/crm/invoices/${encodeURIComponent(inv.invoice_number)}`);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        toast.error("This quote has already been converted.");
      } else {
        toast.error(e instanceof ApiError ? e.detail : "Conversion failed");
      }
      qc.invalidateQueries({ queryKey: ["crm-quotes-convertible"] });
    },
    onSettled: () => setConverting(null),
  });

  if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 503)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Convert Quote to Invoice" />
        <CrmFeatureDisabled
          title="AOS Quotes not enabled"
          message="The SuiteCRM quotes feature is disabled, so there are no quotes to convert. Ask an administrator to enable AOS_QUOTES_ENABLED."
        />
      </div>
    );
  }

  const quotes: CrmQuote[] = query.data?.quotes ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Convert Quote to Invoice"
        description="Generate a SuiteCRM AOS invoice from an existing quote."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => query.refetch()}>
              <RefreshCw className="mr-1 h-4 w-4" />
              Refresh
            </Button>
            <Button variant="ghost" size="sm" onClick={() => navigate("/crm/invoices")}>
              <ArrowLeft className="mr-1 h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Quotes</CardTitle>
        </CardHeader>
        <CardContent>
          {query.isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : quotes.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              No quotes available to convert.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Quote #</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead className="text-right">Tax</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {quotes.map((q) => {
                  const already = !!q.converted_to_invoice_number;
                  return (
                    <TableRow key={q.quote_id}>
                      <TableCell className="font-medium">{q.quote_number}</TableCell>
                      <TableCell>{q.title || "—"}</TableCell>
                      <TableCell className="capitalize">{q.stage}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {formatCents(q.tax_cents, q.currency)}
                      </TableCell>
                      <TableCell className="text-right font-medium tabular-nums">
                        {formatCents(q.total_cents, q.currency)}
                      </TableCell>
                      <TableCell className="text-right">
                        {already ? (
                          <Badge variant="secondary">
                            → {q.converted_to_invoice_number}
                          </Badge>
                        ) : (
                          <Button
                            size="sm"
                            disabled={converting === q.quote_id || convertMut.isPending}
                            onClick={() => convertMut.mutate(q.quote_id)}
                          >
                            <ArrowRightLeft className="mr-1 h-4 w-4" />
                            {converting === q.quote_id ? "Converting…" : "Convert"}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
