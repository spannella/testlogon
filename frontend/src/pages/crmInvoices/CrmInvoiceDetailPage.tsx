import { useParams, Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Ban,
  Download,
  Mail,
  Send,
  CheckCircle2,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError, withApiBase } from "@/api/client";
import {
  getCrmInvoice,
  sendCrmInvoice,
  voidCrmInvoice,
  payCrmInvoice,
  emailCrmInvoice,
  crmInvoicePdfUrl,
  formatCents,
} from "@/api/endpoints/crmInvoices";
import { CrmFeatureDisabled } from "./CrmFeatureDisabled";

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
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

export default function CrmInvoiceDetailPage() {
  const { invoiceNumber = "" } = useParams<{ invoiceNumber: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const query = useQuery({
    queryKey: ["crm-invoice", invoiceNumber],
    queryFn: () => getCrmInvoice(invoiceNumber),
    enabled: !!invoiceNumber,
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 404 || err.status === 503)) && count < 2,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["crm-invoice", invoiceNumber] });
    qc.invalidateQueries({ queryKey: ["crm-invoices"] });
  };

  const sendMut = useMutation({
    mutationFn: () => sendCrmInvoice(invoiceNumber),
    onSuccess: () => {
      toast.success("Invoice marked as sent");
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to send invoice"),
  });

  const voidMut = useMutation({
    mutationFn: () => voidCrmInvoice(invoiceNumber),
    onSuccess: () => {
      toast.success("Invoice voided");
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to void invoice"),
  });

  const payMut = useMutation({
    mutationFn: () => payCrmInvoice(invoiceNumber),
    onSuccess: () => {
      toast.success("Invoice marked as paid");
      invalidate();
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to mark paid"),
  });

  const emailMut = useMutation({
    mutationFn: () => emailCrmInvoice(invoiceNumber),
    onSuccess: (r) => {
      toast.success(r.emailed_to ? `Emailed to ${r.emailed_to}` : "Invoice emailed");
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to email invoice"),
  });

  if (query.error instanceof ApiError && query.error.status === 404) {
    return (
      <div className="space-y-6">
        <PageHeader title="Invoice" />
        <CrmFeatureDisabled
          title="Invoice not found"
          message="This invoice does not exist, or invoices are not enabled."
        />
      </div>
    );
  }

  const inv = query.data;
  const busy = sendMut.isPending || voidMut.isPending || payMut.isPending || emailMut.isPending;
  const isVoid = inv?.status === "void";
  const isPaid = inv?.status === "paid";

  return (
    <div className="space-y-6">
      <PageHeader
        title={inv ? `Invoice ${inv.invoice_number}` : "Invoice"}
        description={inv ? `${inv.invoice_type} · ${inv.currency.toUpperCase()}` : undefined}
        actions={
          <Button variant="ghost" size="sm" onClick={() => navigate("/crm/invoices")}>
            <ArrowLeft className="mr-1 h-4 w-4" />
            Back
          </Button>
        }
      />

      {query.isLoading ? (
        <Card>
          <CardContent className="space-y-3 py-6">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-32 w-full" />
          </CardContent>
        </Card>
      ) : !inv ? null : (
        <>
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <CardTitle className="text-base">{inv.invoice_number}</CardTitle>
                <Badge variant={statusVariant(inv.status)} className="capitalize">
                  {inv.status}
                </Badge>
                {inv.aos_quote_id && (
                  <Badge variant="outline" className="text-[10px]">
                    converted from quote {inv.aos_quote_id}
                  </Badge>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy || isVoid}
                  onClick={() => sendMut.mutate()}
                >
                  <Send className="mr-1 h-4 w-4" />
                  Send
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => emailMut.mutate()}
                >
                  <Mail className="mr-1 h-4 w-4" />
                  Email
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy || isVoid || isPaid}
                  onClick={() => payMut.mutate()}
                >
                  <CheckCircle2 className="mr-1 h-4 w-4" />
                  Mark Paid
                </Button>
                <Button asChild variant="outline" size="sm">
                  <a href={withApiBase(crmInvoicePdfUrl(inv.invoice_number))} target="_blank" rel="noreferrer">
                    <Download className="mr-1 h-4 w-4" />
                    PDF
                  </a>
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={busy || isVoid}
                  onClick={() => voidMut.mutate()}
                >
                  <Ban className="mr-1 h-4 w-4" />
                  Void
                </Button>
              </div>
            </CardHeader>
            <CardContent className="grid gap-6 md:grid-cols-2">
              <div className="space-y-1 text-sm">
                <div className="text-xs font-medium uppercase text-muted-foreground">Bill To</div>
                <div className="font-medium">{inv.buyer_name || "—"}</div>
                <div className="text-muted-foreground">{inv.buyer_email || "—"}</div>
              </div>
              <div className="space-y-1 text-sm">
                <div className="text-xs font-medium uppercase text-muted-foreground">Details</div>
                <div>
                  <span className="text-muted-foreground">Created: </span>
                  {fmtDate(inv.created_at)}
                </div>
                <div>
                  <span className="text-muted-foreground">Due: </span>
                  {inv.due_date ? fmtDate(inv.due_date) : "—"}
                </div>
                {inv.payment_terms_days != null && (
                  <div>
                    <span className="text-muted-foreground">Terms: </span>
                    {inv.payment_terms_days} days
                  </div>
                )}
                {inv.seller_name && (
                  <div>
                    <span className="text-muted-foreground">Seller: </span>
                    {inv.seller_name}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Line Items</CardTitle>
            </CardHeader>
            <CardContent>
              {inv.line_items.length === 0 ? (
                <div className="py-6 text-center text-sm text-muted-foreground">
                  No line items.
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Description</TableHead>
                      <TableHead className="text-right">Qty</TableHead>
                      <TableHead className="text-right">Unit Price</TableHead>
                      <TableHead className="text-right">Amount</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {inv.line_items.map((li, idx) => (
                      <TableRow key={idx}>
                        <TableCell>{li.description}</TableCell>
                        <TableCell className="text-right tabular-nums">{li.quantity}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {formatCents(li.unit_price_cents, inv.currency)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {formatCents(li.amount_cents, inv.currency)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}

              <Separator className="my-4" />

              <div className="ml-auto w-full max-w-xs space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Subtotal</span>
                  <span className="tabular-nums">{formatCents(inv.amount_cents, inv.currency)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Tax</span>
                  <span className="tabular-nums">{formatCents(inv.tax_cents, inv.currency)}</span>
                </div>
                <Separator className="my-1" />
                <div className="flex justify-between text-base font-semibold">
                  <span>Total</span>
                  <span className="tabular-nums">{formatCents(inv.total_cents, inv.currency)}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="text-xs text-muted-foreground">
            Need to create a new invoice?{" "}
            <Link to="/crm/invoices/convert" className="text-primary hover:underline">
              Convert from a quote
            </Link>
            .
          </div>
        </>
      )}
    </div>
  );
}
