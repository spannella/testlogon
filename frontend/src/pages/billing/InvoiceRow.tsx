import { useState } from "react";
import { Download, Mail, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { downloadInvoicePdf, emailInvoice } from "@/api/endpoints/invoices";
import type { Invoice } from "@/api/types";

function formatCents(cents: number, currency: string): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: (currency || "usd").toUpperCase(),
    }).format(cents / 100);
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

function formatDate(ts: number): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function InvoiceRow({ invoice }: { invoice: Invoice }) {
  const [downloading, setDownloading] = useState(false);
  const [emailing, setEmailing] = useState(false);

  const onDownload = async () => {
    setDownloading(true);
    try {
      await downloadInvoicePdf(invoice.invoice_number);
    } catch {
      toast.error("Unable to download invoice PDF");
    } finally {
      setDownloading(false);
    }
  };

  const onEmail = async () => {
    setEmailing(true);
    try {
      const res = await emailInvoice(invoice.invoice_number);
      toast.success(`Invoice emailed${res.emailed_to ? ` to ${res.emailed_to}` : ""}`);
    } catch {
      toast.error("Unable to email invoice");
    } finally {
      setEmailing(false);
    }
  };

  return (
    <Card data-testid="invoice-row" data-invoice-number={invoice.invoice_number}>
      <CardContent className="p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-medium font-mono text-sm">{invoice.invoice_number}</span>
            <Badge variant="secondary" className="capitalize">
              {invoice.invoice_type}
            </Badge>
            {invoice.status === "emailed" && (
              <Badge variant="outline">emailed</Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            {formatDate(invoice.created_at)}
            {invoice.seller_name ? ` · ${invoice.seller_name}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-semibold text-sm">
            {formatCents(invoice.total_cents, invoice.currency)}
          </span>
          <Button
            size="sm"
            variant="outline"
            onClick={onDownload}
            disabled={downloading}
            aria-label="Download PDF"
          >
            {downloading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={onEmail}
            disabled={emailing}
            aria-label="Email invoice"
          >
            {emailing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Mail className="h-4 w-4" />
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default InvoiceRow;
