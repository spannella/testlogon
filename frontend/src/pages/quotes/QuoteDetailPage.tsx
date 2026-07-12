import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, FileSignature, Loader2, Receipt, Save } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/api/client";
import {
  convertQuoteToContract,
  convertQuoteToInvoice,
  getQuote,
  patchQuote,
  transitionQuoteStage,
  type Quote,
  type QuoteStage,
} from "@/api/endpoints/quotes";
import { NotEnabledCard } from "./NotEnabledCard";
import {
  LineItemEditor,
  draftToApi,
  type DraftLineItem,
} from "./LineItemEditor";
import {
  QUOTE_TRANSITIONS,
  centsToDollarsInput,
  fmtDate,
  formatCents,
  isNotEnabled,
  quoteStageVariant,
} from "./quotesUtils";

export default function QuoteDetailPage() {
  const { quoteId = "" } = useParams();
  const qc = useQueryClient();
  const navigate = useNavigate();

  const quoteQuery = useQuery({
    queryKey: ["quotes", "detail", quoteId],
    queryFn: () => getQuote(quoteId),
    retry: false,
    enabled: !!quoteId,
  });

  const quote = quoteQuery.data;
  const locked = quote?.stage === "converted";

  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const [lines, setLines] = useState<DraftLineItem[]>([]);

  useEffect(() => {
    if (!quote) return;
    setTitle(quote.title);
    setNotes(quote.notes ?? "");
    setLines(
      quote.line_items.map((li) => ({
        description: li.description,
        qty: li.qty,
        unitPriceInput: centsToDollarsInput(li.unit_price_cents),
        discountPct: (li.discount_bps ?? 0) / 100,
        taxPct: (li.tax_rate_bps ?? 0) / 100,
      })),
    );
  }, [quote]);

  const saveMut = useMutation({
    mutationFn: () =>
      patchQuote(quoteId, {
        title: title.trim(),
        notes: notes.trim(),
        line_items: lines.map(draftToApi).filter((l) => l.description),
      }),
    onSuccess: () => {
      toast.success("Quote saved");
      qc.invalidateQueries({ queryKey: ["quotes"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to save"),
  });

  const stageMut = useMutation({
    mutationFn: (stage: QuoteStage) => transitionQuoteStage(quoteId, stage),
    onSuccess: (_d, stage) => {
      toast.success(`Quote marked ${stage}`);
      qc.invalidateQueries({ queryKey: ["quotes"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Stage change failed"),
  });

  const invoiceMut = useMutation({
    mutationFn: () => convertQuoteToInvoice(quoteId),
    onSuccess: (inv) => {
      toast.success(`Invoice ${inv.invoice_number} created`);
      qc.invalidateQueries({ queryKey: ["quotes"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Conversion failed"),
  });

  const contractMut = useMutation({
    mutationFn: () => convertQuoteToContract(quoteId),
    onSuccess: (c) => {
      toast.success(`Contract ${c.contract_number} created`);
      qc.invalidateQueries({ queryKey: ["quotes"] });
      qc.invalidateQueries({ queryKey: ["contracts"] });
      navigate(`/crm/contracts/${c.contract_id}`);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Conversion failed"),
  });

  if (quoteQuery.isError && isNotEnabled(quoteQuery.error)) {
    return (
      <div className="space-y-6">
        <BackLink />
        <NotEnabledCard feature="Quotes" />
      </div>
    );
  }

  if (quoteQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (quoteQuery.isError || !quote) {
    return (
      <div className="space-y-6">
        <BackLink />
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            Quote not found.
          </CardContent>
        </Card>
      </div>
    );
  }

  const nextStages = QUOTE_TRANSITIONS[quote.stage] ?? [];

  return (
    <div className="space-y-6">
      <BackLink />
      <PageHeader
        title={quote.title}
        description={`${quote.quote_number} · created ${fmtDate(quote.created_at)}`}
        actions={
          <Badge variant={quoteStageVariant(quote.stage)} className="capitalize">
            {quote.stage}
          </Badge>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1">
                <Label htmlFor="d-title">Title</Label>
                <Input
                  id="d-title"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  disabled={locked}
                />
              </div>
              <div className="space-y-1">
                <Label>Line items</Label>
                {locked ? (
                  <ReadOnlyLineItems quote={quote} />
                ) : (
                  <LineItemEditor items={lines} currency={quote.currency} onChange={setLines} />
                )}
              </div>
              <div className="space-y-1">
                <Label htmlFor="d-notes">Notes</Label>
                <Textarea
                  id="d-notes"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  disabled={locked}
                />
              </div>
              {!locked && (
                <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
                  {saveMut.isPending ? (
                    <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="mr-1 h-4 w-4" />
                  )}
                  Save changes
                </Button>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Totals</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <Row label="Subtotal" value={formatCents(quote.subtotal_cents, quote.currency)} />
              <Row label="Discount" value={`-${formatCents(quote.discount_cents, quote.currency)}`} />
              <Row label="Tax" value={formatCents(quote.tax_cents, quote.currency)} />
              <div className="flex justify-between border-t pt-2 text-base font-semibold">
                <span>Total</span>
                <span className="tabular-nums">{formatCents(quote.total_cents, quote.currency)}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Stage</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {nextStages.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No further stage transitions available.
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {nextStages
                    .filter((s) => s !== "converted")
                    .map((s) => (
                      <Button
                        key={s}
                        variant="outline"
                        size="sm"
                        className="capitalize"
                        disabled={stageMut.isPending}
                        onClick={() => stageMut.mutate(s)}
                      >
                        Mark {s}
                      </Button>
                    ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Convert</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {quote.converted_to_invoice_number ? (
                <p className="text-sm text-muted-foreground">
                  Converted to invoice{" "}
                  <span className="font-mono">{quote.converted_to_invoice_number}</span>.
                </p>
              ) : null}
              {quote.converted_to_contract_id ? (
                <p className="text-sm text-muted-foreground">
                  Converted to{" "}
                  <Link
                    className="underline"
                    to={`/crm/contracts/${quote.converted_to_contract_id}`}
                  >
                    contract
                  </Link>
                  .
                </p>
              ) : null}
              <Button
                variant="secondary"
                className="w-full"
                disabled={invoiceMut.isPending || locked}
                onClick={() => invoiceMut.mutate()}
              >
                {invoiceMut.isPending ? (
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                ) : (
                  <Receipt className="mr-1 h-4 w-4" />
                )}
                Convert to invoice
              </Button>
              <Button
                variant="secondary"
                className="w-full"
                disabled={contractMut.isPending || locked}
                onClick={() => contractMut.mutate()}
              >
                {contractMut.isPending ? (
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                ) : (
                  <FileSignature className="mr-1 h-4 w-4" />
                )}
                Convert to contract
              </Button>
              {locked && (
                <p className="text-xs text-muted-foreground">
                  This quote has been converted and is read-only.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/crm/quotes"
      className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="mr-1 h-4 w-4" /> Back to quotes
    </Link>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="tabular-nums">{value}</span>
    </div>
  );
}

function ReadOnlyLineItems({ quote }: { quote: Quote }) {
  return (
    <div className="rounded-md border divide-y">
      {quote.line_items.map((li, i) => (
        <div key={i} className="flex items-center justify-between px-3 py-2 text-sm">
          <span>
            {li.qty} × {li.description}
          </span>
          <span className="tabular-nums">{formatCents(li.line_total_cents, quote.currency)}</span>
        </div>
      ))}
    </div>
  );
}
