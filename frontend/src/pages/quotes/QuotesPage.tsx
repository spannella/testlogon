import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileText, Loader2, Plus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { createQuote, listQuotes, type QuoteStage } from "@/api/endpoints/quotes";
import { NotEnabledCard } from "./NotEnabledCard";
import {
  LineItemEditor,
  draftToApi,
  emptyLineItem,
  type DraftLineItem,
} from "./LineItemEditor";
import {
  QUOTE_STAGES,
  fmtDate,
  formatCents,
  isNotEnabled,
  quoteStageVariant,
} from "./quotesUtils";

export default function QuotesPage() {
  const qc = useQueryClient();
  const [stageFilter, setStageFilter] = useState<"all" | QuoteStage>("all");
  const [createOpen, setCreateOpen] = useState(false);

  const quotesQuery = useQuery({
    queryKey: ["quotes", "list", stageFilter],
    queryFn: () => listQuotes({ stage: stageFilter === "all" ? undefined : stageFilter, limit: 100 }),
    retry: false,
  });

  // Create form state
  const [title, setTitle] = useState("");
  const [currency, setCurrency] = useState("usd");
  const [notes, setNotes] = useState("");
  const [lines, setLines] = useState<DraftLineItem[]>([emptyLineItem()]);

  const resetForm = () => {
    setTitle("");
    setCurrency("usd");
    setNotes("");
    setLines([emptyLineItem()]);
  };

  const createMut = useMutation({
    mutationFn: () =>
      createQuote({
        title: title.trim(),
        currency: currency.trim() || "usd",
        notes: notes.trim(),
        line_items: lines.map(draftToApi).filter((l) => l.description),
      }),
    onSuccess: () => {
      toast.success("Quote created");
      setCreateOpen(false);
      resetForm();
      qc.invalidateQueries({ queryKey: ["quotes"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to create quote"),
  });

  const canSubmit =
    title.trim().length > 0 &&
    lines.some((l) => l.description.trim().length > 0) &&
    !createMut.isPending;

  if (quotesQuery.isError && isNotEnabled(quotesQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Quotes" description="Sales quotes & estimates" />
        <NotEnabledCard feature="Quotes" />
      </div>
    );
  }

  const quotes = quotesQuery.data?.quotes ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Quotes"
        description="Build sales quotes, track stages, and convert to invoices or contracts."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> New quote
          </Button>
        }
      />

      <div className="flex items-center gap-2">
        <Label htmlFor="stage-filter" className="text-sm text-muted-foreground">
          Stage
        </Label>
        <Select value={stageFilter} onValueChange={(v) => setStageFilter(v as "all" | QuoteStage)}>
          <SelectTrigger id="stage-filter" className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All stages</SelectItem>
            {QUOTE_STAGES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {quotesQuery.isLoading ? (
        <Card>
          <CardContent className="flex items-center justify-center py-16">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </CardContent>
        </Card>
      ) : quotes.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <FileText className="h-10 w-10 text-muted-foreground" />
            <div className="text-lg font-medium">No quotes yet</div>
            <p className="text-sm text-muted-foreground">
              Create your first quote to get started.
            </p>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1 h-4 w-4" /> New quote
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead>Valid until</TableHead>
                  <TableHead>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {quotes.map((q) => (
                  <TableRow key={q.quote_id}>
                    <TableCell className="font-mono text-xs">
                      <Link className="hover:underline" to={`/crm/quotes/${q.quote_id}`}>
                        {q.quote_number || q.quote_id}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link className="font-medium hover:underline" to={`/crm/quotes/${q.quote_id}`}>
                        {q.title}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant={quoteStageVariant(q.stage)} className="capitalize">
                        {q.stage}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(q.total_cents, q.currency)}
                    </TableCell>
                    <TableCell>{fmtDate(q.valid_until)}</TableCell>
                    <TableCell>{fmtDate(q.updated_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={(o) => (o ? setCreateOpen(true) : setCreateOpen(false))}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>New quote</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1 sm:col-span-2">
                <Label htmlFor="q-title">Title</Label>
                <Input
                  id="q-title"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Q3 services proposal"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="q-currency">Currency</Label>
                <Input
                  id="q-currency"
                  value={currency}
                  onChange={(e) => setCurrency(e.target.value)}
                  placeholder="usd"
                />
              </div>
            </div>

            <div className="space-y-1">
              <Label>Line items</Label>
              <LineItemEditor items={lines} currency={currency} onChange={setLines} />
            </div>

            <div className="space-y-1">
              <Label htmlFor="q-notes">Notes</Label>
              <Textarea
                id="q-notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Optional notes for the customer"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button disabled={!canSubmit} onClick={() => createMut.mutate()}>
              {createMut.isPending && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
              Create quote
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
