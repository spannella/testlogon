import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { NotebookPen, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import {
  listGLJournal,
  postGLJournal,
  type GLJournalEntry,
} from "@/api/endpoints/erpFinance";

function fmtCents(c: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(c / 100);
}

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

interface DraftLine {
  account_code: string;
  side: "debit" | "credit";
  amount: string;
}

export default function GLJournalPage() {
  const queryClient = useQueryClient();
  const [start, setStart] = useState(todayIso());
  const [end, setEnd] = useState(todayIso());
  const [postOpen, setPostOpen] = useState(false);
  const [memo, setMemo] = useState("");
  const [glDate, setGlDate] = useState(todayIso());
  const [srcId, setSrcId] = useState("");
  const [lines, setLines] = useState<DraftLine[]>([
    { account_code: "", side: "debit", amount: "" },
    { account_code: "", side: "credit", amount: "" },
  ]);

  const query = useQuery({
    queryKey: ["gl", "journal", { start, end }],
    queryFn: () => listGLJournal(start, end, 100),
    staleTime: 15_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  const totalDebit = lines
    .filter((l) => l.side === "debit")
    .reduce((s, l) => s + (parseInt(l.amount, 10) || 0), 0);
  const totalCredit = lines
    .filter((l) => l.side === "credit")
    .reduce((s, l) => s + (parseInt(l.amount, 10) || 0), 0);
  const balanced = totalDebit > 0 && totalDebit === totalCredit;

  const postMut = useMutation({
    mutationFn: () =>
      postGLJournal({
        lines: lines.map((l) => ({
          account_code: l.account_code.trim(),
          side: l.side,
          amount_cents: parseInt(l.amount, 10) || 0,
        })),
        source_type: "manual_admin",
        source_entity_id: srcId.trim() || `manual-${Date.now()}`,
        memo: memo.trim(),
        gl_date: glDate,
      }),
    onSuccess: () => {
      toast.success("Journal entry posted");
      setPostOpen(false);
      setMemo(""); setSrcId("");
      setLines([
        { account_code: "", side: "debit", amount: "" },
        { account_code: "", side: "credit", amount: "" },
      ]);
      queryClient.invalidateQueries({ queryKey: ["gl", "journal"] });
    },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Post failed"),
  });

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="The GL journal is available only to finance operators."
      />
    );
  }

  const entries = query.data?.entries ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="GL Journal"
        description="Double-entry journal entries by ledger date"
        actions={
          <Button size="sm" onClick={() => setPostOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> Post Entry
          </Button>
        }
      />

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="start">Start date</Label>
          <Input id="start" type="date" value={start} onChange={(e) => setStart(e.target.value)} className="w-40" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="end">End date</Label>
          <Input id="end" type="date" value={end} onChange={(e) => setEnd(e.target.value)} className="w-40" />
        </div>
      </div>

      {query.isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)}
        </div>
      )}

      {!query.isLoading && entries.length === 0 && (
        <EmptyState icon={<NotebookPen className="h-6 w-6" />} title="No journal entries" description="No entries in this date range." />
      )}

      <div className="space-y-3">
        {entries.map((e: GLJournalEntry) => (
          <Card key={e.journal_entry_id}>
            <CardContent className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs">{e.journal_entry_id}</span>
                <span className="text-xs text-muted-foreground">{e.ledger_date}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="capitalize text-muted-foreground">{e.source_type?.replace(/_/g, " ")}</span>
                <span className="font-medium">{fmtCents(e.total_debit_cents)}</span>
              </div>
              {e.memo && <p className="text-sm">{e.memo}</p>}
              {e.lines?.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Account</TableHead>
                      <TableHead>Side</TableHead>
                      <TableHead className="text-right">Amount</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {e.lines.map((l) => (
                      <TableRow key={l.seq}>
                        <TableCell className="font-mono text-xs">
                          {l.account_code}{l.account_name ? ` · ${l.account_name}` : ""}
                        </TableCell>
                        <TableCell className="capitalize">{l.side}</TableCell>
                        <TableCell className="text-right">{fmtCents(l.amount_cents)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <Dialog open={postOpen} onOpenChange={setPostOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader><DialogTitle>Post Journal Entry</DialogTitle></DialogHeader>
          <div className="space-y-3 py-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="gl-date">GL date</Label>
                <Input id="gl-date" type="date" value={glDate} onChange={(e) => setGlDate(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="src-id">Source reference</Label>
                <Input id="src-id" placeholder="optional idempotency ref" value={srcId} onChange={(e) => setSrcId(e.target.value)} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="memo">Memo</Label>
              <Input id="memo" value={memo} onChange={(e) => setMemo(e.target.value)} />
            </div>

            <div className="space-y-2">
              <Label>Lines (amounts in cents; must balance)</Label>
              {lines.map((l, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    placeholder="account code"
                    value={l.account_code}
                    onChange={(e) => setLines(lines.map((x, j) => j === i ? { ...x, account_code: e.target.value } : x))}
                    className="font-mono"
                  />
                  <select
                    value={l.side}
                    onChange={(e) => setLines(lines.map((x, j) => j === i ? { ...x, side: e.target.value as "debit" | "credit" } : x))}
                    className="h-9 rounded-md border bg-background px-2 text-sm"
                  >
                    <option value="debit">debit</option>
                    <option value="credit">credit</option>
                  </select>
                  <Input
                    type="number"
                    placeholder="cents"
                    value={l.amount}
                    onChange={(e) => setLines(lines.map((x, j) => j === i ? { ...x, amount: e.target.value } : x))}
                    className="w-28"
                  />
                  <Button
                    size="icon"
                    variant="ghost"
                    disabled={lines.length <= 2}
                    onClick={() => setLines(lines.filter((_, j) => j !== i))}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
              <Button size="sm" variant="outline" onClick={() => setLines([...lines, { account_code: "", side: "debit", amount: "" }])}>
                <Plus className="mr-1 h-3.5 w-3.5" /> Add line
              </Button>
            </div>

            <div className="flex items-center justify-between rounded-md bg-muted p-2 text-sm">
              <span>Debits {fmtCents(totalDebit)} · Credits {fmtCents(totalCredit)}</span>
              <span className={balanced ? "text-success" : "text-destructive"}>
                {balanced ? "Balanced" : "Unbalanced"}
              </span>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPostOpen(false)}>Cancel</Button>
            <Button
              onClick={() => postMut.mutate()}
              disabled={!balanced || lines.some((l) => !l.account_code.trim()) || postMut.isPending}
            >
              Post Entry
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
