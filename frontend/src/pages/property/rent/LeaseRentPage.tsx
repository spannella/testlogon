/**
 * LeaseRentPage — Per-lease rent ledger: charges, payments, running balance
 * Route: /property/rent/leases/:leaseId
 *
 * RNT-002 (record payment), RNT-003 (history + void), RNT-005 (charge now)
 * Flag off → 404/503; shows a "not enabled" state.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  PlusCircle,
  XCircle,
  Zap,
  Receipt,
  TrendingDown,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

import { ApiError } from "@/api/client";
import {
  getRentLedger,
  getRentCharges,
  recordRentPayment,
  chargeLeaseNow,
  voidRentRow,
  type RentLedgerRowOut,
  type RentPaymentMethod,
} from "@/api/endpoints/rentLedger";

// ─── Helpers ────────────────────────────────────────────────────────────────

function fmtCents(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function statusVariant(status?: string | null): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "paid":
      return "default";
    case "partial":
      return "secondary";
    case "overdue":
      return "destructive";
    case "voided":
      return "outline";
    default:
      return "secondary";
  }
}

function kindBadge(kind: string) {
  return kind === "charge" ? (
    <Badge variant="outline" className="text-orange-600 border-orange-400">
      Charge
    </Badge>
  ) : (
    <Badge variant="outline" className="text-green-600 border-green-400">
      Payment
    </Badge>
  );
}

// ─── Running balance row ─────────────────────────────────────────────────────

function computeRunningBalance(rows: RentLedgerRowOut[]): (RentLedgerRowOut & { running_cents: number })[] {
  // rows are newest-first from API; reverse to compute running balance oldest-first
  const sorted = [...rows].reverse();
  let balance = 0;
  const out = sorted.map((r) => {
    if (r.state !== "reversed") {
      if (r.rent_kind === "charge") balance += r.amount_cents;
      else if (r.rent_kind === "payment") balance -= r.amount_cents;
    }
    return { ...r, running_cents: balance };
  });
  return out.reverse(); // back to newest-first
}

// ─── Record Payment Dialog ───────────────────────────────────────────────────

const METHODS: { value: RentPaymentMethod; label: string }[] = [
  { value: "cash", label: "Cash" },
  { value: "check", label: "Check" },
  { value: "bank_transfer", label: "Bank Transfer" },
  { value: "card_external", label: "External Card" },
  { value: "other", label: "Other" },
];

interface RecordPaymentDialogProps {
  leaseId: string;
  open: boolean;
  onClose: () => void;
  currentPeriod: string;
}

function RecordPaymentDialog({ leaseId, open, onClose, currentPeriod }: RecordPaymentDialogProps) {
  const qc = useQueryClient();
  const [amountStr, setAmountStr] = useState("");
  const [method, setMethod] = useState<RentPaymentMethod>("bank_transfer");
  const [reference, setReference] = useState("");
  const [notes, setNotes] = useState("");
  const [period, setPeriod] = useState(currentPeriod);

  const mutation = useMutation({
    mutationFn: () =>
      recordRentPayment(leaseId, {
        amount_cents: Math.round(parseFloat(amountStr) * 100),
        method,
        reference,
        notes,
        period: period || undefined,
      }),
    onSuccess: (data) => {
      toast.success(
        `Payment of ${fmtCents(data.amount_cents)} recorded` +
          (data.charge_status ? ` — charge is now ${data.charge_status}` : ""),
      );
      void qc.invalidateQueries({ queryKey: ["rent", "ledger", leaseId] });
      void qc.invalidateQueries({ queryKey: ["rent", "charges", leaseId] });
      void qc.invalidateQueries({ queryKey: ["rent", "summary"] });
      onClose();
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.detail : "Failed to record payment");
    },
  });

  const handleSubmit = () => {
    const cents = Math.round(parseFloat(amountStr) * 100);
    if (!amountStr || isNaN(cents) || cents < 1) {
      toast.error("Enter a valid amount (minimum $0.01)");
      return;
    }
    mutation.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Record Rent Payment</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label>Amount</Label>
            <div className="relative">
              <span className="absolute left-3 top-2.5 text-muted-foreground">$</span>
              <Input
                className="pl-7"
                placeholder="0.00"
                value={amountStr}
                onChange={(e) => setAmountStr(e.target.value)}
                type="number"
                min="0.01"
                step="0.01"
              />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label>Payment Method</Label>
            <Select value={method} onValueChange={(v) => setMethod(v as RentPaymentMethod)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label>Period (YYYY-MM)</Label>
            <Input
              placeholder={currentPeriod}
              value={period}
              onChange={(e) => setPeriod(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label>Reference</Label>
            <Input
              placeholder="Check #, transaction ID, etc."
              value={reference}
              onChange={(e) => setReference(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label>Notes</Label>
            <Textarea
              placeholder="Optional notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={mutation.isPending}>
            {mutation.isPending ? "Saving…" : "Record Payment"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Void Dialog ─────────────────────────────────────────────────────────────

interface VoidDialogProps {
  leaseId: string;
  row: RentLedgerRowOut | null;
  onClose: () => void;
}

function VoidDialog({ leaseId, row, onClose }: VoidDialogProps) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("");

  const mutation = useMutation({
    mutationFn: () => voidRentRow(leaseId, row!.sk, { reason }),
    onSuccess: () => {
      toast.success("Row voided successfully");
      void qc.invalidateQueries({ queryKey: ["rent", "ledger", leaseId] });
      void qc.invalidateQueries({ queryKey: ["rent", "charges", leaseId] });
      onClose();
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.detail : "Failed to void row");
    },
  });

  return (
    <Dialog open={row !== null} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Void Ledger Row</DialogTitle>
        </DialogHeader>
        {row && (
          <div className="grid gap-4 py-2">
            <p className="text-sm text-muted-foreground">
              Void{" "}
              <strong>{row.rent_kind}</strong> of{" "}
              <strong>{fmtCents(row.amount_cents)}</strong> for period{" "}
              <strong>{row.period ?? "—"}</strong>?
            </p>
            <div className="grid gap-1.5">
              <Label>Reason (optional)</Label>
              <Textarea
                placeholder="Reason for voiding"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={2}
              />
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending ? "Voiding…" : "Void Row"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function LeaseRentPage() {
  const { leaseId = "" } = useParams<{ leaseId: string }>();
  const qc = useQueryClient();

  const [showPaymentDialog, setShowPaymentDialog] = useState(false);
  const [voidRow, setVoidRow] = useState<RentLedgerRowOut | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const now = new Date();
  const currentPeriod = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;

  const ledgerQuery = useQuery({
    queryKey: ["rent", "ledger", leaseId, cursor],
    queryFn: () => getRentLedger(leaseId, { limit: 50, cursor }),
    enabled: !!leaseId,
    retry: false,
  });

  const chargesQuery = useQuery({
    queryKey: ["rent", "charges", leaseId],
    queryFn: () => getRentCharges(leaseId),
    enabled: !!leaseId,
    retry: false,
  });

  const chargeNowMutation = useMutation({
    mutationFn: () => chargeLeaseNow(leaseId, {}),
    onSuccess: (data) => {
      if ("skipped" in data && data.skipped) {
        toast.info(`Already charged for period ${data.period}`);
      } else {
        const d = data as import("@/api/endpoints/rentLedger").RentChargeOut;
        toast.success(`Rent charge of ${fmtCents(d.amount_cents)} posted for ${d.period}`);
      }
      void qc.invalidateQueries({ queryKey: ["rent", "ledger", leaseId] });
      void qc.invalidateQueries({ queryKey: ["rent", "charges", leaseId] });
    },
    onError: (e) => {
      toast.error(e instanceof ApiError ? e.detail : "Failed to post charge");
    },
  });

  const isNotEnabled =
    (ledgerQuery.error instanceof ApiError &&
      (ledgerQuery.error.status === 404 || ledgerQuery.error.status === 503)) ||
    (chargesQuery.error instanceof ApiError &&
      (chargesQuery.error.status === 404 || chargesQuery.error.status === 503));

  if (isNotEnabled) {
    return (
      <div className="flex flex-col gap-6 p-6">
        <PageHeader title="Rent Ledger" />
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <Receipt className="h-10 w-10 text-muted-foreground" />
            <p className="text-lg font-medium">Rent Ledger is not enabled</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const rows = ledgerQuery.data?.rows ?? [];
  const withBalance = computeRunningBalance(rows);
  const charges = chargesQuery.data?.charges ?? [];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title={`Rent Ledger — Lease ${leaseId}`}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => chargeNowMutation.mutate()}
              disabled={chargeNowMutation.isPending}
            >
              <Zap className="mr-1 h-4 w-4" />
              {chargeNowMutation.isPending ? "Charging…" : "Charge Now"}
            </Button>
            <Button size="sm" onClick={() => setShowPaymentDialog(true)}>
              <PlusCircle className="mr-1 h-4 w-4" />
              Record Payment
            </Button>
          </div>
        }
      />

      <Button variant="ghost" size="sm" className="w-fit" asChild>
        <Link to="/property/rent">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to Rent Ledger
        </Link>
      </Button>

      <Tabs defaultValue="history">
        <TabsList>
          <TabsTrigger value="history">Full History</TabsTrigger>
          <TabsTrigger value="charges">Charges</TabsTrigger>
        </TabsList>

        {/* ── Full history tab ── */}
        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                Ledger History
                {ledgerQuery.data && (
                  <span className="ml-2 text-xs font-normal text-muted-foreground">
                    ({ledgerQuery.data.count} total)
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {ledgerQuery.isLoading ? (
                <div className="p-4 space-y-3">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : rows.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
                  <TrendingDown className="h-8 w-8" />
                  <p>No ledger entries yet for this lease.</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Date</TableHead>
                      <TableHead>Kind</TableHead>
                      <TableHead>Period</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>Running Balance</TableHead>
                      <TableHead>Status / State</TableHead>
                      <TableHead>Method</TableHead>
                      <TableHead>Reference</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {withBalance.map((row) => (
                      <TableRow key={row.sk} className={row.state === "reversed" ? "opacity-50" : ""}>
                        <TableCell className="whitespace-nowrap">{fmtTs(row.ts)}</TableCell>
                        <TableCell>{kindBadge(row.rent_kind)}</TableCell>
                        <TableCell>{row.period ?? "—"}</TableCell>
                        <TableCell className="font-mono">
                          {row.rent_kind === "payment" ? "-" : ""}
                          {fmtCents(row.amount_cents, row.currency ?? "usd")}
                        </TableCell>
                        <TableCell className={`font-mono ${row.running_cents > 0 ? "text-destructive" : "text-green-600"}`}>
                          {fmtCents(row.running_cents, row.currency ?? "usd")}
                        </TableCell>
                        <TableCell>
                          {row.rent_kind === "charge" && row.status ? (
                            <Badge variant={statusVariant(row.status)}>{row.status}</Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">{row.state}</span>
                          )}
                        </TableCell>
                        <TableCell>{row.method ?? "—"}</TableCell>
                        <TableCell className="max-w-[120px] truncate">{row.reference ?? "—"}</TableCell>
                        <TableCell>
                          {row.state !== "reversed" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setVoidRow(row)}
                            >
                              <XCircle className="h-4 w-4 text-destructive" />
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}

              {/* Pagination */}
              {(ledgerQuery.data?.next_cursor || cursor) && (
                <div className="flex justify-between gap-2 p-4">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!cursor}
                    onClick={() => setCursor(undefined)}
                  >
                    First Page
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!ledgerQuery.data?.next_cursor}
                    onClick={() => setCursor(ledgerQuery.data?.next_cursor ?? undefined)}
                  >
                    Next Page
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Charges tab ── */}
        <TabsContent value="charges">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Rent Charges</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {chargesQuery.isLoading ? (
                <div className="p-4 space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : charges.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
                  <Receipt className="h-8 w-8" />
                  <p>No rent charges posted yet.</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Period</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>State</TableHead>
                      <TableHead>Posted</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {charges.map((charge) => (
                      <TableRow key={charge.sk} className={charge.state === "reversed" ? "opacity-50" : ""}>
                        <TableCell className="font-medium">{charge.period ?? "—"}</TableCell>
                        <TableCell className="font-mono">{fmtCents(charge.amount_cents, charge.currency ?? "usd")}</TableCell>
                        <TableCell>
                          {charge.status ? (
                            <Badge variant={statusVariant(charge.status)}>{charge.status}</Badge>
                          ) : (
                            "—"
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">{charge.state}</span>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">{fmtTs(charge.ts)}</TableCell>
                        <TableCell>
                          {charge.state !== "reversed" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setVoidRow(charge)}
                            >
                              <XCircle className="h-4 w-4 text-destructive" />
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Dialogs */}
      <RecordPaymentDialog
        leaseId={leaseId}
        open={showPaymentDialog}
        onClose={() => setShowPaymentDialog(false)}
        currentPeriod={currentPeriod}
      />
      <VoidDialog
        leaseId={leaseId}
        row={voidRow}
        onClose={() => setVoidRow(null)}
      />
    </div>
  );
}
