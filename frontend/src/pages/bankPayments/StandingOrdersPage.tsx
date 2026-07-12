/**
 * OBP PAY-002 — Standing Orders (recurring payments)
 *
 * Feature-flagged: gracefully shows "not enabled" state on 404.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Repeat, Plus, Pause, Play, XCircle, RefreshCw, AlertCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  listStandingOrders,
  createStandingOrder,
  pauseStandingOrder,
  resumeStandingOrder,
  cancelStandingOrder,
  listCounterparties,
  type StandingOrder,
  type StandingOrderCadence,
} from "@/api/endpoints/bankPayments";

function fmtCents(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active") return "default";
  if (status === "paused") return "secondary";
  if (status === "cancelled") return "destructive";
  return "outline";
}

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-sm font-medium">Standing Orders not enabled</p>
      <p className="text-xs max-w-sm">
        This feature requires the Open Banking Project and Payments flags.
        Contact your administrator to enable PAY-002.
      </p>
    </div>
  );
}

const CADENCES: StandingOrderCadence[] = ["weekly", "biweekly", "monthly"];

export default function StandingOrdersPage() {
  const qc = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [showCreate, setShowCreate] = useState(false);

  // Create form
  const [counterpartyId, setCounterpartyId] = useState("");
  const [amountStr, setAmountStr] = useState("");
  const [currency, setCurrency] = useState("usd");
  const [cadence, setCadence] = useState<StandingOrderCadence>("monthly");
  const [startAt, setStartAt] = useState("");
  const [endAt, setEndAt] = useState("");
  const [reason, setReason] = useState("");

  const listQuery = useQuery({
    queryKey: ["standing-orders", cursor],
    queryFn: () => listStandingOrders({ limit: 50, cursor }),
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
  });

  const counterpartiesQuery = useQuery({
    queryKey: ["counterparties", "all"],
    queryFn: () => listCounterparties({ limit: 200 }),
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
    enabled: showCreate,
  });

  const isDisabled =
    listQuery.isError &&
    listQuery.error instanceof ApiError &&
    (listQuery.error.status === 404 || listQuery.error.status === 503);

  const createMut = useMutation({
    mutationFn: () => {
      const startTs = startAt ? Math.floor(new Date(startAt).getTime() / 1000) : Math.floor(Date.now() / 1000);
      const endTs = endAt ? Math.floor(new Date(endAt).getTime() / 1000) : undefined;
      return createStandingOrder({
        counterparty_id: counterpartyId,
        amount_cents: Math.round(parseFloat(amountStr) * 100),
        currency,
        cadence,
        start_at: startTs,
        end_at: endTs,
        reason: reason.trim() || undefined,
      });
    },
    onSuccess: () => {
      toast.success("Standing order created");
      setShowCreate(false);
      setCounterpartyId("");
      setAmountStr("");
      setCurrency("usd");
      setCadence("monthly");
      setStartAt("");
      setEndAt("");
      setReason("");
      void qc.invalidateQueries({ queryKey: ["standing-orders"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create standing order"),
  });

  const pauseMut = useMutation({
    mutationFn: (id: string) => pauseStandingOrder(id),
    onSuccess: () => {
      toast.success("Standing order paused");
      void qc.invalidateQueries({ queryKey: ["standing-orders"] });
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to pause"),
  });

  const resumeMut = useMutation({
    mutationFn: (id: string) => resumeStandingOrder(id),
    onSuccess: () => {
      toast.success("Standing order resumed");
      void qc.invalidateQueries({ queryKey: ["standing-orders"] });
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to resume"),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelStandingOrder(id),
    onSuccess: () => {
      toast.success("Standing order cancelled");
      void qc.invalidateQueries({ queryKey: ["standing-orders"] });
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to cancel"),
  });

  const items: StandingOrder[] = listQuery.data?.standing_orders ?? [];
  const nextCursor = listQuery.data?.cursor ?? null;
  const counterparties = counterpartiesQuery.data?.counterparties ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Standing Orders"
        description="Manage recurring payment instructions."
        actions={
          !isDisabled && (
            <Button onClick={() => setShowCreate(true)} size="sm">
              <Plus className="h-4 w-4 mr-1" /> New standing order
            </Button>
          )
        }
      />

      {isDisabled && <FeatureDisabled />}

      {!isDisabled && (
        <>
          {listQuery.isLoading && (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-20 w-full rounded-lg" />
              ))}
            </div>
          )}

          {!listQuery.isLoading && items.length === 0 && !listQuery.isError && (
            <div className="flex flex-col items-center gap-2 py-16 text-center text-muted-foreground">
              <Repeat className="h-10 w-10" />
              <p className="text-sm">No standing orders yet. Create one to schedule recurring payments.</p>
            </div>
          )}

          {items.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Active orders ({items.length})</CardTitle>
                <CardDescription>Recurring payment schedule.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {items.map((so) => (
                    <div
                      key={so.standing_order_id}
                      className="flex items-start justify-between gap-3 rounded-lg border p-3"
                      data-testid={`so-${so.standing_order_id}`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm">
                            {fmtCents(so.amount_cents, so.currency)}
                          </span>
                          <Badge variant={statusVariant(so.status)} className="text-xs capitalize">
                            {so.status}
                          </Badge>
                          <span className="text-xs capitalize text-muted-foreground">{so.cadence}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          Counterparty: {so.counterparty_id}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Next: {fmtTs(so.next_run_at)} · Runs: {so.runs_count}
                          {so.last_run_at ? ` · Last: ${fmtTs(so.last_run_at)}` : ""}
                        </p>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        {so.status === "active" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label="Pause"
                            onClick={() => pauseMut.mutate(so.standing_order_id)}
                            disabled={pauseMut.isPending}
                          >
                            <Pause className="h-4 w-4" />
                          </Button>
                        )}
                        {so.status === "paused" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label="Resume"
                            onClick={() => resumeMut.mutate(so.standing_order_id)}
                            disabled={resumeMut.isPending}
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                        )}
                        {so.status !== "cancelled" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label="Cancel"
                            onClick={() => cancelMut.mutate(so.standing_order_id)}
                            disabled={cancelMut.isPending}
                          >
                            <XCircle className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => qc.invalidateQueries({ queryKey: ["standing-orders"] })}
                    disabled={listQuery.isFetching}
                  >
                    <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(nextCursor ?? undefined)}
                    disabled={!nextCursor}
                  >
                    Next page
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>New standing order</DialogTitle>
            <DialogDescription>Schedule a recurring payment to a counterparty.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 pt-2">
            <div className="space-y-1">
              <Label>Counterparty</Label>
              {counterparties.length > 0 ? (
                <Select value={counterpartyId} onValueChange={setCounterpartyId}>
                  <SelectTrigger data-testid="so-counterparty">
                    <SelectValue placeholder="Select counterparty" />
                  </SelectTrigger>
                  <SelectContent>
                    {counterparties.map((cp) => (
                      <SelectItem key={cp.counterparty_id} value={cp.counterparty_id}>
                        {cp.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  placeholder="counterparty_id"
                  value={counterpartyId}
                  onChange={(e) => setCounterpartyId(e.target.value)}
                  data-testid="so-counterparty-id"
                />
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Amount</Label>
                <Input
                  type="number"
                  min="0.01"
                  step="0.01"
                  placeholder="100.00"
                  value={amountStr}
                  onChange={(e) => setAmountStr(e.target.value)}
                  data-testid="so-amount"
                />
              </div>
              <div className="space-y-1">
                <Label>Currency</Label>
                <Input
                  placeholder="usd"
                  value={currency}
                  onChange={(e) => setCurrency(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Cadence</Label>
              <Select value={cadence} onValueChange={(v) => setCadence(v as StandingOrderCadence)}>
                <SelectTrigger data-testid="so-cadence">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CADENCES.map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Start date</Label>
                <Input
                  type="date"
                  value={startAt}
                  onChange={(e) => setStartAt(e.target.value)}
                  data-testid="so-start"
                />
              </div>
              <div className="space-y-1">
                <Label>End date (optional)</Label>
                <Input
                  type="date"
                  value={endAt}
                  onChange={(e) => setEndAt(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Reason / reference (optional)</Label>
              <Input
                placeholder="Monthly rent"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                onClick={() => createMut.mutate()}
                disabled={
                  createMut.isPending ||
                  !counterpartyId ||
                  !amountStr ||
                  parseFloat(amountStr) <= 0
                }
                data-testid="so-create-btn"
              >
                {createMut.isPending ? "Creating…" : "Create order"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
