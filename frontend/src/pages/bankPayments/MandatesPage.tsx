/**
 * OBP PAY-003 — Direct-Debit Mandates
 *
 * Feature-flagged: gracefully shows "not enabled" state on 404.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileText, Plus, ShieldOff, Pause, RefreshCw, AlertCircle } from "lucide-react";

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
  listMandates,
  createMandate,
  revokeMandate,
  pauseMandate,
  listCounterparties,
  type Mandate,
  type MandateCadence,
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
  if (status === "revoked") return "destructive";
  return "outline";
}

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-sm font-medium">Direct-Debit Mandates not enabled</p>
      <p className="text-xs max-w-sm">
        This feature requires the Open Banking Project and Payments flags.
        Contact your administrator to enable PAY-003.
      </p>
    </div>
  );
}

const CADENCES: MandateCadence[] = ["weekly", "monthly"];

export default function MandatesPage() {
  const qc = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [showCreate, setShowCreate] = useState(false);

  // Create form
  const [counterpartyId, setCounterpartyId] = useState("");
  const [maxAmountStr, setMaxAmountStr] = useState("");
  const [currency, setCurrency] = useState("usd");
  const [cadence, setCadence] = useState<MandateCadence>("monthly");
  const [startAt, setStartAt] = useState("");
  const [endAt, setEndAt] = useState("");
  const [reference, setReference] = useState("");

  const listQuery = useQuery({
    queryKey: ["mandates", cursor],
    queryFn: () => listMandates({ limit: 50, cursor }),
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
      return createMandate({
        counterparty_id: counterpartyId,
        max_amount_cents: Math.round(parseFloat(maxAmountStr) * 100),
        currency,
        cadence,
        start_at: startTs,
        end_at: endTs,
        reference: reference.trim() || undefined,
      });
    },
    onSuccess: () => {
      toast.success("Mandate created");
      setShowCreate(false);
      setCounterpartyId("");
      setMaxAmountStr("");
      setCurrency("usd");
      setCadence("monthly");
      setStartAt("");
      setEndAt("");
      setReference("");
      void qc.invalidateQueries({ queryKey: ["mandates"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create mandate"),
  });

  const revokeMut = useMutation({
    mutationFn: (id: string) => revokeMandate(id),
    onSuccess: () => {
      toast.success("Mandate revoked");
      void qc.invalidateQueries({ queryKey: ["mandates"] });
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to revoke"),
  });

  const pauseMut = useMutation({
    mutationFn: (id: string) => pauseMandate(id),
    onSuccess: () => {
      toast.success("Mandate paused");
      void qc.invalidateQueries({ queryKey: ["mandates"] });
    },
    onError: (err: unknown) => toast.error(err instanceof Error ? err.message : "Failed to pause"),
  });

  const items: Mandate[] = listQuery.data?.mandates ?? [];
  const nextCursor = listQuery.data?.cursor ?? null;
  const counterparties = counterpartiesQuery.data?.counterparties ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Direct-Debit Mandates"
        description="Authorise counterparties to pull funds on your behalf."
        actions={
          !isDisabled && (
            <Button onClick={() => setShowCreate(true)} size="sm">
              <Plus className="h-4 w-4 mr-1" /> New mandate
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
              <FileText className="h-10 w-10" />
              <p className="text-sm">No mandates yet. Create one to allow recurring direct-debit pulls.</p>
            </div>
          )}

          {items.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Mandates ({items.length})</CardTitle>
                <CardDescription>Active direct-debit authorisations.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {items.map((m) => (
                    <div
                      key={m.mandate_id}
                      className="flex items-start justify-between gap-3 rounded-lg border p-3"
                      data-testid={`mandate-${m.mandate_id}`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm">
                            Max {fmtCents(m.max_amount_cents, m.currency)}
                          </span>
                          <Badge variant={statusVariant(m.status)} className="text-xs capitalize">
                            {m.status}
                          </Badge>
                          <span className="text-xs capitalize text-muted-foreground">{m.cadence}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          Counterparty: {m.counterparty_id}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Pulled this window: {fmtCents(m.pulled_this_window_cents, m.currency)}
                          {" · "}Runs: {m.runs_count}
                          {" · "}Next: {fmtTs(m.next_run_at)}
                        </p>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        {m.status === "active" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label="Pause mandate"
                            onClick={() => pauseMut.mutate(m.mandate_id)}
                            disabled={pauseMut.isPending}
                          >
                            <Pause className="h-4 w-4" />
                          </Button>
                        )}
                        {m.status !== "revoked" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label="Revoke mandate"
                            onClick={() => revokeMut.mutate(m.mandate_id)}
                            disabled={revokeMut.isPending}
                          >
                            <ShieldOff className="h-4 w-4 text-destructive" />
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
                    onClick={() => qc.invalidateQueries({ queryKey: ["mandates"] })}
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
            <DialogTitle>New direct-debit mandate</DialogTitle>
            <DialogDescription>
              Authorise a counterparty to pull funds up to a maximum amount per window.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 pt-2">
            <div className="space-y-1">
              <Label>Counterparty</Label>
              {counterparties.length > 0 ? (
                <Select value={counterpartyId} onValueChange={setCounterpartyId}>
                  <SelectTrigger data-testid="mandate-counterparty">
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
                  data-testid="mandate-counterparty-id"
                />
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Max amount per pull</Label>
                <Input
                  type="number"
                  min="0.01"
                  step="0.01"
                  placeholder="500.00"
                  value={maxAmountStr}
                  onChange={(e) => setMaxAmountStr(e.target.value)}
                  data-testid="mandate-max-amount"
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
              <Select value={cadence} onValueChange={(v) => setCadence(v as MandateCadence)}>
                <SelectTrigger data-testid="mandate-cadence">
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
                  data-testid="mandate-start"
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
              <Label>Reference (optional)</Label>
              <Input
                placeholder="MANDATE-2024-001"
                value={reference}
                onChange={(e) => setReference(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                onClick={() => createMut.mutate()}
                disabled={
                  createMut.isPending ||
                  !counterpartyId ||
                  !maxAmountStr ||
                  parseFloat(maxAmountStr) <= 0
                }
                data-testid="mandate-create-btn"
              >
                {createMut.isPending ? "Creating…" : "Create mandate"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
