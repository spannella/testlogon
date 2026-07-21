import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Gauge, Trophy, Calculator, FileText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  getApiUsageLeaderboard,
  finalizeBillingPeriod,
  recomputeUsage,
  generateInvoiceLines,
  createBillingAdjustment,
  type LeaderboardItem,
} from "@/api/endpoints/adminUsage";

function currentPeriod(): string {
  return new Date().toISOString().slice(0, 7);
}

export default function UsageMeteringPage() {
  const [period, setPeriod] = useState(currentPeriod());

  // finalize
  const [finalizeUser, setFinalizeUser] = useState("");
  // recompute
  const [recomputeUser, setRecomputeUser] = useState("");
  // invoice lines
  const [ilUser, setIlUser] = useState("");
  const [ilSnapshot, setIlSnapshot] = useState("1");
  // adjustment
  const [adjUser, setAdjUser] = useState("");
  const [adjSnapshot, setAdjSnapshot] = useState("1");
  const [adjType, setAdjType] = useState<"credit" | "debit">("credit");
  const [adjAmount, setAdjAmount] = useState("");
  const [adjReason, setAdjReason] = useState("");

  const leaderboard = useQuery({
    queryKey: ["admin-usage", "leaderboard", { period }],
    queryFn: () => getApiUsageLeaderboard({ periodId: period, dimension: "consumers", topN: 20 }),
    staleTime: 30_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  const finalizeMut = useMutation({
    mutationFn: () => finalizeBillingPeriod({ period_id: period, user_id: finalizeUser.trim() || undefined }),
    onSuccess: () => toast.success("Billing period finalized"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Finalize failed"),
  });

  const recomputeMut = useMutation({
    mutationFn: () =>
      recomputeUsage({
        scope: recomputeUser.trim() ? "user" : "all",
        period_id: period,
        user_id: recomputeUser.trim() || undefined,
        apply: true,
      }),
    onSuccess: () => toast.success("Usage recomputed"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Recompute failed"),
  });

  const invoiceMut = useMutation({
    mutationFn: () =>
      generateInvoiceLines({ user_id: ilUser.trim(), period_id: period, snapshot_version: parseInt(ilSnapshot, 10) || 1 }),
    onSuccess: () => toast.success("Invoice lines generated"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Generate failed"),
  });

  const adjustMut = useMutation({
    mutationFn: () =>
      createBillingAdjustment({
        user_id: adjUser.trim(),
        period_id: period,
        snapshot_version: parseInt(adjSnapshot, 10) || 1,
        adjustment_type: adjType,
        amount_cents: parseInt(adjAmount, 10) || 0,
        reason: adjReason.trim(),
      }),
    onSuccess: () => { toast.success("Adjustment created"); setAdjAmount(""); setAdjReason(""); },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Adjustment failed"),
  });

  if (leaderboard.error instanceof ApiError && leaderboard.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="Usage metering / billing admin is available only to billing operators."
      />
    );
  }

  const items = leaderboard.data?.items ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Usage Metering & Billing Admin" description="API-usage leaderboard, period finalization, recompute, invoice lines, and adjustments" />

      <div className="flex items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="period">Billing period (YYYY-MM)</Label>
          <Input id="period" value={period} onChange={(e) => setPeriod(e.target.value)} className="w-40" />
        </div>
      </div>

      <Tabs defaultValue="leaderboard">
        <TabsList className="flex-wrap">
          <TabsTrigger value="leaderboard"><Trophy className="mr-1 h-3.5 w-3.5" /> Leaderboard</TabsTrigger>
          <TabsTrigger value="finalize"><Calculator className="mr-1 h-3.5 w-3.5" /> Finalize</TabsTrigger>
          <TabsTrigger value="recompute"><Gauge className="mr-1 h-3.5 w-3.5" /> Recompute</TabsTrigger>
          <TabsTrigger value="invoice"><FileText className="mr-1 h-3.5 w-3.5" /> Invoice lines</TabsTrigger>
          <TabsTrigger value="adjust">Adjustments</TabsTrigger>
        </TabsList>

        <TabsContent value="leaderboard" className="pt-4">
          {leaderboard.isLoading && (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          )}
          {!leaderboard.isLoading && items.length === 0 && (
            <EmptyState icon={<Trophy className="h-6 w-6" />} title="No usage data" description="No metered usage for this period yet." />
          )}
          {items.length > 0 && (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Consumer</TableHead>
                      <TableHead className="text-right">Calls</TableHead>
                      <TableHead className="text-right">Cost (micros)</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((it: LeaderboardItem, i) => (
                      <TableRow key={`${it.key}-${i}`}>
                        <TableCell className="text-xs">{it.label || it.key}</TableCell>
                        <TableCell className="text-right">{it.calls_total ?? "—"}</TableCell>
                        <TableCell className="text-right">{it.cost_subtotal_micros ?? "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="finalize" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <p className="text-sm text-muted-foreground">Finalize the billing period for all users, or a single user.</p>
            <div className="space-y-1.5">
              <Label htmlFor="fin-user">User ID (optional)</Label>
              <Input id="fin-user" placeholder="all users" value={finalizeUser} onChange={(e) => setFinalizeUser(e.target.value)} />
            </div>
            <Button onClick={() => finalizeMut.mutate()} disabled={finalizeMut.isPending}>Finalize period {period}</Button>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="recompute" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <p className="text-sm text-muted-foreground">Recompute metered usage. Leave user blank to recompute all.</p>
            <div className="space-y-1.5">
              <Label htmlFor="rec-user">User ID (optional)</Label>
              <Input id="rec-user" placeholder="all users" value={recomputeUser} onChange={(e) => setRecomputeUser(e.target.value)} />
            </div>
            <Button onClick={() => recomputeMut.mutate()} disabled={recomputeMut.isPending}>Recompute</Button>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="invoice" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="il-user">User ID</Label>
                <Input id="il-user" value={ilUser} onChange={(e) => setIlUser(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="il-snap">Snapshot version</Label>
                <Input id="il-snap" type="number" value={ilSnapshot} onChange={(e) => setIlSnapshot(e.target.value)} />
              </div>
            </div>
            <Button onClick={() => invoiceMut.mutate()} disabled={!ilUser.trim() || invoiceMut.isPending}>Generate invoice lines</Button>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="adjust" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="adj-user">User ID</Label>
                <Input id="adj-user" value={adjUser} onChange={(e) => setAdjUser(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="adj-snap">Snapshot version</Label>
                <Input id="adj-snap" type="number" value={adjSnapshot} onChange={(e) => setAdjSnapshot(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="adj-type">Type</Label>
                <select id="adj-type" value={adjType}
                  onChange={(e) => setAdjType(e.target.value as "credit" | "debit")}
                  className="h-9 w-full rounded-md border bg-background px-2 text-sm">
                  <option value="credit">credit</option>
                  <option value="debit">debit</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="adj-amt">Amount (cents)</Label>
                <Input id="adj-amt" type="number" value={adjAmount} onChange={(e) => setAdjAmount(e.target.value)} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="adj-reason">Reason</Label>
              <Input id="adj-reason" value={adjReason} onChange={(e) => setAdjReason(e.target.value)} />
            </div>
            <Button
              onClick={() => adjustMut.mutate()}
              disabled={!adjUser.trim() || !adjAmount.trim() || !adjReason.trim() || adjustMut.isPending}
            >
              Create adjustment
            </Button>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
