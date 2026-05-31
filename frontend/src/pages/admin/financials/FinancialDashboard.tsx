import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, LineChart } from "lucide-react";
import { toast } from "sonner";
import {
  getFinancialDashboardKpis,
  getFinancialDashboardTrends,
  getFinancialDashboardProviders,
  getFinancialDashboardTypes,
  getFinancialDashboardTopCreators,
  triggerFinancialDashboardRollup,
  exportFinancialDashboardCsv,
} from "@/api/endpoints/platformFinancialDashboard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";

const fmtUsd = (cents: number) => `$${(cents / 100).toFixed(2)}`;

function isoDaysAgo(days: number): string {
  const d = new Date(Date.now() - days * 86400000);
  return d.toISOString().slice(0, 10);
}

type Granularity = "daily" | "weekly" | "monthly";

function KpiCard({ title, value }: { title: string; value: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold" data-testid={`kpi-${title}`}>
          {value}
        </div>
      </CardContent>
    </Card>
  );
}

export default function FinancialDashboard() {
  const qc = useQueryClient();
  const accessToken = useAuthStore((s) => s.accessToken);
  const isRoot = getRoleFromAccessToken(accessToken) === "root";

  const [startDate, setStartDate] = useState(isoDaysAgo(30));
  const [endDate, setEndDate] = useState(isoDaysAgo(0));
  const [granularity, setGranularity] = useState<Granularity>("daily");

  const range = useMemo(() => ({ start_date: startDate, end_date: endDate }), [startDate, endDate]);

  const kpis = useQuery({
    queryKey: ["fin-dash", "kpis", range],
    queryFn: () => getFinancialDashboardKpis(range),
  });

  const trends = useQuery({
    queryKey: ["fin-dash", "trends", range, granularity],
    queryFn: () => getFinancialDashboardTrends({ ...range, granularity }),
  });

  const providers = useQuery({
    queryKey: ["fin-dash", "providers", range],
    queryFn: () => getFinancialDashboardProviders(range),
  });

  const types = useQuery({
    queryKey: ["fin-dash", "types", range],
    queryFn: () => getFinancialDashboardTypes(range),
  });

  const topCreators = useQuery({
    queryKey: ["fin-dash", "top-creators", range],
    queryFn: () => getFinancialDashboardTopCreators({ ...range, limit: 20 }),
  });

  const rollupMut = useMutation({
    mutationFn: () => triggerFinancialDashboardRollup({}),
    onSuccess: (r) => {
      toast.success(`Rollup computed for ${r.date}`);
      qc.invalidateQueries({ queryKey: ["fin-dash"] });
    },
    onError: () => toast.error("Rollup failed (root only)"),
  });

  const onExportCsv = async () => {
    try {
      const blob = await exportFinancialDashboardCsv(range);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `financials_${startDate}_${endDate}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("CSV export failed");
    }
  };

  const k = kpis.data;

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center gap-2">
        <LineChart className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Platform Financials</h1>
      </div>

      {/* Date range + controls */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 pt-4">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">Start</label>
            <Input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              data-testid="fin-start-date"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-muted-foreground">End</label>
            <Input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              data-testid="fin-end-date"
            />
          </div>
          <div className="flex gap-1">
            {(["daily", "weekly", "monthly"] as Granularity[]).map((g) => (
              <Button
                key={g}
                size="sm"
                variant={granularity === g ? "default" : "outline"}
                onClick={() => setGranularity(g)}
              >
                {g}
              </Button>
            ))}
          </div>
          <div className="ml-auto flex gap-2">
            <Button variant="outline" onClick={onExportCsv}>
              <Download className="mr-1 h-4 w-4" /> Export CSV
            </Button>
            {isRoot && (
              <Button onClick={() => rollupMut.mutate()} disabled={rollupMut.isPending}>
                Run Rollup
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <KpiCard title="GMV" value={fmtUsd(k?.gmv_cents ?? 0)} />
        <KpiCard title="Net Revenue" value={fmtUsd(k?.net_revenue_cents ?? 0)} />
        <KpiCard title="Take Rate" value={`${((k?.take_rate_bps ?? 0) / 100).toFixed(1)}%`} />
        <KpiCard title="Transactions" value={(k?.tx_count ?? 0).toLocaleString()} />
        <KpiCard title="Avg Transaction" value={fmtUsd(k?.avg_tx_cents ?? 0)} />
      </div>

      {/* Trends + providers */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Revenue Trends ({granularity})</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>GMV</TableHead>
                  <TableHead>Net Revenue</TableHead>
                  <TableHead>Tx</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(trends.data?.data ?? []).map((p) => (
                  <TableRow key={p.date}>
                    <TableCell>{p.date}</TableCell>
                    <TableCell>{fmtUsd(p.gmv_cents)}</TableCell>
                    <TableCell>{fmtUsd(p.net_revenue_cents)}</TableCell>
                    <TableCell>{p.tx_count}</TableCell>
                  </TableRow>
                ))}
                {(trends.data?.data ?? []).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center text-muted-foreground">
                      No data in range
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Provider Split</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Provider</TableHead>
                  <TableHead>Volume</TableHead>
                  <TableHead>%</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(providers.data?.data ?? []).map((p) => (
                  <TableRow key={p.provider}>
                    <TableCell>{p.provider}</TableCell>
                    <TableCell>{fmtUsd(p.total_cents)}</TableCell>
                    <TableCell>{p.pct.toFixed(1)}%</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Tables */}
      <Tabs defaultValue="creators">
        <TabsList>
          <TabsTrigger value="creators">Top Creators</TabsTrigger>
          <TabsTrigger value="types">By Type</TabsTrigger>
        </TabsList>
        <TabsContent value="creators">
          <Card>
            <CardContent className="pt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Creator</TableHead>
                    <TableHead>Revenue</TableHead>
                    <TableHead>Tx</TableHead>
                    <TableHead>Avg</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(topCreators.data?.data ?? []).map((c) => (
                    <TableRow key={c.user_id}>
                      <TableCell className="font-mono text-xs">{c.user_id}</TableCell>
                      <TableCell>{fmtUsd(c.revenue_cents)}</TableCell>
                      <TableCell>{c.tx_count}</TableCell>
                      <TableCell>{fmtUsd(c.avg_cents)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="types">
          <Card>
            <CardContent className="pt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Tx</TableHead>
                    <TableHead>Avg</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(types.data?.data ?? []).map((t) => (
                    <TableRow key={t.entry_type}>
                      <TableCell>{t.entry_type}</TableCell>
                      <TableCell>{fmtUsd(t.total_cents)}</TableCell>
                      <TableCell>{t.tx_count}</TableCell>
                      <TableCell>{fmtUsd(t.avg_cents)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
