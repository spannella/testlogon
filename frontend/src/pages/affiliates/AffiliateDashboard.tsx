import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link2, Plus, Trash2, Copy, BarChart3, AlertCircle } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  listAffiliateLinks,
  createAffiliateLink,
  deleteAffiliateLink,
  getAffiliateSummary,
  getLinkClickTimeSeries,
  getAffiliateEarnings,
  getTopProducts,
  type AffiliateLinkOut,
  type AffiliateSummaryOut,
  type AffiliateClickBucket,
  type AffiliateEarningsBreakdownOut,
  type AffiliateTopProductItem,
} from "@/api/endpoints/affiliates";

// GAP-0198 / GAP-0197: The four analytics endpoints (/ui/affiliates/summary,
// /timeseries, /earnings, /top-products) are live, so analytics are enabled by
// default. The build-time flag is retained as a kill switch for rollout windows:
// set VITE_AFFILIATE_ANALYTICS=0 to fall back to the progressive-disclosure
// "coming soon" panels and keep the Links tab working if the backend is absent.
const ANALYTICS_ENABLED =
  String(import.meta.env.VITE_AFFILIATE_ANALYTICS ?? "1") !== "0";

function formatCents(cents: number): string {
  return `$${((cents ?? 0) / 100).toFixed(2)}`;
}

function formatDate(ts: number): string {
  if (!ts) return "N/A";
  return new Date(ts * 1000).toLocaleDateString();
}

function ComingSoon({ feature }: { feature: string }) {
  return (
    <Alert>
      <AlertCircle className="h-4 w-4" />
      <AlertTitle>{feature} coming soon</AlertTitle>
      <AlertDescription>
        Affiliate analytics are not enabled yet. Create links in the Links tab —
        all analytics derive from your existing links.
      </AlertDescription>
    </Alert>
  );
}

function QueryError({ onRetry }: { onRetry: () => void }) {
  return (
    <Alert variant="destructive">
      <AlertCircle className="h-4 w-4" />
      <AlertTitle>Failed to load</AlertTitle>
      <AlertDescription className="flex items-center justify-between gap-4">
        <span>Something went wrong fetching analytics data.</span>
        <Button size="sm" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      </AlertDescription>
    </Alert>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="mt-1 text-2xl font-semibold">{value}</p>
      </CardContent>
    </Card>
  );
}

function SummaryCards({
  data,
  loading,
}: {
  data?: AffiliateSummaryOut;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }
  if (!data) return null;
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
      <StatCard label="Total Links" value={String(data.total_links)} />
      <StatCard label="Total Clicks" value={String(data.total_clicks)} />
      <StatCard label="Unique Clicks" value={String(data.unique_clicks)} />
      <StatCard label="Conversions" value={String(data.total_conversions)} />
      <StatCard label="Total Revenue" value={formatCents(data.total_revenue_cents)} />
      <StatCard
        label="Total Commission"
        value={formatCents(data.total_commission_cents)}
      />
    </div>
  );
}

function ClickTimeSeriesChart({
  data,
  loading,
  interval,
  onIntervalChange,
}: {
  data: AffiliateClickBucket[];
  loading: boolean;
  interval: "day" | "week";
  onIntervalChange: (i: "day" | "week") => void;
}) {
  return (
    <Card className="mt-4">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Clicks over time</CardTitle>
        <div className="flex gap-1">
          <Button
            size="sm"
            variant={interval === "day" ? "default" : "outline"}
            onClick={() => onIntervalChange("day")}
          >
            Day
          </Button>
          <Button
            size="sm"
            variant={interval === "week" ? "default" : "outline"}
            onClick={() => onIntervalChange("week")}
          >
            Week
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-64 w-full" />
        ) : data.length === 0 ? (
          <p className="text-sm text-muted-foreground">No click data yet.</p>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="bucket" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="clicks" fill="hsl(var(--primary))" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}

function EarningsBreakdownTable({
  data,
  loading,
}: {
  data?: AffiliateEarningsBreakdownOut;
  loading: boolean;
}) {
  if (loading) return <Skeleton className="h-48 w-full" />;
  const items = data?.items ?? [];
  if (items.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No earnings yet. Create links in the Links tab to start earning
        commission.
      </p>
    );
  }
  const topId = items.reduce(
    (best, it) =>
      it.commission_earned_cents > (best?.commission_earned_cents ?? -1)
        ? it
        : best,
    items[0]
  )?.link_id;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Product</TableHead>
          <TableHead>Type</TableHead>
          <TableHead className="text-right">Conversions</TableHead>
          <TableHead className="text-right">Revenue</TableHead>
          <TableHead className="text-right">Commission</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((it) => (
          <TableRow
            key={it.link_id}
            className={it.link_id === topId ? "font-medium" : undefined}
          >
            <TableCell>{it.target_name}</TableCell>
            <TableCell>{it.target_type}</TableCell>
            <TableCell className="text-right">{it.conversions}</TableCell>
            <TableCell className="text-right">
              {formatCents(it.revenue_cents)}
            </TableCell>
            <TableCell className="text-right">
              {formatCents(it.commission_earned_cents)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function TopProductsTable({
  data,
  loading,
}: {
  data: AffiliateTopProductItem[];
  loading: boolean;
}) {
  if (loading) return <Skeleton className="h-48 w-full" />;
  if (data.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No products to rank yet. Create links in the Links tab.
      </p>
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-12">#</TableHead>
          <TableHead>Product</TableHead>
          <TableHead className="text-right">Clicks</TableHead>
          <TableHead className="text-right">Conversions</TableHead>
          <TableHead className="text-right">Earned</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((it, idx) => (
          <TableRow key={it.link_id}>
            <TableCell className="text-muted-foreground">{idx + 1}</TableCell>
            <TableCell>{it.target_name}</TableCell>
            <TableCell className="text-right">{it.click_count}</TableCell>
            <TableCell className="text-right">{it.conversion_count}</TableCell>
            <TableCell className="text-right">
              {formatCents(it.commission_earned_cents)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function AffiliateDashboard() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [targetType] = useState("catalog_item");
  const [targetId, setTargetId] = useState("");
  const [commissionPercent, setCommissionPercent] = useState("");
  const [customCode, setCustomCode] = useState("");
  const [interval, setIntervalState] = useState<"day" | "week">("day");

  const { data, isLoading } = useQuery({
    queryKey: ["affiliate-links"],
    queryFn: () => listAffiliateLinks(),
  });

  const summaryQ = useQuery({
    queryKey: ["affiliate-summary"],
    queryFn: getAffiliateSummary,
    staleTime: 60_000,
    enabled: ANALYTICS_ENABLED,
  });
  const timeseriesQ = useQuery({
    queryKey: ["affiliate-timeseries", interval],
    queryFn: () => getLinkClickTimeSeries({ interval }),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    enabled: ANALYTICS_ENABLED,
  });
  const earningsQ = useQuery({
    queryKey: ["affiliate-earnings"],
    queryFn: () => getAffiliateEarnings(),
    staleTime: 60_000,
    enabled: ANALYTICS_ENABLED,
  });
  const topProductsQ = useQuery({
    queryKey: ["affiliate-top-products"],
    queryFn: () => getTopProducts(10),
    staleTime: 60_000,
    enabled: ANALYTICS_ENABLED,
  });

  const createMut = useMutation({
    mutationFn: createAffiliateLink,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["affiliate-links"] });
      setCreateOpen(false);
      setTargetId("");
      setCommissionPercent("");
      setCustomCode("");
      toast.success("Affiliate link created");
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to create link");
    },
  });

  const deleteMut = useMutation({
    mutationFn: deleteAffiliateLink,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["affiliate-links"] });
      toast.success("Link revoked");
    },
  });

  const links: AffiliateLinkOut[] = data?.links ?? [];

  const handleCreate = () => {
    createMut.mutate({
      target_type: targetType,
      target_id: targetId,
      commission_percent: commissionPercent ? Number(commissionPercent) : undefined,
      custom_code: customCode || undefined,
    });
  };

  const handleCopy = (url: string) => {
    navigator.clipboard.writeText(window.location.origin + url);
    toast.success("Link copied to clipboard");
  };

  return (
    <div className="space-y-6">
      <Tabs defaultValue="links">
        <TabsList>
          <TabsTrigger value="links">Links</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="earnings">Earnings</TabsTrigger>
          <TabsTrigger value="top-products">Top Products</TabsTrigger>
        </TabsList>

        <TabsContent value="links">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Link2 className="h-5 w-5" />
                Affiliate Links
              </CardTitle>
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="mr-1 h-4 w-4" />
                Create Link
              </Button>
            </CardHeader>
            <CardContent>
              {isLoading && <p className="text-muted-foreground">Loading...</p>}
              {!isLoading && links.length === 0 && (
                <p className="text-muted-foreground">
                  No affiliate links yet. Create one to get started.
                </p>
              )}
              {links.length > 0 && (
                <div className="space-y-4">
                  {links.map((link) => (
                    <div
                      key={link.link_id}
                      className="flex items-center justify-between rounded-lg border p-4"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{link.target_name}</span>
                          <Badge
                            variant={
                              link.status === "active" ? "default" : "secondary"
                            }
                          >
                            {link.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Code: <code>{link.tracking_code}</code> | Commission:{" "}
                          {link.commission_percent}%
                        </p>
                        <div className="flex gap-4 text-xs text-muted-foreground">
                          <span>
                            <BarChart3 className="inline h-3 w-3 mr-1" />
                            {link.click_count} clicks
                          </span>
                          <span>{link.conversion_count} conversions</span>
                          <span>
                            {formatCents(link.commission_earned_cents)} earned
                          </span>
                          <span>Created {formatDate(link.created_at)}</span>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleCopy(link.short_url)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                        {link.status === "active" && (
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => deleteMut.mutate(link.link_id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics">
          {!ANALYTICS_ENABLED ? (
            <ComingSoon feature="Analytics" />
          ) : summaryQ.isError ? (
            <QueryError onRetry={() => summaryQ.refetch()} />
          ) : (
            <>
              <SummaryCards data={summaryQ.data} loading={summaryQ.isLoading} />
              <ClickTimeSeriesChart
                data={timeseriesQ.data?.items ?? []}
                loading={timeseriesQ.isLoading}
                interval={interval}
                onIntervalChange={setIntervalState}
              />
            </>
          )}
        </TabsContent>

        <TabsContent value="earnings">
          {!ANALYTICS_ENABLED ? (
            <ComingSoon feature="Earnings" />
          ) : earningsQ.isError ? (
            <QueryError onRetry={() => earningsQ.refetch()} />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Earnings breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <EarningsBreakdownTable
                  data={earningsQ.data}
                  loading={earningsQ.isLoading}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="top-products">
          {!ANALYTICS_ENABLED ? (
            <ComingSoon feature="Top Products" />
          ) : topProductsQ.isError ? (
            <QueryError onRetry={() => topProductsQ.refetch()} />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Top products</CardTitle>
              </CardHeader>
              <CardContent>
                <TopProductsTable
                  data={topProductsQ.data?.items ?? []}
                  loading={topProductsQ.isLoading}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* Create Link Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Affiliate Link</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <Label htmlFor="target_id">Product ID</Label>
              <Input
                id="target_id"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder="Enter product ID"
              />
            </div>
            <div>
              <Label htmlFor="commission">Commission %</Label>
              <Input
                id="commission"
                type="number"
                value={commissionPercent}
                onChange={(e) => setCommissionPercent(e.target.value)}
                placeholder={`Default: ${10}%`}
                min={1}
                max={50}
              />
            </div>
            <div>
              <Label htmlFor="custom_code">Custom Code (optional)</Label>
              <Input
                id="custom_code"
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                placeholder="e.g. MYLINK2026"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!targetId || createMut.isPending}
            >
              {createMut.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
