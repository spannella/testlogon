import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Download, DollarSign, Layers, BarChart3 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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
  getContentRevenueList,
  contentRevenueExportUrl,
} from "@/api/endpoints/perContentRevenue";
import type { ContentRevenueItem } from "@/api/types";

const CONTENT_TYPE_OPTIONS = [
  { value: "all", label: "All Content" },
  { value: "vod", label: "Videos" },
  { value: "post", label: "Posts" },
  { value: "broadcast", label: "Broadcasts" },
];

const SORT_OPTIONS = [
  { value: "total_cents", label: "Total Revenue" },
  { value: "tips_cents", label: "Tips" },
  { value: "unlocks_cents", label: "Unlocks" },
  { value: "published_at", label: "Date Published" },
];

function fmtMoney(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format((cents || 0) / 100);
}

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

function typeBadge(t: string) {
  const label = t === "vod" ? "VOD" : t === "broadcast" ? "Broadcast" : "Post";
  return <Badge variant="secondary">{label}</Badge>;
}

export default function ContentRevenuePage() {
  const navigate = useNavigate();
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [contentType, setContentType] = useState("all");
  const [sortBy, setSortBy] = useState("total_cents");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  const params = useMemo(
    () => ({
      from_date: fromDate || undefined,
      to_date: toDate || undefined,
      content_type: contentType === "all" ? undefined : contentType,
      sort_by: sortBy,
      sort_order: sortOrder,
      limit: 200,
    }),
    [fromDate, toDate, contentType, sortBy, sortOrder],
  );

  const { data, isLoading, isError } = useQuery({
    queryKey: ["content-revenue", params],
    queryFn: () => getContentRevenueList(params),
    staleTime: 30_000,
  });

  const items: ContentRevenueItem[] = data?.items ?? [];
  const currency = data?.currency ?? "USD";
  const totalRevenue = data?.total_revenue_cents ?? 0;
  const contentCount = data?.total_items ?? 0;
  const avgRevenue = contentCount > 0 ? Math.round(totalRevenue / contentCount) : 0;

  const toggleSortTotal = () => {
    if (sortBy === "total_cents") {
      setSortOrder((o) => (o === "desc" ? "asc" : "desc"));
    } else {
      setSortBy("total_cents");
      setSortOrder("desc");
    }
  };

  const handleExport = () => {
    const url = contentRevenueExportUrl({
      from_date: fromDate || undefined,
      to_date: toDate || undefined,
    });
    window.open(url, "_blank");
  };

  return (
    <div className="space-y-4 p-4" data-testid="content-revenue-page">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Content Revenue
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Toolbar */}
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">From</label>
              <Input
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
                className="w-40"
                aria-label="from date"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">To</label>
              <Input
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
                className="w-40"
                aria-label="to date"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">Type</label>
              <Select value={contentType} onValueChange={setContentType}>
                <SelectTrigger className="w-40" aria-label="content type filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONTENT_TYPE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs text-muted-foreground">Sort by</label>
              <Select value={sortBy} onValueChange={setSortBy}>
                <SelectTrigger className="w-44" aria-label="sort by">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SORT_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              variant="outline"
              onClick={handleExport}
              className="gap-2"
              data-testid="content-revenue-export"
            >
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
          </div>

          {/* Summary */}
          <div className="flex flex-wrap gap-3">
            <div className="flex items-center gap-2 rounded-md border px-3 py-2">
              <DollarSign className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Total Revenue</span>
              <span className="font-semibold" data-testid="cr-total-revenue">
                {fmtMoney(totalRevenue, currency)}
              </span>
            </div>
            <div className="flex items-center gap-2 rounded-md border px-3 py-2">
              <Layers className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Content Items</span>
              <span className="font-semibold" data-testid="cr-content-count">
                {contentCount}
              </span>
            </div>
            <div className="flex items-center gap-2 rounded-md border px-3 py-2">
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">Avg / Content</span>
              <span className="font-semibold">{fmtMoney(avgRevenue, currency)}</span>
            </div>
          </div>

          {/* Table */}
          <Table data-testid="content-revenue-table">
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Published</TableHead>
                <TableHead className="text-right">Tips</TableHead>
                <TableHead className="text-right">Unlocks</TableHead>
                <TableHead className="text-right">Subscriptions</TableHead>
                <TableHead className="text-right">Ads</TableHead>
                <TableHead className="text-right">VOD</TableHead>
                <TableHead className="text-right">
                  <button
                    type="button"
                    className="font-semibold hover:underline"
                    onClick={toggleSortTotal}
                    data-testid="cr-sort-total"
                  >
                    Total
                  </button>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              )}
              {isError && !isLoading && (
                <TableRow>
                  <TableCell colSpan={9} className="text-center text-destructive">
                    Failed to load content revenue.
                  </TableCell>
                </TableRow>
              )}
              {!isLoading && !isError && items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={9}
                    className="text-center text-muted-foreground"
                    data-testid="cr-empty"
                  >
                    No content revenue yet.
                  </TableCell>
                </TableRow>
              )}
              {items.map((item) => (
                <TableRow
                  key={item.content_id}
                  className="cursor-pointer"
                  data-testid="cr-row"
                  onClick={() => navigate(`/analytics?content=${encodeURIComponent(item.content_id)}`)}
                >
                  <TableCell className="font-medium">{item.title}</TableCell>
                  <TableCell>{typeBadge(item.content_type)}</TableCell>
                  <TableCell>{fmtDate(item.published_at)}</TableCell>
                  <TableCell className="text-right">{fmtMoney(item.tips_cents, currency)}</TableCell>
                  <TableCell className="text-right">{fmtMoney(item.unlocks_cents, currency)}</TableCell>
                  <TableCell className="text-right">{fmtMoney(item.subscriptions_cents, currency)}</TableCell>
                  <TableCell className="text-right">{fmtMoney(item.ads_cents, currency)}</TableCell>
                  <TableCell className="text-right">{fmtMoney(item.vod_cents, currency)}</TableCell>
                  <TableCell className="text-right font-semibold" data-testid="cr-row-total">
                    {fmtMoney(item.total_cents, currency)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
