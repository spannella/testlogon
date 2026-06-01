import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  getAdRevenueBreakdown,
  getAdvertiserTransparency,
} from "@/api/endpoints/contentAdControls";
import type { AdRevenueBreakdown, AdvertiserTransparency } from "@/api/types";

function dollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

const PERIODS = [7, 30, 90, 365];

/**
 * AdRevenueBreakdownCard (ADS-010) — transparency / analytics card.
 *
 * Shows total ad revenue for a selectable period, the creator's revenue share,
 * a by-content breakdown, and the advertiser transparency list.
 */
export default function AdRevenueBreakdownCard() {
  const [days, setDays] = useState(30);

  const { data, isLoading, refetch, isFetching } = useQuery<AdRevenueBreakdown>({
    queryKey: ["ad-revenue-breakdown", days],
    queryFn: () => getAdRevenueBreakdown(days),
    staleTime: 120_000,
  });

  const { data: advertisers } = useQuery<AdvertiserTransparency[]>({
    queryKey: ["ad-transparency"],
    queryFn: () => getAdvertiserTransparency(),
    staleTime: 120_000,
  });

  const top = data?.top_content ?? [];
  const maxRev = top.reduce((m, c) => Math.max(m, c.revenue_cents), 0) || 1;

  return (
    <Card data-testid="ad-revenue-breakdown">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5" /> Ad Revenue Breakdown
        </CardTitle>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => refetch()}
          aria-label="Refresh"
        >
          <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          {PERIODS.map((p) => (
            <Button
              key={p}
              size="sm"
              variant={p === days ? "default" : "outline"}
              onClick={() => setDays(p)}
            >
              {p}d
            </Button>
          ))}
        </div>

        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <>
            <div className="flex items-baseline gap-3">
              <span
                className="text-3xl font-bold"
                data-testid="ad-revenue-total"
              >
                {dollars(data?.total_ad_revenue_cents ?? 0)}
              </span>
              <span className="text-sm text-muted-foreground">
                over {data?.days ?? days} days · {data?.entry_count ?? 0} events
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              Your revenue share: {((data?.revenue_share_bps ?? 7000) / 100).toFixed(0)}%
            </p>

            <div>
              <h4 className="mb-2 text-sm font-semibold">Top Earning Content</h4>
              {top.length === 0 ? (
                <p className="text-sm text-muted-foreground" data-testid="ad-revenue-empty">
                  No ad revenue yet.
                </p>
              ) : (
                <ul className="space-y-2">
                  {top.map((c) => (
                    <li key={c.content_id} className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span className="truncate font-mono">{c.content_id}</span>
                        <span className="font-medium">{dollars(c.revenue_cents)}</span>
                      </div>
                      <div className="h-2 w-full rounded bg-muted">
                        <div
                          className="h-2 rounded bg-primary"
                          style={{ width: `${(c.revenue_cents / maxRev) * 100}%` }}
                        />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {advertisers && advertisers.length > 0 && (
              <div>
                <h4 className="mb-2 text-sm font-semibold">Advertisers on Your Content</h4>
                <ul className="space-y-1">
                  {advertisers.map((a) => (
                    <li
                      key={a.account_id}
                      className="flex justify-between text-sm"
                    >
                      <span>{a.company_name}</span>
                      <span className="text-muted-foreground">
                        {a.total_impressions} imp · {dollars(a.total_revenue_cents)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
