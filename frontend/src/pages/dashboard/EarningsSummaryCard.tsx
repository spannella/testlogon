import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { DashboardEarningsBreakdown } from "@/api/types";

interface EarningsSummaryCardProps {
  breakdown: DashboardEarningsBreakdown;
  currency: string;
}

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function EarningsSummaryCard({ breakdown, currency }: EarningsSummaryCardProps) {
  const items = [
    { label: "Subscriptions", value: breakdown.subscriptions },
    { label: "Tips", value: breakdown.tips },
    { label: "Unlocks", value: breakdown.unlocks },
    { label: "VOD Purchases", value: breakdown.vod_purchases },
    { label: "Other", value: breakdown.other },
  ].filter((i) => i.value > 0);

  const total = Object.values(breakdown).reduce((sum, v) => sum + v, 0);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Earnings Breakdown</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {items.length === 0 && (
          <p className="text-sm text-muted-foreground">No earnings today</p>
        )}
        {items.map((item) => (
          <div key={item.label} className="flex justify-between text-sm">
            <span className="text-muted-foreground">{item.label}</span>
            <span className="font-medium">{formatCents(item.value)}</span>
          </div>
        ))}
        {items.length > 0 && (
          <div className="flex justify-between text-sm font-bold border-t pt-2 mt-2">
            <span>Total</span>
            <span>{formatCents(total)}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
