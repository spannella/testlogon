import { useQuery } from "@tanstack/react-query";
import { getOptimizations } from "@/api/endpoints/accountantAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Lightbulb, MoonStar, TrendingDown, AlertTriangle, Gauge } from "lucide-react";
import type { OptimizationRecommendation } from "@/api/types";

const TYPE_ICON: Record<string, React.ReactNode> = {
  idle_worker: <MoonStar className="h-4 w-4" />,
  model_downgrade: <TrendingDown className="h-4 w-4" />,
  high_cost_ticket: <AlertTriangle className="h-4 w-4" />,
  underutilized_agent: <Gauge className="h-4 w-4" />,
};

export function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function RecommendationCard({ rec }: { rec: OptimizationRecommendation }) {
  return (
    <Card data-testid="optimization-card" className="border-l-4 border-l-amber-400">
      <CardContent className="flex items-start justify-between gap-4 p-4">
        <div className="flex items-start gap-3">
          <div className="mt-1 text-amber-500">{TYPE_ICON[rec.type] ?? <Lightbulb className="h-4 w-4" />}</div>
          <div>
            <p className="font-semibold">{rec.title}</p>
            <p className="text-sm text-muted-foreground">{rec.description}</p>
            <Badge variant="secondary" className="mt-2">
              Save {formatCents(rec.potential_savings_cents)}
            </Badge>
          </div>
        </div>
        <Button size="sm" variant="outline" data-testid="optimization-action">
          {rec.action.replace(/_/g, " ")}
        </Button>
      </CardContent>
    </Card>
  );
}

export default function OptimizationsPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["accountant", "optimizations"],
    queryFn: getOptimizations,
    staleTime: 30_000,
  });
  const recs = data ?? [];
  return (
    <Card data-testid="optimizations-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Lightbulb className="h-4 w-4" /> Cost Optimizations
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading && <p className="text-sm text-muted-foreground">Loading recommendations…</p>}
        {!isLoading && recs.length === 0 && (
          <p className="text-sm text-muted-foreground" data-testid="optimizations-empty">
            No optimizations identified — spending looks efficient.
          </p>
        )}
        {recs.map((rec, i) => (
          <RecommendationCard key={`${rec.type}-${i}`} rec={rec} />
        ))}
      </CardContent>
    </Card>
  );
}
