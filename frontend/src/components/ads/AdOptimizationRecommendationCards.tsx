import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { OptimizationRecommendation } from "@/api/types";

interface AdOptimizationRecommendationCardsProps {
  recommendations: OptimizationRecommendation[];
  onApply: (recommendationId: string) => void;
  onDismiss: (recommendationId: string) => void;
  pending?: boolean;
}

const ACTION_LABEL: Record<string, string> = {
  pause_creative: "Pause Creative",
  reallocate_budget: "Reallocate Budget",
  adjust_bid: "Adjust Bid",
};

export default function AdOptimizationRecommendationCards({
  recommendations,
  onApply,
  onDismiss,
  pending,
}: AdOptimizationRecommendationCardsProps) {
  if (recommendations.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="ad-opt-empty">
        No optimization recommendations yet. Run an optimization pass to generate
        recommendations.
      </p>
    );
  }

  return (
    <div className="space-y-3" data-testid="ad-opt-recommendations">
      {recommendations.map((rec) => (
        <Card key={rec.recommendation_id} data-testid={`ad-opt-rec-${rec.action}`}>
          <CardContent className="flex flex-col gap-2 p-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge
                  variant={rec.severity === "warning" ? "destructive" : "secondary"}
                >
                  {ACTION_LABEL[rec.action] ?? rec.action}
                </Badge>
                <span className="font-medium">{rec.title}</span>
              </div>
              <Badge variant="outline">{rec.status}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">{rec.description}</p>
            {rec.impact ? (
              <p className="text-xs text-muted-foreground">Impact: {rec.impact}</p>
            ) : null}
            {rec.status === "open" ? (
              <div className="flex gap-2 pt-1">
                <Button
                  size="sm"
                  disabled={pending}
                  onClick={() => onApply(rec.recommendation_id)}
                  data-testid={`ad-opt-apply-${rec.recommendation_id}`}
                >
                  Apply
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={pending}
                  onClick={() => onDismiss(rec.recommendation_id)}
                  data-testid={`ad-opt-dismiss-${rec.recommendation_id}`}
                >
                  Dismiss
                </Button>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
