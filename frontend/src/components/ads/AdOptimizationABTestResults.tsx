import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ABTestResult } from "@/api/types";

interface AdOptimizationABTestResultsProps {
  result: ABTestResult | null | undefined;
  creativeAId: string;
  creativeBId: string;
}

export default function AdOptimizationABTestResults({
  result,
  creativeAId,
  creativeBId,
}: AdOptimizationABTestResultsProps) {
  if (!result) return null;

  return (
    <Card data-testid="ad-opt-abtest">
      <CardHeader>
        <CardTitle className="text-base">A/B Test Result</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span>Variant A ({creativeAId})</span>
          <span>{(result.variant_a_ctr * 100).toFixed(2)}% CTR</span>
        </div>
        <div className="flex justify-between">
          <span>Variant B ({creativeBId})</span>
          <span>{(result.variant_b_ctr * 100).toFixed(2)}% CTR</span>
        </div>
        <div className="flex justify-between">
          <span>Lift</span>
          <span>{result.lift_percent}%</span>
        </div>
        <div className="flex justify-between">
          <span>p-value</span>
          <span>{result.p_value}</span>
        </div>
        <div className="flex items-center justify-between pt-1">
          {!result.sample_size_sufficient ? (
            <Badge variant="outline" data-testid="ad-opt-abtest-needsdata">
              Needs more data
            </Badge>
          ) : result.significant ? (
            <Badge data-testid="ad-opt-abtest-winner">
              Significant — winner: variant {result.winner}
            </Badge>
          ) : (
            <Badge variant="secondary">Not significant</Badge>
          )}
          <span className="text-xs text-muted-foreground">
            {(result.confidence_level * 100).toFixed(0)}% confidence
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
