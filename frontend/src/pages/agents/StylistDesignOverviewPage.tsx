import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPageScores,
  getOverallScore,
  triggerUIReview,
} from "@/api/endpoints/stylistAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Palette, RefreshCw } from "lucide-react";

function scoreColor(score: number): string {
  if (score >= 85) return "text-green-600";
  if (score >= 70) return "text-yellow-600";
  return "text-red-600";
}

function ScoreGauge({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-4xl font-bold ${scoreColor(value)}`} data-testid={`gauge-${label.toLowerCase().replace(/\s+/g, "-")}`}>
          {value.toFixed(1)}
        </div>
        <div className="mt-2 h-2 w-full rounded-full bg-muted">
          <div
            className="h-2 rounded-full bg-primary"
            style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
          />
        </div>
      </CardContent>
    </Card>
  );
}

export default function StylistDesignOverviewPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: overall } = useQuery({
    queryKey: ["stylist-overall-score"],
    queryFn: () => getOverallScore().catch(() => undefined),
  });

  const { data: pageScores } = useQuery({
    queryKey: ["stylist-page-scores"],
    queryFn: () => getPageScores().catch(() => [] as Awaited<ReturnType<typeof getPageScores>>),
  });

  const runReview = useMutation({
    mutationFn: () =>
      triggerUIReview(["/messages", "/feed", "/billing"], "full_page"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["stylist-page-scores"] });
      queryClient.invalidateQueries({ queryKey: ["stylist-overall-score"] });
    },
  });

  return (
    <div className="space-y-6 p-6" data-testid="design-overview-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Palette className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">Design Overview</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate("/agents/stylist/rules")}>
            Design Rules
          </Button>
          <Button
            onClick={() => runReview.mutate()}
            disabled={runReview.isPending}
            data-testid="run-review-btn"
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${runReview.isPending ? "animate-spin" : ""}`} />
            Run Review
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <ScoreGauge label="Design Score" value={overall?.overall_design_score ?? 0} />
        <ScoreGauge label="Accessibility" value={overall?.overall_accessibility_score ?? 0} />
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">Pages Reviewed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-4xl font-bold">{overall?.pages_reviewed ?? 0}</div>
            <p className="mt-2 text-sm text-muted-foreground">
              {overall?.total_issues ?? 0} total issues
            </p>
          </CardContent>
        </Card>
      </div>

      <div>
        <h2 className="mb-3 text-lg font-semibold">Pages (worst first)</h2>
        {(!pageScores || pageScores.length === 0) ? (
          <Card>
            <CardContent className="py-10 text-center text-muted-foreground" data-testid="no-page-scores">
              No reviews yet. Run a review to see per-page design scores.
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {pageScores.map((p) => (
              <Card
                key={p.page_url}
                className="cursor-pointer transition-shadow hover:shadow-md"
                data-testid="page-score-card"
                onClick={() => navigate(`/agents/stylist/reviews?page_url=${encodeURIComponent(p.page_url)}`)}
              >
                <CardHeader>
                  <CardTitle className="flex items-center justify-between text-base">
                    <span className="truncate">{p.page_name || p.page_url}</span>
                    <Badge variant={p.issues_found > 0 ? "destructive" : "secondary"}>
                      {p.issues_found} issues
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={`text-2xl font-bold ${scoreColor(p.design_score)}`}>
                    {p.design_score.toFixed(1)}
                  </div>
                  <div className="mt-2 h-2 w-full rounded-full bg-muted">
                    <div
                      className="h-2 rounded-full bg-primary"
                      style={{ width: `${Math.min(100, Math.max(0, p.design_score))}%` }}
                    />
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    Last reviewed {p.last_reviewed ? new Date(p.last_reviewed * 1000).toLocaleDateString() : "—"}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
