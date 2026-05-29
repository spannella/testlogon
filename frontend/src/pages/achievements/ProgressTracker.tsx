import { useQuery } from "@tanstack/react-query";
import { getAchievementProgress } from "@/api/endpoints/achievements";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

function formatMetricKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ProgressTracker() {
  const { data, isLoading } = useQuery({
    queryKey: ["achievements", "progress"],
    queryFn: getAchievementProgress,
  });

  if (isLoading)
    return <div className="text-muted-foreground">Loading progress...</div>;

  const progress = data?.progress ?? [];

  if (progress.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No progress tracked yet.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {progress.map((p) => {
        const pct = p.next_threshold
          ? Math.min(100, (p.current_value / p.next_threshold) * 100)
          : 100;
        return (
          <Card key={p.metric_key}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center justify-between">
                <span>{formatMetricKey(p.metric_key)}</span>
                {p.next_achievement && (
                  <span className="text-xs text-muted-foreground">
                    Next: {p.next_achievement.label}
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Progress value={pct} className="h-3" />
              <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                <span>{p.current_value}</span>
                <span>{p.next_threshold ?? "Complete"}</span>
              </div>
              {p.streak_anchor_date && (
                <div className="text-xs text-muted-foreground mt-1">
                  Streak started: {p.streak_anchor_date} / Best:{" "}
                  {p.highest_value}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
