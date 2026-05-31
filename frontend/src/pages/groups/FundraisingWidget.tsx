import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { listGroupFundraisers } from "@/api/endpoints/groups";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Target } from "lucide-react";

function fmt(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

/**
 * Compact progress widget embedded on the GroupPage. Shows the most recent
 * active fundraiser's progress + a link to the public donation page.
 */
export default function FundraisingWidget({ groupId }: { groupId: string }) {
  const q = useQuery({
    queryKey: ["group-fundraisers", groupId],
    queryFn: () => listGroupFundraisers(groupId),
    enabled: !!groupId,
    staleTime: 60_000,
  });

  const active = (q.data?.fundraisers ?? []).find((f) => f.status === "active");
  if (!active) return null;

  const pct =
    active.goal_cents && active.goal_cents > 0
      ? Math.min(100, Math.round((active.raised_cents / active.goal_cents) * 100))
      : 0;

  return (
    <Card data-testid="fundraising-widget">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Target className="h-4 w-4" />
          {active.title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {active.goal_cents && active.goal_cents > 0 ? (
          <div data-testid="widget-progress">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium">{fmt(active.raised_cents)}</span>
              <span className="text-muted-foreground">of {fmt(active.goal_cents)}</span>
            </div>
            <div className="mt-1 h-2 rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">
            {fmt(active.raised_cents)} raised
          </div>
        )}
        <Button asChild size="sm" data-testid="widget-donate-link">
          <Link to={`/donate/${active.fundraiser_id}`}>Donate</Link>
        </Button>
      </CardContent>
    </Card>
  );
}
