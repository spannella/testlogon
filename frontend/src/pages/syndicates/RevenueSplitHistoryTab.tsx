import { useQuery } from "@tanstack/react-query";
import { History } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { listSplits } from "@/api/endpoints/syndicateRevenueSplit";

const fmt = (cents: number) => `$${(cents / 100).toFixed(2)}`;

export default function RevenueSplitHistoryTab({
  syndicateId,
}: {
  syndicateId: string;
}) {
  const { data: splits = [] } = useQuery({
    queryKey: ["revenue-split", syndicateId, "splits"],
    queryFn: () => listSplits(syndicateId),
    enabled: !!syndicateId,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-5 w-5" />
          Split History
        </CardTitle>
      </CardHeader>
      <CardContent>
        {splits.length === 0 ? (
          <p className="text-muted-foreground">No revenue splits yet.</p>
        ) : (
          <div className="space-y-3" data-testid="split-history">
            {splits.map((s) => (
              <div key={s.split_id} className="rounded-lg border p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-sm">
                    <span className="font-medium">Gross {fmt(s.gross_amount_cents)}</span>{" "}
                    <span className="text-muted-foreground">
                      · Fee {fmt(s.platform_fee_cents)} · Net {fmt(s.net_amount_cents)}
                    </span>
                  </div>
                  <Badge variant="secondary">{s.mode}</Badge>
                </div>
                <p className="text-xs text-muted-foreground mb-2">
                  {new Date(s.created_at * 1000).toLocaleString()}
                </p>
                <div className="space-y-1">
                  {s.distributions.map((d) => (
                    <div
                      key={d.user_id}
                      className="flex items-center justify-between text-sm"
                    >
                      <span>{d.display_name || d.user_id}</span>
                      <span className="text-muted-foreground">
                        {fmt(d.amount_cents)} ({(d.percentage_bps / 100).toFixed(2)}%)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
