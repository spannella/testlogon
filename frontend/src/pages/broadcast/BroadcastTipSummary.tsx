import { useQuery } from "@tanstack/react-query";
import { DollarSign, TrendingUp, Users } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getTipSummary } from "@/api/endpoints/broadcast-tips";

interface BroadcastTipSummaryProps {
  sessionId: string;
  isBroadcaster: boolean;
}

export function BroadcastTipSummary({ sessionId, isBroadcaster }: BroadcastTipSummaryProps) {
  const summaryQuery = useQuery({
    queryKey: ["broadcast", "tips", "summary", sessionId],
    queryFn: () => getTipSummary(sessionId, { top_limit: 10, recent_limit: 10 }),
    refetchInterval: 10_000,
    enabled: isBroadcaster,
  });

  if (!isBroadcaster) return null;

  const summary = summaryQuery.data;
  if (!summary) return null;

  return (
    <Card data-testid="broadcast-tip-summary">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <DollarSign className="h-4 w-4" />
          Tip Summary
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Totals */}
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold text-green-600">
              ${(summary.total_cents / 100).toFixed(2)}
            </p>
            <p className="text-xs text-muted-foreground flex items-center justify-center gap-1">
              <TrendingUp className="h-3 w-3" /> Total Tips
            </p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold">{summary.tip_count}</p>
            <p className="text-xs text-muted-foreground flex items-center justify-center gap-1">
              <Users className="h-3 w-3" /> Tip Count
            </p>
          </div>
        </div>

        {/* Top Tippers */}
        {summary.top_tippers.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-muted-foreground mb-2">Top Tippers</h4>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Supporter</TableHead>
                  <TableHead className="text-xs text-right">Amount</TableHead>
                  <TableHead className="text-xs text-right">Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {summary.top_tippers.map((tipper) => (
                  <TableRow key={tipper.user_id}>
                    <TableCell className="text-xs truncate max-w-[120px]">
                      {tipper.display_name}
                    </TableCell>
                    <TableCell className="text-xs text-right">
                      ${(tipper.total_cents / 100).toFixed(2)}
                    </TableCell>
                    <TableCell className="text-xs text-right">{tipper.tip_count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
