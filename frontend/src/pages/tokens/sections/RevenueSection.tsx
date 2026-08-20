import type { UseQueryResult } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import type { RevenueSummary } from "@/api/endpoints/tokens";
import { formatBps, formatCents } from "@/lib/tokens";
import { PendingBackend } from "../PendingBackend";

export function RevenueSection({
  query,
  onClaim,
  claiming,
}: {
  query: UseQueryResult<RevenueSummary>;
  onClaim: () => void;
  claiming: boolean;
}) {
  const data = query.data;
  const claimable = data?.my_claimable ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Revenue distributions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {query.isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : query.isError ? (
          <PendingBackend label="Revenue distributions" />
        ) : (
          <>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Metric label="My holding" value={(data?.my_qty ?? 0).toLocaleString()} />
              <Metric label="My share" value={formatBps(data?.my_pct_bps)} />
              <Metric label="Claimable" value={formatCents(claimable)} accent />
            </div>

            <div className="flex items-center justify-between rounded-lg border bg-muted/30 p-3">
              <p className="text-sm text-muted-foreground">
                Pro-rata distributions of the creator&rsquo;s content revenue accrue to your holding.
              </p>
              <Button onClick={onClaim} disabled={claiming || claimable <= 0} data-testid="claim-revenue">
                {claiming ? "Claiming..." : `Claim ${formatCents(claimable)}`}
              </Button>
            </div>

            <Separator />

            <div>
              <p className="mb-2 text-sm font-medium">Distribution history</p>
              {(data?.distributions ?? []).length === 0 ? (
                <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
                  No distributions yet.
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Date</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead className="text-right">Per token</TableHead>
                      <TableHead className="text-right">Total</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(data?.distributions ?? []).map((d, i) => (
                      <TableRow key={`${d.ts}-${i}`}>
                        <TableCell className="tabular-nums">
                          {new Date(d.ts * 1000).toLocaleDateString()}
                        </TableCell>
                        <TableCell>{d.source}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {formatCents(d.per_token_amount)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {formatCents(d.total_amount)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function Metric({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded-lg border p-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={`mt-0.5 text-lg font-semibold tabular-nums ${accent ? "text-emerald-600 dark:text-emerald-400" : ""}`}>
        {value}
      </p>
    </div>
  );
}
