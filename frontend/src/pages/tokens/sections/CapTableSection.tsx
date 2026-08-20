import type { UseQueryResult } from "@tanstack/react-query";
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
import type { CapTable } from "@/api/endpoints/tokens";
import { formatBps } from "@/lib/tokens";
import { PendingBackend } from "../PendingBackend";

function shortSub(sub: string): string {
  return sub.length > 14 ? `${sub.slice(0, 8)}...${sub.slice(-4)}` : sub;
}

export function CapTableSection({ query }: { query: UseQueryResult<CapTable> }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Cap table</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {query.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-7 w-full" />
            <Skeleton className="h-7 w-full" />
          </div>
        ) : query.isError ? (
          <PendingBackend label="The cap table" />
        ) : (
          <>
            <div className="rounded-lg border bg-muted/30 p-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Creator retained</span>
                <span className="font-semibold tabular-nums">
                  {formatBps(query.data?.creator_pct_bps)}
                </span>
              </div>
            </div>
            {(query.data?.holders ?? []).length === 0 ? (
              <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
                No outside holders yet - the creator holds 100% until the token is listed.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Holder</TableHead>
                    <TableHead className="text-right">Quantity</TableHead>
                    <TableHead className="text-right">Share</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(query.data?.holders ?? []).map((h) => (
                    <TableRow key={h.sub}>
                      <TableCell className="font-mono text-xs">{shortSub(h.sub)}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {h.qty.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{formatBps(h.pct_bps)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
