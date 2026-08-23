import SurfaceIntro from "@/components/onboarding/SurfaceIntro";
import { Link } from "react-router-dom";
import { Coins, Plus, FileText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { useTokenMarket, useMyTokens, isPendingBackend } from "@/hooks/useTokens";
import type { Token, TokenStatus } from "@/api/endpoints/tokens";
import { formatBps, formatCents } from "@/lib/tokens";
import { PendingBackend } from "./PendingBackend";

const STATUS_VARIANT: Record<TokenStatus, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  minted: "secondary",
  listed: "default",
  frozen: "destructive",
  delisted: "outline",
};

function StatusBadge({ status }: { status: TokenStatus }) {
  return <Badge variant={STATUS_VARIANT[status] ?? "outline"}>{status}</Badge>;
}

function TokenTable({ tokens }: { tokens: Token[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Ticker</TableHead>
          <TableHead>Name</TableHead>
          <TableHead className="text-right">Rev-share</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Clearing / last</TableHead>
          <TableHead className="w-16" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {tokens.map((t) => (
          <TableRow key={t.token_id} data-testid="token-row">
            <TableCell className="font-semibold tabular-nums">{t.ticker}</TableCell>
            <TableCell className="max-w-[16rem] truncate">{t.name}</TableCell>
            <TableCell className="text-right tabular-nums">{formatBps(t.revenue_share_bps)}</TableCell>
            <TableCell>
              <StatusBadge status={t.status} />
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {t.clearing_price != null ? formatCents(t.clearing_price) : "—"}
            </TableCell>
            <TableCell>
              <Button asChild variant="ghost" size="sm">
                <Link to={`/tokens/${encodeURIComponent(t.token_id)}`}>View</Link>
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function TokenMarketPage() {
  const market = useTokenMarket();
  const mine = useMyTokens();

  const marketTokens = market.data?.tokens ?? [];
  const myTokens = mine.data?.tokens ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <SurfaceIntro surfaceId="tokens" />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Coins className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Creator Tokens</h1>
            <p className="text-sm text-muted-foreground">
              Tradeable revenue-share claims minted by content creators.
            </p>
          </div>
        </div>
        <Button asChild data-testid="mint-token-cta">
          <Link to="/tokens/new">
            <Plus className="mr-1.5 h-4 w-4" /> Mint a token
          </Link>
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Market — listed creator tokens</CardTitle>
        </CardHeader>
        <CardContent>
          {market.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : market.isError && isPendingBackend(market.error) ? (
            <PendingBackend label="The creator-token market" />
          ) : market.isError ? (
            <PendingBackend label="The creator-token market" />
          ) : marketTokens.length === 0 ? (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              No creator tokens are listed yet. Be the first to{" "}
              <Link to="/tokens/new" className="font-medium text-primary underline-offset-4 hover:underline">
                mint one
              </Link>
              .
            </div>
          ) : (
            <TokenTable tokens={marketTokens} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="h-4 w-4" /> My issued tokens
          </CardTitle>
        </CardHeader>
        <CardContent>
          {mine.isLoading ? (
            <Skeleton className="h-8 w-full" />
          ) : mine.isError ? (
            <PendingBackend label="Your issued tokens" />
          ) : myTokens.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              You haven&rsquo;t minted any tokens yet.
            </div>
          ) : (
            <TokenTable tokens={myTokens} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
