import { useMemo, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Coins, Snowflake } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthStore } from "@/stores/authStore";
import {
  useToken,
  useCapTable,
  useRevenue,
  useUpkeep,
  useAuction,
  useClaimRevenue,
  usePayUpkeep,
} from "@/hooks/useTokens";
import type { Token, TokenStatus } from "@/api/endpoints/tokens";
import { formatBps, formatCents } from "@/lib/tokens";
import { PendingBackend } from "./PendingBackend";
import { CapTableSection } from "./sections/CapTableSection";
import { RevenueSection } from "./sections/RevenueSection";
import { UpkeepSection } from "./sections/UpkeepSection";
import { AuctionSection } from "./sections/AuctionSection";

const STATUS_VARIANT: Record<TokenStatus, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  minted: "secondary",
  listed: "default",
  frozen: "destructive",
  delisted: "outline",
};

function shortSub(sub: string | undefined): string {
  if (!sub) return "-";
  return sub.length > 12 ? `${sub.slice(0, 6)}...${sub.slice(-4)}` : sub;
}

export default function TokenDetailPage() {
  const { id } = useParams<{ id: string }>();
  const userId = useAuthStore((s) => s.userId);

  const tokenQ = useToken(id);
  const capQ = useCapTable(id);
  const revenueQ = useRevenue(id);
  const upkeepQ = useUpkeep(id);
  const auctionQ = useAuction(id);

  const claim = useClaimRevenue(id);
  const payUpkeep = usePayUpkeep(id);

  const token: Token | undefined = tokenQ.data;
  const isIssuer = !!token && !!userId && token.creator_sub === userId;
  const isFrozen = token?.status === "frozen";

  const [tab, setTab] = useState("captable");

  const header = useMemo(() => {
    if (tokenQ.isLoading) return <Skeleton className="h-9 w-64" />;
    if (!token) return <h1 className="text-2xl font-bold tracking-tight">Token</h1>;
    return (
      <div className="flex flex-wrap items-center gap-2">
        <Coins className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold tracking-tight">
          {token.ticker} <span className="text-muted-foreground">- {token.name}</span>
        </h1>
        <Badge variant={STATUS_VARIANT[token.status] ?? "outline"}>{token.status}</Badge>
        {isFrozen && (
          <Badge variant="destructive" className="gap-1">
            <Snowflake className="h-3 w-3" /> Book frozen
          </Badge>
        )}
      </div>
    );
  }, [tokenQ.isLoading, token, isFrozen]);

  const onClaim = async () => {
    try {
      await claim.mutateAsync();
      toast.success("Claim submitted.");
    } catch {
      /* error toast handled in hook */
    }
  };

  const onPayUpkeep = async () => {
    try {
      await payUpkeep.mutateAsync();
      toast.success("Upkeep paid.");
    } catch {
      /* error toast handled in hook */
    }
  };

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="icon">
          <Link to="/tokens" aria-label="Back to tokens">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        {header}
      </div>

      {tokenQ.isError ? (
        <PendingBackend label="This token" />
      ) : (
        <>
          {token && (
            <Card>
              <CardContent className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
                <Stat label="Revenue-share" value={formatBps(token.revenue_share_bps)} />
                <Stat label="Total supply" value={token.total_supply.toLocaleString()} />
                <Stat
                  label="Offered (IPO)"
                  value={token.offered_pct_bps != null ? formatBps(token.offered_pct_bps) : "-"}
                />
                <Stat
                  label="Clearing price"
                  value={token.clearing_price != null ? formatCents(token.clearing_price) : "-"}
                />
                <Stat label="Creator" value={shortSub(token.creator_sub)} />
                <Stat label="Issuer view" value={isIssuer ? "Yes (you)" : "No"} />
              </CardContent>
            </Card>
          )}

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="captable">Cap table</TabsTrigger>
              <TabsTrigger value="revenue">Revenue</TabsTrigger>
              <TabsTrigger value="upkeep">Upkeep</TabsTrigger>
              <TabsTrigger value="auction">{isIssuer ? "List / IPO" : "Auction"}</TabsTrigger>
            </TabsList>

            <TabsContent value="captable" className="pt-4">
              <CapTableSection query={capQ} />
            </TabsContent>

            <TabsContent value="revenue" className="pt-4">
              <RevenueSection query={revenueQ} onClaim={onClaim} claiming={claim.isPending} />
            </TabsContent>

            <TabsContent value="upkeep" className="pt-4">
              <UpkeepSection query={upkeepQ} onPay={onPayUpkeep} paying={payUpkeep.isPending} />
            </TabsContent>

            <TabsContent value="auction" className="pt-4">
              <AuctionSection
                tokenId={id}
                token={token}
                query={auctionQ}
                isIssuer={isIssuer}
              />
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-0.5 font-semibold tabular-nums">{value}</p>
    </div>
  );
}
