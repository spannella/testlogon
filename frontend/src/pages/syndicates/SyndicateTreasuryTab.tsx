import { useQuery } from "@tanstack/react-query";
import { Wallet, Info } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getTreasuryBalance,
  getTreasuryContributions,
} from "@/api/endpoints/syndicateTreasury";
import type { SyndicateMemberOut } from "@/api/types";
import SyndicateTreasuryContributeDialog from "./SyndicateTreasuryContributeDialog";
import SyndicateTreasuryDisburseDialog from "./SyndicateTreasuryDisburseDialog";
import SyndicateTreasuryLedgerTable from "./SyndicateTreasuryLedgerTable";

function fmt(cents: number) {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function SyndicateTreasuryTab({
  syndicateId,
  isAdmin,
  members,
}: {
  syndicateId: string;
  isAdmin: boolean;
  members: SyndicateMemberOut[];
}) {
  const { data: balance } = useQuery({
    queryKey: ["syndicate-treasury", syndicateId, "balance"],
    queryFn: () => getTreasuryBalance(syndicateId),
    enabled: !!syndicateId,
  });

  const { data: contributors = [] } = useQuery({
    queryKey: ["syndicate-treasury", syndicateId, "contributions"],
    queryFn: () => getTreasuryContributions(syndicateId),
    enabled: !!syndicateId,
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Wallet className="h-5 w-5" /> Treasury Balance
          </CardTitle>
          <div className="flex gap-2">
            <SyndicateTreasuryContributeDialog syndicateId={syndicateId} />
            {isAdmin && (
              <SyndicateTreasuryDisburseDialog syndicateId={syndicateId} members={members} />
            )}
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-3xl font-bold" data-testid="treasury-balance">
            {fmt(balance?.balance_cents ?? 0)}
          </p>
          <div className="mt-3 flex gap-6 text-sm text-muted-foreground">
            <span>Deposited: {fmt(balance?.total_deposited_cents ?? 0)}</span>
            <span>Disbursed: {fmt(balance?.total_disbursed_cents ?? 0)}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Contributors</CardTitle>
        </CardHeader>
        <CardContent>
          {contributors.length === 0 ? (
            <p className="text-muted-foreground">No contributions yet.</p>
          ) : (
            <div className="space-y-2" data-testid="treasury-contributors">
              {contributors.map((c) => (
                <div
                  key={c.user_id}
                  className="flex items-center justify-between rounded border p-3 text-sm"
                >
                  <span className="font-medium">{c.user_id}</span>
                  <div className="flex gap-4 text-muted-foreground">
                    <span>Contributed: {fmt(c.total_contributed_cents)}</span>
                    <span>Net: {fmt(c.net_contributed_cents)}</span>
                    <span>{c.contribution_count}x</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <SyndicateTreasuryLedgerTable syndicateId={syndicateId} />

      <div className="flex items-start gap-2 rounded-md border bg-muted/40 p-3 text-sm text-muted-foreground">
        <Info className="h-4 w-4 mt-0.5 flex-shrink-0" />
        <span>
          Treasury funds are pooled. Only syndicate admins can disburse funds to members; members
          cannot withdraw their contributions directly.
        </span>
      </div>
    </div>
  );
}
