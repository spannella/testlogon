import { useQuery } from "@tanstack/react-query";
import { ArrowDownCircle, ArrowUpCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getTreasuryLedger } from "@/api/endpoints/syndicateTreasury";

function fmt(cents: number) {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function SyndicateTreasuryLedgerTable({ syndicateId }: { syndicateId: string }) {
  const { data } = useQuery({
    queryKey: ["syndicate-treasury", syndicateId, "ledger"],
    queryFn: () => getTreasuryLedger(syndicateId),
    enabled: !!syndicateId,
  });

  const entries = data?.entries ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Transaction History</CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-muted-foreground" data-testid="treasury-ledger-empty">
            No transactions yet.
          </p>
        ) : (
          <div className="space-y-2" data-testid="treasury-ledger">
            {entries.map((e) => (
              <div
                key={e.entry_id}
                className="flex items-center justify-between rounded border p-3 text-sm"
              >
                <div className="flex items-center gap-3">
                  {e.direction === "credit" ? (
                    <ArrowDownCircle className="h-5 w-5 text-green-600" />
                  ) : (
                    <ArrowUpCircle className="h-5 w-5 text-red-600" />
                  )}
                  <div>
                    <p className="font-medium">{e.reason}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(e.ts * 1000).toLocaleString()}
                    </p>
                  </div>
                </div>
                <span
                  className={
                    e.direction === "credit"
                      ? "font-semibold text-green-600"
                      : "font-semibold text-red-600"
                  }
                >
                  {e.direction === "credit" ? "+" : "-"}
                  {fmt(e.amount_cents)}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
