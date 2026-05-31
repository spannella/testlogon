import { useQuery } from "@tanstack/react-query";
import { Wallet } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getMyEarnings } from "@/api/endpoints/syndicateRevenueSplit";

const fmt = (cents: number) => `$${(cents / 100).toFixed(2)}`;

export default function RevenueSplitEarningsCard({
  syndicateId,
}: {
  syndicateId: string;
}) {
  const { data: earnings } = useQuery({
    queryKey: ["revenue-split", syndicateId, "my-earnings"],
    queryFn: () => getMyEarnings(syndicateId),
    enabled: !!syndicateId,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wallet className="h-5 w-5" />
          My Earnings
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-bold" data-testid="my-earnings-total">
          {fmt(earnings?.total_cents ?? 0)}
        </p>
        <p className="text-sm text-muted-foreground">
          across {earnings?.split_count ?? 0} split(s)
        </p>
      </CardContent>
    </Card>
  );
}
