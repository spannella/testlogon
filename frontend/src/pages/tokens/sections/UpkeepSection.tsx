import type { UseQueryResult } from "@tanstack/react-query";
import { Snowflake } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import type { UpkeepSummary, UpkeepStatus } from "@/api/endpoints/tokens";
import { formatCents, upkeepCoverageFraction } from "@/lib/tokens";
import { PendingBackend, ShortfallAssumptionNote } from "../PendingBackend";

const STATUS_VARIANT: Record<UpkeepStatus, "default" | "secondary" | "destructive" | "outline"> = {
  covered: "secondary",
  due: "default",
  paid: "secondary",
  delinquent: "destructive",
  frozen: "destructive",
};

export function UpkeepSection({
  query,
  onPay,
  paying,
}: {
  query: UseQueryResult<UpkeepSummary>;
  onPay: () => void;
  paying: boolean;
}) {
  const data = query.data;
  const threshold = data?.threshold ?? 100_00;
  const fees = data?.fees_generated ?? 0;
  const coveragePct = Math.round(upkeepCoverageFraction(fees, threshold) * 100);
  const myShare = data?.my_share ?? 0;
  const frozen = data?.status === "frozen";

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Book upkeep</CardTitle>
        {data && (
          <Badge variant={STATUS_VARIANT[data.status] ?? "outline"} className="gap-1">
            {frozen && <Snowflake className="h-3 w-3" />}
            {data.status}
          </Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {query.isLoading ? (
          <Skeleton className="h-28 w-full" />
        ) : query.isError ? (
          <PendingBackend label="Upkeep" />
        ) : (
          <>
            <ShortfallAssumptionNote />

            <div className="space-y-1.5">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">
                  Trading fees this month{data?.month ? ` (${data.month})` : ""}
                </span>
                <span className="tabular-nums">
                  {formatCents(fees)} / {formatCents(threshold)}
                </span>
              </div>
              <Progress value={coveragePct} />
              <p className="text-xs text-muted-foreground">
                {coveragePct}% of the ${(threshold / 100).toFixed(0)} monthly threshold covered by
                trading fees.
              </p>
            </div>

            <Separator />

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Metric label="Book bill (shortfall)" value={formatCents(data?.amount_due)} />
              <Metric label="My pro-rata share" value={formatCents(myShare)} accent />
              <Metric label="Status" value={data?.status ?? "-"} />
            </div>

            {frozen && (
              <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                This book is <span className="font-semibold">frozen</span> (non-tradeable) for
                non-payment. Paying your share below will reverse the freeze.
              </div>
            )}

            <div className="flex items-center justify-end">
              <Button
                onClick={onPay}
                disabled={paying || myShare <= 0}
                variant={frozen ? "destructive" : "default"}
                data-testid="pay-upkeep"
              >
                {paying ? "Paying..." : `Pay my share ${formatCents(myShare)}`}
              </Button>
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
      <p className={`mt-0.5 text-lg font-semibold tabular-nums ${accent ? "text-amber-600 dark:text-amber-400" : ""}`}>
        {value}
      </p>
    </div>
  );
}
