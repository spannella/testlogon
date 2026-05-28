import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Trophy } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getTopSupporters } from "@/api/endpoints/social";
import type { TopSupporter } from "@/api/types";

const PERIODS = [
  { key: "7d", label: "7 Days" },
  { key: "30d", label: "30 Days" },
  { key: "all", label: "All Time" },
] as const;

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function MedalBadge({ rank }: { rank: number }) {
  if (rank === 1) return <span className="text-lg" title="Gold">&#129351;</span>;
  if (rank === 2) return <span className="text-lg" title="Silver">&#129352;</span>;
  if (rank === 3) return <span className="text-lg" title="Bronze">&#129353;</span>;
  return (
    <span className="flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
      {rank}
    </span>
  );
}

function SupporterRow({ supporter }: { supporter: TopSupporter }) {
  const initials = (supporter.display_name || supporter.user_id)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? "")
    .join("");

  return (
    <div className="flex items-center gap-3 py-2">
      <MedalBadge rank={supporter.rank} />
      {supporter.avatar_url ? (
        <img
          src={supporter.avatar_url}
          alt={supporter.display_name}
          className="h-8 w-8 rounded-full object-cover"
        />
      ) : (
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
          {initials}
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="truncate text-sm font-medium">{supporter.display_name || supporter.user_id}</p>
        <p className="text-xs text-muted-foreground">
          {supporter.tip_count} tip{supporter.tip_count !== 1 ? "s" : ""}
        </p>
      </div>
      <span className="text-sm font-semibold">{formatCents(supporter.total_cents)}</span>
    </div>
  );
}

export default function TopSupportersCard({ creatorId }: { creatorId: string }) {
  const [period, setPeriod] = useState<string>("30d");

  const { data, isLoading } = useQuery({
    queryKey: ["top-supporters", creatorId, period],
    queryFn: () => getTopSupporters(creatorId, { period, limit: 10 }),
    staleTime: 300_000,
    enabled: !!creatorId,
  });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Trophy className="h-5 w-5 text-yellow-500" />
            Top Supporters
          </CardTitle>
          <div className="flex gap-1 rounded-full bg-muted p-1">
            {PERIODS.map((p) => (
              <button
                key={p.key}
                onClick={() => setPeriod(p.key)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                  period === p.key
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="animate-pulse space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-10 rounded bg-muted" />
            ))}
          </div>
        ) : !data?.supporters?.length ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No tips received in this period
          </p>
        ) : (
          <>
            <div className="divide-y">
              {data.supporters.map((s) => (
                <SupporterRow key={s.user_id} supporter={s} />
              ))}
            </div>
            {data.total_supporters > 0 && (
              <p className="mt-4 text-center text-xs text-muted-foreground">
                {data.total_supporters} supporter{data.total_supporters !== 1 ? "s" : ""} tipped{" "}
                {formatCents(data.total_tip_cents)} total
              </p>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
