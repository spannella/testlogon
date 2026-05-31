// frontend/src/pages/ads/ContentBoostDetail.tsx
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { contentBoostApi } from "@/api/endpoints/contentBoost";

function dollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function ContentBoostDetail() {
  const { boostId } = useParams<{ boostId: string }>();
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["content-boost", boostId],
    queryFn: () => contentBoostApi.get(boostId as string),
    enabled: !!boostId,
  });

  const cancelMut = useMutation({
    mutationFn: () => contentBoostApi.cancel(boostId as string),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["content-boost", boostId] });
      queryClient.invalidateQueries({ queryKey: ["content-boosts"] });
    },
  });

  if (isLoading) return <p className="p-4">Loading…</p>;
  if (isError || !data)
    return (
      <p data-testid="boost-detail-error" className="p-4">
        Boost not found.
      </p>
    );

  const pct =
    data.budget_cents > 0
      ? Math.min(100, Math.round((data.spent_cents / data.budget_cents) * 100))
      : 0;

  return (
    <div data-testid="content-boost-detail" className="mx-auto max-w-2xl space-y-4 p-4">
      <Link to="/ads/boost" className="text-sm underline">
        ← Back to boosts
      </Link>
      <h1 className="text-2xl font-semibold">Boost {data.boost_id}</h1>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <dt className="font-medium">Content</dt>
        <dd>
          {data.content_type} · {data.content_id}
        </dd>
        <dt className="font-medium">Status</dt>
        <dd data-testid="boost-detail-status">{data.status}</dd>
        <dt className="font-medium">Budget</dt>
        <dd>{dollars(data.budget_cents)}</dd>
        <dt className="font-medium">Spent</dt>
        <dd data-testid="boost-detail-spent">
          {dollars(data.spent_cents)} ({pct}%)
        </dd>
        <dt className="font-medium">Remaining</dt>
        <dd data-testid="boost-detail-remaining">{dollars(data.remaining_cents)}</dd>
        <dt className="font-medium">Duration</dt>
        <dd>{Math.round(data.duration_seconds / 60)} min</dd>
        <dt className="font-medium">Ends at</dt>
        <dd>{new Date(data.ends_at * 1000).toLocaleString()}</dd>
      </dl>
      {data.status === "active" && (
        <button
          data-testid="boost-detail-cancel"
          onClick={() => cancelMut.mutate()}
          disabled={cancelMut.isPending}
          className="rounded border px-4 py-2"
        >
          Cancel & refund remaining
        </button>
      )}
    </div>
  );
}
