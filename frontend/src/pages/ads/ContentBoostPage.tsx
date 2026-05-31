// frontend/src/pages/ads/ContentBoostPage.tsx
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { contentBoostApi } from "@/api/endpoints/contentBoost";
import type { ContentBoostCreateInput } from "@/api/types";

const BOOST_QUERY_KEY = ["content-boosts"];

function dollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function ContentBoostPage() {
  const queryClient = useQueryClient();
  const [contentType, setContentType] = useState("post");
  const [contentId, setContentId] = useState("");
  const [budgetDollars, setBudgetDollars] = useState("5.00");
  const [durationMinutes, setDurationMinutes] = useState("60");
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: BOOST_QUERY_KEY,
    queryFn: () => contentBoostApi.list(),
  });

  const createMut = useMutation({
    mutationFn: (body: ContentBoostCreateInput) => contentBoostApi.create(body),
    onSuccess: () => {
      setError(null);
      setContentId("");
      queryClient.invalidateQueries({ queryKey: BOOST_QUERY_KEY });
    },
    onError: (e: any) => {
      setError(e?.detail ?? e?.message ?? "Failed to create boost");
    },
  });

  const cancelMut = useMutation({
    mutationFn: (boostId: string) => contentBoostApi.cancel(boostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: BOOST_QUERY_KEY });
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const budget_cents = Math.round(parseFloat(budgetDollars || "0") * 100);
    const duration_seconds = Math.round(parseFloat(durationMinutes || "0") * 60);
    createMut.mutate({
      content_type: contentType,
      content_id: contentId.trim(),
      budget_cents,
      duration_seconds,
    });
  }

  const boosts = data?.boosts ?? [];

  return (
    <div data-testid="content-boost-page" className="mx-auto max-w-3xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Boost Your Content</h1>
        <p className="text-sm text-muted-foreground">
          Promote your own post, video, or broadcast. Set a budget and duration;
          we charge your wallet up-front and elevate your content's reach until
          the budget or time runs out.
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        data-testid="boost-create-form"
        className="space-y-3 rounded-lg border p-4"
      >
        <label className="block text-sm">
          Content type
          <select
            data-testid="boost-content-type"
            value={contentType}
            onChange={(e) => setContentType(e.target.value)}
            className="mt-1 block w-full rounded border px-2 py-1"
          >
            <option value="post">Post</option>
            <option value="video">Video</option>
            <option value="broadcast">Broadcast</option>
          </select>
        </label>
        <label className="block text-sm">
          Content ID
          <input
            data-testid="boost-content-id"
            value={contentId}
            onChange={(e) => setContentId(e.target.value)}
            placeholder="e.g. post_abc123"
            className="mt-1 block w-full rounded border px-2 py-1"
          />
        </label>
        <label className="block text-sm">
          Budget (USD)
          <input
            data-testid="boost-budget"
            value={budgetDollars}
            onChange={(e) => setBudgetDollars(e.target.value)}
            inputMode="decimal"
            className="mt-1 block w-full rounded border px-2 py-1"
          />
        </label>
        <label className="block text-sm">
          Duration (minutes)
          <input
            data-testid="boost-duration"
            value={durationMinutes}
            onChange={(e) => setDurationMinutes(e.target.value)}
            inputMode="numeric"
            className="mt-1 block w-full rounded border px-2 py-1"
          />
        </label>
        <button
          type="submit"
          data-testid="boost-submit"
          disabled={createMut.isPending || !contentId.trim()}
          className="rounded bg-primary px-4 py-2 text-primary-foreground disabled:opacity-50"
        >
          {createMut.isPending ? "Boosting…" : "Boost"}
        </button>
      </form>

      {error && (
        <p data-testid="boost-error" role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <div>
        <h2 className="mb-2 text-lg font-medium">Your boosts</h2>
        {isLoading ? (
          <p>Loading…</p>
        ) : boosts.length === 0 ? (
          <p data-testid="boost-empty" className="text-sm text-muted-foreground">
            No boosts yet.
          </p>
        ) : (
          <ul data-testid="boost-list" className="space-y-2">
            {boosts.map((b) => (
              <li
                key={b.boost_id}
                data-testid={`boost-row-${b.boost_id}`}
                className="rounded border p-3 text-sm"
              >
                <Link to={`/ads/boost/${b.boost_id}`} className="font-medium underline">
                  {b.content_type} · {b.content_id}
                </Link>{" "}
                — <span data-testid="boost-status">{b.status}</span> ·{" "}
                {dollars(b.spent_cents)} / {dollars(b.budget_cents)} spent ·{" "}
                {dollars(b.remaining_cents)} remaining
                {b.status === "active" && (
                  <button
                    data-testid={`boost-cancel-${b.boost_id}`}
                    onClick={() => cancelMut.mutate(b.boost_id)}
                    disabled={cancelMut.isPending}
                    className="ml-2 rounded border px-2 py-0.5"
                  >
                    Cancel & refund
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
