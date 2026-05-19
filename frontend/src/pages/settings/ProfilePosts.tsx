import { FeedTimeline } from "@/pages/feed/FeedTimeline";
import { useAuthStore } from "@/stores/authStore";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { useSearchParams } from "react-router-dom";
import { parseProfileFeedUrlState, writeProfileFeedUrlState } from "@/lib/profileFeedUrlState";
import { useEffect, useState } from "react";

export function ProfilePosts() {
  const userId = useAuthStore((s) => s.userId);
  const [searchParams, setSearchParams] = useSearchParams();
  const urlState = parseProfileFeedUrlState(searchParams);
  const [searchDraft, setSearchDraft] = useState(urlState.q ?? "");

  if (!userId) {
    return null;
  }

  useEffect(() => {
    setSearchDraft(urlState.q ?? "");
  }, [urlState.q]);

  const q = urlState.q ?? "";
  const fromDate = urlState.from ?? "";
  const toDate = urlState.to ?? "";
  const hasMedia = urlState.hasMedia;
  const cursor = urlState.cursor;

  const updateState = (patch: Parameters<typeof writeProfileFeedUrlState>[1], replace = false) => {
    const next = writeProfileFeedUrlState(searchParams, patch);
    setSearchParams(next, { replace });
  };

  const clearFilters = () => {
    setSearchDraft("");
    updateState({ q: undefined, from: undefined, to: undefined, hasMedia: undefined, cursor: undefined });
  };

  const fromIso = fromDate ? `${fromDate}T00:00:00Z` : undefined;
  const toIso = toDate ? `${toDate}T23:59:59Z` : undefined;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border bg-card p-3">
        <div className="grid gap-3 md:grid-cols-4">
          <div className="space-y-1 md:col-span-2">
            <Label htmlFor="profile-posts-search">Search posts</Label>
            <Input
              id="profile-posts-search"
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  updateState({ q: searchDraft || undefined, cursor: undefined });
                }
              }}
              onBlur={() => updateState({ q: searchDraft || undefined, cursor: undefined })}
              placeholder="Search your posts"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="profile-posts-from">From</Label>
            <Input
              id="profile-posts-from"
              type="date"
              value={fromDate}
              onChange={(e) => updateState({ from: e.target.value || undefined, cursor: undefined })}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="profile-posts-to">To</Label>
            <Input
              id="profile-posts-to"
              type="date"
              value={toDate}
              onChange={(e) => updateState({ to: e.target.value || undefined, cursor: undefined })}
            />
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <div className="inline-flex items-center gap-2 text-sm text-muted-foreground">
            <Label htmlFor="profile-posts-media-filter">Media</Label>
            <select
              id="profile-posts-media-filter"
              className="h-8 rounded-md border bg-background px-2 text-sm"
              value={hasMedia === true ? "with" : hasMedia === false ? "without" : "all"}
              onChange={(e) => {
                const next =
                  e.target.value === "with" ? true : e.target.value === "without" ? false : undefined;
                updateState({ hasMedia: next, cursor: undefined });
              }}
            >
              <option value="all">All posts</option>
              <option value="with">With media</option>
              <option value="without">Without media</option>
            </select>
          </div>
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            Clear
          </Button>
        </div>
      </div>

      <FeedTimeline
        authorId={userId}
        q={q || undefined}
        from={fromIso}
        to={toIso}
        hasMedia={hasMedia}
        cursor={cursor}
        onCursorChange={(nextCursor) => updateState({ cursor: nextCursor }, true)}
        emptyTitle="No posts on your profile yet"
        emptyDescription="Posts you create will appear here."
      />
    </div>
  );
}
