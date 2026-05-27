import { useState, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getStoryBar } from "@/api/endpoints/stories";
import type { StoryBarEntry } from "@/api/types";
import { StoryViewer } from "./StoryViewer";
import { StoryComposer } from "./StoryComposer";

export function StoryBar() {
  const queryClient = useQueryClient();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [viewerOpen, setViewerOpen] = useState(false);
  const [composerOpen, setComposerOpen] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);

  const { data, isLoading } = useQuery({
    queryKey: ["stories", "bar"],
    queryFn: () => getStoryBar(),
    refetchInterval: 60_000,
  });

  const bar = data?.bar ?? [];

  const scroll = (dir: "left" | "right") => {
    if (!scrollRef.current) return;
    const amount = 200;
    scrollRef.current.scrollBy({
      left: dir === "left" ? -amount : amount,
      behavior: "smooth",
    });
  };

  const openViewer = (userId: string) => {
    const idx = bar.findIndex((b) => b.user_id === userId);
    setSelectedUserId(userId);
    setSelectedIndex(idx >= 0 ? idx : 0);
    setViewerOpen(true);
  };

  const handleNextCreator = () => {
    if (selectedIndex < bar.length - 1) {
      const next = bar[selectedIndex + 1]!;
      setSelectedUserId(next.user_id);
      setSelectedIndex(selectedIndex + 1);
    } else {
      setViewerOpen(false);
    }
  };

  const handlePrevCreator = () => {
    if (selectedIndex > 0) {
      const prev = bar[selectedIndex - 1]!;
      setSelectedUserId(prev.user_id);
      setSelectedIndex(selectedIndex - 1);
    }
  };

  if (isLoading) {
    return (
      <div className="flex gap-3 overflow-hidden py-2" data-testid="story-bar-loading">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex flex-col items-center gap-1">
            <div className="h-16 w-16 animate-pulse rounded-full bg-muted" />
            <div className="h-3 w-12 animate-pulse rounded bg-muted" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <>
      <div className="relative" data-testid="story-bar">
        <div className="flex items-center gap-2">
          {bar.length > 4 && (
            <Button
              variant="ghost"
              size="icon"
              className="hidden shrink-0 sm:flex"
              onClick={() => scroll("left")}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          )}

          <div
            ref={scrollRef}
            className="flex gap-3 overflow-x-auto py-2 scrollbar-hide"
            style={{ scrollbarWidth: "none" }}
          >
            {/* Create story button */}
            <button
              onClick={() => setComposerOpen(true)}
              className="flex shrink-0 flex-col items-center gap-1"
              data-testid="create-story-button"
            >
              <div className="flex h-16 w-16 items-center justify-center rounded-full border-2 border-dashed border-muted-foreground/30 bg-muted/50 transition hover:border-primary/50 hover:bg-muted">
                <Plus className="h-6 w-6 text-muted-foreground" />
              </div>
              <span className="max-w-[64px] truncate text-xs text-muted-foreground">
                Your story
              </span>
            </button>

            {/* Story entries */}
            {bar.map((entry) => (
              <StoryBarAvatar
                key={entry.user_id}
                entry={entry}
                onClick={() => openViewer(entry.user_id)}
              />
            ))}
          </div>

          {bar.length > 4 && (
            <Button
              variant="ghost"
              size="icon"
              className="hidden shrink-0 sm:flex"
              onClick={() => scroll("right")}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Story Viewer Overlay */}
      {viewerOpen && selectedUserId && (
        <StoryViewer
          userId={selectedUserId}
          onClose={() => {
            setViewerOpen(false);
            queryClient.invalidateQueries({ queryKey: ["stories", "bar"] });
          }}
          onNextCreator={handleNextCreator}
          onPrevCreator={handlePrevCreator}
        />
      )}

      {/* Story Composer Dialog */}
      {composerOpen && (
        <StoryComposer
          open={composerOpen}
          onClose={() => {
            setComposerOpen(false);
            queryClient.invalidateQueries({ queryKey: ["stories", "bar"] });
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------

function StoryBarAvatar({
  entry,
  onClick,
}: {
  entry: StoryBarEntry;
  onClick: () => void;
}) {
  const ringColor = entry.has_unseen
    ? "bg-gradient-to-tr from-pink-500 via-red-500 to-yellow-500"
    : "bg-muted-foreground/30";

  return (
    <button
      onClick={onClick}
      className="flex shrink-0 flex-col items-center gap-1"
      data-testid={`story-avatar-${entry.user_id}`}
    >
      <div className={`rounded-full p-[2px] ${ringColor}`}>
        <div className="rounded-full bg-background p-[2px]">
          <div className="flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-muted text-xs font-medium uppercase">
            {entry.user_id.charAt(0)}
          </div>
        </div>
      </div>
      <span className="max-w-[64px] truncate text-xs text-muted-foreground">
        {entry.user_id.split("@")[0]}
      </span>
      {entry.story_count > 1 && (
        <span className="text-[10px] text-muted-foreground">
          {entry.story_count} stories
        </span>
      )}
    </button>
  );
}
