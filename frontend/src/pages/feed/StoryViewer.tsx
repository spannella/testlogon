import { useState, useEffect, useCallback, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { X, ChevronLeft, ChevronRight, ExternalLink, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getUserStories, recordStoryView, getStoryViewers } from "@/api/endpoints/stories";
import type { Story } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";

interface StoryViewerProps {
  userId: string;
  onClose: () => void;
  onNextCreator: () => void;
  onPrevCreator: () => void;
}

const SLIDE_DURATION_MS = 5000;

export function StoryViewer({
  userId,
  onClose,
  onNextCreator,
  onPrevCreator,
}: StoryViewerProps) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [showViewers, setShowViewers] = useState(false);
  const viewedSetRef = useRef(new Set<string>());
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const currentUser = useAuthStore((s) => s.userId);

  const { data, isLoading } = useQuery({
    queryKey: ["stories", "user", userId],
    queryFn: () => getUserStories(userId),
  });

  const stories = data?.stories ?? [];
  const currentStory = stories[currentIndex] as Story | undefined;
  const isOwn = currentStory?.author_id === currentUser;

  const viewMut = useMutation({
    mutationFn: (storyId: string) => recordStoryView(storyId),
  });

  // Record view when a slide becomes visible
  useEffect(() => {
    if (!currentStory) return;
    if (viewedSetRef.current.has(currentStory.story_id)) return;
    viewedSetRef.current.add(currentStory.story_id);
    viewMut.mutate(currentStory.story_id);
  }, [currentStory?.story_id]);

  // Auto-advance timer
  useEffect(() => {
    if (!currentStory || isPaused) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const duration = currentStory.media_type === "video" && currentStory.duration_seconds
      ? currentStory.duration_seconds * 1000
      : SLIDE_DURATION_MS;

    const tickMs = 50;
    let elapsed = 0;
    setProgress(0);

    timerRef.current = setInterval(() => {
      elapsed += tickMs;
      const pct = Math.min((elapsed / duration) * 100, 100);
      setProgress(pct);

      if (elapsed >= duration) {
        if (timerRef.current) clearInterval(timerRef.current);
        goNext();
      }
    }, tickMs);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [currentIndex, isPaused, stories.length, userId]);

  const goNext = useCallback(() => {
    if (currentIndex < stories.length - 1) {
      setCurrentIndex((i) => i + 1);
      setProgress(0);
    } else {
      onNextCreator();
    }
  }, [currentIndex, stories.length, onNextCreator]);

  const goPrev = useCallback(() => {
    if (currentIndex > 0) {
      setCurrentIndex((i) => i - 1);
      setProgress(0);
    } else {
      onPrevCreator();
    }
  }, [currentIndex, onPrevCreator]);

  // Reset index when userId changes
  useEffect(() => {
    setCurrentIndex(0);
    setProgress(0);
    setShowViewers(false);
  }, [userId]);

  // Keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") goNext();
      else if (e.key === "ArrowLeft") goPrev();
      else if (e.key === "Escape") onClose();
      else if (e.key === " ") {
        e.preventDefault();
        setIsPaused((p) => !p);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [goNext, goPrev, onClose]);

  if (isLoading || !currentStory) {
    return (
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black"
        data-testid="story-viewer"
      >
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  const timeAgo = getTimeAgo(currentStory.created_at);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black"
      data-testid="story-viewer"
    >
      {/* Progress bars */}
      <div className="absolute left-4 right-4 top-4 z-10 flex gap-1" data-testid="story-progress">
        {stories.map((_, i) => (
          <div key={i} className="h-0.5 flex-1 overflow-hidden rounded-full bg-white/30">
            <div
              className="h-full rounded-full bg-white transition-all duration-[50ms] ease-linear"
              style={{
                width:
                  i < currentIndex
                    ? "100%"
                    : i === currentIndex
                    ? `${progress}%`
                    : "0%",
              }}
            />
          </div>
        ))}
      </div>

      {/* Header */}
      <div className="absolute left-4 right-4 top-8 z-10 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-medium uppercase text-muted-foreground">
            {userId.charAt(0)}
          </div>
          <div>
            <p className="text-sm font-medium text-white">
              {userId.split("@")[0]}
            </p>
            <p className="text-xs text-white/60">{timeAgo}</p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="text-white hover:bg-white/20"
          onClick={onClose}
          data-testid="story-close"
        >
          <X className="h-5 w-5" />
        </Button>
      </div>

      {/* Tap zones */}
      <div className="absolute inset-0 flex">
        <button
          className="w-1/3 cursor-pointer"
          onClick={goPrev}
          aria-label="Previous"
        />
        <button
          className="w-1/3 cursor-pointer"
          onClick={() => setIsPaused((p) => !p)}
          aria-label="Pause"
        />
        <button
          className="w-1/3 cursor-pointer"
          onClick={goNext}
          aria-label="Next"
        />
      </div>

      {/* Media content */}
      <div className="relative flex h-full w-full max-w-lg items-center justify-center">
        {currentStory.media_type === "video" ? (
          <video
            src={currentStory.media_url}
            className="max-h-full max-w-full object-contain"
            autoPlay
            playsInline
            muted={false}
          />
        ) : (
          <img
            src={currentStory.media_url}
            alt="Story"
            className="max-h-full max-w-full object-contain"
            data-testid="story-media"
          />
        )}

        {/* Text overlay */}
        {currentStory.text_overlay && (
          <div className="absolute bottom-20 left-4 right-4 text-center">
            <p
              className="rounded-lg bg-black/50 px-4 py-2 text-lg font-medium text-white"
              data-testid="story-text-overlay"
            >
              {currentStory.text_overlay}
            </p>
          </div>
        )}

        {/* Link sticker */}
        {currentStory.link_url && (
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2">
            <a
              href={currentStory.link_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 rounded-full bg-white/90 px-4 py-2 text-sm font-medium text-black transition hover:bg-white"
              data-testid="story-link-sticker"
            >
              <ExternalLink className="h-4 w-4" />
              {currentStory.link_label || "Learn More"}
            </a>
          </div>
        )}
      </div>

      {/* View count (owner only) */}
      {isOwn && (
        <button
          className="absolute bottom-4 left-1/2 z-10 flex -translate-x-1/2 items-center gap-1 rounded-full bg-white/20 px-3 py-1 text-sm text-white backdrop-blur-sm transition hover:bg-white/30"
          onClick={() => setShowViewers(!showViewers)}
          data-testid="story-view-count"
        >
          <Eye className="h-4 w-4" />
          {currentStory.view_count} views
        </button>
      )}

      {/* Navigation arrows (large screens) */}
      <Button
        variant="ghost"
        size="icon"
        className="absolute left-2 top-1/2 z-10 hidden -translate-y-1/2 text-white hover:bg-white/20 sm:flex"
        onClick={goPrev}
      >
        <ChevronLeft className="h-6 w-6" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-2 top-1/2 z-10 hidden -translate-y-1/2 text-white hover:bg-white/20 sm:flex"
        onClick={goNext}
      >
        <ChevronRight className="h-6 w-6" />
      </Button>

      {/* Viewers panel (owner only) */}
      {showViewers && isOwn && currentStory && (
        <ViewersPanel storyId={currentStory.story_id} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

function ViewersPanel({ storyId }: { storyId: string }) {
  const { data } = useQuery({
    queryKey: ["stories", storyId, "viewers"],
    queryFn: () => getStoryViewers(storyId),
  });

  const viewers = data?.viewers ?? [];

  return (
    <div className="absolute bottom-16 left-1/2 z-20 w-72 -translate-x-1/2 rounded-xl bg-gray-900/95 p-4 backdrop-blur-sm">
      <p className="mb-2 text-sm font-medium text-white">
        Viewers ({data?.total_count ?? 0})
      </p>
      <div className="max-h-48 space-y-2 overflow-y-auto">
        {viewers.length === 0 && (
          <p className="text-xs text-white/50">No viewers yet</p>
        )}
        {viewers.map((v) => (
          <div key={v.user_id} className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] font-medium uppercase">
              {v.user_id.charAt(0)}
            </div>
            <span className="text-xs text-white">
              {v.user_id.split("@")[0]}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

function getTimeAgo(isoStr: string): string {
  const diff = Date.now() - new Date(isoStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
