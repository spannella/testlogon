/**
 * BroadcastPostCard -- unified card for broadcast-related newsfeed posts (BCAST-010).
 *
 * Renders differently based on post_type:
 * - broadcast_announcement: countdown timer, scheduled date, "Set Reminder" CTA
 * - broadcast_live: pulsing LIVE badge, "Watch Now" CTA
 * - broadcast_vod: duration badge, viewer count, "Watch Recording" CTA
 */

import { useState, useEffect } from "react";
import { Radio, Play, Clock, Users, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { BroadcastPostMeta } from "@/api/types";

interface BroadcastPostCardProps {
  broadcastMeta: BroadcastPostMeta;
}

function useCountdown(scheduledAt: number | undefined): string | null {
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    if (!scheduledAt) return;

    const update = () => {
      const diff = scheduledAt * 1000 - Date.now();
      if (diff <= 0) {
        setText("Starting soon...");
        return;
      }
      if (diff > 24 * 60 * 60 * 1000) {
        setText(null);
        return;
      }
      const hours = Math.floor(diff / (60 * 60 * 1000));
      const minutes = Math.floor((diff % (60 * 60 * 1000)) / (60 * 1000));
      const seconds = Math.floor((diff % (60 * 1000)) / 1000);
      if (hours > 0) {
        setText(`${hours}h ${minutes}m`);
      } else {
        setText(`${minutes}m ${seconds}s`);
      }
    };

    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [scheduledAt]);

  return text;
}

function formatScheduledDate(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleDateString(undefined, {
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function AnnouncementContent({ meta }: { meta: BroadcastPostMeta }) {
  const countdown = useCountdown(meta.scheduled_at);

  return (
    <div className="mt-3 rounded-lg border border-blue-200 bg-blue-50/50 p-4 dark:border-blue-800 dark:bg-blue-950/30">
      {meta.thumbnail_url && (
        <div className="relative mb-3 overflow-hidden rounded-md">
          <img
            src={meta.thumbnail_url}
            alt={meta.session_name || "Broadcast thumbnail"}
            className="aspect-video w-full object-cover"
          />
          <div className="absolute bottom-2 right-2 rounded bg-black/60 px-2 py-1">
            <Calendar className="inline h-3.5 w-3.5 text-white" />
          </div>
        </div>
      )}

      <h3 className="text-base font-semibold" data-testid="broadcast-session-name">
        {meta.session_name || "Upcoming Broadcast"}
      </h3>

      {meta.scheduled_at && (
        <p className="mt-1 text-sm text-muted-foreground" data-testid="broadcast-scheduled-time">
          <Clock className="mr-1 inline h-3.5 w-3.5" />
          {formatScheduledDate(meta.scheduled_at)}
        </p>
      )}

      {countdown && (
        <div className="mt-2" data-testid="broadcast-countdown">
          <span className="inline-flex items-center rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800 dark:bg-blue-900 dark:text-blue-200">
            Starts in {countdown}
          </span>
        </div>
      )}

      {meta.session_description && (
        <p className="mt-2 text-sm text-muted-foreground line-clamp-2">
          {meta.session_description}
        </p>
      )}

      <div className="mt-3 flex items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          asChild
        >
          <a href={meta.broadcast_url || "#"}>View Broadcast</a>
        </Button>
      </div>
    </div>
  );
}

function LiveContent({ meta }: { meta: BroadcastPostMeta }) {
  return (
    <div className="mt-3 rounded-lg border border-red-200 bg-red-50/50 p-4 dark:border-red-800 dark:bg-red-950/30">
      {meta.thumbnail_url && (
        <div className="relative mb-3 overflow-hidden rounded-md">
          <img
            src={meta.thumbnail_url}
            alt={meta.session_name || "Live broadcast"}
            className="aspect-video w-full object-cover"
          />
          <div className="absolute left-2 top-2">
            <span className="inline-flex animate-pulse items-center gap-1 rounded bg-red-600 px-2 py-0.5 text-xs font-bold text-white">
              <span className="inline-block h-2 w-2 rounded-full bg-white" />
              LIVE
            </span>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <span
          className="inline-flex animate-pulse items-center gap-1 rounded bg-red-600 px-2 py-0.5 text-xs font-bold text-white"
          data-testid="broadcast-live-badge"
        >
          <Radio className="h-3 w-3" />
          LIVE
        </span>
        <h3 className="text-base font-semibold" data-testid="broadcast-session-name">
          {meta.session_name || "Live Broadcast"}
        </h3>
      </div>

      {meta.session_description && (
        <p className="mt-2 text-sm text-muted-foreground line-clamp-2">
          {meta.session_description}
        </p>
      )}

      <div className="mt-3">
        <Button
          size="sm"
          className="bg-red-600 text-white hover:bg-red-700"
          asChild
        >
          <a href={meta.broadcast_url || "#"}>Watch Now</a>
        </Button>
      </div>
    </div>
  );
}

function VodContent({ meta }: { meta: BroadcastPostMeta }) {
  return (
    <div className="mt-3 rounded-lg border border-gray-200 bg-gray-50/50 p-4 dark:border-gray-700 dark:bg-gray-900/30">
      {meta.thumbnail_url && (
        <div className="relative mb-3 overflow-hidden rounded-md">
          <img
            src={meta.thumbnail_url}
            alt={meta.session_name || "Broadcast recording"}
            className="aspect-video w-full object-cover"
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="rounded-full bg-black/50 p-3">
              <Play className="h-6 w-6 text-white" fill="white" />
            </div>
          </div>
          {meta.recording_duration_seconds != null && meta.recording_duration_seconds > 0 && (
            <div className="absolute bottom-2 right-2 rounded bg-black/70 px-1.5 py-0.5 text-xs font-medium text-white">
              {formatDuration(meta.recording_duration_seconds)}
            </div>
          )}
        </div>
      )}

      <h3 className="text-base font-semibold" data-testid="broadcast-session-name">
        {meta.session_name || "Broadcast Recording"}
      </h3>

      <div className="mt-1 flex items-center gap-3 text-sm text-muted-foreground">
        {meta.recording_duration_seconds != null && meta.recording_duration_seconds > 0 && (
          <span className="flex items-center gap-1" data-testid="broadcast-vod-duration">
            <Clock className="h-3.5 w-3.5" />
            {formatDuration(meta.recording_duration_seconds)}
          </span>
        )}
        {meta.peak_viewer_count != null && meta.peak_viewer_count > 0 && (
          <span className="flex items-center gap-1" data-testid="broadcast-vod-viewers">
            <Users className="h-3.5 w-3.5" />
            {meta.peak_viewer_count.toLocaleString()} live viewers
          </span>
        )}
      </div>

      <div className="mt-3">
        <Button
          size="sm"
          variant="default"
          asChild
        >
          <a href={meta.broadcast_url || "#"}>Watch Recording</a>
        </Button>
      </div>
    </div>
  );
}

export function BroadcastPostCard({ broadcastMeta }: BroadcastPostCardProps) {
  const postType = broadcastMeta.post_type;

  switch (postType) {
    case "broadcast_live":
      return <LiveContent meta={broadcastMeta} />;
    case "broadcast_vod":
      return <VodContent meta={broadcastMeta} />;
    case "broadcast_announcement":
    default:
      return <AnnouncementContent meta={broadcastMeta} />;
  }
}
