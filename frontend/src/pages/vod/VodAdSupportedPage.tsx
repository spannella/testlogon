import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { vodAdSupportedApi } from "@/api/endpoints/vodAdSupported";
import type { VodAdBreak, VodAdSupportedStartResponse } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// VOD-018: Ad-Supported viewer affordance.
//
// The viewer can watch an ad_supported video for free in exchange for watching
// ad breaks. Starting a session returns an ad schedule + a free playback grant.
// Continued playback is gated until each required ad break is reported complete.
export default function VodAdSupportedPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const qc = useQueryClient();
  const [session, setSession] = useState<VodAdSupportedStartResponse | null>(
    null,
  );

  const statusQuery = useQuery({
    queryKey: ["vod-ad-supported", videoId],
    queryFn: () => vodAdSupportedApi.getSession(videoId!),
    enabled: !!videoId,
  });

  const startMut = useMutation({
    mutationFn: () => vodAdSupportedApi.start(videoId!),
    onSuccess: (data) => {
      setSession(data);
      qc.invalidateQueries({ queryKey: ["vod-ad-supported", videoId] });
    },
  });

  const reportMut = useMutation({
    mutationFn: (breakId: string) =>
      vodAdSupportedApi.reportBreak(videoId!, {
        break_id: breakId,
        event_type: "complete",
      }),
    onSuccess: (data) => {
      setSession((prev) =>
        prev
          ? {
              ...prev,
              status: data.status as VodAdSupportedStartResponse["status"],
              breaks_completed: data.breaks_completed,
              next_required_break_id: data.next_required_break_id,
              playback_unlocked: data.playback_unlocked,
              ad_schedule: prev.ad_schedule.map((b) =>
                b.break_id === data.break_id ? { ...b, completed: true } : b,
              ),
            }
          : prev,
      );
      qc.invalidateQueries({ queryKey: ["vod-ad-supported", videoId] });
    },
  });

  const schedule: VodAdBreak[] = session?.ad_schedule ?? [];

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-4" data-testid="vod-ad-supported-page">
      <h1 className="text-2xl font-bold">Watch Free with Ads</h1>

      <Card>
        <CardHeader>
          <CardTitle>Ad-Supported Viewing</CardTitle>
        </CardHeader>
        <CardContent className="p-4 space-y-3">
          <p data-testid="ad-session-status">
            Status:{" "}
            {session?.status ?? statusQuery.data?.status ?? "not started"}
          </p>

          {!session && (
            <Button
              data-testid="start-ad-session"
              onClick={() => startMut.mutate()}
              disabled={startMut.isPending}
            >
              Watch free with ads
            </Button>
          )}

          {startMut.isError && (
            <p className="text-red-500">
              Could not start ad-supported session.
            </p>
          )}

          {session && (
            <div className="space-y-3">
              <p data-testid="playback-unlocked">
                Playback {session.playback_unlocked ? "unlocked" : "locked"} (
                {session.breaks_completed}/{session.breaks_total} ad breaks
                watched)
              </p>

              {schedule.length === 0 && (
                <p className="text-muted-foreground">
                  No ads for you — enjoy ad-free playback.
                </p>
              )}

              <ul className="space-y-2">
                {schedule.map((b) => (
                  <li
                    key={b.break_id}
                    className="flex items-center justify-between rounded border p-2"
                    data-testid={`ad-break-${b.slot_index}`}
                  >
                    <span>
                      {b.slot_type} @ {b.position_seconds}s · {b.duration_seconds}s
                    </span>
                    {b.completed ? (
                      <span className="text-green-600">Watched</span>
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        data-testid={`watch-break-${b.slot_index}`}
                        onClick={() => reportMut.mutate(b.break_id)}
                        disabled={reportMut.isPending}
                      >
                        Watch ad
                      </Button>
                    )}
                  </li>
                ))}
              </ul>

              {session.playback_unlocked && session.playback_url && (
                <p className="text-sm text-muted-foreground break-all">
                  Playback ready: {session.playback_url}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
