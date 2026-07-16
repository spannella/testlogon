import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Ticket, Trophy, Lock, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  getLotteryStatus,
  enterLottery,
  closeLotteryEntries,
  drawLottery,
} from "@/api/endpoints/broadcast-chat";
import type { BroadcastLotteryViewerStatus } from "@/api/types";

interface BroadcastLotteryCardProps {
  sessionId: string;
  lotteryId: string;
  title: string;
  isBroadcaster: boolean;
}

export function BroadcastLotteryCard({
  sessionId,
  lotteryId,
  title,
  isBroadcaster,
}: BroadcastLotteryCardProps) {
  const queryClient = useQueryClient();
  const [countdown, setCountdown] = useState<string | null>(null);

  const { data: lottery } = useQuery<BroadcastLotteryViewerStatus>({
    queryKey: ["broadcast-lottery", sessionId, lotteryId],
    queryFn: () => getLotteryStatus(sessionId, lotteryId),
    refetchInterval: (query) =>
      query.state.data?.status !== "drawn" ? 5000 : false,
  });

  // Countdown timer
  useEffect(() => {
    if (!lottery?.closes_at || lottery.status !== "open") {
      setCountdown(null);
      return;
    }
    const interval = setInterval(() => {
      const remaining = lottery.closes_at! - Math.floor(Date.now() / 1000);
      if (remaining <= 0) {
        setCountdown("Closed");
        clearInterval(interval);
        queryClient.invalidateQueries({
          queryKey: ["broadcast-lottery", sessionId, lotteryId],
        });
      } else {
        const m = Math.floor(remaining / 60);
        const s = remaining % 60;
        setCountdown(`${m}m ${s.toString().padStart(2, "0")}s`);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [lottery?.closes_at, lottery?.status, sessionId, lotteryId, queryClient]);

  const enterMut = useMutation({
    mutationFn: () => enterLottery(sessionId, lotteryId),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["broadcast-lottery", sessionId, lotteryId],
      }),
  });

  const closeMut = useMutation({
    mutationFn: () => closeLotteryEntries(sessionId, lotteryId),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["broadcast-lottery", sessionId, lotteryId],
      }),
  });

  const drawMut = useMutation({
    mutationFn: () => drawLottery(sessionId, lotteryId),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["broadcast-lottery", sessionId, lotteryId],
      }),
  });

  const statusColor =
    lottery?.status === "open"
      ? "bg-green-500/20 text-green-400"
      : lottery?.status === "entries_closed"
        ? "bg-yellow-500/20 text-yellow-400"
        : "bg-blue-500/20 text-blue-400";

  return (
    <Card
      className="my-1 border-primary/30 bg-primary/5"
      data-testid="lottery-card"
    >
      <CardContent className="p-3 space-y-2">
        <div className="flex items-center gap-2">
          <Ticket className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold" data-testid="lottery-title">
            {title}
          </span>
          <Badge className={`text-[10px] ml-auto ${statusColor}`} data-testid="lottery-status">
            {lottery?.status?.toUpperCase() ?? "LOADING"}
          </Badge>
        </div>

        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1" data-testid="lottery-entries">
            <Users className="h-3 w-3" />
            {lottery?.entry_count ?? 0}
            {lottery?.max_entries ? ` / ${lottery.max_entries}` : ""}
          </span>
          {lottery?.entry_fee_cents ? (
            <span data-testid="lottery-fee">
              Fee: ${(lottery.entry_fee_cents / 100).toFixed(2)}
            </span>
          ) : null}
          {countdown && (
            <span data-testid="lottery-countdown">
              Closes in: {countdown}
            </span>
          )}
        </div>

        {/* Viewer enter button */}
        {!isBroadcaster && lottery?.status === "open" && !lottery.has_entered && (
          <Button
            size="sm"
            className="w-full text-xs h-7"
            onClick={() => enterMut.mutate()}
            disabled={enterMut.isPending}
            data-testid="lottery-enter-btn"
          >
            Enter Lottery
          </Button>
        )}

        {/* Entered confirmation */}
        {lottery?.has_entered && lottery.status !== "drawn" && (
          <div className="text-xs text-green-500 flex items-center gap-1" data-testid="lottery-entered">
            <Trophy className="h-3 w-3" /> You&apos;re in! Waiting for draw...
          </div>
        )}

        {/* Viewer result after draw */}
        {lottery?.status === "drawn" && lottery.viewer_outcome && (
          <div
            className="rounded bg-primary/10 p-2 text-center"
            data-testid="lottery-result"
          >
            <Trophy className="h-5 w-5 mx-auto text-primary mb-1" />
            <div className="text-sm font-semibold">
              {lottery.viewer_outcome.display_label ?? "Result"}
            </div>
            {lottery.viewer_outcome.text_content && (
              <div className="text-xs text-muted-foreground mt-1">
                {lottery.viewer_outcome.text_content}
              </div>
            )}
          </div>
        )}

        {/* Draw complete for non-entrants */}
        {lottery?.status === "drawn" && !lottery.has_entered && (
          <div className="text-xs text-muted-foreground flex items-center gap-1" data-testid="lottery-drawn">
            <Lock className="h-3 w-3" /> Draw complete
          </div>
        )}

        {/* Broadcaster controls */}
        {isBroadcaster && lottery?.status === "open" && (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="text-xs h-7 flex-1"
              onClick={() => closeMut.mutate()}
              disabled={closeMut.isPending}
              data-testid="lottery-close-btn"
            >
              Close Entries
            </Button>
            <Button
              size="sm"
              variant="default"
              className="text-xs h-7 flex-1"
              onClick={() => drawMut.mutate()}
              disabled={drawMut.isPending || (lottery?.entry_count ?? 0) === 0}
              data-testid="lottery-draw-btn"
            >
              Draw Winners
            </Button>
          </div>
        )}

        {isBroadcaster && lottery?.status === "entries_closed" && (
          <Button
            size="sm"
            className="w-full text-xs h-7"
            onClick={() => drawMut.mutate()}
            disabled={drawMut.isPending}
            data-testid="lottery-draw-btn"
          >
            Draw Winners
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
