import { useEffect, useMemo, useRef, useState } from "react";
import { Play, Pause, RotateCcw, Gauge } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { SshRecordingEvent } from "@/api/types";

interface SshRecordingPlayerProps {
  events: SshRecordingEvent[];
  cols?: number;
  rows?: number;
  autoPlay?: boolean;
}

const SPEEDS = [0.5, 1, 2, 4];

/**
 * Lightweight asciicast playback component (INFRA-010).
 *
 * Replays the recorded event stream ([offset, type, data]) into a terminal-like
 * <pre>, advancing through events on a timer. No external asciinema-player
 * dependency — keeps playback deterministic for E2E tests.
 */
export default function SshRecordingPlayer({
  events,
  cols = 80,
  rows = 24,
  autoPlay = false,
}: SshRecordingPlayerProps) {
  // Only output events carry terminal content for playback.
  const outputEvents = useMemo(
    () => events.filter((e) => e[1] === "o"),
    [events],
  );
  const totalDuration = useMemo(
    () => (outputEvents.length ? outputEvents[outputEvents.length - 1][0] : 0),
    [outputEvents],
  );

  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(autoPlay);
  const [speed, setSpeed] = useState(1);
  const timerRef = useRef<number | null>(null);

  // Accumulated terminal text up to (but not including) `index`.
  const buffer = useMemo(
    () => outputEvents.slice(0, index).map((e) => e[2]).join(""),
    [outputEvents, index],
  );

  useEffect(() => {
    if (!playing) return;
    if (index >= outputEvents.length) {
      setPlaying(false);
      return;
    }
    const prevOffset = index > 0 ? outputEvents[index - 1][0] : 0;
    const nextOffset = outputEvents[index][0];
    const delayMs = Math.max(0, (nextOffset - prevOffset) * 1000) / speed;
    timerRef.current = window.setTimeout(() => {
      setIndex((i) => i + 1);
    }, delayMs);
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [playing, index, outputEvents, speed]);

  const finished = index >= outputEvents.length;

  const handlePlayPause = () => {
    if (finished) {
      setIndex(0);
      setPlaying(true);
    } else {
      setPlaying((p) => !p);
    }
  };

  const handleRestart = () => {
    setIndex(0);
    setPlaying(false);
  };

  const cycleSpeed = () => {
    const next = SPEEDS[(SPEEDS.indexOf(speed) + 1) % SPEEDS.length];
    setSpeed(next);
  };

  return (
    <div data-testid="ssh-recording-player" className="space-y-2">
      <pre
        data-testid="ssh-recording-terminal"
        className="overflow-auto rounded-md bg-black p-3 font-mono text-xs leading-snug text-green-300"
        style={{ minHeight: `${Math.min(rows, 24) * 1.1}rem`, maxHeight: "24rem" }}
      >
        {buffer || (events.length === 0 ? "(no recorded output)" : "")}
      </pre>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="secondary"
          onClick={handlePlayPause}
          data-testid="ssh-recording-playpause"
        >
          {playing && !finished ? (
            <Pause className="mr-1 h-4 w-4" />
          ) : (
            <Play className="mr-1 h-4 w-4" />
          )}
          {finished ? "Replay" : playing ? "Pause" : "Play"}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={handleRestart}>
          <RotateCcw className="mr-1 h-4 w-4" />
          Restart
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={cycleSpeed}>
          <Gauge className="mr-1 h-4 w-4" />
          {speed}x
        </Button>
        <span className="ml-auto text-xs text-muted-foreground">
          {index}/{outputEvents.length} events · {cols}×{rows} ·{" "}
          {totalDuration.toFixed(1)}s
        </span>
      </div>
    </div>
  );
}
