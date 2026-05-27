import { useState, useRef, useEffect, useCallback } from "react";
import { Play, Pause } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface WaveformPlayerProps {
  audioUrl: string;
  waveform: number[];
  durationSeconds: number;
  consumed?: boolean;
  onPlaybackComplete?: () => void;
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}

const SPEED_OPTIONS = [1, 1.5, 2] as const;
type PlaybackSpeed = (typeof SPEED_OPTIONS)[number];

export function WaveformPlayer({
  audioUrl,
  waveform,
  durationSeconds,
  consumed,
  onPlaybackComplete,
}: WaveformPlayerProps) {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const animationRef = useRef<number>(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [speed, setSpeed] = useState<PlaybackSpeed>(1);
  const [hasPlayed, setHasPlayed] = useState(false);

  // Normalize waveform to have at least some values
  const bars = waveform.length > 0 ? waveform : Array(30).fill(0.2);
  const barCount = bars.length;

  const progress = durationSeconds > 0 ? currentTime / durationSeconds : 0;
  const remaining = Math.max(0, durationSeconds - currentTime);

  const updateTime = useCallback(() => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
      if (!audioRef.current.paused) {
        animationRef.current = requestAnimationFrame(updateTime);
      }
    }
  }, []);

  useEffect(() => {
    const audio = new Audio(audioUrl);
    audio.preload = "metadata";
    audioRef.current = audio;

    const onEnded = () => {
      setIsPlaying(false);
      setCurrentTime(0);
      setHasPlayed(true);
      onPlaybackComplete?.();
    };
    const onPause = () => setIsPlaying(false);
    const onPlay = () => setIsPlaying(true);

    audio.addEventListener("ended", onEnded);
    audio.addEventListener("pause", onPause);
    audio.addEventListener("play", onPlay);

    return () => {
      cancelAnimationFrame(animationRef.current);
      audio.removeEventListener("ended", onEnded);
      audio.removeEventListener("pause", onPause);
      audio.removeEventListener("play", onPlay);
      audio.pause();
      audio.src = "";
    };
  }, [audioUrl, onPlaybackComplete, updateTime]);

  const togglePlay = () => {
    const audio = audioRef.current;
    if (!audio) return;

    if (consumed && hasPlayed) return;

    if (audio.paused) {
      audio.playbackRate = speed;
      audio.play().catch(() => {});
      animationRef.current = requestAnimationFrame(updateTime);
    } else {
      audio.pause();
      cancelAnimationFrame(animationRef.current);
    }
  };

  const cycleSpeed = () => {
    const idx = SPEED_OPTIONS.indexOf(speed);
    const next = SPEED_OPTIONS[(idx + 1) % SPEED_OPTIONS.length] ?? 1;
    setSpeed(next as PlaybackSpeed);
    if (audioRef.current) {
      audioRef.current.playbackRate = next;
    }
  };

  const handleBarClick = (barIndex: number) => {
    if (!audioRef.current || (consumed && hasPlayed)) return;
    const seekTo = (barIndex / barCount) * durationSeconds;
    audioRef.current.currentTime = seekTo;
    setCurrentTime(seekTo);
  };

  const showConsumed = consumed && hasPlayed;

  return (
    <div className="flex items-center gap-2 min-w-[200px] max-w-[320px]" data-testid="waveform-player">
      {/* Play / Pause button */}
      <Button
        variant="ghost"
        size="icon"
        className="h-9 w-9 shrink-0 rounded-full"
        onClick={togglePlay}
        disabled={showConsumed}
        aria-label={isPlaying ? "Pause voice message" : "Play voice message"}
      >
        {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
      </Button>

      {/* Waveform bars */}
      <div className="flex-1 flex items-end gap-[2px] h-8 cursor-pointer" role="slider" aria-label="Voice message waveform">
        {bars.map((amplitude, i) => {
          const barProgress = i / barCount;
          const isPlayed = barProgress < progress;
          const minH = 3;
          const maxH = 28;
          const h = minH + amplitude * (maxH - minH);
          return (
            <div
              key={i}
              className={cn(
                "rounded-full transition-colors",
                isPlayed ? "bg-primary" : "bg-muted-foreground/30",
                showConsumed && "opacity-50",
              )}
              style={{ width: `${100 / barCount}%`, height: `${h}px` }}
              onClick={() => handleBarClick(i)}
            />
          );
        })}
      </div>

      {/* Duration / remaining time */}
      <span className="text-xs text-muted-foreground tabular-nums shrink-0 min-w-[32px]" data-testid="voice-duration">
        {isPlaying ? formatDuration(remaining) : formatDuration(durationSeconds)}
      </span>

      {/* Speed toggle */}
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-1 text-[10px] font-medium text-muted-foreground shrink-0"
        onClick={cycleSpeed}
        aria-label={`Playback speed ${speed}x`}
        data-testid="speed-toggle"
      >
        {speed}x
      </Button>

      {/* Consumed overlay */}
      {showConsumed && (
        <span className="text-xs text-muted-foreground italic" data-testid="already-listened">
          Already listened
        </span>
      )}
    </div>
  );
}
