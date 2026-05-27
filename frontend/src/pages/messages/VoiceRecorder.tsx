import { useState, useRef, useEffect, useCallback } from "react";
import { Mic, X, Send, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface VoiceRecorderProps {
  onComplete: (blob: Blob, meta: { duration: number; waveform: number[]; contentType: string }) => void;
  onCancel: () => void;
  maxDuration?: number; // default 300s (5 minutes)
}

function formatTimer(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function detectMimeType(): string {
  if (typeof MediaRecorder === "undefined") return "audio/webm";
  if (MediaRecorder.isTypeSupported("audio/webm;codecs=opus")) return "audio/webm;codecs=opus";
  if (MediaRecorder.isTypeSupported("audio/webm")) return "audio/webm";
  if (MediaRecorder.isTypeSupported("audio/mp4")) return "audio/mp4";
  if (MediaRecorder.isTypeSupported("audio/ogg;codecs=opus")) return "audio/ogg;codecs=opus";
  return "audio/webm";
}

export function VoiceRecorder({ onComplete, onCancel, maxDuration = 300 }: VoiceRecorderProps) {
  const [phase, setPhase] = useState<"idle" | "recording" | "preview">("idle");
  const [elapsed, setElapsed] = useState(0);
  const [amplitudes, setAmplitudes] = useState<number[]>([]);
  const [previewBlob, setPreviewBlob] = useState<Blob | null>(null);
  const [previewWaveform, setPreviewWaveform] = useState<number[]>([]);
  const [previewDuration, setPreviewDuration] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<number>(0);
  const ampTimerRef = useRef<number>(0);
  const startTimeRef = useRef<number>(0);
  const mimeTypeRef = useRef<string>("");

  const cleanup = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (ampTimerRef.current) clearInterval(ampTimerRef.current);
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (audioCtxRef.current && audioCtxRef.current.state !== "closed") {
      audioCtxRef.current.close().catch(() => {});
      audioCtxRef.current = null;
    }
    analyserRef.current = null;
    mediaRecorderRef.current = null;
  }, []);

  useEffect(() => {
    return cleanup;
  }, [cleanup]);

  // Escape key cancels recording
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        cleanup();
        onCancel();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [cleanup, onCancel]);

  const startRecording = async () => {
    setError(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;

      // Set up Web Audio analyser for live amplitude
      const audioCtx = new AudioContext();
      audioCtxRef.current = audioCtx;
      const source = audioCtx.createMediaStreamSource(stream);
      const analyser = audioCtx.createAnalyser();
      analyser.fftSize = 256;
      source.connect(analyser);
      analyserRef.current = analyser;

      const mimeType = detectMimeType();
      mimeTypeRef.current = mimeType;
      const recorder = new MediaRecorder(stream, { mimeType });
      mediaRecorderRef.current = recorder;
      chunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };

      recorder.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: mimeType.split(";")[0] });
        const duration = (Date.now() - startTimeRef.current) / 1000;
        setPreviewBlob(blob);
        setPreviewDuration(duration);
        // Downsample live amplitudes to ~50-100 values
        setAmplitudes((prev) => {
          const target = Math.min(100, Math.max(30, prev.length));
          const step = prev.length / target;
          const downsampled: number[] = [];
          for (let i = 0; i < target; i++) {
            const idx = Math.floor(i * step);
            downsampled.push(prev[Math.min(idx, prev.length - 1)] ?? 0.2);
          }
          setPreviewWaveform(downsampled);
          return prev;
        });
        setPhase("preview");
      };

      recorder.start(100); // collect data every 100ms
      startTimeRef.current = Date.now();
      setPhase("recording");
      setElapsed(0);
      setAmplitudes([]);

      // Timer for elapsed display
      timerRef.current = window.setInterval(() => {
        const secs = (Date.now() - startTimeRef.current) / 1000;
        setElapsed(secs);
        if (secs >= maxDuration) {
          recorder.stop();
          cleanup();
        }
      }, 250);

      // Amplitude sampling at ~10Hz
      const dataArray = new Uint8Array(analyser.frequencyBinCount);
      ampTimerRef.current = window.setInterval(() => {
        if (!analyserRef.current) return;
        analyserRef.current.getByteFrequencyData(dataArray);
        // RMS amplitude normalized to 0-1
        let sum = 0;
        for (let i = 0; i < dataArray.length; i++) sum += (dataArray[i] ?? 0) * (dataArray[i] ?? 0);
        const rms = Math.sqrt(sum / dataArray.length) / 255;
        setAmplitudes((prev) => [...prev, Math.min(1, rms * 2)]);
      }, 100);
    } catch {
      setError("Microphone access required. Please allow microphone access and try again.");
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === "recording") {
      mediaRecorderRef.current.stop();
    }
    if (timerRef.current) clearInterval(timerRef.current);
    if (ampTimerRef.current) clearInterval(ampTimerRef.current);
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
    }
  };

  const handleSend = () => {
    if (!previewBlob) return;
    onComplete(previewBlob, {
      duration: previewDuration,
      waveform: previewWaveform,
      contentType: mimeTypeRef.current.split(";")[0] || "audio/webm",
    });
  };

  const handleReRecord = () => {
    setPreviewBlob(null);
    setPreviewWaveform([]);
    setPreviewDuration(0);
    setPhase("idle");
    setAmplitudes([]);
    startRecording();
  };

  const handleCancel = () => {
    cleanup();
    setPhase("idle");
    onCancel();
  };

  // Idle: show mic button to start
  if (phase === "idle") {
    return (
      <div className="flex items-center gap-2">
        {error && <span className="text-xs text-destructive">{error}</span>}
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 shrink-0"
          onClick={startRecording}
          aria-label="Record voice message"
        >
          <Mic className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  // Recording: show live waveform + timer + stop/cancel
  if (phase === "recording") {
    const showWarning = maxDuration - elapsed <= 30;
    return (
      <div className="flex items-center gap-2 w-full" data-testid="voice-recorder-recording">
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 shrink-0"
          onClick={handleCancel}
          aria-label="Cancel recording"
        >
          <X className="h-4 w-4" />
        </Button>

        {/* Live waveform */}
        <div className="flex-1 flex items-end gap-[2px] h-8 overflow-hidden">
          {amplitudes.slice(-50).map((amp, i) => (
            <div
              key={i}
              className="bg-destructive/70 rounded-full"
              style={{
                width: "3px",
                height: `${Math.max(3, amp * 28)}px`,
              }}
            />
          ))}
        </div>

        {/* Timer */}
        <span className={cn(
          "text-sm font-mono tabular-nums",
          showWarning ? "text-destructive font-bold" : "text-muted-foreground",
        )}>
          {formatTimer(elapsed)}
        </span>

        {/* Recording indicator */}
        <div className="h-3 w-3 rounded-full bg-destructive animate-pulse" aria-label="Recording" />

        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 shrink-0"
          onClick={stopRecording}
          aria-label="Stop recording"
        >
          <Square className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  // Preview: show waveform + send/re-record/cancel
  return (
    <div className="flex items-center gap-2 w-full" data-testid="voice-recorder-preview">
      <Button
        variant="ghost"
        size="icon"
        className="h-9 w-9 shrink-0"
        onClick={handleCancel}
        aria-label="Cancel voice message"
      >
        <X className="h-4 w-4" />
      </Button>

      {/* Preview waveform */}
      <div className="flex-1 flex items-end gap-[2px] h-8">
        {previewWaveform.map((amp, i) => (
          <div
            key={i}
            className="bg-primary/60 rounded-full"
            style={{
              width: `${100 / previewWaveform.length}%`,
              height: `${Math.max(3, amp * 28)}px`,
            }}
          />
        ))}
      </div>

      <span className="text-sm font-mono tabular-nums text-muted-foreground">
        {formatTimer(previewDuration)}
      </span>

      <Button
        variant="ghost"
        size="sm"
        className="h-8 text-xs"
        onClick={handleReRecord}
        aria-label="Re-record"
      >
        Re-record
      </Button>

      <Button
        size="icon"
        className="h-9 w-9 shrink-0 rounded-full"
        onClick={handleSend}
        aria-label="Send voice message"
      >
        <Send className="h-4 w-4" />
      </Button>
    </div>
  );
}
