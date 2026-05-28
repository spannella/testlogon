import * as React from "react";
import { Mic, Video, Square, Play, RotateCcw, Send, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { sendVoicemail } from "@/api/endpoints/messaging";
import { useToast } from "@/hooks/use-toast";

type Phase = "idle" | "recording" | "previewing" | "uploading" | "sent";

interface VoicemailRecorderProps {
  conversationId: string;
  callId: string;
  onSent: () => void;
  onSkip: () => void;
}

function detectAudioMimeType(): string {
  if (typeof MediaRecorder === "undefined") return "audio/webm";
  if (MediaRecorder.isTypeSupported("audio/webm;codecs=opus")) return "audio/webm;codecs=opus";
  if (MediaRecorder.isTypeSupported("audio/webm")) return "audio/webm";
  if (MediaRecorder.isTypeSupported("audio/mp4")) return "audio/mp4";
  if (MediaRecorder.isTypeSupported("audio/ogg;codecs=opus")) return "audio/ogg;codecs=opus";
  return "audio/webm";
}

function detectVideoMimeType(): string {
  if (typeof MediaRecorder === "undefined") return "video/webm";
  if (MediaRecorder.isTypeSupported("video/webm;codecs=vp8,opus")) return "video/webm;codecs=vp8,opus";
  if (MediaRecorder.isTypeSupported("video/webm;codecs=vp9,opus")) return "video/webm;codecs=vp9,opus";
  if (MediaRecorder.isTypeSupported("video/webm")) return "video/webm";
  if (MediaRecorder.isTypeSupported("video/mp4")) return "video/mp4";
  return "video/webm";
}

const MAX_DURATION = 60; // seconds

export function VoicemailRecorder({ conversationId, callId, onSent, onSkip }: VoicemailRecorderProps) {
  const { toast } = useToast();
  const [phase, setPhase] = React.useState<Phase>("idle");
  const [mode, setMode] = React.useState<"audio" | "video">("audio");
  const [elapsed, setElapsed] = React.useState(0);
  const [blob, setBlob] = React.useState<Blob | null>(null);
  const [waveform, setWaveform] = React.useState<number[]>([]);
  const [mimeType, setMimeType] = React.useState("");
  const [error, setError] = React.useState("");

  const recorderRef = React.useRef<MediaRecorder | null>(null);
  const streamRef = React.useRef<MediaStream | null>(null);
  const chunksRef = React.useRef<Blob[]>([]);
  const timerRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const waveformRef = React.useRef<number[]>([]);
  const analyserRef = React.useRef<AnalyserNode | null>(null);
  const waveformTimerRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // Cleanup on unmount
  React.useEffect(() => {
    return () => {
      if (streamRef.current) {
        streamRef.current.getTracks().forEach((t) => t.stop());
      }
      if (timerRef.current) clearInterval(timerRef.current);
      if (waveformTimerRef.current) clearInterval(waveformTimerRef.current);
    };
  }, []);

  const startRecording = async (recordMode: "audio" | "video") => {
    setMode(recordMode);
    setError("");
    setElapsed(0);
    setBlob(null);
    waveformRef.current = [];
    chunksRef.current = [];

    try {
      const constraints: MediaStreamConstraints =
        recordMode === "video"
          ? {
              video: { width: { ideal: 1280, max: 1280 }, height: { ideal: 720, max: 720 }, facingMode: "user" },
              audio: { echoCancellation: true, noiseSuppression: true },
            }
          : { audio: { echoCancellation: true, noiseSuppression: true } };

      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      streamRef.current = stream;

      const mime = recordMode === "video" ? detectVideoMimeType() : detectAudioMimeType();
      setMimeType(mime);

      const recorder = new MediaRecorder(stream, { mimeType: mime });
      recorderRef.current = recorder;

      // Waveform sampling via AnalyserNode
      const audioCtx = new AudioContext();
      const source = audioCtx.createMediaStreamSource(stream);
      const analyser = audioCtx.createAnalyser();
      analyser.fftSize = 256;
      source.connect(analyser);
      analyserRef.current = analyser;

      waveformTimerRef.current = setInterval(() => {
        if (!analyserRef.current) return;
        const data = new Uint8Array(analyserRef.current.frequencyBinCount);
        analyserRef.current.getByteTimeDomainData(data);
        let sum = 0;
        for (let i = 0; i < data.length; i++) {
          const v = (data[i] - 128) / 128;
          sum += v * v;
        }
        const rms = Math.min(1, Math.sqrt(sum / data.length) * 2);
        waveformRef.current.push(rms);
      }, 100);

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };
      recorder.onstop = () => {
        const b = new Blob(chunksRef.current, { type: mime });
        setBlob(b);
        // Downsample waveform to 30-100 samples
        const raw = waveformRef.current;
        const targetLen = Math.max(30, Math.min(100, raw.length));
        const step = raw.length / targetLen;
        const downsampled: number[] = [];
        for (let i = 0; i < targetLen; i++) {
          const idx = Math.floor(i * step);
          downsampled.push(raw[idx] ?? 0);
        }
        setWaveform(downsampled);
        setPhase("previewing");
      };

      recorder.start(100);
      setPhase("recording");

      // Timer + auto-stop
      const startTime = Date.now();
      timerRef.current = setInterval(() => {
        const secs = Math.floor((Date.now() - startTime) / 1000);
        setElapsed(secs);
        if (secs >= MAX_DURATION) {
          recorder.stop();
          stream.getTracks().forEach((t) => t.stop());
          if (timerRef.current) clearInterval(timerRef.current);
          if (waveformTimerRef.current) clearInterval(waveformTimerRef.current);
        }
      }, 250);
    } catch {
      setError("Could not access microphone/camera. Please check permissions.");
    }
  };

  const stopRecording = () => {
    if (recorderRef.current && recorderRef.current.state !== "inactive") {
      recorderRef.current.stop();
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
    }
    if (timerRef.current) clearInterval(timerRef.current);
    if (waveformTimerRef.current) clearInterval(waveformTimerRef.current);
  };

  const handleSend = async () => {
    if (!blob) return;
    setPhase("uploading");
    setError("");
    try {
      await sendVoicemail(conversationId, blob, {
        callId,
        durationSeconds: Math.max(1, elapsed),
        waveform,
        contentType: mimeType.split(";")[0], // strip codec params
        mode,
      });
      setPhase("sent");
      toast({ title: "Voicemail sent" });
      onSent();
    } catch {
      setError("Could not send voicemail. Try again.");
      setPhase("previewing");
    }
  };

  const formatTime = (s: number) => {
    const mm = Math.floor(s / 60).toString().padStart(2, "0");
    const ss = (s % 60).toString().padStart(2, "0");
    return `${mm}:${ss}`;
  };

  return (
    <div className="space-y-3 p-2" data-testid="voicemail-recorder">
      {phase === "idle" && (
        <div className="space-y-2">
          <p className="text-sm font-medium">Leave a voicemail?</p>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => startRecording("audio")} aria-label="Record audio voicemail">
              <Mic className="mr-1 h-4 w-4" /> Record Audio
            </Button>
            <Button size="sm" variant="outline" onClick={() => startRecording("video")} aria-label="Record video voicemail">
              <Video className="mr-1 h-4 w-4" /> Record Video
            </Button>
          </div>
          <Button size="sm" variant="ghost" onClick={onSkip} aria-label="Skip voicemail">
            <X className="mr-1 h-4 w-4" /> Skip
          </Button>
        </div>
      )}

      {phase === "recording" && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-sm font-medium">Recording {mode}...</span>
            <span className="text-sm text-muted-foreground">{formatTime(elapsed)} / {formatTime(MAX_DURATION)}</span>
          </div>
          <Button size="sm" variant="destructive" onClick={stopRecording} aria-label="Stop recording">
            <Square className="mr-1 h-4 w-4" /> Stop
          </Button>
        </div>
      )}

      {phase === "previewing" && blob && (
        <div className="space-y-2">
          <p className="text-sm font-medium">Preview ({formatTime(elapsed)})</p>
          {mode === "audio" ? (
            <audio src={URL.createObjectURL(blob)} controls className="w-full" data-testid="voicemail-preview-audio" />
          ) : (
            <video src={URL.createObjectURL(blob)} controls className="rounded-md max-w-xs w-full" data-testid="voicemail-preview-video" />
          )}
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => startRecording(mode)} aria-label="Re-record voicemail">
              <RotateCcw className="mr-1 h-4 w-4" /> Re-record
            </Button>
            <Button size="sm" onClick={handleSend} aria-label="Send voicemail">
              <Send className="mr-1 h-4 w-4" /> Send
            </Button>
          </div>
        </div>
      )}

      {phase === "uploading" && (
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm">Sending voicemail...</span>
        </div>
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}

      {(phase === "recording" || phase === "previewing" || phase === "uploading") && (
        <Button size="sm" variant="ghost" onClick={onSkip} aria-label="Skip voicemail">
          <X className="mr-1 h-4 w-4" /> Skip
        </Button>
      )}
    </div>
  );
}
