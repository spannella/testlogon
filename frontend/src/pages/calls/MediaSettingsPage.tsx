/**
 * MediaSettingsPage — manage camera/mic/speaker preferences for WebRTC calls.
 *
 * Features:
 * - Device selector dropdowns (camera, microphone, speaker)
 * - Video preview / audio level meter test buttons
 * - Default mute & video-off toggles
 * - Resolution preference
 * - Persists preferences to backend DynamoDB
 * - Shows permission status banner
 */
import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Camera,
  CameraOff,
  Mic,
  MicOff,
  Volume2,
  MonitorSpeaker,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";

import { useMediaDevices } from "@/hooks/useMediaDevices";
import { getMediaPreferences, saveMediaPreferences } from "@/api/endpoints/mediaPreferences";
import type { MediaPreferencesIn } from "@/api/types";

// ---------------------------------------------------------------------------
// Permission status helpers
// ---------------------------------------------------------------------------

type PermStatus = "granted" | "denied" | "prompt" | "unsupported" | "unknown";

async function queryPermissionStatus(name: "camera" | "microphone"): Promise<PermStatus> {
  if (typeof navigator === "undefined" || !navigator.permissions?.query) return "unknown";
  try {
    const result = await navigator.permissions.query({ name: name as PermissionName });
    return result.state as PermStatus;
  } catch {
    return "unknown";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function MediaSettingsPage() {
  const queryClient = useQueryClient();
  const devices = useMediaDevices();

  // Permission status
  const [micPerm, setMicPerm] = React.useState<PermStatus>("unknown");
  const [camPerm, setCamPerm] = React.useState<PermStatus>("unknown");

  // Preview state
  const [previewStream, setPreviewStream] = React.useState<MediaStream | null>(null);
  const [audioLevel, setAudioLevel] = React.useState<number>(0);
  const audioAnalyserRef = React.useRef<{ analyser: AnalyserNode; ctx: AudioContext } | null>(null);
  const audioRafRef = React.useRef<number>(0);
  const videoRef = React.useRef<HTMLVideoElement>(null);

  // Local form state
  const [selectedAudio, setSelectedAudio] = React.useState<string>("");
  const [selectedVideo, setSelectedVideo] = React.useState<string>("");
  const [selectedOutput, setSelectedOutput] = React.useState<string>("");
  const [defaultMuted, setDefaultMuted] = React.useState(false);
  const [defaultVideoOff, setDefaultVideoOff] = React.useState(false);
  const [resolution, setResolution] = React.useState<string>("720");

  // Check support
  const mediaSupported =
    typeof navigator !== "undefined" && !!navigator.mediaDevices?.getUserMedia;

  // Check permissions on mount
  React.useEffect(() => {
    queryPermissionStatus("microphone").then(setMicPerm);
    queryPermissionStatus("camera").then(setCamPerm);
  }, []);

  // Fetch saved preferences
  const prefsQuery = useQuery({
    queryKey: ["media-preferences"],
    queryFn: getMediaPreferences,
    staleTime: 30_000,
  });

  // Populate local state when prefs load
  React.useEffect(() => {
    const prefs = prefsQuery.data;
    if (!prefs) return;
    if (prefs.preferred_audio_input_id) setSelectedAudio(prefs.preferred_audio_input_id);
    if (prefs.preferred_video_input_id) setSelectedVideo(prefs.preferred_video_input_id);
    if (prefs.preferred_audio_output_id) setSelectedOutput(prefs.preferred_audio_output_id);
    setDefaultMuted(prefs.default_audio_muted);
    setDefaultVideoOff(prefs.default_video_off);
    setResolution(prefs.video_resolution || "720");
  }, [prefsQuery.data]);

  // Save preferences mutation
  const saveMutation = useMutation({
    mutationFn: (body: MediaPreferencesIn) => saveMediaPreferences(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["media-preferences"] });
      toast.success("Media preferences saved");
    },
    onError: () => {
      toast.error("Failed to save media preferences");
    },
  });

  const handleSave = () => {
    saveMutation.mutate({
      preferred_audio_input_id: selectedAudio || null,
      preferred_video_input_id: selectedVideo || null,
      preferred_audio_output_id: selectedOutput || null,
      default_audio_muted: defaultMuted,
      default_video_off: defaultVideoOff,
      video_resolution: resolution as MediaPreferencesIn["video_resolution"],
    });
  };

  // ---------------------------------------------------------------------------
  // Preview & Test
  // ---------------------------------------------------------------------------

  const stopPreview = React.useCallback(() => {
    if (previewStream) {
      for (const track of previewStream.getTracks()) track.stop();
      setPreviewStream(null);
    }
    if (audioAnalyserRef.current) {
      audioAnalyserRef.current.ctx.close().catch(() => {});
      audioAnalyserRef.current = null;
    }
    if (audioRafRef.current) {
      cancelAnimationFrame(audioRafRef.current);
      audioRafRef.current = 0;
    }
    setAudioLevel(0);
  }, [previewStream]);

  // Cleanup on unmount
  React.useEffect(() => {
    return () => {
      // eslint-disable-next-line react-hooks/exhaustive-deps
      stopPreview();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startVideoPreview = async () => {
    if (!mediaSupported) {
      toast.error("Media devices API is not available in this browser");
      return;
    }
    stopPreview();
    try {
      const constraints: MediaStreamConstraints = {
        video: selectedVideo
          ? { deviceId: { exact: selectedVideo } }
          : true,
        audio: false,
      };
      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      setPreviewStream(stream);
      setCamPerm("granted");
      await devices.refresh();
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
    } catch (err: unknown) {
      const name = err instanceof DOMException ? err.name : "unknown";
      if (name === "NotAllowedError") {
        setCamPerm("denied");
        toast.error("Camera access denied. Check your browser permissions.");
      } else if (name === "NotFoundError") {
        toast.error("No camera found. Connect a device and try again.");
      } else if (name === "NotReadableError") {
        toast.error("Camera is in use by another application.");
      } else {
        toast.error("Failed to access camera.");
      }
    }
  };

  const startAudioTest = async () => {
    if (!mediaSupported) {
      toast.error("Media devices API is not available in this browser");
      return;
    }
    stopPreview();
    try {
      const constraints: MediaStreamConstraints = {
        audio: selectedAudio
          ? { deviceId: { exact: selectedAudio } }
          : true,
        video: false,
      };
      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      setPreviewStream(stream);
      setMicPerm("granted");
      await devices.refresh();

      // Set up audio level meter
      const ctx = new AudioContext();
      const source = ctx.createMediaStreamSource(stream);
      const analyser = ctx.createAnalyser();
      analyser.fftSize = 256;
      source.connect(analyser);
      audioAnalyserRef.current = { analyser, ctx };

      const dataArray = new Uint8Array(analyser.frequencyBinCount);
      const tick = () => {
        analyser.getByteFrequencyData(dataArray);
        const avg = dataArray.reduce((sum, v) => sum + v, 0) / dataArray.length;
        setAudioLevel(Math.round((avg / 255) * 100));
        audioRafRef.current = requestAnimationFrame(tick);
      };
      tick();
    } catch (err: unknown) {
      const name = err instanceof DOMException ? err.name : "unknown";
      if (name === "NotAllowedError") {
        setMicPerm("denied");
        toast.error("Microphone access denied. Check your browser permissions.");
      } else if (name === "NotFoundError") {
        toast.error("No microphone found. Connect a device and try again.");
      } else if (name === "NotReadableError") {
        toast.error("Microphone is in use by another application.");
      } else {
        toast.error("Failed to access microphone.");
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Permission status badge
  // ---------------------------------------------------------------------------

  function PermBadge({ status, label }: { status: PermStatus; label: string }) {
    if (status === "granted")
      return (
        <Badge variant="outline" className="gap-1 border-green-500 text-green-600">
          <CheckCircle className="h-3 w-3" /> {label}: Granted
        </Badge>
      );
    if (status === "denied")
      return (
        <Badge variant="destructive" className="gap-1">
          <XCircle className="h-3 w-3" /> {label}: Denied
        </Badge>
      );
    if (status === "prompt")
      return (
        <Badge variant="secondary" className="gap-1">
          <AlertTriangle className="h-3 w-3" /> {label}: Not requested
        </Badge>
      );
    return (
      <Badge variant="secondary" className="gap-1">
        {label}: Unknown
      </Badge>
    );
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (!mediaSupported) {
    return (
      <div className="container max-w-2xl py-8">
        <Card>
          <CardHeader>
            <CardTitle>Media Settings</CardTitle>
          </CardHeader>
          <CardContent>
            <Alert variant="destructive">
              <AlertDescription>
                Your browser does not support the Media Devices API. Camera and
                microphone features are unavailable.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container max-w-2xl py-8 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Media Settings</h1>
        <p className="text-muted-foreground mt-1">
          Configure your camera, microphone, and speaker preferences for calls.
        </p>
      </div>

      {/* Permission Status */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Permission Status</CardTitle>
          <CardDescription>
            Browser permissions for camera and microphone access.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <PermBadge status={micPerm} label="Microphone" />
          <PermBadge status={camPerm} label="Camera" />
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto gap-1"
            onClick={async () => {
              const m = await queryPermissionStatus("microphone");
              const c = await queryPermissionStatus("camera");
              setMicPerm(m);
              setCamPerm(c);
            }}
          >
            <RefreshCw className="h-3 w-3" /> Refresh
          </Button>
        </CardContent>
      </Card>

      {/* Device Selectors */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Device Selection</CardTitle>
          <CardDescription>
            Choose your preferred audio and video devices.
            {devices.audioInputs.length === 0 && devices.videoInputs.length === 0 && (
              <span className="block mt-1 text-yellow-600 dark:text-yellow-400">
                No devices detected. Grant permission first to see device labels.
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Microphone */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2">
              <Mic className="h-4 w-4" /> Microphone
            </Label>
            <Select value={selectedAudio} onValueChange={setSelectedAudio}>
              <SelectTrigger>
                <SelectValue placeholder="Default microphone" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">Default microphone</SelectItem>
                {devices.audioInputs.map((d) => (
                  <SelectItem key={d.deviceId} value={d.deviceId}>
                    {d.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Camera */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2">
              <Camera className="h-4 w-4" /> Camera
            </Label>
            <Select value={selectedVideo} onValueChange={setSelectedVideo}>
              <SelectTrigger>
                <SelectValue placeholder="Default camera" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">Default camera</SelectItem>
                {devices.videoInputs.map((d) => (
                  <SelectItem key={d.deviceId} value={d.deviceId}>
                    {d.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Speaker */}
          <div className="space-y-2">
            <Label className="flex items-center gap-2">
              <Volume2 className="h-4 w-4" /> Speaker
            </Label>
            <Select value={selectedOutput} onValueChange={setSelectedOutput}>
              <SelectTrigger>
                <SelectValue placeholder="Default speaker" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">Default speaker</SelectItem>
                {devices.audioOutputs.map((d) => (
                  <SelectItem key={d.deviceId} value={d.deviceId}>
                    {d.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => devices.refresh()}
              className="gap-1"
            >
              <RefreshCw className="h-3 w-3" /> Refresh devices
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Test Devices */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Test Devices</CardTitle>
          <CardDescription>
            Preview your camera or test microphone audio levels.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={startVideoPreview}
              className="gap-1"
            >
              <Camera className="h-4 w-4" /> Preview camera
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={startAudioTest}
              className="gap-1"
            >
              <Mic className="h-4 w-4" /> Test microphone
            </Button>
            {previewStream && (
              <Button
                variant="ghost"
                size="sm"
                onClick={stopPreview}
                className="gap-1"
              >
                Stop
              </Button>
            )}
          </div>

          {/* Video preview */}
          {previewStream && previewStream.getVideoTracks().length > 0 && (
            <div className="relative overflow-hidden rounded-lg border bg-black">
              <video
                ref={videoRef}
                autoPlay
                playsInline
                muted
                className="w-full max-h-64 object-contain"
              />
            </div>
          )}

          {/* Audio level meter */}
          {previewStream && previewStream.getAudioTracks().length > 0 && (
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">
                Audio Level
              </Label>
              <div className="h-3 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-green-500 transition-all duration-75"
                  style={{ width: `${audioLevel}%` }}
                  data-testid="audio-level-bar"
                />
              </div>
              <p className="text-xs text-muted-foreground">{audioLevel}%</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Defaults */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Call Defaults</CardTitle>
          <CardDescription>
            Set default behaviors when joining or starting a call.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="default-muted" className="flex items-center gap-2">
              {defaultMuted ? (
                <MicOff className="h-4 w-4 text-muted-foreground" />
              ) : (
                <Mic className="h-4 w-4" />
              )}
              Start calls muted
            </Label>
            <Switch
              id="default-muted"
              checked={defaultMuted}
              onCheckedChange={setDefaultMuted}
            />
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="default-video-off" className="flex items-center gap-2">
              {defaultVideoOff ? (
                <CameraOff className="h-4 w-4 text-muted-foreground" />
              ) : (
                <Camera className="h-4 w-4" />
              )}
              Start video calls with camera off
            </Label>
            <Switch
              id="default-video-off"
              checked={defaultVideoOff}
              onCheckedChange={setDefaultVideoOff}
            />
          </div>

          <Separator />

          <div className="space-y-2">
            <Label className="flex items-center gap-2">
              <MonitorSpeaker className="h-4 w-4" /> Video Resolution
            </Label>
            <Select value={resolution} onValueChange={setResolution}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="360">360p (Low)</SelectItem>
                <SelectItem value="480">480p (Medium)</SelectItem>
                <SelectItem value="720">720p (HD)</SelectItem>
                <SelectItem value="1080">1080p (Full HD)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end gap-2">
        <Button onClick={handleSave} disabled={saveMutation.isPending}>
          {saveMutation.isPending && (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          )}
          Save Preferences
        </Button>
      </div>
    </div>
  );
}
