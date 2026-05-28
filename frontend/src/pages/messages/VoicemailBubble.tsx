import * as React from "react";
import { PhoneMissed, PhoneCall } from "lucide-react";
import { Button } from "@/components/ui/button";
import { WaveformPlayer } from "./WaveformPlayer";
import type { Message } from "@/api/types";

interface VoicemailBubbleProps {
  message: Message;
  onCallBack?: () => void;
}

export function VoicemailBubble({ message, onCallBack }: VoicemailBubbleProps) {
  const vm = message.voicemail;
  if (!vm) return null;

  const callStateLabel =
    vm.call_state === "declined"
      ? "Call declined"
      : vm.call_state === "busy"
        ? "Busy"
        : "Missed call";

  return (
    <div className="mt-1" data-testid="voicemail-bubble">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <PhoneMissed className="h-4 w-4 text-destructive shrink-0" />
        <span className="text-xs font-medium text-destructive">{callStateLabel} — voicemail</span>
      </div>

      {/* Audio voicemail */}
      {vm.mode === "audio" && vm.audio_url && (
        <WaveformPlayer
          audioUrl={vm.audio_url}
          waveform={vm.waveform_data}
          durationSeconds={vm.duration_seconds}
        />
      )}

      {/* Video voicemail */}
      {vm.mode === "video" && vm.video_url && (
        <video
          src={vm.video_url}
          controls
          preload="metadata"
          className="rounded-md max-w-xs w-full"
          data-testid="voicemail-video"
        />
      )}

      {/* Call back button */}
      {onCallBack && (
        <Button
          variant="outline"
          size="sm"
          className="mt-2"
          onClick={onCallBack}
          aria-label="Call back"
        >
          <PhoneCall className="mr-1 h-3.5 w-3.5" />
          Call back
        </Button>
      )}
    </div>
  );
}
