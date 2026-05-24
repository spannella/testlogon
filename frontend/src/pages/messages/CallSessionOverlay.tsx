import { Phone, PhoneCall, PhoneIncoming, PhoneOff, Video, Mic, MicOff, VideoOff, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { DirectCallMode } from "@/api/endpoints/messaging";

export type CallUiState =
  | "idle"
  | "incoming_ringing"
  | "outgoing_inviting"
  | "outgoing_ringing"
  | "outgoing_connecting"
  | "reconnecting"
  | "connected"
  | "declined"
  | "busy"
  | "timeout"
  | "ended"
  | "failure";

export interface CallSessionUi {
  state: CallUiState;
  direction: "incoming" | "outgoing";
  mode: DirectCallMode;
  peerName: string;
  callId?: string;
  reasonMessage?: string;
}

interface Props {
  session: CallSessionUi;
  isBusy?: boolean;
  isMuted?: boolean;
  isCameraOff?: boolean;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
}

const outcomeCopy: Record<Extract<CallUiState, "declined" | "busy" | "timeout" | "ended" | "failure">, string> = {
  declined: "Call declined.",
  busy: "User is busy on another call.",
  timeout: "Call timed out with no answer.",
  ended: "Call ended.",
  failure: "Call failed to connect.",
};

/** Detect if a failure is permission-related based on the reason message. */
function isPermissionDeniedFailure(session: CallSessionUi): boolean {
  if (session.state !== "failure") return false;
  const msg = (session.reasonMessage ?? "").toLowerCase();
  return msg.includes("denied") || msg.includes("access") || msg.includes("permission") || msg.includes("not found");
}

export function CallSessionOverlay({
  session,
  isBusy = false,
  isMuted,
  isCameraOff,
  onAccept,
  onDecline,
  onEnd,
  onDismiss,
  onToggleMute,
  onToggleCamera,
}: Props) {
  const isIncoming = session.state === "incoming_ringing";
  const isOutgoing = ["outgoing_inviting", "outgoing_ringing", "outgoing_connecting", "reconnecting"].includes(session.state);
  const isConnected = session.state === "connected";
  const isOutcome = ["declined", "busy", "timeout", "ended", "failure"].includes(session.state);
  const isPermissionDenied = isPermissionDeniedFailure(session);

  if (session.state === "idle") {
    return null;
  }

  const modeLabel = session.mode === "video" ? "video" : "audio";

  return (
    <Dialog open onOpenChange={(open) => !open && onDismiss()}>
      <DialogContent className="sm:max-w-md" aria-label="Direct call">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isPermissionDenied ? (
              <ShieldAlert className="h-4 w-4 text-destructive" />
            ) : isIncoming ? (
              <PhoneIncoming className="h-4 w-4" />
            ) : isConnected ? (
              <PhoneCall className="h-4 w-4" />
            ) : (
              <Phone className="h-4 w-4" />
            )}
            {isPermissionDenied
              ? "Permission Required"
              : isIncoming
                ? `Incoming ${modeLabel} call`
                : isOutgoing
                  ? `${session.mode === "video" ? "Video" : "Audio"} call`
                  : "Call status"}
          </DialogTitle>
          <DialogDescription>
            {isPermissionDenied && (
              <span data-testid="permission-denied-message">
                {session.mode === "video"
                  ? "Camera and microphone access denied. Please allow camera and microphone access in your browser settings."
                  : "Microphone access denied. Please allow microphone access in your browser settings."}
              </span>
            )}
            {!isPermissionDenied && isIncoming && `${session.peerName} is calling you.`}
            {!isPermissionDenied && session.state === "outgoing_ringing" && `Ringing ${session.peerName}…`}
            {!isPermissionDenied && session.state === "outgoing_inviting" && `Starting call with ${session.peerName}…`}
            {!isPermissionDenied && session.state === "outgoing_connecting" && `Connecting to ${session.peerName}…`}
            {!isPermissionDenied && session.state === "reconnecting" && `Reconnecting to ${session.peerName}…`}
            {!isPermissionDenied && isConnected && `Connected with ${session.peerName}.`}
            {!isPermissionDenied && isOutcome && (session.reasonMessage ?? outcomeCopy[session.state as keyof typeof outcomeCopy])}
          </DialogDescription>
        </DialogHeader>

        <DialogFooter className="gap-2 sm:justify-start">
          {isIncoming && (
            <>
              <Button variant="outline" onClick={onDecline} disabled={isBusy} aria-label="Decline call">
                <PhoneOff className="mr-2 h-4 w-4" />
                Decline
              </Button>
              <Button onClick={onAccept} disabled={isBusy} aria-label="Accept call">
                {session.mode === "video" ? <Video className="mr-2 h-4 w-4" /> : <PhoneCall className="mr-2 h-4 w-4" />}
                Accept
              </Button>
            </>
          )}
          {isOutgoing && (
            <Button variant="outline" onClick={onEnd} disabled={isBusy} aria-label="Cancel call">
              <PhoneOff className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {isConnected && (
            <>
              {onToggleMute && (
                <Button
                  variant={isMuted ? "secondary" : "ghost"}
                  size="icon"
                  onClick={onToggleMute}
                  aria-label={isMuted ? "Unmute" : "Mute"}
                >
                  {isMuted ? <MicOff className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
                </Button>
              )}
              {session.mode === "video" && onToggleCamera && (
                <Button
                  variant={isCameraOff ? "secondary" : "ghost"}
                  size="icon"
                  onClick={onToggleCamera}
                  aria-label={isCameraOff ? "Turn camera on" : "Turn camera off"}
                >
                  {isCameraOff ? <VideoOff className="h-4 w-4" /> : <Video className="h-4 w-4" />}
                </Button>
              )}
              <Button variant="destructive" onClick={onEnd} disabled={isBusy} aria-label="End call">
                <PhoneOff className="mr-2 h-4 w-4" />
                End call
              </Button>
            </>
          )}
          {isOutcome && (
            <Button onClick={onDismiss} aria-label="Dismiss call status">
              Dismiss
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
