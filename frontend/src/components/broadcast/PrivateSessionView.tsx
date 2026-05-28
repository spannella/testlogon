import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Phone,
  PhoneOff,
  Video,
  VideoOff,
  Mic,
  MicOff,
  DollarSign,
  Clock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { endPrivateSession } from "@/api/endpoints/broadcastPrivate";

interface PrivateSessionViewProps {
  sessionId: string;
  privateSessionId: string;
  callId: string;
  ratePerMinuteCents: number;
  viewerDisplayName?: string;
  isCreator: boolean;
  onEnded?: () => void;
}

export function PrivateSessionView({
  sessionId,
  privateSessionId,
  callId,
  ratePerMinuteCents,
  viewerDisplayName,
  isCreator,
  onEnded,
}: PrivateSessionViewProps) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoOff, setIsVideoOff] = useState(false);

  // Billing timer
  useEffect(() => {
    const interval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const billedMinutes = Math.max(1, Math.ceil(elapsedSeconds / 60));
  const currentBilled = billedMinutes * ratePerMinuteCents;

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  };

  const endMutation = useMutation({
    mutationFn: () => endPrivateSession(sessionId, privateSessionId),
    onSuccess: (data) => {
      toast.success(
        `Session ended. Total billed: $${(data.total_billed_cents / 100).toFixed(2)}`,
      );
      onEnded?.();
    },
    onError: () => toast.error("Failed to end session"),
  });

  return (
    <Card className="border-purple-500/50">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Phone className="h-5 w-5 text-green-500" />
            Private Session
            {viewerDisplayName && (
              <span className="text-sm font-normal text-muted-foreground">
                with {viewerDisplayName}
              </span>
            )}
          </div>
          <Badge variant="outline" className="text-xs">
            Call: {callId.slice(0, 12)}...
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Video placeholders */}
        <div className="grid grid-cols-2 gap-4">
          <div className="aspect-video rounded-lg bg-muted flex items-center justify-center">
            <Video className="h-8 w-8 text-muted-foreground" />
            <span className="ml-2 text-sm text-muted-foreground">
              {isCreator ? "You" : "Creator"}
            </span>
          </div>
          <div className="aspect-video rounded-lg bg-muted flex items-center justify-center">
            <Video className="h-8 w-8 text-muted-foreground" />
            <span className="ml-2 text-sm text-muted-foreground">
              {isCreator ? viewerDisplayName || "Viewer" : "You"}
            </span>
          </div>
        </div>

        {/* Billing info */}
        <div className="flex items-center justify-between rounded-lg bg-muted/50 p-3">
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-1">
              <Clock className="h-4 w-4" />
              {formatTime(elapsedSeconds)}
            </div>
            <div className="flex items-center gap-1">
              <DollarSign className="h-4 w-4" />
              {(ratePerMinuteCents / 100).toFixed(2)}/min
            </div>
            <div className="font-semibold">
              Billed: ${(currentBilled / 100).toFixed(2)}
            </div>
          </div>
        </div>

        {/* Call controls */}
        <div className="flex items-center justify-center gap-3">
          <Button
            size="icon"
            variant={isMuted ? "destructive" : "outline"}
            onClick={() => setIsMuted(!isMuted)}
          >
            {isMuted ? (
              <MicOff className="h-4 w-4" />
            ) : (
              <Mic className="h-4 w-4" />
            )}
          </Button>

          <Button
            size="icon"
            variant={isVideoOff ? "destructive" : "outline"}
            onClick={() => setIsVideoOff(!isVideoOff)}
          >
            {isVideoOff ? (
              <VideoOff className="h-4 w-4" />
            ) : (
              <Video className="h-4 w-4" />
            )}
          </Button>

          <Button
            variant="destructive"
            className="gap-2 px-6"
            onClick={() => endMutation.mutate()}
            disabled={endMutation.isPending}
          >
            <PhoneOff className="h-4 w-4" />
            End Session
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * PrivateHoldingScreen -- displayed to remaining viewers when broadcast is paused
 * for a private session.
 */
export function PrivateHoldingScreen() {
  return (
    <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-black/80 text-white">
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-purple-600/20 mb-4">
          <Phone className="h-8 w-8 text-purple-400 animate-pulse" />
        </div>
        <h2 className="text-xl font-semibold">
          Creator is in a private session
        </h2>
        <p className="text-sm text-gray-400">
          Please wait... The broadcast will resume shortly.
        </p>
        <p className="text-xs text-gray-500">Chat remains active below</p>
      </div>
    </div>
  );
}
