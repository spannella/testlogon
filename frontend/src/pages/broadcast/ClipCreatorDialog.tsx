import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createBroadcastClip } from "@/api/endpoints/clips";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Scissors } from "lucide-react";
import { toast } from "sonner";

interface ClipCreatorDialogProps {
  sessionId: string;
  broadcastDuration: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ClipCreatorDialog({ sessionId, broadcastDuration, open, onOpenChange }: ClipCreatorDialogProps) {
  const captureWindow = 90; // seconds
  const windowStart = Math.max(0, broadcastDuration - captureWindow);

  const [startSec, setStartSec] = useState(windowStart + 30);
  const [endSec, setEndSec] = useState(Math.min(windowStart + 60, broadcastDuration));
  const [title, setTitle] = useState("");

  const queryClient = useQueryClient();
  const createMut = useMutation({
    mutationFn: () => createBroadcastClip(sessionId, {
      start_seconds: startSec,
      end_seconds: endSec,
      title: title || undefined,
    }),
    onSuccess: (data) => {
      toast.success(`Clip "${data.title}" is being created!`);
      queryClient.invalidateQueries({ queryKey: ["clips", sessionId] });
      onOpenChange(false);
    },
    onError: (err: any) => {
      const body = err?.body as Record<string, any> | undefined;
      const detail = body?.detail ?? err?.detail;
      const code = typeof detail === "object" ? detail?.code : undefined;
      if (code === "CLIP_QUOTA_EXCEEDED") {
        toast.error("You have reached the maximum number of clips for this broadcast.");
      } else if (code === "CLIP_RATE_LIMITED") {
        toast.error("Please wait before creating another clip.");
      } else {
        toast.error(typeof detail === "string" ? detail : "Failed to create clip.");
      }
    },
  });

  const clipDuration = endSec - startSec;
  const isValid = clipDuration >= 5 && clipDuration <= 60 && startSec < endSec;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Scissors className="h-5 w-5" /> Create Clip
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="clip-start">Start (seconds)</Label>
              <Input
                id="clip-start"
                type="number"
                min={windowStart}
                max={broadcastDuration}
                step={0.5}
                value={startSec}
                onChange={(e) => setStartSec(Number(e.target.value))}
              />
            </div>
            <div>
              <Label htmlFor="clip-end">End (seconds)</Label>
              <Input
                id="clip-end"
                type="number"
                min={windowStart}
                max={broadcastDuration}
                step={0.5}
                value={endSec}
                onChange={(e) => setEndSec(Number(e.target.value))}
              />
            </div>
          </div>

          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">
              {formatTime(startSec)} - {formatTime(endSec)}
            </span>
            {clipDuration < 5 && (
              <span className="text-destructive">Minimum 5 seconds</span>
            )}
            {clipDuration > 60 && (
              <span className="text-destructive">Maximum 60 seconds</span>
            )}
            {isValid && (
              <span className="text-muted-foreground">
                Duration: {clipDuration.toFixed(1)}s
              </span>
            )}
          </div>

          <div>
            <Label htmlFor="clip-title">Clip title (optional)</Label>
            <Input
              id="clip-title"
              placeholder="Clip title (optional)"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={100}
            />
          </div>

          <Button
            onClick={() => createMut.mutate()}
            disabled={!isValid || createMut.isPending}
            className="w-full"
          >
            {createMut.isPending ? "Creating..." : "Create Clip"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}
