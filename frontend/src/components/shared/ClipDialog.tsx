/**
 * ClipDialog (VOD-015) -- Dialog for creating a clip from an existing video.
 *
 * Uses React Hook Form + Zod for validation. Calls POST /ui/videos/{videoId}/clip.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Scissors, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createClip, type ClipVideoRequest } from "@/api/endpoints/clips";

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatTimestamp(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const frac = Math.round((seconds % 1) * 10);
  const base =
    h > 0
      ? `${h}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`
      : `${m}:${s.toString().padStart(2, "0")}`;
  return frac > 0 ? `${base}.${frac}` : base;
}

// ─── Props ──────────────────────────────────────────────────────────────────

interface ClipDialogProps {
  videoId: string;
  durationSeconds: number;
  title: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function ClipDialog({
  videoId,
  durationSeconds,
  title,
  open,
  onOpenChange,
}: ClipDialogProps) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  const clipSchema = z
    .object({
      start_seconds: z.coerce
        .number()
        .min(0, "Start must be >= 0"),
      end_seconds: z.coerce
        .number()
        .min(0.1, "End must be > 0"),
      title: z.string().min(1).max(256),
    })
    .refine((d) => d.end_seconds > d.start_seconds, {
      message: "End must be after start",
      path: ["end_seconds"],
    })
    .refine((d) => d.end_seconds <= durationSeconds, {
      message: `End cannot exceed ${formatTimestamp(durationSeconds)}`,
      path: ["end_seconds"],
    })
    .refine((d) => d.end_seconds - d.start_seconds >= 5, {
      message: "Clip must be at least 5 seconds",
      path: ["end_seconds"],
    });

  type ClipFormValues = z.infer<typeof clipSchema>;

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<ClipFormValues>({
    resolver: zodResolver(clipSchema),
    defaultValues: {
      start_seconds: 0,
      end_seconds: Math.min(durationSeconds, 60),
      title: `${title} (clip)`,
    },
  });

  const startVal = watch("start_seconds");
  const endVal = watch("end_seconds");
  const clipDuration = Math.max(0, (endVal || 0) - (startVal || 0));

  const clipMutation = useMutation({
    mutationFn: (body: ClipVideoRequest) => createClip(videoId, body),
    onSuccess: (data) => {
      onOpenChange(false);
      navigate(`/videos/${data.video_id}`);
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail || "Failed to create clip";
      setError(msg);
    },
  });

  const onSubmit = (values: ClipFormValues) => {
    setError(null);
    clipMutation.mutate({
      start_seconds: values.start_seconds,
      end_seconds: values.end_seconds,
      title: values.title,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg" data-testid="clip-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Scissors className="h-5 w-5" />
            Create Clip
          </DialogTitle>
          <DialogDescription>
            Select a time range to extract from this video.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* Start / End time inputs */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="clip-start">Start (seconds)</Label>
              <Input
                id="clip-start"
                type="number"
                step="0.1"
                min={0}
                max={durationSeconds}
                {...register("start_seconds", { valueAsNumber: true })}
                data-testid="clip-start-input"
              />
              {errors.start_seconds && (
                <p className="text-xs text-destructive">
                  {errors.start_seconds.message}
                </p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="clip-end">End (seconds)</Label>
              <Input
                id="clip-end"
                type="number"
                step="0.1"
                min={0}
                max={durationSeconds}
                {...register("end_seconds", { valueAsNumber: true })}
                data-testid="clip-end-input"
              />
              {errors.end_seconds && (
                <p className="text-xs text-destructive">
                  {errors.end_seconds.message}
                </p>
              )}
            </div>
          </div>

          {/* Duration preview */}
          <div className="text-sm text-muted-foreground" data-testid="clip-duration-preview">
            Clip duration: {formatTimestamp(clipDuration)} (
            {clipDuration.toFixed(1)}s)
          </div>

          {/* Title input */}
          <div className="space-y-1.5">
            <Label htmlFor="clip-title">Title</Label>
            <Input
              id="clip-title"
              maxLength={256}
              {...register("title")}
              data-testid="clip-title-input"
            />
            {errors.title && (
              <p className="text-xs text-destructive">
                {errors.title.message}
              </p>
            )}
          </div>

          {/* Error display */}
          {error && (
            <p className="text-sm text-destructive" data-testid="clip-error">
              {error}
            </p>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={clipMutation.isPending}
              className="gap-2"
              data-testid="clip-submit-button"
            >
              {clipMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Scissors className="h-4 w-4" />
              )}
              Create Clip
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
