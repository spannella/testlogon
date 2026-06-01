import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Download, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  requestVodWatermarkDownload,
  pollVodWatermarkStatus,
} from "@/api/endpoints/vodWatermarkDownload";

type DownloadState = "idle" | "processing" | "ready";

interface VodWatermarkDownloadButtonProps {
  videoId: string;
}

/**
 * VOD-020: forensic per-viewer watermarked download affordance.
 *
 * Requests a watermarked copy of the video, polls render status while it is
 * being prepared, and auto-triggers the browser download once a URL is ready.
 * In dev mode the backend completes the render synchronously, so the button
 * transitions straight to "ready".
 */
export function VodWatermarkDownloadButton({
  videoId,
}: VodWatermarkDownloadButtonProps) {
  const [state, setState] = useState<DownloadState>("idle");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => clearPolling, []);

  const triggerDownload = (url: string) => {
    setState("ready");
    window.location.href = url;
  };

  const startPolling = () => {
    clearPolling();
    pollRef.current = setInterval(async () => {
      try {
        const result = await pollVodWatermarkStatus(videoId);
        if (result.status === "ready" && result.download_url) {
          clearPolling();
          triggerDownload(result.download_url);
        } else if (result.status === "failed") {
          clearPolling();
          setState("idle");
          toast.error("Download preparation failed. Please try again.");
        }
      } catch {
        clearPolling();
        setState("idle");
        toast.error("Download preparation failed. Please try again.");
      }
    }, 2000);
  };

  const requestMutation = useMutation({
    mutationFn: () => requestVodWatermarkDownload(videoId),
    onSuccess: (data) => {
      if (data.status === "ready" && data.download_url) {
        triggerDownload(data.download_url);
      } else if (data.status === "failed") {
        setState("idle");
        toast.error("Download preparation failed. Please try again.");
      } else {
        setState("processing");
        startPolling();
      }
    },
    onError: () => {
      setState("idle");
      toast.error("Could not start watermarked download.");
    },
  });

  const isBusy = state === "processing" || requestMutation.isPending;

  return (
    <Button
      onClick={() => requestMutation.mutate()}
      disabled={isBusy}
      className="gap-2"
      data-testid="vod-watermark-download-button"
    >
      {isBusy ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          Preparing download...
        </>
      ) : (
        <>
          <ShieldCheck className="h-4 w-4" />
          <Download className="h-4 w-4" />
          Download (watermarked)
        </>
      )}
    </Button>
  );
}

export default VodWatermarkDownloadButton;
