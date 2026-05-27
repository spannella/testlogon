/**
 * VOD-020: Watermarked Download Button
 *
 * Replaces the plain download button when watermark_downloads is enabled on a video.
 * In dev mode, the download completes instantly (mock watermark).
 * In production, shows a "Preparing download..." state while the FFmpeg job runs.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { Download, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  requestWatermarkedDownload,
  pollWatermarkStatus,
} from "@/api/endpoints/watermark";

interface WatermarkedDownloadButtonProps {
  videoId: string;
}

export default function WatermarkedDownloadButton({
  videoId,
}: WatermarkedDownloadButtonProps) {
  const [status, setStatus] = useState<"idle" | "processing" | "ready">(
    "idle",
  );
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
    };
  }, []);

  const startPolling = useCallback(
    (_jobId: string) => {
      pollRef.current = setInterval(async () => {
        try {
          const result = await pollWatermarkStatus(videoId);
          if (result.status === "ready" && result.download_url) {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            setStatus("ready");
            window.location.href = result.download_url;
            // Reset to idle after a moment so the button is usable again
            setTimeout(() => setStatus("idle"), 3000);
          } else if (result.status === "failed") {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            setStatus("idle");
            setError("Download preparation failed. Please try again.");
          }
        } catch {
          // Polling error — keep trying
        }
      }, 2000);
    },
    [videoId],
  );

  const handleClick = useCallback(async () => {
    setError(null);
    setStatus("processing");
    try {
      const data = await requestWatermarkedDownload(videoId);
      if (data.status === "ready" && data.download_url) {
        setStatus("ready");
        window.location.href = data.download_url;
        setTimeout(() => setStatus("idle"), 3000);
      } else {
        setStatus("processing");
        startPolling(data.job_id);
      }
    } catch {
      setStatus("idle");
      setError("Failed to request download. Please try again.");
    }
  }, [videoId, startPolling]);

  return (
    <div className="flex flex-col gap-1">
      <Button
        onClick={handleClick}
        disabled={status === "processing"}
        className="gap-2"
        data-testid="watermarked-download-button"
      >
        {status === "processing" ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Preparing download...
          </>
        ) : (
          <>
            <Download className="h-4 w-4" />
            Download
          </>
        )}
      </Button>
      {error && (
        <p className="text-sm text-destructive" data-testid="download-error">
          {error}
        </p>
      )}
    </div>
  );
}
