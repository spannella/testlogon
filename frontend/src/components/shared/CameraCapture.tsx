import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Camera, Upload, RefreshCw } from "lucide-react";

export interface CameraCaptureProps {
  onCapture: (file: File) => void;
  /** "user" = selfie (front camera); "environment" = document (rear camera). */
  facing?: "user" | "environment";
  label?: string;
  /** Accept attribute for the file-upload fallback. */
  accept?: string;
  disabled?: boolean;
}

/**
 * Mobile-friendly camera capture with a graceful file-upload fallback.
 *
 * In headless test environments (no getUserMedia / camera), the live preview
 * never starts and the component degrades to the file-upload input, which is
 * always rendered. Tests should drive the file input directly.
 */
export function CameraCapture({
  onCapture,
  facing = "user",
  label,
  accept = "image/*",
  disabled = false,
}: CameraCaptureProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [cameraError, setCameraError] = useState<string | null>(null);

  useEffect(() => {
    return () => {
      // Stop tracks on unmount to release the camera.
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [stream]);

  const startCamera = async () => {
    setCameraError(null);
    try {
      const md = navigator.mediaDevices;
      if (!md || typeof md.getUserMedia !== "function") {
        setCameraError("Camera not available. Please upload a file instead.");
        return;
      }
      const mediaStream = await md.getUserMedia({
        video: { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      setStream(mediaStream);
      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
      }
    } catch {
      setCameraError("Camera access was denied. Please upload a file instead.");
    }
  };

  const stopCamera = () => {
    stream?.getTracks().forEach((t) => t.stop());
    setStream(null);
  };

  const capture = () => {
    const video = videoRef.current;
    if (!video) return;
    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    canvas.toBlob(
      (blob) => {
        if (!blob) return;
        const file = new File([blob], "capture.jpg", { type: "image/jpeg" });
        setPreview(canvas.toDataURL("image/jpeg"));
        onCapture(file);
        stopCamera();
      },
      "image/jpeg",
      0.9,
    );
  };

  const onFileSelected = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setPreview(URL.createObjectURL(file));
    onCapture(file);
  };

  const retake = () => {
    setPreview(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <div className="space-y-3" data-testid="camera-capture">
      {label ? <p className="text-sm font-medium">{label}</p> : null}

      {preview ? (
        <div className="space-y-2">
          <img
            src={preview}
            alt="Captured preview"
            className="max-h-64 w-auto rounded border"
            data-testid="camera-preview"
          />
          <Button type="button" variant="outline" size="sm" onClick={retake} disabled={disabled}>
            <RefreshCw className="mr-2 h-4 w-4" /> Retake
          </Button>
        </div>
      ) : (
        <>
          {stream ? (
            <div className="space-y-2">
              <video
                ref={videoRef}
                autoPlay
                playsInline
                muted
                className="max-h-64 w-auto rounded border bg-black"
              />
              <div className="flex gap-2">
                <Button type="button" size="sm" onClick={capture} disabled={disabled}>
                  <Camera className="mr-2 h-4 w-4" /> Take Photo
                </Button>
                <Button type="button" variant="outline" size="sm" onClick={stopCamera}>
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={startCamera}
                disabled={disabled}
              >
                <Camera className="mr-2 h-4 w-4" /> Use Camera
              </Button>
              <label className="inline-flex">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={disabled}
                >
                  <Upload className="mr-2 h-4 w-4" /> Upload File
                </Button>
              </label>
            </div>
          )}
          {cameraError ? (
            <p className="text-xs text-amber-600" data-testid="camera-error">
              {cameraError}
            </p>
          ) : null}
        </>
      )}

      {/* Always-rendered file fallback input (used directly by tests). */}
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        capture={facing}
        onChange={onFileSelected}
        className="block text-xs"
        data-testid="camera-file-input"
        disabled={disabled}
      />
    </div>
  );
}

export default CameraCapture;
