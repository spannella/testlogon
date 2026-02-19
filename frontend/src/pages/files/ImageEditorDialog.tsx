import * as React from "react";
import { Scissors, Square, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import type { FileEntry } from "@/api/types";
import { uploadFile } from "@/api/endpoints/files";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { normalizeRect } from "./imageEdit";

type Props = {
  open: boolean;
  file: FileEntry | null;
  onOpenChange: (open: boolean) => void;
  onSaved?: () => void;
};

export function ImageEditorDialog({ open, file, onOpenChange, onSaved }: Props) {
  const canvasRef = React.useRef<HTMLCanvasElement | null>(null);
  const sourceBlobRef = React.useRef<Blob | null>(null);
  const imageRef = React.useRef<HTMLImageElement | null>(null);
  const workingCanvasRef = React.useRef<HTMLCanvasElement | null>(null);
  const [selection, setSelection] = React.useState<{ x: number; y: number; w: number; h: number } | null>(null);
  const [dragStart, setDragStart] = React.useState<{ x: number; y: number } | null>(null);
  const [status, setStatus] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  const draw = React.useCallback(() => {
    const canvas = canvasRef.current;
    const working = workingCanvasRef.current;
    if (!canvas || !working) return;
    const maxWidth = 900;
    const maxHeight = 520;
    const scale = Math.min(1, maxWidth / working.width, maxHeight / working.height);
    canvas.width = working.width;
    canvas.height = working.height;
    canvas.style.width = `${Math.max(1, Math.round(working.width * scale))}px`;
    canvas.style.height = `${Math.max(1, Math.round(working.height * scale))}px`;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(working, 0, 0);
    if (selection && selection.w > 1 && selection.h > 1) {
      ctx.fillStyle = "rgba(0,0,0,0.3)";
      ctx.fillRect(selection.x, selection.y, selection.w, selection.h);
      ctx.strokeStyle = "#fff";
      ctx.lineWidth = 2;
      ctx.strokeRect(selection.x, selection.y, selection.w, selection.h);
    }
  }, [selection]);

  React.useEffect(() => {
    void (async () => {
      if (!open || !file) return;
      if (file.is_encrypted) {
        setStatus("Editing encrypted images is not supported.");
        return;
      }
      try {
        setStatus("Loading image...");
        const res = await fetch(`/v1/fs/download?path=${encodeURIComponent(file.path)}`, { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load image.");
        const srcBlob = await res.blob();
        sourceBlobRef.current = srcBlob;
        const objectUrl = URL.createObjectURL(srcBlob);
        const img = new Image();
        await new Promise<void>((resolve, reject) => {
          img.onload = () => resolve();
          img.onerror = () => reject(new Error("Unable to decode image."));
          img.src = objectUrl;
        });
        URL.revokeObjectURL(objectUrl);
        imageRef.current = img;
        const workingCanvas = document.createElement("canvas");
        workingCanvas.width = img.naturalWidth || img.width;
        workingCanvas.height = img.naturalHeight || img.height;
        const ctx = workingCanvas.getContext("2d");
        if (!ctx) throw new Error("Canvas is unavailable.");
        ctx.drawImage(img, 0, 0);
        workingCanvasRef.current = workingCanvas;
        setSelection(null);
        setDragStart(null);
        setStatus("Drag to select an area. Crop keeps selection, block fills black.");
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unable to open editor.";
        setStatus(message);
      }
    })();
  }, [open, file]);

  React.useEffect(() => {
    draw();
  }, [draw]);

  const toCanvasPoint = (ev: React.PointerEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    const working = workingCanvasRef.current;
    if (!canvas || !working) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return { x: 0, y: 0 };
    const x = Math.max(0, Math.min(working.width, ((ev.clientX - rect.left) * working.width) / rect.width));
    const y = Math.max(0, Math.min(working.height, ((ev.clientY - rect.top) * working.height) / rect.height));
    return { x, y };
  };

  const requireSelection = () => {
    if (!selection || selection.w < 2 || selection.h < 2) {
      setStatus("Drag to select an area first.");
      return false;
    }
    return true;
  };

  const handleCrop = () => {
    if (!requireSelection()) return;
    const working = workingCanvasRef.current;
    if (!working || !selection) return;
    const next = document.createElement("canvas");
    next.width = Math.max(1, Math.round(selection.w));
    next.height = Math.max(1, Math.round(selection.h));
    const nextCtx = next.getContext("2d");
    if (!nextCtx) return;
    nextCtx.drawImage(
      working,
      selection.x,
      selection.y,
      selection.w,
      selection.h,
      0,
      0,
      next.width,
      next.height,
    );
    workingCanvasRef.current = next;
    setSelection(null);
    setStatus(`Cropped to ${next.width} × ${next.height}.`);
    draw();
  };

  const handleBlock = () => {
    if (!requireSelection()) return;
    const working = workingCanvasRef.current;
    if (!working || !selection) return;
    const ctx = working.getContext("2d");
    if (!ctx) return;
    ctx.fillStyle = "#000";
    ctx.fillRect(selection.x, selection.y, selection.w, selection.h);
    setStatus("Blocked selected area.");
    draw();
  };

  const handleReset = () => {
    const img = imageRef.current;
    if (!img) return;
    const next = document.createElement("canvas");
    next.width = img.naturalWidth || img.width;
    next.height = img.naturalHeight || img.height;
    const ctx = next.getContext("2d");
    if (!ctx) return;
    ctx.drawImage(img, 0, 0);
    workingCanvasRef.current = next;
    setSelection(null);
    setStatus("Reset to original image.");
    draw();
  };

  const handleSave = async () => {
    if (!file) return;
    const working = workingCanvasRef.current;
    const srcBlob = sourceBlobRef.current;
    if (!working || !srcBlob) return;
    setSaving(true);
    setStatus("Saving...");
    try {
      const outBlob = await new Promise<Blob>((resolve, reject) => {
        working.toBlob((blob) => {
          if (blob) resolve(blob);
          else reject(new Error("Failed to encode edited image."));
        }, srcBlob.type || "image/png", 0.92);
      });
      const upload = new File([outBlob], file.name || "edited-image", {
        type: outBlob.type || srcBlob.type || "image/png",
      });
      await uploadFile(upload, file.path);
      setStatus("Saved updated image.");
      toast.success("Image updated");
      onSaved?.();
      onOpenChange(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save image.";
      setStatus(message);
      toast.error(message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>Edit image: {file?.name ?? ""}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={handleCrop}>
              <Scissors className="mr-1 h-4 w-4" /> Crop selection
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={handleBlock}>
              <Square className="mr-1 h-4 w-4" /> Block selection
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={handleReset}>
              <RotateCcw className="mr-1 h-4 w-4" /> Reset
            </Button>
          </div>
          <canvas
            ref={canvasRef}
            className="max-w-full rounded-md border bg-black/80"
            style={{ touchAction: "none", cursor: "crosshair" }}
            onPointerDown={(ev) => {
              const start = toCanvasPoint(ev);
              setDragStart(start);
              setSelection({ x: start.x, y: start.y, w: 0, h: 0 });
            }}
            onPointerMove={(ev) => {
              if (!dragStart || !workingCanvasRef.current) return;
              const current = toCanvasPoint(ev);
              setSelection(normalizeRect(dragStart, current, workingCanvasRef.current.width, workingCanvasRef.current.height));
            }}
            onPointerUp={(ev) => {
              if (!dragStart || !workingCanvasRef.current) return;
              const current = toCanvasPoint(ev);
              setSelection(normalizeRect(dragStart, current, workingCanvasRef.current.width, workingCanvasRef.current.height));
              setDragStart(null);
            }}
          />
          <p className="text-sm text-muted-foreground">{status}</p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Close</Button>
          <Button onClick={handleSave} disabled={saving || !file}>Save image</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
