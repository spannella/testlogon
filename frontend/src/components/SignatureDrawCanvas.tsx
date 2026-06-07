import * as React from "react";
import { Button } from "@/components/ui/button";

// Maximum number of normalized points we emit. The signature packet fill pipeline
// (validateFieldInput / parseDrawnStrokes in SignaturePacketComposer) requires an
// array of [x,y] points with 2..20 entries, each within 0..1. We downsample the raw
// freehand path to at most this many points so validation always passes.
const MAX_POINTS = 20;

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

// Reduce a dense list of normalized points to at most `max` evenly-spaced points,
// always keeping the first and last so the captured shape is preserved.
function downsample(points: number[][], max: number): number[][] {
  if (points.length <= max) return points;
  const result: number[][] = [];
  const step = (points.length - 1) / (max - 1);
  for (let i = 0; i < max; i += 1) {
    const pt = points[Math.round(i * step)];
    if (pt) result.push(pt);
  }
  return result;
}

export interface SignatureDrawCanvasProps {
  /** Called with the serialized JSON string of normalized [x,y] points (matching
   *  the existing drawn_strokes / parseDrawnStrokes shape) whenever the drawing changes. */
  onChange: (serialized: string) => void;
  /** Optional test id forwarded to the canvas element. */
  testId?: string;
  width?: number;
  height?: number;
}

/**
 * Freehand signature capture surface. Renders an HTML5 <canvas> and records the
 * pointer path (mouse + touch via Pointer Events) as normalized 0..1 coordinates.
 * On every change it serializes a downsampled point array to JSON and reports it
 * via onChange, so the existing fill submission pipeline consumes it unchanged.
 */
export function SignatureDrawCanvas({
  onChange,
  testId,
  width = 320,
  height = 120,
}: SignatureDrawCanvasProps) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const drawingRef = React.useRef(false);
  // Raw normalized points captured during the current drawing.
  const pointsRef = React.useRef<number[][]>([]);

  const emit = React.useCallback(() => {
    const sampled = downsample(pointsRef.current, MAX_POINTS);
    onChange(JSON.stringify(sampled));
  }, [onChange]);

  const toNormalized = React.useCallback((e: React.PointerEvent<HTMLCanvasElement>): number[] => {
    const canvas = canvasRef.current;
    if (!canvas) return [0, 0];
    const rect = canvas.getBoundingClientRect();
    const x = clamp01((e.clientX - rect.left) / rect.width);
    const y = clamp01((e.clientY - rect.top) / rect.height);
    return [Number(x.toFixed(4)), Number(y.toFixed(4))];
  }, []);

  const redraw = React.useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const pts = pointsRef.current;
    if (pts.length === 0) return;
    ctx.lineWidth = 2;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = "#0f172a";
    ctx.beginPath();
    pts.forEach((pt, i) => {
      const px = (pt[0] ?? 0) * canvas.width;
      const py = (pt[1] ?? 0) * canvas.height;
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    });
    ctx.stroke();
  }, []);

  const handlePointerDown = React.useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      e.preventDefault();
      drawingRef.current = true;
      canvasRef.current?.setPointerCapture(e.pointerId);
      pointsRef.current = [toNormalized(e)];
      redraw();
    },
    [redraw, toNormalized],
  );

  const handlePointerMove = React.useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      if (!drawingRef.current) return;
      e.preventDefault();
      pointsRef.current.push(toNormalized(e));
      redraw();
    },
    [redraw, toNormalized],
  );

  const handlePointerUp = React.useCallback(
    (e: React.PointerEvent<HTMLCanvasElement>) => {
      if (!drawingRef.current) return;
      e.preventDefault();
      drawingRef.current = false;
      try {
        canvasRef.current?.releasePointerCapture(e.pointerId);
      } catch {
        /* pointer may already be released */
      }
      emit();
    },
    [emit],
  );

  const handleClear = React.useCallback(() => {
    pointsRef.current = [];
    drawingRef.current = false;
    redraw();
    onChange("");
  }, [onChange, redraw]);

  return (
    <div className="space-y-2">
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className="touch-none rounded border bg-white"
        style={{ touchAction: "none", width: "100%", maxWidth: width, height }}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        data-testid={testId}
        role="img"
        aria-label="Signature drawing canvas"
      />
      <Button type="button" size="sm" variant="outline" onClick={handleClear} className="h-7">
        Clear
      </Button>
    </div>
  );
}
