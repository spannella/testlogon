import { useMemo } from "react";
import { generateQR } from "./qr";

interface QRCodeProps {
  value: string;
  /** Rendered pixel size of the whole code (square). */
  size?: number;
  className?: string;
}

/**
 * Dependency-free QR renderer. Draws the module matrix from ./qr as a single
 * inline SVG path (crisp at any size, no canvas, no npm dep). Returns null if
 * the value can't be encoded (caller still shows the address text).
 */
export function QRCode({ value, size = 200, className }: QRCodeProps) {
  const matrix = useMemo(() => {
    try {
      return generateQR(value, "M");
    } catch {
      return null;
    }
  }, [value]);

  if (!matrix || matrix.length === 0) {
    return null;
  }

  const n = matrix.length;
  const quiet = 4; // quiet-zone modules
  const dim = n + quiet * 2;

  // Build one path string of all dark modules.
  let d = "";
  for (let r = 0; r < n; r++) {
    const row = matrix[r];
    if (!row) continue;
    for (let c = 0; c < n; c++) {
      if (row[c]) {
        d += `M${c + quiet} ${r + quiet}h1v1h-1z`;
      }
    }
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      className={className}
      shapeRendering="crispEdges"
      role="img"
      aria-label="Deposit address QR code"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}

export default QRCode;
