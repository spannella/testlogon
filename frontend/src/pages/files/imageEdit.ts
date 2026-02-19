import type { FileEntry } from "@/api/types";

export function isEditableImageFile(file: Pick<FileEntry, "type" | "name" | "path" | "content_type" | "is_encrypted">): boolean {
  if (file.type !== "file") return false;
  if (file.is_encrypted) return false;
  const contentType = (file.content_type ?? "").toLowerCase();
  if (contentType.startsWith("image/")) return true;
  const name = (file.name || file.path || "").toLowerCase();
  return /\.(png|jpe?g|gif|webp|bmp)$/i.test(name);
}

export type Rect = { x: number; y: number; w: number; h: number };

export function normalizeRect(
  start: { x: number; y: number },
  end: { x: number; y: number },
  maxW: number,
  maxH: number,
): Rect {
  const x1 = Math.max(0, Math.min(maxW, Math.min(start.x, end.x)));
  const y1 = Math.max(0, Math.min(maxH, Math.min(start.y, end.y)));
  const x2 = Math.max(0, Math.min(maxW, Math.max(start.x, end.x)));
  const y2 = Math.max(0, Math.min(maxH, Math.max(start.y, end.y)));
  return { x: x1, y: y1, w: x2 - x1, h: y2 - y1 };
}
