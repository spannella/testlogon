import { useQuery } from "@tanstack/react-query";

import { requestImageOptimization } from "@/api/endpoints/imageOptimization";
import type { ImageOptimizationRecord, ImageVariant } from "@/api/types";

interface UseOptimizedImageOptions {
  // When false, the optimization request is not made (used by <OptimizedImage>
  // when pre-computed variants are already available).
  enabled?: boolean;
  format?: string;
}

/**
 * Extracts the `s3_key` from an `/uploads/object?s3_key=...` proxy URL.
 * Returns null for absolute/external URLs (which cannot be optimized on demand).
 */
export function extractSourceKey(src: string | undefined): string | null {
  if (!src) return null;
  const idx = src.indexOf("s3_key=");
  if (idx === -1) return null;
  const raw = src.slice(idx + "s3_key=".length).split("&")[0] ?? "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * Requests on-demand image optimization for an uploaded image and returns the
 * resulting responsive variants. The backend caches per source key, so repeated
 * calls return the cached record cheaply.
 *
 * Returns `{ variants, record, isLoading }`. `variants` is shaped for direct use
 * by <ResponsiveImage>/<OptimizedImage> (a `Record<name, ImageVariant>`).
 */
export function useOptimizedImage(
  src: string | undefined,
  options: UseOptimizedImageOptions = {},
): {
  variants: Record<string, ImageVariant> | undefined;
  record: ImageOptimizationRecord | undefined;
  isLoading: boolean;
} {
  const { enabled = true, format = "webp" } = options;
  const sourceKey = extractSourceKey(src);

  const query = useQuery({
    queryKey: ["image-optimization", sourceKey, format],
    queryFn: () =>
      requestImageOptimization({ source_key: sourceKey ?? undefined, format }),
    enabled: enabled && !!sourceKey,
    staleTime: 60 * 60 * 1000, // variants are immutable; cache for an hour
  });

  const record = query.data;
  let variants: Record<string, ImageVariant> | undefined;
  if (record?.variants) {
    variants = Object.fromEntries(
      Object.entries(record.variants).map(([name, v]) => [
        name,
        { url: v.url, width: v.width, height: v.height, size_bytes: v.size_bytes },
      ]),
    );
  }

  return { variants, record, isLoading: query.isLoading };
}
