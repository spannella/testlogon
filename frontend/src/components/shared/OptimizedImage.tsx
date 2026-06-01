import { ResponsiveImage } from "@/components/shared/ResponsiveImage";
import { useOptimizedImage } from "@/hooks/useOptimizedImage";
import type { ImageVariant } from "@/api/types";

interface OptimizedImageProps {
  src: string;
  // Pre-computed variants (e.g. from a post item). When provided, no on-demand
  // optimization request is made -- they are used directly.
  variants?: Record<string, ImageVariant>;
  alt?: string;
  className?: string;
  sizes?: string;
  loading?: "lazy" | "eager";
  onClick?: () => void;
  // When true (and no pre-computed variants exist), request optimization on
  // demand via the /ui/images/optimize endpoint.
  optimizeOnDemand?: boolean;
}

/**
 * Drop-in responsive image. Prefers pre-computed `variants`; otherwise, when
 * `optimizeOnDemand` is set, lazily requests optimization from the backend and
 * renders the returned WebP variants via <ResponsiveImage>. Falls back to a
 * plain <img src> while loading or when optimization is unavailable.
 */
export function OptimizedImage({
  src,
  variants,
  alt = "",
  className,
  sizes,
  loading = "lazy",
  onClick,
  optimizeOnDemand = false,
}: OptimizedImageProps) {
  const hasPrecomputed = !!variants && Object.keys(variants).length > 0;
  const { variants: fetched } = useOptimizedImage(src, {
    enabled: optimizeOnDemand && !hasPrecomputed,
  });

  const effectiveVariants = hasPrecomputed ? variants : fetched;

  return (
    <ResponsiveImage
      src={src}
      variants={effectiveVariants}
      alt={alt}
      className={className}
      sizes={sizes}
      loading={loading}
      onClick={onClick}
    />
  );
}
