import { cn } from "@/lib/utils";
import type { ImageVariant } from "@/api/types";

interface ResponsiveImageProps {
  src: string;
  variants?: Record<string, ImageVariant>;
  alt?: string;
  className?: string;
  sizes?: string;
  loading?: "lazy" | "eager";
  onClick?: () => void;
}

/**
 * Renders an <img> with srcset when variants are available,
 * falling back to a plain <img src> when no variants exist.
 *
 * The browser selects the optimal variant based on viewport width
 * and device pixel ratio -- no JavaScript is needed.
 */
export function ResponsiveImage({
  src,
  variants,
  alt = "",
  className,
  sizes = "(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 33vw",
  loading = "lazy",
  onClick,
}: ResponsiveImageProps) {
  if (!variants || Object.keys(variants).length === 0) {
    return (
      <img
        src={src}
        alt={alt}
        className={className}
        loading={loading}
        onClick={onClick}
      />
    );
  }

  const srcset = Object.entries(variants)
    .sort(([, a], [, b]) => a.width - b.width) // smallest to largest
    .map(([, v]) => `${v.url} ${v.width}w`)
    .join(", ");

  return (
    <img
      src={src}
      srcSet={srcset}
      sizes={sizes}
      alt={alt}
      className={className}
      loading={loading}
      onClick={onClick}
    />
  );
}
