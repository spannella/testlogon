import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { searchGifs, getTrendingGifs, type GifSearchResult } from "@/api/endpoints/stickers";

interface GifPickerProps {
  onSelect: (gif: { url: string; alt_text: string; width: number; height: number }) => void;
  onClose?: () => void;
}

export function GifPicker({ onSelect }: GifPickerProps) {
  const [query, setQuery] = React.useState("");
  const [debounced, setDebounced] = React.useState("");

  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  const { data: gifs = [], isLoading } = useQuery<GifSearchResult[]>({
    queryKey: ["gifs", debounced],
    queryFn: () => (debounced ? searchGifs(debounced, 20) : getTrendingGifs(20)),
    staleTime: 60_000,
  });

  return (
    <div data-testid="gif-picker" className="w-72 space-y-2 p-1">
      <Input
        autoFocus
        placeholder="Search GIFs…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        data-testid="gif-search-input"
      />
      <div className="grid max-h-64 grid-cols-2 gap-2 overflow-y-auto">
        {isLoading
          ? Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full rounded-md" />
            ))
          : gifs.map((gif) => (
              <button
                key={gif.id}
                type="button"
                className="overflow-hidden rounded-md border hover:ring-2 hover:ring-primary"
                onClick={() =>
                  onSelect({
                    url: gif.url,
                    alt_text: gif.alt_text,
                    width: gif.width,
                    height: gif.height,
                  })
                }
                title={gif.alt_text}
                data-testid="gif-result"
              >
                <img
                  src={gif.url}
                  alt={gif.alt_text || "GIF"}
                  className="h-full w-full object-cover"
                  loading="lazy"
                />
              </button>
            ))}
        {!isLoading && gifs.length === 0 && (
          <p className="col-span-2 py-4 text-center text-xs text-muted-foreground">
            No GIFs found
          </p>
        )}
      </div>
    </div>
  );
}
