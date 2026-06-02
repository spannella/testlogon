import * as React from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  listFavoriteCollections,
  listStickerCollections,
  addFavoriteCollection,
  type StickerCollection,
} from "@/api/endpoints/stickers";

interface StickerPickerProps {
  onSelect: (sticker: {
    id: string;
    collection_id: string;
    url: string;
    alt_text: string;
  }) => void;
  onClose?: () => void;
}

export function StickerPicker({ onSelect }: StickerPickerProps) {
  const queryClient = useQueryClient();
  const [search, setSearch] = React.useState("");

  const { data: favorites = [], isLoading: favLoading } = useQuery<StickerCollection[]>({
    queryKey: ["sticker-favorites"],
    queryFn: listFavoriteCollections,
    staleTime: 60_000,
  });

  const { data: allCollections = [], isLoading: allLoading } = useQuery<StickerCollection[]>({
    queryKey: ["sticker-collections"],
    queryFn: listStickerCollections,
    staleTime: 60_000,
  });

  const addFavMut = useMutation({
    mutationFn: (collectionId: string) => addFavoriteCollection(collectionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sticker-favorites"] });
    },
  });

  const filterStickers = (col: StickerCollection) => {
    const q = search.trim().toLowerCase();
    if (!q) return col.stickers;
    return col.stickers.filter((s) => (s.alt_text || "").toLowerCase().includes(q));
  };

  const favoriteIds = new Set(favorites.map((c) => c.collection_id));

  return (
    <div data-testid="sticker-picker" className="w-80 space-y-2 p-1">
      <Input
        placeholder="Search stickers…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        data-testid="sticker-search-input"
      />
      <Tabs defaultValue="favorites">
        <TabsList className="w-full">
          <TabsTrigger value="favorites" className="flex-1">
            Favorites
          </TabsTrigger>
          <TabsTrigger value="browse" className="flex-1">
            Browse All
          </TabsTrigger>
        </TabsList>

        <TabsContent value="favorites" className="max-h-64 overflow-y-auto">
          {favLoading ? (
            <div className="grid grid-cols-4 gap-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full rounded-md" />
              ))}
            </div>
          ) : favorites.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground">
              No favorite collections yet. Add some from Browse All.
            </p>
          ) : (
            favorites.map((col) => (
              <div key={col.collection_id} className="mb-2">
                <p className="mb-1 text-xs font-semibold">{col.name}</p>
                <div className="grid grid-cols-4 gap-2">
                  {filterStickers(col).map((s) => (
                    <button
                      key={s.sticker_id}
                      type="button"
                      className="overflow-hidden rounded-md border hover:ring-2 hover:ring-primary"
                      title={s.alt_text}
                      data-testid="sticker-result"
                      onClick={() =>
                        onSelect({
                          id: s.sticker_id,
                          collection_id: col.collection_id,
                          url: s.image_url,
                          alt_text: s.alt_text,
                        })
                      }
                    >
                      <img
                        src={s.image_url}
                        alt={s.alt_text || "Sticker"}
                        className="h-14 w-full object-contain"
                        loading="lazy"
                      />
                    </button>
                  ))}
                </div>
              </div>
            ))
          )}
        </TabsContent>

        <TabsContent value="browse" className="max-h-64 overflow-y-auto">
          {allLoading ? (
            <Skeleton className="h-16 w-full rounded-md" />
          ) : allCollections.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground">
              No collections available
            </p>
          ) : (
            allCollections.map((col) => (
              <div
                key={col.collection_id}
                className="mb-2 flex items-center justify-between gap-2 rounded-md border p-2"
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-semibold">{col.name}</p>
                  <p className="truncate text-[10px] text-muted-foreground">
                    {col.sticker_count} stickers
                  </p>
                </div>
                {favoriteIds.has(col.collection_id) ? (
                  <span className="text-[10px] text-muted-foreground">Favorited</span>
                ) : (
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    className="h-7 px-2 text-xs"
                    onClick={() => addFavMut.mutate(col.collection_id)}
                    data-testid="add-favorite"
                  >
                    Add to Favorites
                  </Button>
                )}
              </div>
            ))
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
