import { api } from "@/api/client";

// ---- Types (MSG-008) ----

export interface GifSearchResult {
  id: string;
  url: string;
  alt_text: string;
  width: number;
  height: number;
}

export interface Sticker {
  sticker_id: string;
  image_url: string;
  alt_text: string;
  sort_order: number;
  width: number;
  height: number;
}

export interface StickerCollection {
  collection_id: string;
  name: string;
  description: string;
  thumbnail_url?: string | null;
  sticker_count: number;
  is_active: boolean;
  created_at: number;
  stickers: Sticker[];
}

export interface StickerSearchResult {
  sticker_id: string;
  collection_id: string;
  image_url: string;
  alt_text: string;
  collection_name: string;
}

// ---- GIF search ----

export async function searchGifs(q: string, limit = 20): Promise<GifSearchResult[]> {
  return api.get<GifSearchResult[]>("/ui/stickers/gifs/search", {
    q,
    limit: String(limit),
  });
}

export async function getTrendingGifs(limit = 20): Promise<GifSearchResult[]> {
  return api.get<GifSearchResult[]>("/ui/stickers/gifs/trending", {
    limit: String(limit),
  });
}

// ---- Sticker collections ----

export async function listStickerCollections(): Promise<StickerCollection[]> {
  const res = await api.get<{ collections: StickerCollection[] }>(
    "/ui/stickers/collections",
  );
  return res.collections;
}

export async function getCollectionStickers(collectionId: string): Promise<Sticker[]> {
  const res = await api.get<{ stickers: Sticker[] }>(
    `/ui/stickers/collections/${collectionId}/stickers`,
  );
  return res.stickers;
}

export async function listFavoriteCollections(): Promise<StickerCollection[]> {
  const res = await api.get<{ collections: StickerCollection[] }>(
    "/ui/stickers/favorites",
  );
  return res.collections;
}

export async function addFavoriteCollection(
  collectionId: string,
): Promise<{ ok: boolean; collection_id: string }> {
  return api.post<{ ok: boolean; collection_id: string }>(
    `/ui/stickers/favorites/${collectionId}`,
  );
}

export async function removeFavoriteCollection(
  collectionId: string,
): Promise<{ ok: boolean; collection_id: string }> {
  return api.del<{ ok: boolean; collection_id: string }>(
    `/ui/stickers/favorites/${collectionId}`,
  );
}

export async function searchStickers(q: string): Promise<StickerSearchResult[]> {
  const res = await api.get<{ results: StickerSearchResult[] }>(
    "/ui/stickers/search",
    { q },
  );
  return res.results;
}
