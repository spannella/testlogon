import { api } from "@/api/client";
import type { SeoMetadata } from "@/api/types";

// PLATFORM-005: app-facing client for the public SEO / OpenGraph metadata API.
// These endpoints are public (no auth) and only ever return data for genuinely
// public resources; private / locked content yields generic default metadata.

export type SeoResourceType = "profile" | "event" | "post" | "video" | "live";

/** Fetch SEO/OpenGraph metadata for a resource by type + id. */
export const getSeoMetadata = (
  type: SeoResourceType,
  id: string,
  secondaryId?: string,
) =>
  api.get<SeoMetadata>("/seo/metadata", {
    params: { type, id, ...(secondaryId ? { secondary_id: secondaryId } : {}) },
  });

/** Fetch SEO/OpenGraph metadata for a public URL path (e.g. "/u/alice"). */
export const getSeoMetadataForPath = (path: string) =>
  api.get<SeoMetadata>("/seo/metadata", { params: { path } });
