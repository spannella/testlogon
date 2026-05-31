import { useQuery } from "@tanstack/react-query";

import {
  getSeoMetadata,
  getSeoMetadataForPath,
  type SeoResourceType,
} from "@/api/endpoints/seoMetadata";
import type { SeoMetadata } from "@/api/types";

// PLATFORM-005: hook to fetch backend SEO / OpenGraph metadata for a public
// resource. The result can be passed straight to <SeoHead metadata={...} />.
//
// Usage:
//   const { data } = useSeoMeta("profile", identifier);
//   return <SeoHead metadata={data} />;

export function useSeoMeta(
  type: SeoResourceType,
  id: string | undefined,
  secondaryId?: string,
) {
  return useQuery<SeoMetadata>({
    queryKey: ["seo", "metadata", type, id ?? "", secondaryId ?? ""],
    queryFn: () => getSeoMetadata(type, id as string, secondaryId),
    enabled: Boolean(id),
    retry: false,
    staleTime: 300_000,
  });
}

export function useSeoMetaForPath(path: string | undefined) {
  return useQuery<SeoMetadata>({
    queryKey: ["seo", "metadata", "path", path ?? ""],
    queryFn: () => getSeoMetadataForPath(path as string),
    enabled: Boolean(path),
    retry: false,
    staleTime: 300_000,
  });
}
