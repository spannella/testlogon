import { useInfiniteQuery } from "@tanstack/react-query";
import { getConversationGallery } from "@/api/endpoints/messaging";
import type { MessageGalleryType } from "@/api/types";

export function useConversationGallery(
  conversationId: string,
  type: MessageGalleryType,
  enabled: boolean,
  limit = 30,
) {
  return useInfiniteQuery({
    queryKey: ["conversation-gallery", conversationId, type, limit],
    queryFn: ({ pageParam }) => getConversationGallery(conversationId, { type, cursor: pageParam, limit }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled,
  });
}
