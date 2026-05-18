import type { QueryClient } from "@tanstack/react-query";
import { feedQueryKeys } from "./feedQueryKeys";

export async function invalidateFeedCaches(queryClient: QueryClient, authorId?: string): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: feedQueryKeys.all });

  if (authorId) {
    await queryClient.invalidateQueries({
      queryKey: feedQueryKeys.timeline({ authorId }),
      exact: false,
    });
  }
}
