import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Users, X, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuthStore } from "@/stores/authStore";
import { listManagedCreators } from "@/api/endpoints/delegates";
import type { ManagedCreatorOut } from "@/api/types";

/**
 * Banner shown at the top of the messages page when in delegate mode.
 * Shows "Managing @creatorName" with a creator switcher dropdown and exit button.
 */
export function DelegateBanner() {
  const managingCreatorId = useAuthStore((s) => s.managingCreatorId);
  const managingCreatorName = useAuthStore((s) => s.managingCreatorName);
  const setManagingCreator = useAuthStore((s) => s.setManagingCreator);

  const { data: managedCreators } = useQuery<ManagedCreatorOut[]>({
    queryKey: ["delegates", "managed"],
    queryFn: listManagedCreators,
    staleTime: 60_000,
  });

  if (!managingCreatorId) return null;

  const chatCreators = (managedCreators ?? []).filter(
    (c) =>
      c.status === "active" &&
      c.permissions.includes("chat_read"),
  );

  return (
    <div
      className="flex items-center gap-2 border-b border-border bg-blue-50 px-4 py-2 dark:bg-blue-950"
      data-testid="delegate-banner"
    >
      <Users className="h-4 w-4 text-blue-600 dark:text-blue-400" />
      <span className="text-sm font-medium text-blue-700 dark:text-blue-300">
        Managing @{managingCreatorName || managingCreatorId}
      </span>

      {chatCreators.length > 1 && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-6 px-2">
              <ChevronDown className="h-3 w-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            {chatCreators.map((c) => (
              <DropdownMenuItem
                key={c.creator_id}
                onClick={() =>
                  setManagingCreator(c.creator_id, c.label || c.creator_id)
                }
              >
                {c.label || c.creator_id}
                {c.creator_id === managingCreatorId && " (current)"}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}

      <div className="flex-1" />

      <Button
        variant="ghost"
        size="sm"
        className="h-6 gap-1 px-2 text-blue-600 dark:text-blue-400"
        onClick={() => setManagingCreator(null)}
        data-testid="exit-delegate-mode"
      >
        <X className="h-3 w-3" />
        Exit
      </Button>
    </div>
  );
}
