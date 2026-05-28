import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban } from "lucide-react";
import { toast } from "sonner";

import { getBlockedUsers, unblockUser } from "@/api/endpoints/blocking";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function BlockedUsersPage() {
  const queryClient = useQueryClient();

  const blockedQ = useQuery({
    queryKey: ["blocked-users"],
    queryFn: () => getBlockedUsers({ limit: "100" }),
  });

  const unblockMut = useMutation({
    mutationFn: (userId: string) => unblockUser({ target_user_id: userId }),
    onSuccess: () => {
      toast.success("User unblocked");
      queryClient.invalidateQueries({ queryKey: ["blocked-users"] });
      queryClient.invalidateQueries({ queryKey: ["social", "status"] });
    },
    onError: () => toast.error("Failed to unblock user"),
  });

  const blockedUsers = blockedQ.data?.blocked_users ?? [];

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Blocked Users"
        description="Manage users you have blocked. Blocked users cannot message you or see your content."
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Ban className="h-4 w-4" />
            Blocked Users
          </CardTitle>
        </CardHeader>
        <CardContent>
          {blockedQ.isLoading && (
            <p className="text-sm text-muted-foreground">Loading...</p>
          )}

          {!blockedQ.isLoading && blockedUsers.length === 0 && (
            <p className="text-sm text-muted-foreground">
              You haven't blocked anyone
            </p>
          )}

          {blockedUsers.length > 0 && (
            <ul className="divide-y divide-border">
              {blockedUsers.map((user) => (
                <li
                  key={user.user_id}
                  className="flex items-center justify-between py-3"
                >
                  <div className="flex items-center gap-3">
                    {user.profile_photo_url ? (
                      <img
                        src={user.profile_photo_url}
                        alt={user.display_name ?? user.user_id}
                        className="h-8 w-8 rounded-full object-cover"
                      />
                    ) : (
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
                        {(user.display_name ?? user.user_id)
                          .slice(0, 1)
                          .toUpperCase()}
                      </div>
                    )}
                    <div>
                      <p className="text-sm font-medium">
                        {user.display_name ?? user.user_id}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Blocked {user.blocked_at ? new Date(user.blocked_at).toLocaleDateString() : ""}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={unblockMut.isPending}
                    onClick={() => unblockMut.mutate(user.user_id)}
                  >
                    Unblock
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
