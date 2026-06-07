import { useState } from "react";
import { Ban, MoreVertical } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { blockUser, unblockUser, getBlockStatus } from "@/api/endpoints/blocking";

interface BlockButtonProps {
  targetUserId: string;
  targetDisplayName?: string;
}

export function BlockButton({ targetUserId, targetDisplayName = "this user" }: BlockButtonProps) {
  const queryClient = useQueryClient();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const statusQ = useQuery({
    queryKey: ["block-status", targetUserId],
    queryFn: () => getBlockStatus(targetUserId),
    enabled: Boolean(targetUserId),
    staleTime: 30_000,
  });

  const isBlocked = statusQ.data?.is_blocked_by_me ?? false;

  const blockMut = useMutation({
    mutationFn: () => blockUser({ target_user_id: targetUserId }),
    onSuccess: () => {
      toast.success(`${targetDisplayName} has been blocked`);
      void queryClient.invalidateQueries({ queryKey: ["block-status", targetUserId] });
      void queryClient.invalidateQueries({ queryKey: ["blocked-users"] });
    },
    onError: () => toast.error("Failed to block user"),
  });

  const unblockMut = useMutation({
    mutationFn: () => unblockUser({ target_user_id: targetUserId }),
    onSuccess: () => {
      toast.success(`${targetDisplayName} has been unblocked`);
      void queryClient.invalidateQueries({ queryKey: ["block-status", targetUserId] });
      void queryClient.invalidateQueries({ queryKey: ["blocked-users"] });
    },
    onError: () => toast.error("Failed to unblock user"),
  });

  if (statusQ.isLoading) return null;

  if (isBlocked) {
    return (
      <Button
        variant="outline"
        size="sm"
        className="w-full text-destructive border-destructive sm:w-auto"
        onClick={() => unblockMut.mutate()}
        disabled={unblockMut.isPending}
        data-testid="block-button-unblock"
      >
        <Ban className="mr-2 h-4 w-4" />
        Unblock
      </Button>
    );
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" aria-label="More actions" data-testid="block-button-more">
            <MoreVertical className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            className="text-destructive focus:text-destructive"
            onClick={() => setConfirmOpen(true)}
            data-testid="block-button-menuitem"
          >
            <Ban className="mr-2 h-4 w-4" />
            Block {targetDisplayName}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Block {targetDisplayName}?</AlertDialogTitle>
            <AlertDialogDescription>
              Blocking this user will prevent them from messaging you or seeing your content.
              You can unblock at any time from their profile or Settings → Blocked Users.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                blockMut.mutate();
                setConfirmOpen(false);
              }}
              disabled={blockMut.isPending}
            >
              Block
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
