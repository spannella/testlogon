import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { shareFile, unshareFile, getSharedWith } from "@/api/endpoints/files";

interface ShareDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  filePath: string;
}

export function ShareDialog({ open, onOpenChange, filePath }: ShareDialogProps) {
  const [userId, setUserId] = React.useState("");
  const [permission, setPermission] = React.useState<"read" | "write">("read");
  const queryClient = useQueryClient();

  const shared = useQuery({
    queryKey: ["file-shared", filePath],
    queryFn: () => getSharedWith(filePath),
    enabled: open,
  });

  const addShare = useMutation({
    mutationFn: () => shareFile({ path: filePath, to_user: userId, permission }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["file-shared", filePath] });
      setUserId("");
    },
  });

  const removeShare = useMutation({
    mutationFn: (toUser: string) => unshareFile(filePath, toUser),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["file-shared", filePath] });
    },
  });

  const sharedWith = shared.data?.shared_with ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Share File</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <p className="text-xs text-muted-foreground font-mono truncate">{filePath}</p>

          {/* Add share */}
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="share-user">User ID</Label>
              <Input
                id="share-user"
                placeholder="Enter user ID"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
              />
            </div>
            <div className="w-28 space-y-1.5">
              <Label>Permission</Label>
              <Select value={permission} onValueChange={(v) => setPermission(v as "read" | "write")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="read">Read</SelectItem>
                  <SelectItem value="write">Write</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Current shares */}
          {sharedWith.length > 0 && (
            <div className="space-y-2">
              <Label>Shared with</Label>
              <div className="space-y-1">
                {sharedWith.map((s) => (
                  <div
                    key={s.user_id}
                    className="flex items-center justify-between rounded-lg border px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{s.user_id}</span>
                      <Badge variant="secondary" className="text-[10px]">
                        {s.permission}
                      </Badge>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive"
                      onClick={() => removeShare.mutate(s.user_id)}
                      disabled={removeShare.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            onClick={() => addShare.mutate()}
            disabled={!userId.trim() || addShare.isPending}
          >
            {addShare.isPending ? "Sharing..." : "Share"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
