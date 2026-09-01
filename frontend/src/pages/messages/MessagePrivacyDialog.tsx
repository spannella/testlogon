import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { X, ShieldCheck } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { UserSearch } from "./UserSearch";
import type { UserSearchResult } from "@/api/types";
import {
  getMessagePrivacy,
  updateMessagePrivacy,
  addAllowlist,
  removeAllowlist,
} from "@/api/endpoints/messaging";
import {
  defaultMessagePrivacy,
  validateMinAmountCents,
  formatCents,
  describePrivacy,
  type MessagePrivacy,
} from "@/lib/messagePrivacy";

const QUERY_KEY = ["messaging", "privacy", "message"] as const;

interface MessagePrivacyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Pay-to-message (TIP-401) settings surface: toggle the tip gate, set the
 * minimum tip in integer cents, and manage the tip-free allowlist. Reads
 * degrade-on-404 (honest-empty, gate off); mutations surface an error toast.
 */
export function MessagePrivacyDialog({ open, onOpenChange }: MessagePrivacyDialogProps) {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery<MessagePrivacy>({
    queryKey: QUERY_KEY,
    queryFn: getMessagePrivacy,
    enabled: open,
    retry: false,
  });

  const privacy = data ?? defaultMessagePrivacy();

  // Local draft of the min-amount field (cents, as a string for the input).
  const [amountInput, setAmountInput] = React.useState<string>("");
  React.useEffect(() => {
    if (data) setAmountInput(String(data.min_tip_cents));
  }, [data]);

  const write = (next: MessagePrivacy) => queryClient.setQueryData(QUERY_KEY, next);

  const toggleMutation = useMutation({
    mutationFn: (require: boolean) => updateMessagePrivacy({ require_tip_to_message: require }),
    onSuccess: write,
    onError: () => toast.error("Could not update your message privacy. Try again."),
  });

  const amountMutation = useMutation({
    mutationFn: (cents: number) => updateMessagePrivacy({ min_tip_cents: cents }),
    onSuccess: (next) => {
      write(next);
      toast.success(`Minimum tip set to ${formatCents(next.min_tip_cents)}.`);
    },
    onError: () => toast.error("Could not save the minimum amount. Try again."),
  });

  const addMutation = useMutation({
    mutationFn: (userId: string) => addAllowlist(userId),
    onSuccess: write,
    onError: () => toast.error("Could not add that person to the allowlist."),
  });

  const removeMutation = useMutation({
    mutationFn: (userId: string) => removeAllowlist(userId),
    onSuccess: write,
    onError: () => toast.error("Could not remove that person from the allowlist."),
  });

  const amountValidation = validateMinAmountCents(amountInput);
  const amountDirty = amountInput !== String(privacy.min_tip_cents);

  const handleSaveAmount = () => {
    if (!amountValidation.ok) return;
    amountMutation.mutate(amountValidation.cents);
  };

  const handleAddUser = (user: UserSearchResult) => {
    if (!user.user_id) return;
    if (privacy.tip_free_allowlist.includes(user.user_id)) return;
    addMutation.mutate(user.user_id);
  };

  const busy =
    toggleMutation.isPending ||
    amountMutation.isPending ||
    addMutation.isPending ||
    removeMutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            Message Privacy
          </DialogTitle>
          <DialogDescription>{describePrivacy(privacy)}</DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-6 text-center text-sm text-muted-foreground">Loading...</div>
        ) : (
          <div className="space-y-4">
            {/* Require-tip toggle */}
            <div className="flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <Label htmlFor="require-tip" className="text-sm font-medium">
                  Require a tip to message me
                </Label>
                <p className="text-xs text-muted-foreground">
                  New senders must attach a tip to reach your inbox.
                </p>
              </div>
              <Switch
                id="require-tip"
                checked={privacy.require_tip_to_message}
                disabled={busy}
                onCheckedChange={(v) => toggleMutation.mutate(v)}
              />
            </div>

            {privacy.require_tip_to_message && (
              <>
                <Separator />
                {/* Minimum amount (cents) */}
                <div className="space-y-1.5">
                  <Label htmlFor="min-amount" className="text-sm font-medium">
                    Minimum tip (cents)
                  </Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="min-amount"
                      type="number"
                      min={0}
                      step={1}
                      inputMode="numeric"
                      value={amountInput}
                      disabled={busy}
                      onChange={(e) => setAmountInput(e.target.value)}
                      className="w-32"
                    />
                    <span className="text-sm text-muted-foreground">
                      = {formatCents(amountValidation.cents)}
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      className="ml-auto"
                      disabled={busy || !amountValidation.ok || !amountDirty}
                      onClick={handleSaveAmount}
                    >
                      Save
                    </Button>
                  </div>
                  {!amountValidation.ok && amountInput !== "" && (
                    <p className="text-xs text-destructive">{amountValidation.error}</p>
                  )}
                </div>

                <Separator />
                {/* Allowlist */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium">Tip-free allowlist</Label>
                  <p className="text-xs text-muted-foreground">
                    These people can always message you for free.
                  </p>
                  <UserSearch
                    onSelect={handleAddUser}
                    placeholder="Add a person to the allowlist..."
                  />
                  {privacy.tip_free_allowlist.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No one is exempt yet.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {privacy.tip_free_allowlist.map((uid) => (
                        <Badge key={uid} variant="secondary" className="gap-1 pr-1">
                          <span className="max-w-[10rem] truncate">{uid}</span>
                          <button
                            type="button"
                            aria-label={`Remove ${uid}`}
                            className="rounded-full p-0.5 hover:bg-muted"
                            disabled={busy}
                            onClick={() => removeMutation.mutate(uid)}
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
