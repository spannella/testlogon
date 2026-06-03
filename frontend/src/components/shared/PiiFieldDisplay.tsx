/**
 * PiiFieldDisplay (KYC-023) -- Shows a masked PII field value with an optional
 * "Reveal" button for the assigned admin. Revealing prompts for a reason,
 * calls POST /pii/decrypt (audited), and auto-re-masks after a timeout.
 */
import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { decryptPii } from "@/api/endpoints/kyc-cases";

const REVEAL_TIMEOUT_MS = 30_000;

export interface PiiFieldDisplayProps {
  fieldName: string;
  maskedValue: string;
  /** True if the viewer is the assigned admin (or root) and may decrypt. */
  canReveal: boolean;
  caseId: string;
  onRevealed?: (plaintext: string) => void;
}

export function PiiFieldDisplay({
  fieldName,
  maskedValue,
  canReveal,
  caseId,
  onRevealed,
}: PiiFieldDisplayProps) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [reason, setReason] = useState("");
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const revealMut = useMutation({
    mutationFn: () =>
      decryptPii(caseId, { fields: [fieldName], reason: reason.trim() }),
    onSuccess: (resp) => {
      const value = resp.pii?.[fieldName] ?? "";
      setRevealed(value);
      onRevealed?.(value);
      setDialogOpen(false);
      setReason("");
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setRevealed(null), REVEAL_TIMEOUT_MS);
    },
    onError: () => {
      toast.error("Unable to reveal this field.");
    },
  });

  const hide = () => {
    setRevealed(null);
    if (timerRef.current) clearTimeout(timerRef.current);
  };

  return (
    <div
      className="flex items-center justify-between gap-2 py-1"
      data-testid={`pii-field-${fieldName}`}
    >
      <span className="text-sm text-muted-foreground">{fieldName}</span>
      <div className="flex items-center gap-2">
        <code className="font-mono text-sm" data-testid={`pii-value-${fieldName}`}>
          {revealed ?? maskedValue}
        </code>
        {canReveal && revealed === null && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => setDialogOpen(true)}
            data-testid={`pii-reveal-${fieldName}`}
          >
            <Eye className="mr-1 h-3.5 w-3.5" /> Reveal
          </Button>
        )}
        {canReveal && revealed !== null && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={hide}
            data-testid={`pii-hide-${fieldName}`}
          >
            <EyeOff className="mr-1 h-3.5 w-3.5" /> Hide
          </Button>
        )}
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reveal {fieldName}</DialogTitle>
            <DialogDescription>
              Accessing PII is logged for compliance. Enter a reason for viewing
              this field.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor={`pii-reason-${fieldName}`}>Reason</Label>
            <Input
              id={`pii-reason-${fieldName}`}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Reviewing case for Tier 2 approval"
              data-testid={`pii-reason-${fieldName}`}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => revealMut.mutate()}
              disabled={reason.trim().length < 3 || revealMut.isPending}
              data-testid={`pii-reveal-confirm-${fieldName}`}
            >
              {revealMut.isPending && (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              )}
              Reveal
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default PiiFieldDisplay;
