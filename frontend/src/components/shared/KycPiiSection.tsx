/**
 * KycPiiSection (KYC-023) -- Drop-in admin panel for a KYC case detail view.
 *
 * Renders masked PII by default with per-field "Reveal" buttons for the assigned
 * admin, plus a root-only audit log and key-management actions (rotate / destroy).
 * Composes PiiFieldDisplay + PiiAuditLog and the kyc-cases endpoints.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, ShieldX, Loader2 } from "lucide-react";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { PiiFieldDisplay } from "@/components/shared/PiiFieldDisplay";
import { PiiAuditLog } from "@/components/shared/PiiAuditLog";
import {
  getMaskedPii,
  rotateUserKey,
  destroyUserKeys,
} from "@/api/endpoints/kyc-cases";

export interface KycPiiSectionProps {
  caseId: string;
  /** The case owner's user sub (target of key rotation / destruction). */
  userSub: string;
  /** True if the viewer is the assigned admin (or root) and may reveal PII. */
  canReveal: boolean;
  /** True if the viewer is root (audit log + key management). */
  isRoot: boolean;
}

export function KycPiiSection({
  caseId,
  userSub,
  canReveal,
  isRoot,
}: KycPiiSectionProps) {
  const queryClient = useQueryClient();
  const [confirmDestroy, setConfirmDestroy] = useState(false);

  const maskedQuery = useQuery({
    queryKey: ["kyc", "pii-masked", caseId],
    queryFn: () => getMaskedPii(caseId),
    staleTime: 30_000,
  });

  const rotateMut = useMutation({
    mutationFn: () => rotateUserKey(userSub),
    onSuccess: (r) => {
      toast.success(`Key rotated to v${r.new_version} (${r.fields_re_encrypted} fields).`);
      queryClient.invalidateQueries({ queryKey: ["kyc", "pii-masked", caseId] });
    },
    onError: () => toast.error("Key rotation failed."),
  });

  const destroyMut = useMutation({
    mutationFn: () => destroyUserKeys(userSub),
    onSuccess: (r) => {
      toast.success(`Destroyed ${r.keys_destroyed} key(s); ${r.fields_affected} field(s) now unrecoverable.`);
      setConfirmDestroy(false);
      queryClient.invalidateQueries({ queryKey: ["kyc", "pii-masked", caseId] });
    },
    onError: () => toast.error("Key destruction failed."),
  });

  const pii = maskedQuery.data?.pii ?? {};
  const fieldNames = Object.keys(pii);

  return (
    <Card data-testid="kyc-pii-section">
      <CardHeader>
        <CardTitle>Sensitive PII</CardTitle>
        <CardDescription>
          Fields are encrypted at rest and masked by default. Revealing logs an
          audit entry.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {maskedQuery.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading…
          </div>
        ) : fieldNames.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="kyc-pii-empty">
            No encrypted PII on this case.
          </p>
        ) : (
          <div className="divide-y">
            {fieldNames.map((fn) => (
              <PiiFieldDisplay
                key={fn}
                fieldName={fn}
                maskedValue={pii[fn] ?? "****"}
                canReveal={canReveal}
                caseId={caseId}
              />
            ))}
          </div>
        )}

        {isRoot && (
          <div className="space-y-3 border-t pt-4">
            <h4 className="text-sm font-semibold">Key management</h4>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => rotateMut.mutate()}
                disabled={rotateMut.isPending}
                data-testid="kyc-pii-rotate"
              >
                <KeyRound className="mr-1 h-3.5 w-3.5" /> Rotate key
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => setConfirmDestroy(true)}
                data-testid="kyc-pii-destroy"
              >
                <ShieldX className="mr-1 h-3.5 w-3.5" /> Destroy keys
              </Button>
            </div>

            <div className="border-t pt-4">
              <h4 className="mb-2 text-sm font-semibold">PII access audit log</h4>
              <PiiAuditLog caseId={caseId} />
            </div>
          </div>
        )}
      </CardContent>

      <AlertDialog open={confirmDestroy} onOpenChange={setConfirmDestroy}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Destroy encryption keys?</AlertDialogTitle>
            <AlertDialogDescription>
              This action is irreversible. All encrypted PII for this user will
              become permanently unrecoverable (GDPR erasure).
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                destroyMut.mutate();
              }}
              data-testid="kyc-pii-destroy-confirm"
            >
              Destroy permanently
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

export default KycPiiSection;
