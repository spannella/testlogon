import { Badge } from "@/components/ui/badge";

export type VerificationState = "pending" | "verified" | "rejected" | string;

/**
 * Shared badge that renders a KYC document / case verification state with a
 * consistent colour mapping. Extracted from the inline badge previously living
 * in KycCaseDetailPage so other admin panels can reuse it (GAP-0246).
 */
export function VerificationStateBadge({
  state,
  className,
}: {
  state: VerificationState;
  className?: string;
}) {
  const variant =
    state === "verified"
      ? "default"
      : state === "rejected"
        ? "destructive"
        : "outline";
  return (
    <Badge variant={variant} className={className} data-testid="verification-badge">
      {state}
    </Badge>
  );
}
