import { Badge } from "@/components/ui/badge";

type BadgeVariant =
  | "default"
  | "secondary"
  | "destructive"
  | "success"
  | "warning"
  | "outline";

const STATUS_META: Record<string, { label: string; variant: BadgeVariant }> = {
  compliant: { label: "Compliant", variant: "success" },
  resolved: { label: "Resolved", variant: "success" },
  expiring_soon: { label: "Expiring Soon", variant: "warning" },
  flagged: { label: "Flagged", variant: "warning" },
  license_expired: { label: "License Expired", variant: "destructive" },
  license_revoked: { label: "License Revoked", variant: "destructive" },
  under_review: { label: "Under Review", variant: "secondary" },
  action_required: { label: "Action Required", variant: "destructive" },
  removed: { label: "Removed", variant: "destructive" },
  open: { label: "Open", variant: "warning" },
  investigating: { label: "Investigating", variant: "secondary" },
  dismissed: { label: "Dismissed", variant: "outline" },
};

export function ComplianceBadge({ status }: { status: string }) {
  const meta = STATUS_META[status] ?? {
    label: status || "Unknown",
    variant: "outline" as BadgeVariant,
  };
  return (
    <Badge variant={meta.variant} data-status={status}>
      {meta.label}
    </Badge>
  );
}

export default ComplianceBadge;
