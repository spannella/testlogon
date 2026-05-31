import { CheckCircle, ShieldCheck, Award, Building2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const TIER_CONFIG: Record<number, { label: string; variant: "secondary" | "default" | "outline" | "destructive"; icon: React.ReactNode | null }> = {
  0: { label: "Unverified", variant: "secondary", icon: null },
  1: { label: "Basic", variant: "default", icon: <CheckCircle className="h-3 w-3 mr-1" /> },
  2: { label: "ID Verified", variant: "default", icon: <ShieldCheck className="h-3 w-3 mr-1" /> },
  3: { label: "Enhanced", variant: "default", icon: <Award className="h-3 w-3 mr-1" /> },
  4: { label: "Institutional", variant: "default", icon: <Building2 className="h-3 w-3 mr-1" /> },
};

interface KycTierBadgeProps {
  tier: number;
  className?: string;
}

export default function KycTierBadge({ tier, className }: KycTierBadgeProps) {
  const config = TIER_CONFIG[tier] ?? TIER_CONFIG[0]!;
  return (
    <Badge variant={config.variant} className={className} data-testid="kyc-tier-badge">
      {config.icon}
      {config.label}
    </Badge>
  );
}
