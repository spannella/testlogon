import { Link } from "react-router-dom";
import {
  Boxes,
  PackageCheck,
  BookOpen,
  Scale,
  Tags,
  ArrowRight,
  Lock,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface ModuleCard {
  label: string;
  description: string;
  icon: typeof Boxes;
  to?: string;
  live: boolean;
  note?: string;
}

const MODULES: ModuleCard[] = [
  {
    label: "Inventory Levels",
    description: "On-hand, reserved and available stock per SKU. Set quantities, adjust deltas and reorder points.",
    icon: Boxes,
    to: "/erp/inventory",
    live: true,
  },
  {
    label: "Returns / RMA Queue",
    description: "Review customer return requests and drive them through the approve → receive → refund → close lifecycle.",
    icon: PackageCheck,
    to: "/erp/returns",
    live: true,
  },
  {
    label: "General Ledger",
    description: "Chart of accounts and journal entries.",
    icon: BookOpen,
    live: false,
    note: "No HTTP API mounted yet (GL service exists; router pending).",
  },
  {
    label: "AR / AP Aging",
    description: "Accounts-receivable and accounts-payable aging buckets.",
    icon: Scale,
    live: false,
    note: "No HTTP API mounted yet (AR/AP subledger service exists; router pending).",
  },
  {
    label: "Pricing Rules",
    description: "Promotional and tiered pricing rule management.",
    icon: Tags,
    live: false,
    note: "No admin HTTP API mounted yet (pricing engine consumed internally by cart).",
  },
];

export default function ErpOverviewPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="ERP"
        description="OFBiz-style core ERP administration — inventory, returns, and accounting."
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {MODULES.map((m) => {
          const Icon = m.icon;
          const inner = (
            <Card className={m.live ? "h-full transition-colors hover:border-primary" : "h-full opacity-75"}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-base">{m.label}</CardTitle>
                  </div>
                  {m.live ? (
                    <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <Badge variant="outline" className="gap-1">
                      <Lock className="h-3 w-3" /> No API
                    </Badge>
                  )}
                </div>
                <CardDescription>{m.description}</CardDescription>
              </CardHeader>
              {m.note && (
                <CardContent>
                  <p className="text-xs text-muted-foreground">{m.note}</p>
                </CardContent>
              )}
            </Card>
          );
          return m.live && m.to ? (
            <Link key={m.label} to={m.to} className="block">
              {inner}
            </Link>
          ) : (
            <div key={m.label}>{inner}</div>
          );
        })}
      </div>
    </div>
  );
}
