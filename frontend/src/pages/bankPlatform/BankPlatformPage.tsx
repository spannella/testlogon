/**
 * OBP Platform Developer Dashboard (PLT-001..PLT-005)
 *
 * Sub-views (tabs):
 *  - glossary    PLT-003: API Glossary
 *  - leaderboard PLT-002: Metrics Leaderboard (admin)
 *  - rate-limits PLT-001: Consumer Rate-Limit Info
 *  - webhooks    PLT-005: Ledger Webhook Threshold
 *  - sandbox     PLT-004: Sandbox Import (admin + dev only)
 */

import { useSearchParams } from "react-router-dom";
import { BookOpen, Gauge, KeyRound, Bell, FlaskConical } from "lucide-react";

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";

import GlossaryTab from "./GlossaryTab";
import LeaderboardTab from "./LeaderboardTab";
import RateLimitsTab from "./RateLimitsTab";
import LedgerWebhooksTab from "./LedgerWebhooksTab";
import SandboxTab from "./SandboxTab";

type Tab = "glossary" | "leaderboard" | "rate-limits" | "webhooks" | "sandbox";

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "glossary", label: "API Glossary", icon: <BookOpen className="h-4 w-4" /> },
  { id: "leaderboard", label: "Metrics Leaderboard", icon: <Gauge className="h-4 w-4" /> },
  { id: "rate-limits", label: "Rate Limits", icon: <KeyRound className="h-4 w-4" /> },
  { id: "webhooks", label: "Ledger Webhooks", icon: <Bell className="h-4 w-4" /> },
  { id: "sandbox", label: "Sandbox", icon: <FlaskConical className="h-4 w-4" /> },
];

export default function BankPlatformPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get("tab") as Tab | null;
  const activeTab: Tab = TABS.some((t) => t.id === rawTab) ? rawTab! : "glossary";

  function setTab(tab: Tab) {
    setSearchParams({ tab });
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Platform Developer Dashboard"
        description="OBP platform surface — glossary, metrics, rate limits, ledger webhooks, and sandbox tools."
      />

      <Tabs value={activeTab} onValueChange={(v) => setTab(v as Tab)}>
        <TabsList className="flex flex-wrap gap-1 h-auto">
          {TABS.map((t) => (
            <TabsTrigger key={t.id} value={t.id} className="flex items-center gap-1.5">
              {t.icon}
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="glossary" className="mt-4">
          <GlossaryTab />
        </TabsContent>

        <TabsContent value="leaderboard" className="mt-4">
          <LeaderboardTab />
        </TabsContent>

        <TabsContent value="rate-limits" className="mt-4">
          <RateLimitsTab />
        </TabsContent>

        <TabsContent value="webhooks" className="mt-4">
          <LedgerWebhooksTab />
        </TabsContent>

        <TabsContent value="sandbox" className="mt-4">
          <SandboxTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
