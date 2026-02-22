import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import UsageBillingOverview from "./UsageBillingOverview";
import { BillingOverview } from "./BillingOverview";
import { PaymentMethods } from "./PaymentMethods";
import { Ledger } from "./Ledger";
import { Subscriptions } from "./Subscriptions";
import ImpersonationRouteIndicator from "@/components/shared/ImpersonationRouteIndicator";

const TAB_VALUES = ["usage", "overview", "methods", "ledger", "subscriptions"] as const;

type TabValue = (typeof TAB_VALUES)[number];

export default function BillingPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = useMemo<TabValue>(() => {
    const tab = searchParams.get("tab");
    return TAB_VALUES.includes(tab as TabValue) ? (tab as TabValue) : "usage";
  }, [searchParams]);

  const setTab = (tab: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("tab", tab);
      return next;
    });
  };

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Usage & Billing"
        description="Track file usage, limits, and billing details"
      />
      <ImpersonationRouteIndicator area="billing" />

      <Tabs value={activeTab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="methods">Methods</TabsTrigger>
          <TabsTrigger value="ledger">Ledger</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
        </TabsList>
        <TabsContent value="usage">
          <UsageBillingOverview />
        </TabsContent>
        <TabsContent value="overview">
          <BillingOverview onTabChange={setTab} />
        </TabsContent>
        <TabsContent value="methods">
          <PaymentMethods />
        </TabsContent>
        <TabsContent value="ledger">
          <Ledger />
        </TabsContent>
        <TabsContent value="subscriptions">
          <Subscriptions />
        </TabsContent>
      </Tabs>
    </div>
  );
}
