import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { BillingOverview } from "./BillingOverview";
import { PaymentMethods } from "./PaymentMethods";
import { Ledger } from "./Ledger";
import { Subscriptions } from "./Subscriptions";
import ImpersonationRouteIndicator from "@/components/shared/ImpersonationRouteIndicator";

export default function BillingPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Billing"
        description="Manage your balance, payment methods, and subscriptions"
      />
      <ImpersonationRouteIndicator area="billing" />

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="methods">Methods</TabsTrigger>
          <TabsTrigger value="ledger">Ledger</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <BillingOverview />
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
