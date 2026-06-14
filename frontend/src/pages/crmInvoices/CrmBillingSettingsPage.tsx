import { PageHeader } from "@/components/shared/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CurrencyAdminPanel } from "./CurrencyAdminPanel";
import { TaxRateAdminPanel } from "./TaxRateAdminPanel";

export default function CrmBillingSettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Currency & Tax Settings"
        description="Manage the SuiteCRM currency registry and tax-rate definitions used by invoices."
      />
      <Tabs defaultValue="currencies">
        <TabsList>
          <TabsTrigger value="currencies">Currencies</TabsTrigger>
          <TabsTrigger value="tax-rates">Tax Rates</TabsTrigger>
        </TabsList>
        <TabsContent value="currencies" className="mt-4">
          <CurrencyAdminPanel />
        </TabsContent>
        <TabsContent value="tax-rates" className="mt-4">
          <TaxRateAdminPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
