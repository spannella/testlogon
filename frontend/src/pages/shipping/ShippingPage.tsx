import { PageHeader } from "@/components/shared/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ShipmentsPanel } from "./ShipmentsPanel";
import { CarriersPanel } from "./CarriersPanel";
import { RateQuotePanel } from "./RateQuotePanel";

export default function ShippingPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Shipping & Logistics"
        description="Manage shipments, carriers, and shipping rates."
      />
      <Tabs defaultValue="shipments">
        <TabsList>
          <TabsTrigger value="shipments">Shipments</TabsTrigger>
          <TabsTrigger value="carriers">Carriers</TabsTrigger>
          <TabsTrigger value="rates">Rate quote</TabsTrigger>
        </TabsList>
        <TabsContent value="shipments" className="mt-4">
          <ShipmentsPanel />
        </TabsContent>
        <TabsContent value="carriers" className="mt-4">
          <CarriersPanel />
        </TabsContent>
        <TabsContent value="rates" className="mt-4">
          <RateQuotePanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
