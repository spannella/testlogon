import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";

import { CampaignsPanel } from "./CampaignsPanel";
import { ContactListsPanel } from "./ContactListsPanel";
import { SegmentsPanel } from "./SegmentsPanel";
import { TrackingCodesPanel } from "./TrackingCodesPanel";

/**
 * OFBiz MARKETING (MKT) console.
 * Backend: app/routers/marketing_campaigns.py (/ui/marketing + /ui/admin/marketing).
 * Gated by MARKETING_CAMPAIGNS_ENABLED (default OFF) — each panel surfaces a
 * graceful "not enabled" state when the backend returns 404/503.
 */
export default function MarketingPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Marketing"
        description="Campaigns, contact lists, party segments and tracking codes."
      />

      <Tabs defaultValue="campaigns">
        <TabsList>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="lists">Contact lists</TabsTrigger>
          <TabsTrigger value="segments">Segments</TabsTrigger>
          <TabsTrigger value="tracking">Tracking codes</TabsTrigger>
        </TabsList>

        <TabsContent value="campaigns" className="mt-4">
          <CampaignsPanel />
        </TabsContent>
        <TabsContent value="lists" className="mt-4">
          <ContactListsPanel />
        </TabsContent>
        <TabsContent value="segments" className="mt-4">
          <SegmentsPanel />
        </TabsContent>
        <TabsContent value="tracking" className="mt-4">
          <TrackingCodesPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
