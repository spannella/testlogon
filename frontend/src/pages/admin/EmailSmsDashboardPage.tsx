import { useState } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import EmailDashboardPanel from "@/pages/admin/EmailDashboardPanel";
import SmsDashboardPanel from "@/pages/admin/SmsDashboardPanel";
import MessagingTemplatesPanel from "@/pages/admin/MessagingTemplatesPanel";

export default function EmailSmsDashboardPage() {
  const [days, setDays] = useState(7);

  return (
    <div className="space-y-6 p-4 md:p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Communications</h1>
          <p className="text-sm text-muted-foreground">
            Email &amp; SMS delivery health, suppressions, and notification templates.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Window</span>
          <select
            className="rounded border bg-background px-2 py-1 text-sm"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            data-testid="comms-days-select"
          >
            <option value={1}>1 day</option>
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </select>
        </label>
      </div>

      <Tabs defaultValue="email">
        <TabsList>
          <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="sms">SMS</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>
        <TabsContent value="email" className="mt-4">
          <EmailDashboardPanel days={days} />
        </TabsContent>
        <TabsContent value="sms" className="mt-4">
          <SmsDashboardPanel days={days} />
        </TabsContent>
        <TabsContent value="templates" className="mt-4">
          <MessagingTemplatesPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
