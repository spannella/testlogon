import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { AlertCenter } from "./AlertCenter";
import { AlertPrefs } from "./AlertPrefs";
import { PushDevices } from "./PushDevices";
import { ActivityFeed } from "./ActivityFeed";
import { MentionsFeed } from "./MentionsFeed";
import { TipsFeed } from "./TipsFeed";
import { TipsSentFeed } from "./TipsSentFeed";

export default function AlertsPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Alerts"
        description="View notifications and manage alert preferences"
      />

      <Tabs defaultValue="activity">
        <TabsList className="flex-wrap">
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="mentions">Mentions</TabsTrigger>
          <TabsTrigger value="tips">Tips & Earnings</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
          <TabsTrigger value="push">Push Devices</TabsTrigger>
        </TabsList>
        <TabsContent value="activity">
          <ActivityFeed />
        </TabsContent>
        <TabsContent value="mentions">
          <MentionsFeed />
        </TabsContent>
        <TabsContent value="tips">
          <div className="space-y-6">
            <TipsFeed />
            <TipsSentFeed />
          </div>
        </TabsContent>
        <TabsContent value="security">
          <AlertCenter />
        </TabsContent>
        <TabsContent value="all">
          <AlertCenter />
        </TabsContent>
        <TabsContent value="preferences">
          <AlertPrefs />
        </TabsContent>
        <TabsContent value="push">
          <PushDevices />
        </TabsContent>
      </Tabs>
    </div>
  );
}
